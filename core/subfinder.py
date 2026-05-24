"""
Subdomain discovery helpers.

This module intentionally stays lightweight and self-contained so the
pipeline orchestrator can import it without creating circular imports.
"""

import json
import os
import subprocess
from datetime import datetime
from typing import Any

import requests

from config import Config
from database.connection import get_db
from utils.logger import logger


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_tool_path(tool_path: str) -> str:
    if os.path.isabs(tool_path):
        return tool_path
    return os.path.abspath(os.path.join(_project_root(), tool_path))


def _normalize_subdomain(value: str, domain: str) -> str:
    subdomain = (value or "").strip().lower().rstrip(".")
    root = domain.strip().lower().rstrip(".")

    if not subdomain:
        return ""

    wildcard_prefixes = ("*.", ".")
    for prefix in wildcard_prefixes:
        if subdomain.startswith(prefix):
            subdomain = subdomain[len(prefix):]

    if subdomain == root or subdomain.endswith(f".{root}"):
        return subdomain

    return ""


def _parse_subfinder_output(stdout: str, domain: str) -> tuple[list[str], list[dict[str, Any]]]:
    subdomains = set()
    certificates: list[dict[str, Any]] = []

    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        if line.startswith("{"):
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                item = None

            if isinstance(item, dict):
                host = (
                    item.get("host")
                    or item.get("input")
                    or item.get("domain")
                    or item.get("name")
                    or ""
                )
                normalized = _normalize_subdomain(host, domain)
                if normalized:
                    subdomains.add(normalized)
                continue

        normalized = _normalize_subdomain(line, domain)
        if normalized:
            subdomains.add(normalized)

    return sorted(subdomains), certificates


def _extract_issuer_org(issuer_name: str) -> str:
    if not issuer_name:
        return "Unknown"

    try:
        if "O=" in issuer_name:
            organization = issuer_name.split("O=", 1)[1].split(",", 1)[0].strip()
            if organization:
                return organization
    except (AttributeError, IndexError):
        pass

    return "Unknown"


def _parse_crtsh_entry(entry: dict[str, Any], domain: str) -> tuple[set[str], dict[str, Any] | None]:
    subdomains = set()
    name_value = entry.get("name_value", "") or ""
    raw_names = []

    for line in name_value.splitlines():
        candidate = (line or "").strip().lower().rstrip(".")
        if not candidate:
            continue
        raw_names.append(candidate)
        normalized = _normalize_subdomain(candidate, domain)
        if normalized:
            subdomains.add(normalized)

    common_name_raw = (entry.get("common_name", "") or "").strip().lower().rstrip(".")
    common_name = _normalize_subdomain(common_name_raw, domain)
    serial_number = entry.get("serial_number", "") or ""

    if not serial_number:
        return subdomains, None

    certificate = {
        "serial_number": serial_number,
        "common_name": common_name,
        "san_domains": sorted(subdomains),
        "issuer_name": entry.get("issuer_name", "") or "",
        "issuer_org": _extract_issuer_org(entry.get("issuer_name", "") or ""),
        "not_before": entry.get("not_before"),
        "not_after": entry.get("not_after"),
        "crtsh_id": entry.get("id"),
        "issuer_ca_id": entry.get("issuer_ca_id"),
        "target_domain": domain,
        "is_wildcard": common_name_raw.startswith("*.") or any(name.startswith("*.") for name in raw_names),
    }
    return subdomains, certificate


def _run_crtsh(domain: str) -> tuple[list[str], list[dict[str, Any]]]:
    logger.info("[CRT.SH] Querying certificate transparency logs for %s", domain)

    try:
        response = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.Timeout:
        logger.warning("[CRT.SH] Request timed out for %s", domain)
        return [], []
    except requests.RequestException as exc:
        logger.warning("[CRT.SH] Request failed for %s: %s", domain, exc)
        return [], []
    except json.JSONDecodeError:
        logger.warning("[CRT.SH] Invalid JSON response for %s", domain)
        return [], []

    subdomains = set()
    certificates = []
    seen_serials = set()

    for entry in payload if isinstance(payload, list) else []:
        if not isinstance(entry, dict):
            continue

        entry_subdomains, certificate = _parse_crtsh_entry(entry, domain)
        subdomains.update(entry_subdomains)

        if not certificate:
            continue

        serial_number = certificate["serial_number"]
        if serial_number in seen_serials:
            continue

        seen_serials.add(serial_number)
        certificates.append(certificate)

    certificates.sort(
        key=lambda item: item.get("not_before") or "",
        reverse=True,
    )
    certificates = certificates[:500]

    logger.info(
        "[CRT.SH] Found %d subdomains and %d unique certificates for %s",
        len(subdomains),
        len(certificates),
        domain,
    )
    return sorted(subdomains), certificates


def scan_subdomains(domain: str) -> dict[str, Any]:
    """
    Run subfinder and return discovered subdomains.

    Returns:
        {
            "success": bool,
            "subdomains": [...],
            "count": int,
            "certificates": [...],
            "error": "...",  # optional
        }
    """
    normalized_domain = domain.strip().lower().rstrip(".")
    subfinder_path = _resolve_tool_path(Config.SUBFINDER_PATH)

    if not os.path.exists(subfinder_path):
        message = f"Subfinder binary not found at {subfinder_path}"
        logger.error(message)
        return {
            "success": False,
            "subdomains": [],
            "count": 0,
            "certificates": [],
            "error": message,
        }

    cmd = [subfinder_path, "-d", normalized_domain, "-silent", "-oJ"]
    logger.info("[SUBFINDER] Running: %s", " ".join(cmd))

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.SCAN_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired:
        message = f"Subfinder timed out after {Config.SCAN_TIMEOUT}s"
        logger.error("[SUBFINDER] %s", message)
        return {
            "success": False,
            "subdomains": [],
            "count": 0,
            "certificates": [],
            "error": message,
        }
    except Exception as exc:
        logger.error("[SUBFINDER] Execution failed: %s", exc, exc_info=True)
        return {
            "success": False,
            "subdomains": [],
            "count": 0,
            "certificates": [],
            "error": str(exc),
        }

    stderr = (result.stderr or "").strip()
    if result.returncode != 0:
        message = stderr or f"Subfinder exited with code {result.returncode}"
        logger.error("[SUBFINDER] %s", message)
        return {
            "success": False,
            "subdomains": [],
            "count": 0,
            "certificates": [],
            "error": message,
        }

    subfinder_subdomains, subfinder_certificates = _parse_subfinder_output(
        result.stdout or "",
        normalized_domain,
    )
    crtsh_subdomains, crtsh_certificates = _run_crtsh(normalized_domain)
    merged_subdomains = sorted(
        set(subfinder_subdomains) | set(crtsh_subdomains)
    )
    certificates = crtsh_certificates or subfinder_certificates
    logger.info(
        "[SUBFINDER] Found %d subdomains for %s",
        len(merged_subdomains),
        normalized_domain,
    )

    return {
        "success": True,
        "domain": normalized_domain,
        "subdomains": merged_subdomains,
        "count": len(merged_subdomains),
        "certificates": certificates,
        "stderr": stderr,
        "sources": {
            "subfinder": len(subfinder_subdomains),
            "crtsh": len(crtsh_subdomains),
        },
    }


def save_certificates(domain: str, certificates: list[dict[str, Any]]) -> dict[str, int]:
    """
    Persist certificate transparency records if any are provided.

    The current subfinder integration does not extract certificate details,
    but the scanner calls this helper defensively, so we keep it available
    and schema-compatible for future enrichment.
    """
    if not certificates:
        return {"saved": 0, "updated": 0}

    db = get_db()
    collection = db["certificates"]
    target_domain = domain.strip().lower().rstrip(".")
    saved = 0
    updated = 0

    for cert in certificates:
        if not isinstance(cert, dict):
            continue

        san_domains = []
        for san in cert.get("san_domains", []) or []:
            normalized = _normalize_subdomain(str(san), target_domain)
            if normalized:
                san_domains.append(normalized)

        san_domains = sorted(set(san_domains))
        common_name = _normalize_subdomain(
            str(cert.get("common_name", "")),
            target_domain,
        )

        doc = {
            "target_domain": target_domain,
            "common_name": common_name,
            "san_domains": san_domains,
            "issuer_org": cert.get("issuer_org", ""),
            "issuer_name": cert.get("issuer_name", ""),
            "not_before": cert.get("not_before"),
            "not_after": cert.get("not_after"),
            "serial_number": cert.get("serial_number", ""),
            "is_wildcard": bool(
                cert.get("is_wildcard")
                or common_name.startswith("*.")
                or any(s.startswith("*.") for s in cert.get("san_domains", []) or [])
            ),
            "crtsh_id": cert.get("crtsh_id"),
            "collected_at": cert.get("collected_at") or datetime.utcnow(),
        }

        identity = {
            "target_domain": target_domain,
            "common_name": doc["common_name"],
            "serial_number": doc["serial_number"],
        }

        existing = collection.find_one(identity, {"_id": 1})
        collection.update_one(identity, {"$set": doc}, upsert=True)
        if existing:
            updated += 1
        else:
            saved += 1

    logger.info(
        "[SUBFINDER] Saved %d new and %d updated certificates for %s",
        saved,
        updated,
        target_domain,
    )
    return {"saved": saved, "updated": updated}
