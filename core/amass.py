"""
Amass Subdomain Discovery Module
==================================
Runs OWASP Amass in passive mode alongside Subfinder to widen
the subdomain discovery net without generating network traffic
toward the target.

Amass queries OSINT sources (certificate transparency, DNS aggregators,
web archives, GitHub, Pastebin, etc.) that Subfinder may not cover.

Design:
    - Passive-only by default (no DNS brute-forcing, no zone transfers)
    - Plain text output (Amass v4.0+ removed -json flag)
    - Fallback JSON parser for backwards compatibility
    - No Amass graph database integration — we use our own Change
      Detection Engine in Phase 5 for cross-scan diffing
    - Amass is a pure enumeration tool: it runs, outputs hostnames, exits
    - Graceful degradation: if Amass is not installed, pipeline skips it
"""

import json
import os
import subprocess
import tempfile
from typing import Any

from config import Config
from utils.logger import logger


def _project_root() -> str:
    """Get the absolute path to the project root directory."""
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_tool_path(tool_path: str) -> str:
    """
    Resolve tool path to absolute path.

    If path is already absolute, return as-is.
    Otherwise, resolve relative to project root.
    """
    if os.path.isabs(tool_path):
        return tool_path
    return os.path.abspath(os.path.join(_project_root(), tool_path))


def is_available() -> bool:
    """
    Check if the Amass binary exists at the configured path.

    Returns:
        True if Amass binary is found, False otherwise
    """
    resolved = _resolve_tool_path(Config.AMASS_PATH)
    available = os.path.exists(resolved)

    if available:
        logger.debug("[AMASS] Binary found at: %s", resolved)
    else:
        logger.debug(
            "[AMASS] Binary not found at %s — Amass will be skipped",
            resolved
        )

    return available


def _normalize_subdomain(value: str, domain: str) -> str:
    """
    Normalize a discovered hostname and validate it belongs to the target.

    Handles:
        - Wildcard prefixes (*., .)
        - Case normalization
        - Trailing dots
        - Domain scope validation

    Args:
        value: Raw subdomain string from Amass
        domain: Root domain to validate against

    Returns:
        Normalized subdomain string, or empty string if invalid
    """
    subdomain = (value or "").strip().lower().rstrip(".")
    root = domain.strip().lower().rstrip(".")

    if not subdomain:
        return ""

    # Remove wildcard prefixes
    wildcard_prefixes = ("*.", ".")
    for prefix in wildcard_prefixes:
        if subdomain.startswith(prefix):
            subdomain = subdomain[len(prefix):]

    # Validate subdomain belongs to target domain
    if subdomain == root or subdomain.endswith(f".{root}"):
        return subdomain

    return ""


def _parse_amass_output_file(output_file_path: str, domain: str) -> list[str]:
    """
    Parse Amass output file (supports both JSONL and plain text).

    Amass v3.x outputs JSONL format:
        {"name": "api.example.com", "domain": "example.com", "source": "CertSpotter"}
        {"name": "www.example.com", "domain": "example.com", "source": "Crtsh"}

    Amass v4.0+ outputs plain text format:
        api.example.com
        www.example.com
        mail.example.com

    This parser handles BOTH formats for backwards compatibility.

    Args:
        output_file_path: Path to Amass output file
        domain: Root domain for validation

    Returns:
        Sorted list of unique, normalized subdomains
    """
    subdomains = set()
    total_lines = 0
    json_lines = 0
    plaintext_lines = 0
    invalid_lines = 0

    if not os.path.exists(output_file_path):
        logger.error("[AMASS] Output file not found: %s", output_file_path)
        return []

    try:
        with open(output_file_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                total_lines += 1
                line = line.strip()

                if not line:
                    continue

                # Try parsing as JSON first (for Amass v3.x compatibility)
                try:
                    item = json.loads(line)
                    json_lines += 1

                    if not isinstance(item, dict):
                        logger.warning(
                            "[AMASS] Line %d: Expected dict, got %s",
                            line_num, type(item).__name__
                        )
                        continue

                    # Extract hostname from JSON
                    host = (
                        item.get("name")      # Standard Amass field
                        or item.get("host")   # Alternate field
                        or item.get("domain") # Fallback
                        or ""
                    )

                    if not host:
                        logger.debug(
                            "[AMASS] Line %d: No hostname found in JSON object",
                            line_num
                        )
                        continue

                    normalized = _normalize_subdomain(host, domain)
                    if normalized:
                        subdomains.add(normalized)
                        logger.debug(
                            "[AMASS] Line %d: Found JSON subdomain '%s' from source '%s'",
                            line_num, normalized, item.get("source", "unknown")
                        )
                    else:
                        logger.debug(
                            "[AMASS] Line %d: Subdomain '%s' rejected (out of scope)",
                            line_num, host
                        )

                except json.JSONDecodeError:
                    # FALLBACK: Treat as plain text subdomain (Amass v4.0+)
                    plaintext_lines += 1
                    normalized = _normalize_subdomain(line, domain)

                    if normalized:
                        subdomains.add(normalized)
                        logger.debug(
                            "[AMASS] Line %d: Found plain-text subdomain '%s'",
                            line_num, normalized
                        )
                    else:
                        invalid_lines += 1
                        logger.debug(
                            "[AMASS] Line %d: Invalid/out-of-scope entry '%s'",
                            line_num, line[:50]
                        )

    except FileNotFoundError:
        logger.error("[AMASS] Output file not found: %s", output_file_path)
        return []
    except PermissionError:
        logger.error("[AMASS] Permission denied reading file: %s", output_file_path)
        return []
    except Exception as e:
        logger.error(
            "[AMASS] Unexpected error reading output file: %s",
            e, exc_info=True
        )
        return []

    # Log parsing statistics
    logger.info(
        "[AMASS] Parsed %d lines: %d JSON, %d plain-text, %d invalid, %d unique subdomains",
        total_lines, json_lines, plaintext_lines, invalid_lines, len(subdomains)
    )

    return sorted(subdomains)


def run_amass(domain: str) -> dict[str, Any]:
    """
    Run Amass in passive mode for subdomain enumeration.

    Passive mode queries third-party data sources only — no DNS
    requests reach the target's infrastructure. This is appropriate
    for Phase 1 where we want broad coverage without active probing.

    Args:
        domain: Root domain to enumerate (e.g. "example.com")

    Returns:
        {
            "success": bool,
            "domain": str,
            "subdomains": list[str],
            "count": int,
            "stderr": str,         # Amass stderr output (warnings/info)
            "error": str,          # Error message if failed (optional)
        }
    """
    normalized_domain = domain.strip().lower().rstrip(".")
    amass_path = _resolve_tool_path(Config.AMASS_PATH)

    # Verify Amass binary exists
    if not os.path.exists(amass_path):
        message = f"Amass binary not found at {amass_path}"
        logger.error("[AMASS] %s", message)
        return {
            "success": False,
            "domain": normalized_domain,
            "subdomains": [],
            "count": 0,
            "error": message,
        }

    output_file = None

    try:
        # Create temporary file for output
        # Amass v4.0+ uses plain text output with -o flag
        with tempfile.NamedTemporaryFile(
            mode='w',
            suffix='.txt',
            prefix='amass_',
            delete=False
        ) as tmp:
            output_file = tmp.name

        logger.debug("[AMASS] Created temp output file: %s", output_file)


        cmd = [
            amass_path,
            "enum",                   # Subdomain enumeration mode
            "-passive",               # Passive mode only (no active DNS queries)
            "-d", normalized_domain,  # Target domain
            "-o", output_file,
        ]

        logger.info("[AMASS] Running: %s", " ".join(cmd))
        logger.info("[AMASS] Target domain: %s", normalized_domain)
        logger.info("[AMASS] Timeout: %ds", Config.AMASS_TIMEOUT)

        # Execute Amass
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.AMASS_TIMEOUT,
            check=False,  # Don't raise exception on non-zero exit
        )

        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()

        # Log Amass output
        if stdout:
            logger.debug("[AMASS] STDOUT:\n%s", stdout)
        if stderr:
            logger.debug("[AMASS] STDERR:\n%s", stderr)

        # Check exit code
        if result.returncode != 0:
            message = stderr or f"Amass exited with code {result.returncode}"
            logger.error("[AMASS] Execution failed: %s", message)
            return {
                "success": False,
                "domain": normalized_domain,
                "subdomains": [],
                "count": 0,
                "stderr": stderr,
                "error": message,
            }

        # Check if output file was created
        if not os.path.exists(output_file):
            message = "Amass did not create output file"
            logger.error("[AMASS] %s: %s", message, output_file)
            return {
                "success": False,
                "domain": normalized_domain,
                "subdomains": [],
                "count": 0,
                "stderr": stderr,
                "error": message,
            }

        # Check if output file is empty
        file_size = os.path.getsize(output_file)
        if file_size == 0:
            logger.warning(
                "[AMASS] Output file is empty - no subdomains found for %s",
                normalized_domain
            )
            return {
                "success": True,
                "domain": normalized_domain,
                "subdomains": [],
                "count": 0,
                "stderr": stderr,
            }

        logger.debug("[AMASS] Output file size: %d bytes", file_size)


        subdomains = _parse_amass_output_file(output_file, normalized_domain)

        logger.info(
            "[AMASS] Successfully enumerated %d subdomains for %s",
            len(subdomains), normalized_domain
        )

        return {
            "success": True,
            "domain": normalized_domain,
            "subdomains": subdomains,
            "count": len(subdomains),
            "stderr": stderr,
        }

    except subprocess.TimeoutExpired:
        message = f"Amass timed out after {Config.AMASS_TIMEOUT}s"
        logger.error("[AMASS] %s", message)
        return {
            "success": False,
            "domain": normalized_domain,
            "subdomains": [],
            "count": 0,
            "error": message,
        }

    except FileNotFoundError:
        message = f"Amass binary not found: {amass_path}"
        logger.error("[AMASS] %s", message)
        return {
            "success": False,
            "domain": normalized_domain,
            "subdomains": [],
            "count": 0,
            "error": message,
        }

    except PermissionError:
        message = f"Permission denied executing Amass: {amass_path}"
        logger.error("[AMASS] %s", message)
        return {
            "success": False,
            "domain": normalized_domain,
            "subdomains": [],
            "count": 0,
            "error": message,
        }

    except Exception as exc:
        logger.error("[AMASS] Unexpected error: %s", exc, exc_info=True)
        return {
            "success": False,
            "domain": normalized_domain,
            "subdomains": [],
            "count": 0,
            "error": str(exc),
        }

    finally:
        # Clean up temporary output file
        if output_file and os.path.exists(output_file):
            try:
                os.unlink(output_file)
                logger.debug("[AMASS] Deleted temp file: %s", output_file)
            except PermissionError:
                logger.warning(
                    "[AMASS] Could not delete temp file (permission denied): %s",
                    output_file
                )
            except Exception as e:
                logger.warning(
                    "[AMASS] Failed to delete temp file %s: %s",
                    output_file, e
                )