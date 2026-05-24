"""
Arjun HTTP Parameter Discovery Module
=======================================
Discovers hidden HTTP parameters on live web endpoints by sending
batched probe requests using a wordlist of ~25,890 parameter names.

Arjun is an ACTIVE tool — it sends real HTTP requests with parameter
fuzzing probes. It must be opt-in (enable_parameter_discovery) and
only runs against HTTPX-confirmed live HTTP endpoints.

Design:
    - Runs as Phase 3.5 (between HTTPX and Nuclei)
    - Gated by target scan_config.enable_parameter_discovery (default: false)
    - Uses --stable flag to reduce false positives
    - Rate-limited via Config.ARJUN_RATE_LIMIT
    - Output stored in ENDPOINT collection for future Nuclei integration
"""

import json
import os
import subprocess
import tempfile
from datetime import datetime
from typing import Any

from config import Config
from utils.logger import logger


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _resolve_tool_path(tool_path: str) -> str:
    if os.path.isabs(tool_path):
        return tool_path
    return os.path.abspath(os.path.join(_project_root(), tool_path))


def is_available() -> bool:
    """
    Check if Arjun is installed and callable.

    Arjun is a Python package (pip install arjun), so we check
    if the command exists rather than looking for a binary path.
    """
    arjun_path = _resolve_tool_path(Config.ARJUN_PATH)

    # If it's an absolute/relative path, check file existence
    if os.sep in arjun_path or arjun_path.endswith(".exe"):
        available = os.path.exists(arjun_path)
        if not available:
            logger.debug(
                "[ARJUN] Binary not found at %s — Arjun will be skipped",
                arjun_path
            )
        return available

    # Otherwise it's a command name — check if it's on PATH
    try:
        result = subprocess.run(
            [arjun_path, "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
        logger.debug(
            "[ARJUN] Command '%s' not found on PATH — Arjun will be skipped",
            arjun_path
        )
        return False


# Maximum URLs to scan (prevents hour-long scans on large targets)
MAX_ARJUN_URLS = 25

# Priority URL path patterns (these are scanned first)
_PRIORITY_PATHS = [
    "/api", "/admin", "/search", "/login", "/auth",
    "/oauth", "/graphql", "/webhook", "/dashboard",
    "/v1", "/v2", "/v3", "/users", "/account",
]


def _extract_live_urls(http_result: dict) -> list[str]:
    """
    Extract confirmed live HTTP URLs from HTTPX results.

    Arjun must only run against hosts that HTTPX confirmed as
    serving HTTP/HTTPS. This prevents wasted time probing SSH,
    MySQL, or other non-HTTP services.

    Applies smart URL selection:
      1. Prioritizes URLs with interesting paths (/api, /admin, etc.)
      2. Deduplicates by root origin (scheme://host)
      3. Caps at MAX_ARJUN_URLS to prevent excessive scan times

    Args:
        http_result: Output from Phase 3 (HTTPX)

    Returns:
        List of live URL strings (e.g. ["https://api.example.com"])
    """
    from urllib.parse import urlparse

    all_urls = []
    seen = set()

    for asset in http_result.get("http_assets", []):
        url = asset.get("url", "").strip()
        if url and url not in seen:
            seen.add(url)
            all_urls.append(url)

    if len(all_urls) <= MAX_ARJUN_URLS:
        return all_urls

    # Smart selection: prioritize interesting paths, then unique origins
    priority = []
    remaining = []

    for url in all_urls:
        path = urlparse(url).path.lower()
        if any(p in path for p in _PRIORITY_PATHS):
            priority.append(url)
        else:
            remaining.append(url)

    # Deduplicate remaining by origin (scheme://host)
    seen_origins = set()
    unique_remaining = []
    for url in remaining:
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        if origin not in seen_origins:
            seen_origins.add(origin)
            unique_remaining.append(url)

    selected = priority + unique_remaining
    selected = selected[:MAX_ARJUN_URLS]

    if len(all_urls) > len(selected):
        logger.info(
            "[ARJUN] Smart URL selection: %d/%d URLs selected "
            "(%d priority, %d unique origins)",
            len(selected), len(all_urls),
            len(priority), len(unique_remaining)
        )

    return selected


def _parse_arjun_output(json_path: str) -> list[dict[str, Any]]:
    """
    Parse Arjun's JSON output file into endpoint documents.

    Arjun output format:
        {
            "url": "https://example.com/search",
            "method": "GET",
            "params": ["q", "page", "lang"]
        }

    Args:
        json_path: Path to Arjun's -oJ output file

    Returns:
        List of endpoint dicts ready for MongoDB insertion
    """
    endpoints = []

    if not os.path.exists(json_path):
        logger.warning("[ARJUN] Output file not found: %s", json_path)
        return endpoints

    try:
        with open(json_path, "r", encoding="utf-8") as f:
            content = f.read().strip()

        if not content:
            return endpoints

        # Arjun outputs a JSON object keyed by URL
        # e.g. {"https://example.com/api": {"method": "GET", "params": ["id", "q"]}}
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            # Fallback: try JSONL (one object per line)
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                    if isinstance(item, dict) and "url" in item:
                        endpoints.append({
                            "url": item.get("url", ""),
                            "method": item.get("method", "GET"),
                            "parameters": item.get("params", []),
                        })
                except json.JSONDecodeError:
                    continue
            return endpoints

        # Handle Arjun's native dict-keyed format
        if isinstance(data, dict):
            for url, details in data.items():
                if isinstance(details, dict):
                    params = details.get("params", [])
                    method = details.get("method", "GET")
                elif isinstance(details, list):
                    params = details
                    method = "GET"
                else:
                    continue

                if params:
                    endpoints.append({
                        "url": url,
                        "method": method,
                        "parameters": params,
                    })

        # Handle array format
        elif isinstance(data, list):
            for item in data:
                if isinstance(item, dict) and item.get("params"):
                    endpoints.append({
                        "url": item.get("url", ""),
                        "method": item.get("method", "GET"),
                        "parameters": item.get("params", []),
                    })

    except Exception as exc:
        logger.error("[ARJUN] Error parsing output: %s", exc)

    return endpoints


def run_arjun(
    http_result: dict,
    rate_limit: int = None,
    domain: str = ""
) -> dict[str, Any]:
    """
    Run Arjun against HTTPX-confirmed live HTTP endpoints.

    Args:
        http_result: Output from Phase 3 (HTTPX fingerprinting)
        rate_limit:  Requests per second (overrides Config if set)
        domain:      Target domain (used for dynamic wordlist generation)

    Returns:
        {
            "success": bool,
            "endpoints": [...],
            "count": int,
            "error": "...",  # optional
        }
    """
    live_urls = _extract_live_urls(http_result)

    if not live_urls:
        logger.info("[ARJUN] No live HTTP URLs to scan — skipping")
        return {
            "success": True,
            "endpoints": [],
            "count": 0,
        }

    logger.info(
        "[ARJUN] Starting parameter discovery on %d live URLs",
        len(live_urls)
    )

    # Ensure temp directory exists
    temp_dir = os.path.join(
        os.path.dirname(__file__), "..", "temp"
    )
    os.makedirs(temp_dir, exist_ok=True)

    # Write URLs to temp input file
    input_path = os.path.join(temp_dir, "arjun_input.txt")
    output_path = os.path.join(temp_dir, "arjun_output.json")

    try:
        with open(input_path, "w", encoding="utf-8") as f:
            for url in live_urls:
                f.write(f"{url}\n")

        # Clean previous output if exists
        if os.path.exists(output_path):
            os.remove(output_path)

        # ── Build dynamic wordlist (if auto mode) ────────
        wordlist_path = None
        if Config.ARJUN_WORDLIST_MODE == "auto" and domain:
            try:
                from core.wordlist_builder import build_dynamic_wordlist
                wordlist_path = build_dynamic_wordlist(
                    http_result, domain
                )
                if wordlist_path:
                    logger.info(
                        "[ARJUN] Using dynamic wordlist: %s",
                        wordlist_path
                    )
            except Exception as wl_err:
                logger.warning(
                    "[ARJUN] Dynamic wordlist generation failed "
                    "(falling back to default): %s", wl_err
                )
        elif Config.ARJUN_WORDLIST_MODE in ("small", "medium", "large"):
            mode_map = {
                "small": Config.ARJUN_WORDLIST_SMALL,
                "medium": Config.ARJUN_WORDLIST_MEDIUM,
                "large": Config.ARJUN_WORDLIST_LARGE,
            }
            candidate = mode_map.get(Config.ARJUN_WORDLIST_MODE)
            if candidate and os.path.exists(candidate):
                wordlist_path = candidate
                logger.info(
                    "[ARJUN] Using %s wordlist: %s",
                    Config.ARJUN_WORDLIST_MODE, wordlist_path
                )

        # Build command
        rl = rate_limit or Config.ARJUN_RATE_LIMIT
        arjun_path = _resolve_tool_path(Config.ARJUN_PATH)
        cmd = [
            arjun_path,
            "-i", input_path,
            "-oJ", output_path,
            "--stable",
            "--rate-limit", str(rl),
            "--threads", str(Config.ARJUN_THREADS),
        ]

        # Attach dynamic wordlist if available
        if wordlist_path and os.path.exists(wordlist_path):
            cmd.extend(["-w", wordlist_path])

        logger.info("[ARJUN] Running: %s", " ".join(cmd))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.ARJUN_TIMEOUT,
            check=False,
        )

        stderr = (result.stderr or "").strip()
        if result.returncode != 0 and not os.path.exists(output_path):
            message = stderr or f"Arjun exited with code {result.returncode}"
            logger.error("[ARJUN] %s", message)
            return {
                "success": False,
                "endpoints": [],
                "count": 0,
                "error": message,
            }

        # Parse output
        endpoints = _parse_arjun_output(output_path)

        total_params = sum(
            len(ep.get("parameters", [])) for ep in endpoints
        )
        logger.info(
            "[ARJUN] Discovered %d endpoints with %d total parameters",
            len(endpoints), total_params
        )

        return {
            "success": True,
            "endpoints": endpoints,
            "count": len(endpoints),
        }

    except subprocess.TimeoutExpired:
        message = f"Arjun timed out after {Config.ARJUN_TIMEOUT}s"
        logger.error("[ARJUN] %s", message)
        return {
            "success": False,
            "endpoints": [],
            "count": 0,
            "error": message,
        }

    except Exception as exc:
        logger.error(
            "[ARJUN] Unexpected error: %s", exc, exc_info=True
        )
        return {
            "success": False,
            "endpoints": [],
            "count": 0,
            "error": str(exc),
        }

    finally:
        # Clean up temp files (input + output)
        for path in [input_path, output_path]:
            if os.path.exists(path):
                try:
                    os.remove(path)
                    logger.debug(
                        "[ARJUN] Cleaned up temp file: %s", path
                    )
                except Exception:
                    pass
