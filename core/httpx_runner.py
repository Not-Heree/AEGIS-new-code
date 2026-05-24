"""
HTTPX HTTP Probing Module (Enhanced)
=====================================
Invokes the httpx Go binary via subprocess to probe HTTP/HTTPS services
on a list of hosts. Output is JSONL (one JSON object per line).

Enhancements:
  - Optional response body extraction for JavaScript analysis
  - File type filtering (only store .js, .jsx, .ts, .tsx, .json)
  - Size limits to prevent disk bloat
  - Response headers storage
  - Enhanced error handling

HTTPX binary must be installed separately:
  - Windows: tools/httpx.exe
  - Linux: tools/httpx

Path configured via Config.HTTPX_PATH.
"""

import subprocess
import json
import os
import tempfile
from config import Config
from utils.logger import logger


def parse_httpx_output(raw_output):
    """
    Parse JSONL output from HTTPX.

    Each line is a JSON object with HTTP asset details.
    Returns list of parsed JSON objects, skipping invalid lines.
    """
    if not raw_output:
        return []

    results = []
    for line in raw_output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            results.append(data)
        except json.JSONDecodeError:
            logger.debug("[HTTPX] Skipping invalid JSON line: %s", line[:100])
            continue

    return results


def _should_store_body(url: str) -> bool:
    """
    Determine if response body should be stored based on file extension.

    Args:
        url: URL string

    Returns:
        True if body should be stored, False otherwise
    """
    if not Config.HTTPX_STORE_BODY:
        return False

    url_lower = url.lower()

    # Check if URL ends with allowed extension
    for ext in Config.HTTPX_BODY_EXTENSIONS:
        if url_lower.endswith(ext):
            return True

    # Also store bodies for URLs with no extension (might be API endpoints)
    # but only if they're not static files
    path = url_lower.split('?')[0]  # Remove query params
    if '.' not in path.split('/')[-1]:
        # No extension - might be API endpoint
        return True

    return False


def run_httpx(subdomains_list):
    """
    Run HTTPX to probe HTTP services on a list of subdomains.

    Args:
        subdomains_list: List of subdomain strings to probe

    Returns:
        {
            "success": bool,
            "http_assets": [...],
            "count": int,
            "error": str (optional)
        }
    """
    logger.info(
        "[HTTPX] Starting HTTP probing on %d hosts",
        len(subdomains_list)
    )

    temp_file = None
    try:
        # Write subdomains to a temp file (one per line) for -l flag
        temp_fd, temp_file = tempfile.mkstemp(
            suffix=".txt", prefix="httpx_input_"
        )
        with os.fdopen(temp_fd, "w") as f:
            f.write("\n".join(subdomains_list))

        #  Build HTTPX command with conditional body extraction
        cmd = [
            Config.HTTPX_PATH,
            "-l", temp_file,
            "-json",
            "-silent",
            "-title",
            "-web-server",
            "-tech-detect",
            "-status-code",
            "-content-length",
            "-threads", str(Config.HTTPX_THREADS),
            "-timeout", str(Config.HTTPX_TIMEOUT),
        ]

        #  Add response body extraction if enabled
        if Config.HTTPX_STORE_BODY:
            cmd.extend([
                "-irr",  # include-response: headers + body in JSON output
                "-bp", str(min(Config.HTTPX_BODY_MAX_SIZE, 2048)),  # body-preview chars
            ])
            logger.debug(
                "[HTTPX] Body extraction enabled (max %d bytes, types: %s)",
                Config.HTTPX_BODY_MAX_SIZE,
                ", ".join(Config.HTTPX_BODY_EXTENSIONS)
            )

        logger.debug("[HTTPX] Running: %s", " ".join(cmd))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.SCAN_TIMEOUT
        )

        # Parse the JSONL output
        parsed = parse_httpx_output(result.stdout)

        # Extract relevant fields from each result
        http_assets = []
        bodies_stored = 0

        for entry in parsed:
            url = entry.get("url", "")

            #  Build asset object
            asset = {
                "host": entry.get("host", ""),
                "url": url,
                "status_code": entry.get("status_code", 0),
                "title": entry.get("title", ""),
                "web_server": entry.get("webserver", ""),
                "tech": entry.get("tech", []),
                "content_length": entry.get("content_length", 0),
                "port": entry.get("port", 0),
            }

            #  Store response headers if available
            headers = entry.get("header")
            if headers:
                asset["headers"] = headers

            #  Conditionally store response body (only for JS files)
            if Config.HTTPX_STORE_BODY and _should_store_body(url):
                body = (
                    entry.get("body", "")
                    or entry.get("body-preview", "")
                    or entry.get("body_preview", "")
                    or entry.get("response-body", "")
                )
                if body:
                    # Truncate if over limit (safety check)
                    if len(body) > Config.HTTPX_BODY_MAX_SIZE:
                        body = body[:Config.HTTPX_BODY_MAX_SIZE]
                        logger.debug(
                            "[HTTPX] Truncated body for %s (over %d bytes)",
                            url, Config.HTTPX_BODY_MAX_SIZE
                        )

                    asset["body"] = body
                    bodies_stored += 1

            http_assets.append(asset)

        count = len(http_assets)
        logger.info("[HTTPX] Found %d HTTP assets", count)

        if Config.HTTPX_STORE_BODY:
            logger.info(
                "[HTTPX] Stored response bodies for %d assets (JS/JSON files)",
                bodies_stored
            )

        return {
            "success": True,
            "http_assets": http_assets,
            "count": count,
            "bodies_stored": bodies_stored,
        }

    except subprocess.TimeoutExpired:
        logger.error(
            "[HTTPX] Timed out after %ds", Config.SCAN_TIMEOUT
        )
        return {
            "success": False,
            "error": "HTTPX timed out",
            "http_assets": []
        }

    except FileNotFoundError:
        error = f"HTTPX not found at {Config.HTTPX_PATH}"
        logger.error("[HTTPX] %s", error)
        return {
            "success": False,
            "error": error,
            "http_assets": []
        }

    except Exception as e:
        logger.error("[HTTPX] Unexpected error: %s", e, exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "http_assets": []
        }

    finally:
        # Clean up temp file
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except Exception as e:
                logger.warning("[HTTPX] Failed to remove temp file: %s", e)
