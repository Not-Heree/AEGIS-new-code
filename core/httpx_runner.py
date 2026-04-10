"""
HTTPX HTTP Probing Module
==========================
Invokes the httpx Go binary via subprocess to probe HTTP/HTTPS services
on a list of hosts. Output is JSONL (one JSON object per line).

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
    """Parse JSONL output from HTTPX.
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
            continue

    return results


def run_httpx(subdomains_list):
    """Run HTTPX to probe HTTP services on a list of subdomains."""
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

        result = subprocess.run(
            [
                Config.HTTPX_PATH,
                "-l", temp_file,
                "-json",
                "-silent",
                "-title",
                "-web-server",
                "-tech-detect",
                "-status-code",
                "-threads", str(Config.HTTPX_THREADS),
                "-timeout", str(Config.HTTPX_TIMEOUT)
            ],
            capture_output=True,
            text=True,
            timeout=Config.SCAN_TIMEOUT
        )

        # Parse the JSONL output
        parsed = parse_httpx_output(result.stdout)

        # Extract relevant fields from each result
        http_assets = []
        for entry in parsed:
            asset = {
                "host": entry.get("host", ""),
                "url": entry.get("url", ""),
                "status_code": entry.get("status_code", 0),
                "title": entry.get("title", ""),
                "web_server": entry.get("webserver", ""),
                "tech": entry.get("tech", []),
                "content_length": entry.get("content_length", 0),
                "port": entry.get("port", 0)
            }
            http_assets.append(asset)

        count = len(http_assets)
        logger.info("[HTTPX] Found %d HTTP assets", count)

        return {
            "success": True,
            "http_assets": http_assets,
            "count": count
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
            os.remove(temp_file)
