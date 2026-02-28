import subprocess
import json
import os
import tempfile
from config import Config


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
    print(f"[HTTPX] Starting HTTP probing on {len(subdomains_list)} hosts")

    temp_file = None
    try:
        # Write subdomains to a temp file (one per line) for -l flag
        temp_fd, temp_file = tempfile.mkstemp(suffix=".txt", prefix="httpx_input_")
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
                "-status-code"
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
        print(f"[HTTPX] Found {count} HTTP assets")

        return {
            "success": True,
            "http_assets": http_assets,
            "count": count
        }

    except subprocess.TimeoutExpired:
        print(f"[HTTPX] Error: Timed out after {Config.SCAN_TIMEOUT}s")
        return {
            "success": False,
            "error": "HTTPX timed out",
            "http_assets": []
        }

    except FileNotFoundError:
        error = f"HTTPX not found at {Config.HTTPX_PATH}"
        print(f"[HTTPX] Error: {error}")
        return {
            "success": False,
            "error": error,
            "http_assets": []
        }

    except Exception as e:
        print(f"[HTTPX] Error: {e}")
        return {
            "success": False,
            "error": str(e),
            "http_assets": []
        }

    finally:
        # Clean up temp file
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)
