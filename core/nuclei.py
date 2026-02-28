import subprocess
import json
import os
import tempfile
from config import Config


def parse_nuclei_output(raw_output):
    """Parse JSONL output from Nuclei.
    Each line is a JSON object with vulnerability details.
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


def run_nuclei(subdomains_list):
    """Run Nuclei to scan for vulnerabilities on a list of subdomains."""
    print(f"[NUCLEI] Starting vulnerability scanning on {len(subdomains_list)} hosts")

    temp_file = None
    try:
        # Write subdomains to a temp file (one per line) for -l flag
        temp_fd, temp_file = tempfile.mkstemp(suffix=".txt", prefix="nuclei_input_")
        with os.fdopen(temp_fd, "w") as f:
            f.write("\n".join(subdomains_list))

        result = subprocess.run(
            [
                Config.NUCLEI_PATH,
                "-l", temp_file,
                "-s", Config.NUCLEI_SEVERITY,
                "-json",
                "-silent"
            ],
            capture_output=True,
            text=True,
            timeout=Config.SCAN_TIMEOUT
        )

        # Parse the JSONL output
        parsed = parse_nuclei_output(result.stdout)

        # Extract relevant fields from each result
        vulnerabilities = []
        for entry in parsed:
            # Try to extract URL from curl_command or matched-at, fallback to host
            url = entry.get("matched-at", "")
            if not url:
                curl_cmd = entry.get("curl-command", "")
                if curl_cmd:
                    # Extract URL from curl command (usually after "curl ")
                    parts = curl_cmd.split(" ")
                    for part in parts:
                        if part.startswith("http"):
                            url = part.strip("'\"")
                            break
            if not url:
                url = entry.get("host", "")

            # Extract template info
            info = entry.get("info", {})

            vuln = {
                "host": entry.get("host", ""),
                "url": url,
                "template_id": entry.get("template-id", ""),
                "name": info.get("name", entry.get("name", "")),
                "severity": info.get("severity", entry.get("severity", "unknown")),
                "description": info.get("description", entry.get("description", "")),
                "reference": info.get("reference", []),
                "matched_at": entry.get("matched-at", ""),
                "cve_id": entry.get("cve-id", None)
            }
            vulnerabilities.append(vuln)

        count = len(vulnerabilities)
        print(f"[NUCLEI] Found {count} vulnerabilities")

        return {
            "success": True,
            "vulnerabilities": vulnerabilities,
            "count": count
        }

    except subprocess.TimeoutExpired:
        print(f"[NUCLEI] Error: Timed out after {Config.SCAN_TIMEOUT}s")
        return {
            "success": False,
            "error": "Nuclei timed out",
            "vulnerabilities": []
        }

    except FileNotFoundError:
        error = f"Nuclei not found at {Config.NUCLEI_PATH}"
        print(f"[NUCLEI] Error: {error}")
        return {
            "success": False,
            "error": error,
            "vulnerabilities": []
        }

    except Exception as e:
        print(f"[NUCLEI] Error: {e}")
        return {
            "success": False,
            "error": str(e),
            "vulnerabilities": []
        }

    finally:
        # Clean up temp file
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)
