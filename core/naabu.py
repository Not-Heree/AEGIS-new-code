import subprocess
import json
from config import Config


def parse_naabu_output(raw_output):
    """Parse JSONL output from Naabu.
    Each line is a JSON object with 'host' and 'port' fields.
    Returns dict grouped by host: {"host": [port_list], ...}
    """
    if not raw_output:
        return {}

    results = {}
    for line in raw_output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            host = data.get("host", "")
            port = data.get("port")
            if host and port is not None:
                if host not in results:
                    results[host] = []
                if port not in results[host]:
                    results[host].append(port)
        except json.JSONDecodeError:
            continue

    # Sort ports for each host
    for host in results:
        results[host].sort()

    return results


def run_naabu(subdomains_list):
    """Run Naabu to scan ports on a list of subdomains."""
    print(f"[NAABU] Starting port scanning on {len(subdomains_list)} hosts")

    try:
        # Join subdomains with comma for -host flag
        joined_hosts = ",".join(subdomains_list)

        result = subprocess.run(
            [
                Config.NAABU_PATH,
                "-host", joined_hosts,
                "-top-ports", Config.NAABU_TOP_PORTS,
                "-json",
                "-silent"
            ],
            capture_output=True,
            text=True,
            timeout=Config.SCAN_TIMEOUT
        )

        # Parse the JSONL output into host -> ports mapping
        ports_found = parse_naabu_output(result.stdout)

        # Count total open ports across all hosts
        total_ports = sum(len(ports) for ports in ports_found.values())
        print(f"[NAABU] Found {total_ports} open ports")

        return {
            "success": True,
            "ports_found": ports_found,
            "total_ports": total_ports
        }

    except subprocess.TimeoutExpired:
        print(f"[NAABU] Error: Timed out after {Config.SCAN_TIMEOUT}s")
        return {
            "success": False,
            "error": "Naabu timed out",
            "ports_found": {}
        }

    except FileNotFoundError:
        error = f"Naabu not found at {Config.NAABU_PATH}"
        print(f"[NAABU] Error: {error}")
        return {
            "success": False,
            "error": error,
            "ports_found": {}
        }

    except Exception as e:
        print(f"[NAABU] Error: {e}")
        return {
            "success": False,
            "error": str(e),
            "ports_found": {}
        }
