import os
import subprocess
import json
import tempfile
from config import Config
from utils.logger import logger


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
    """Run Naabu in batches to scan ports on a list of subdomains.

    Optimized for large host lists by using:
    1. Batching (default 100 hosts per batch)
    2. Temporary file input (-list flag) to avoid CMD length limits
    3. Progress logging
    """
    if not subdomains_list:
        return {"success": True, "ports_found": {}, "total_ports": 0}

    total_hosts = len(subdomains_list)
    batch_size = Config.NAABU_BATCH_SIZE
    batches = [subdomains_list[i:i + batch_size] for i in range(0, total_hosts, batch_size)]
    total_batches = len(batches)

    logger.info(f"Starting port scanning on {total_hosts} hosts ({total_batches} batches)")

    all_ports_found = {}
    total_ports_count = 0

    # Ensure temp directory exists
    temp_dir = os.path.join(os.path.dirname(__file__), "..", "temp")
    os.makedirs(temp_dir, exist_ok=True)

    for i, batch in enumerate(batches, 1):
        logger.info(f"[NAABU] Processing batch {i}/{total_batches} ({len(batch)} hosts)...")

        # Write batch to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', dir=temp_dir, delete=False) as tf:
            for host in batch:
                host = str(host).strip()
                if host:
                    tf.write(f"{host}\n")
            temp_list_path = tf.name

        try:
            cmd = [
                Config.NAABU_PATH,
                "-list", temp_list_path,
                "-top-ports", Config.NAABU_TOP_PORTS,
                "-rate", str(Config.NAABU_RATE),
                "-json",
                "-silent"
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=Config.SCAN_TIMEOUT
            )

            # Cleanup temp file
            if os.path.exists(temp_list_path):
                os.remove(temp_list_path)

            # Parse results for this batch
            batch_results = parse_naabu_output(result.stdout)

            # Merge results
            for host, ports in batch_results.items():
                if host not in all_ports_found:
                    all_ports_found[host] = []
                all_ports_found[host].extend(ports)
                # Deduplicate and sort
                all_ports_found[host] = sorted(list(set(all_ports_found[host])))

            batch_port_count = sum(len(ports) for ports in batch_results.values())
            logger.info(f"[NAABU] Batch {i}/{total_batches} complete. Found {batch_port_count} open ports.")

        except subprocess.TimeoutExpired:
            logger.warning(f"[NAABU] Batch {i}/{total_batches} timed out after {Config.SCAN_TIMEOUT}s")
            if os.path.exists(temp_list_path):
                os.remove(temp_list_path)
            continue

        except Exception as e:
            logger.error(f"[NAABU] Error in batch {i}: {e}")
            if os.path.exists(temp_list_path):
                os.remove(temp_list_path)
            continue

    total_ports_count = sum(len(ports) for ports in all_ports_found.values())
    logger.info(f"Port scanning complete. Total found: {total_ports_count} open ports")

    return {
        "success": True,
        "ports_found": all_ports_found,
        "total_ports": total_ports_count
    }
