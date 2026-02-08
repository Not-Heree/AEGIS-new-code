"""
AEGIS - Scanner Module (The "Deep Scan" Engine)
================================================
This module orchestrates the scanning pipeline for the AEGIS EASM system.
It runs each phase sequentially in a background thread:
    1. Discovery (Subfinder) - Find subdomains (THOROUGH mode with -all)
    2. Ports (Naabu) - Scan for open ports (Top 1000 for maximum coverage)
    3. Tech (HTTPX) - Probe for live web servers with tech detection
    4. Vulns (Nuclei) - Scan for ALL vulnerabilities (critical, high, medium, low)

DEEP SCAN MODE: Accuracy and coverage are top priorities. Time is not a constraint.
All functions are designed to be called from app.py and return structured
data that can be directly inserted into the database.
"""

import subprocess
import os
import json
import platform
from typing import List, Dict, Any, Optional

# Local module for remediation advice
from remediation import get_remediation


# =============================================================================
# CONFIGURATION
# =============================================================================
# Get the directory where this script lives. This ensures the 'tools' folder
# can be found regardless of where the script is executed from.
BASE_DIR: str = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR: str = os.path.join(BASE_DIR, "tools")

# Detect if we are running on Windows. This is necessary because the
# scanner binaries have different extensions on Windows (.exe) vs. Linux (none).
IS_WINDOWS: bool = platform.system() == "Windows"
EXT: str = ".exe" if IS_WINDOWS else ""

# Define absolute paths to each scanner binary.
# These are the open-source tools from Project Discovery.
SUBFINDER: str = os.path.join(TOOLS_DIR, f"subfinder{EXT}")
NAABU: str = os.path.join(TOOLS_DIR, f"naabu{EXT}")
HTTPX: str = os.path.join(TOOLS_DIR, f"httpx{EXT}")
NUCLEI: str = os.path.join(TOOLS_DIR, f"nuclei{EXT}")

# Debug: Print the tools directory path at module load time
print(f"[DEBUG] AEGIS Scanner initialized. Using tools at: {TOOLS_DIR}")

# =============================================================================
# DEEP SCAN MODE CONFIGURATION
# =============================================================================
# Core tags that Nuclei should ALWAYS use, regardless of detected technologies.
# This ensures we catch vulnerabilities even if HTTPX fails to identify tech stack.
CORE_NUCLEI_TAGS: str = "cve,misconfig,vulnerability,web,tech"


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _run_command(cmd_list: List[str]) -> str:
    """
    Executes an external command and returns its standard output.

    This is a low-level helper that wraps subprocess.run. It captures stdout
    and handles any exceptions that may occur if the binary is missing or
    crashes unexpectedly.

    Args:
        cmd_list: A list of strings representing the command and its arguments.
                  Example: ["/path/to/subfinder", "-d", "example.com", "-silent"]

    Returns:
        A string containing the raw stdout of the process.
        Returns an empty string if an error occurs.

    Raises:
        None: Exceptions are caught and logged internally.
    """
    try:
        # Use capture_output=True to get stdout/stderr.
        # Use text=True to get string output instead of bytes.
        # shell=False (the default) is safer and avoids shell injection.
        # NO TIMEOUT: Deep scan mode lets tools run as long as needed.
        process = subprocess.run(cmd_list, capture_output=True, text=True)
        return process.stdout
    except FileNotFoundError:
        # This happens if the binary does not exist at the specified path.
        print(f"[!] Error: Tool not found at path: {cmd_list[0]}")
        return ""
    except Exception as e:
        # Catch-all for any other unexpected errors (permissions, etc.)
        print(f"[!] Unexpected error running command: {e}")
        return ""


# =============================================================================
# SCANNING PIPELINE (THE "DEEP SCAN" ENGINE)
# =============================================================================

def step_1_subfinder(domain: str) -> List[str]:
    """
    Phase 1: Asset Discovery using Subfinder (THOROUGH MODE).

    Subfinder passively queries multiple sources (certificate logs, search
    engines, etc.) to find subdomains belonging to the target domain.
    
    DEEP SCAN: Uses -all flag to query ALL available sources for maximum coverage.
    This is slower but finds more subdomains that might host vulnerable services.

    Args:
        domain: The target root domain to scan (e.g., "example.com").

    Returns:
        A list of discovered subdomain strings.
        Example: ["mail.example.com", "api.example.com", "dev.example.com"]
    """
    print(f"\n[1/4] Running Subfinder on {domain} (DEEP SCAN: -all enabled)...")

    # -d: Target domain.
    # -all: DEEP SCAN - Use ALL available sources (slower but thorough).
    # -silent: Suppress banner and informational messages for clean output.
    # -json: Output one JSON object per line, which is easy to parse.
    cmd: List[str] = [SUBFINDER, "-d", domain, "-all", "-silent", "-json"]
    output: str = _run_command(cmd)

    subdomains: List[str] = []
    for line in output.splitlines():
        try:
            # Each line is a JSON object like: {"host": "sub.example.com", ...}
            data: Dict[str, Any] = json.loads(line)
            subdomains.append(data['host'])
        except (json.JSONDecodeError, KeyError):
            # Skip malformed lines or lines without the 'host' key.
            pass

    print(f"    -> Found {len(subdomains)} subdomains.")
    return subdomains


def step_2_naabu(subdomains: List[str]) -> List[Dict[str, Any]]:
    """
    Phase 2: Port Scanning using Naabu (EXPANDED MODE).

    Takes the list of discovered subdomains and scans them for open TCP ports.
    This helps identify services that are exposed to the internet.
    
    DEEP SCAN: Scans top 1000 ports instead of 100 to find hidden admin panels,
    development servers, and non-standard service ports.

    Args:
        subdomains: A list of subdomain strings from step_1.

    Returns:
        A list of dictionaries, where each dict represents an open port.
        Example: [{"host": "mail.example.com", "port": 443}, ...]
    """
    print(f"\n[2/4] Running Naabu (DEEP SCAN: Top 1000 ports)...")
    if not subdomains:
        return []

    # Write the subdomain list to a temporary file. Naabu reads from this file.
    # This is more efficient and avoids command-line length limits for large lists.
    temp_file: str = os.path.join(BASE_DIR, "temp_subs.txt")
    with open(temp_file, "w") as f:
        f.write("\n".join(subdomains))

    # -list: Read targets from a file.
    # -top-ports 1000: DEEP SCAN - Scan top 1000 ports for hidden services.
    # -json: Output one JSON object per line.
    # -silent: Suppress banner.
    cmd: List[str] = [NAABU, "-list", temp_file, "-top-ports", "1000", "-json", "-silent"]
    output: str = _run_command(cmd)

    results: List[Dict[str, Any]] = []
    for line in output.splitlines():
        try:
            # Each line is: {"host": "...", "port": 443, ...}
            data: Dict[str, Any] = json.loads(line)
            host: Optional[str] = data.get('host')
            port: Optional[int] = data.get('port')
            if host and port:
                results.append({"host": host, "port": port})
        except (json.JSONDecodeError, KeyError):
            pass

    print(f"    -> Found {len(results)} open ports.")
    return results


def step_3_httpx(targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Phase 3: Live Web Server Detection using HTTPX.

    Not all open ports run web servers. HTTPX probes each host:port combination
    to see if an HTTP/HTTPS service is running. It also detects technologies
    (e.g., Nginx, Apache, WordPress) for intelligent Nuclei template selection.

    Args:
        targets: A list of dicts from step_2, each with 'host' and 'port' keys.

    Returns:
        A list of dictionaries containing rich info about live web servers.
        Example: [{"url": "https://mail.example.com:443", "status_code": 200, "tech": ["PHP"]}]
    """
    print(f"\n[3/4] Running HTTPX (Live Check with Tech Detection)...")
    if not targets:
        return []

    # Prepare input: HTTPX expects "host:port" strings.
    input_targets: List[str] = []
    for t in targets:
        if isinstance(t, dict):
            input_targets.append(f"{t['host']}:{t['port']}")
        else:
            # Fallback if input is just a string.
            input_targets.append(t)

    temp_file: str = os.path.join(BASE_DIR, "temp_ports.txt")
    with open(temp_file, "w") as f:
        f.write("\n".join(input_targets))

    # -list: Read targets from file.
    # -tech-detect: Detect technologies for smarter Nuclei scanning.
    # -json: Output rich JSON objects.
    # -silent: Suppress banner.
    cmd: List[str] = [HTTPX, "-list", temp_file, "-tech-detect", "-json", "-silent"]
    output: str = _run_command(cmd)

    urls: List[Dict[str, Any]] = []
    for line in output.splitlines():
        try:
            # HTTPX returns rich data including url, status-code, title, tech, etc.
            data: Dict[str, Any] = json.loads(line)
            urls.append(data)
        except json.JSONDecodeError:
            pass

    print(f"    -> Found {len(urls)} live web servers.")
    return urls


def step_4_nuclei(urls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Phase 4: Vulnerability Scanning using Nuclei (MAXIMUM DETECTION MODE).

    This is the core security scanning step. Nuclei runs a library of templates
    against the live URLs to find known vulnerabilities like exposed .git
    directories, default credentials, XSS, SQL injection, and more.

    DEEP SCAN MODE CHANGES:
    - Scans ALL severities: critical, high, medium, low (not just critical/high)
    - NO timeout limit: Let Nuclei run as long as needed
    - NO corroboration filter: Every finding is reported (even one-hit wonders)
    - Uses broad tags: cve,misconfig,vulnerability,web,tech (always included)

    After finding a vulnerability, this function enriches the result with
    remediation advice from our local knowledge base (remediation.py).

    Args:
        urls: A list of dicts from step_3, each containing a 'url' key.

    Returns:
        A list of vulnerability dictionaries, ready for database insertion.
        Each dict includes: template_id, name, severity, matched_at, fix, mitre_id.
    """
    print(f"\n[4/4] Running Nuclei (DEEP SCAN: All Severities)...")
    if not urls:
        return []

    # Prepare input: Nuclei expects full URLs.
    input_urls: List[str] = []
    for u in urls:
        if isinstance(u, dict):
            url: Optional[str] = u.get('url')
            if url:
                input_urls.append(url)
        else:
            input_urls.append(u)

    temp_file: str = os.path.join(BASE_DIR, "temp_urls.txt")
    with open(temp_file, "w") as f:
        f.write("\n".join(input_urls))

    # Build the Nuclei command for MAXIMUM DETECTION:
    # -list: Read targets from file.
    # -severity critical,high,medium,low: DEEP SCAN - Scan ALL meaningful severities.
    # -tags: Use core tags that work on any web application.
    # -json: Output one JSON object per finding.
    # -silent: Suppress banner.
    # NO -timeout: Let Nuclei run as long as needed for thorough scanning.
    cmd: List[str] = [
        NUCLEI,
        "-list", temp_file,
        "-severity", "critical,high,medium,low",
        "-tags", CORE_NUCLEI_TAGS,
        "-json",
        "-silent"
    ]
    
    print(f"    -> Using tags: {CORE_NUCLEI_TAGS}")
    print(f"    -> Scanning severities: critical, high, medium, low")
    
    output: str = _run_command(cmd)

    # DEEP SCAN: NO FILTERING - Every finding is valuable.
    # Previous "corroboration" logic that required 2+ hits is REMOVED.
    # A valid SQL injection on a single URL should NOT be discarded.
    vulns: List[Dict[str, Any]] = []
    for line in output.splitlines():
        try:
            data: Dict[str, Any] = json.loads(line)

            # Extract the template ID, which is the key for our remediation DB.
            template_id: str = data.get('template-id', 'unknown')

            # --- INTELLIGENCE LAYER ---
            # Enrich the finding with remediation advice from our local DB.
            # This provides human-readable fix instructions and MITRE ATT&CK mapping.
            remedy: Dict[str, str] = get_remediation(template_id)

            # Construct the final vulnerability object with all necessary fields.
            vuln_obj: Dict[str, Any] = {
                "template_id": template_id,
                "name": remedy.get('title', template_id),
                "severity": data.get('info', {}).get('severity', 'unknown'),
                "matched_at": data.get('matched-at', ''),
                "mitre_id": remedy.get('mitre_id', 'N/A'),
                "fix": remedy.get('fix', 'See tool documentation.'),
                "curl_command": data.get('curl-command', ''),
                "description": data.get('info', {}).get('description', '')
            }
            vulns.append(vuln_obj)
        except (json.JSONDecodeError, KeyError):
            pass

    print(f"    -> Found {len(vulns)} vulnerabilities (ALL severities).")
    return vulns


# =============================================================================
# MAIN ENTRY POINT (For standalone testing)
# =============================================================================

if __name__ == "__main__":
    # This block allows running scanner.py directly for testing the pipeline.
    print("=" * 60)
    print("AEGIS SCANNER - DEEP SCAN MODE")
    print("=" * 60)
    target: str = input("Enter target domain: ")

    # Run the full pipeline sequentially.
    subs: List[str] = step_1_subfinder(target)

    ports: List[Dict[str, Any]] = []
    if subs:
        ports = step_2_naabu(subs)

    live_urls: List[Dict[str, Any]] = []
    if ports:
        live_urls = step_3_httpx(ports)

    vulnerabilities: List[Dict[str, Any]] = []
    if live_urls:
        vulnerabilities = step_4_nuclei(live_urls)

        print("\n[COMPLETE] Final Vulnerability Report:")
        print(json.dumps(vulnerabilities, indent=2))

    # Clean up temporary files to avoid leaving data on disk.
    for temp in ["temp_subs.txt", "temp_ports.txt", "temp_urls.txt"]:
        temp_path: str = os.path.join(BASE_DIR, temp)
        if os.path.exists(temp_path):
            os.remove(temp_path)