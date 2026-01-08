import subprocess
import os
import json
import shutil
from remediation import get_remediation
# --- CONFIGURATION ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(BASE_DIR, "tools")

# Windows check
import platform
IS_WINDOWS = platform.system() == "Windows"
EXT = ".exe" if IS_WINDOWS else ""

# Define paths
SUBFINDER = os.path.join(TOOLS_DIR, f"subfinder{EXT}")
NAABU = os.path.join(TOOLS_DIR, f"naabu{EXT}")
HTTPX = os.path.join(TOOLS_DIR, f"httpx{EXT}")
NUCLEI = os.path.join(TOOLS_DIR, f"nuclei{EXT}")

def run_command(cmd_list):
    """Helper to run a command and return stdout"""
    try:
        process = subprocess.run(cmd_list, capture_output=True, text=True)
        return process.stdout
    except Exception as e:
        print(f"[!] Error: {e}")
        return ""

def step_1_subfinder(domain):
    """Finds subdomains"""
    print(f"\n[1] Running Subfinder on {domain}...")
    cmd = [SUBFINDER, "-d", domain, "-silent", "-json"]
    output = run_command(cmd)
    
    subdomains = []
    for line in output.splitlines():
        try:
            data = json.loads(line)
            subdomains.append(data['host'])
        except: pass
    
    print(f"    -> Found {len(subdomains)} subdomains.")
    return subdomains

def step_2_naabu(subdomains):
    """Finds open ports"""
    print(f"\n[2] Running Naabu (Port Scan)...")
    if not subdomains: return []

    # Save inputs to file
    with open("temp_subs.txt", "w") as f:
        f.write("\n".join(subdomains))

    # Scan top 100 ports for speed
    cmd = [NAABU, "-list", "temp_subs.txt", "-top-ports", "100", "-json", "-silent"]
    output = run_command(cmd)
    
    # Parse output (host:port)
    results = []
    for line in output.splitlines():
        try:
            data = json.loads(line)
            # Naabu returns ip and port. We want to reconstruct host:port
            host = data.get('host')
            port = data.get('port')
            results.append(f"{host}:{port}")
        except: pass
        
    print(f"    -> Found {len(results)} open ports.")
    return results

def step_3_httpx(targets):
    """Filters for live web servers"""
    print(f"\n[3] Running HTTPX (Live Check)...")
    if not targets: return []

    with open("temp_ports.txt", "w") as f:
        f.write("\n".join(targets))

    cmd = [HTTPX, "-list", "temp_ports.txt", "-json", "-silent"]
    output = run_command(cmd)
    
    urls = []
    for line in output.splitlines():
        try:
            data = json.loads(line)
            urls.append(data['url'])
        except: pass

    print(f"    -> Found {len(urls)} live web servers.")
    return urls

def step_4_nuclei(urls):
    """Scans for vulnerabilities and Adds Remediation"""
    print(f"\n[4] Running Nuclei (Vuln Scan)...")
    if not urls: return []

    with open("temp_urls.txt", "w") as f:
        f.write("\n".join(urls))

    cmd = [NUCLEI, "-list", "temp_urls.txt", "-json", "-silent"] 
    output = run_command(cmd)
    
    vulns = []
    for line in output.splitlines():
        try:
            data = json.loads(line)
            
            # Extract basic info
            vuln_id = data.get('template-id', 'unknown')
            
            # --- INTELLIGENCE LAYER ---
            # Ask remediation.py for the fix
            remedy = get_remediation(vuln_id)
            
            vuln_obj = {
                "id": vuln_id,
                "name": remedy['title'],           # Use our clean title
                "severity": data['info']['severity'],
                "url": data['matched-at'],
                "mitre_id": remedy['mitre_id'],    # Added MITRE
                "fix": remedy['fix']               # Added The Fix!
            }
            vulns.append(vuln_obj)
        except: pass
        
    print(f"    -> Found {len(vulns)} vulnerabilities.")
    return vulns
    # Note: We run a 'tech-detect' scan first to make it fast for testing
    # In real run, remove '-t technologies' to scan everything
    cmd = [NUCLEI, "-list", "temp_urls.txt", "-json", "-silent"] 
    output = run_command(cmd)
    
    vulns = []
    for line in output.splitlines():
        try:
            data = json.loads(line)
            # We only care about name, severity, and host
            vuln = {
                "name": data['info']['name'],
                "severity": data['info']['severity'],
                "url": data['matched-at'],
                "id": data['template-id']
            }
            vulns.append(vuln)
        except: pass
        
    print(f"    -> Found {len(vulns)} vulnerabilities.")
    return vulns

# --- MAIN ORCHESTRATOR ---
if __name__ == "__main__":
    target = input("Enter target domain : ")
    
    # Run the Pipeline
    subs = step_1_subfinder(target)
    
    if subs:
        ports = step_2_naabu(subs)
    
    if ports:
        live_urls = step_3_httpx(ports)
    
    if live_urls:
        vulnerabilities = step_4_nuclei(live_urls)
        
        print("\n[COMPLETE] Final Vulnerability Report:")
        print(json.dumps(vulnerabilities, indent=2))
        
    # Clean up temp files
    for temp in ["temp_subs.txt", "temp_ports.txt", "temp_urls.txt"]:
        if os.path.exists(temp): os.remove(temp)