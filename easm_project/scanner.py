"""
ARES - Scanner Engine (scanner.py)
Deep Scan Orchestrator for External Security Tools

This module orchestrates 4 external binary tools in sequence:
1. Subfinder - Asset Discovery (Passive subdomain enumeration)
2. Naabu - Deep Port Scanning (Top 1000 ports)
3. HTTPX - Live Host Filtration (Find running web servers)
4. Nuclei - Vulnerability Scanning (All severity levels)

Cross-platform compatible: Works on both Windows (.exe) and Linux.
"""

import os
import sys
import json
import platform
import subprocess
import tempfile
import time
from datetime import datetime
from pathlib import Path

# Import database module
from db import db


class Scanner:
    """
    ARES Deep Scanner - Orchestrates security scanning tools.
    
    Executes tools in sequence, passing output between stages,
    and stores results in MongoDB.
    """
    
    def __init__(self, scan_id, target_domain):
        """
        Initialize the scanner with scan ID and target domain.
        
        Args:
            scan_id (str): The MongoDB scan document ID
            target_domain (str): The target domain to scan
        """
        self.scan_id = scan_id
        self.target_domain = target_domain.lower().strip()
        
        # Determine tools directory (relative to this file)
        self.base_dir = Path(__file__).parent
        self.tools_dir = self.base_dir / "tools"
        
        # Temporary files directory
        self.temp_dir = tempfile.mkdtemp(prefix="ares_")
        
        # Results containers
        self.subdomains = []
        self.ports = []
        self.live_hosts = []
        self.vulnerabilities = []
        
        # Scan status
        self.is_running = False
        self.errors = []
        
        print(f"[ARES] Scanner initialized for: {self.target_domain}")
        print(f"[ARES] Tools directory: {self.tools_dir}")
        print(f"[ARES] Temp directory: {self.temp_dir}")
    
    def get_tool_path(self, tool_name):
        """
        Get the full path to a tool binary, handling Windows/Linux differences.
        
        Args:
            tool_name (str): Name of the tool (e.g., 'subfinder')
            
        Returns:
            str: Full path to the tool binary
        """
        if platform.system() == "Windows":
            tool_path = self.tools_dir / f"{tool_name}.exe"
        else:
            tool_path = self.tools_dir / tool_name
        
        return str(tool_path)
    
    def check_tool_exists(self, tool_name):
        """
        Check if a tool binary exists.
        
        Args:
            tool_name (str): Name of the tool
            
        Returns:
            bool: True if tool exists, False otherwise
        """
        tool_path = self.get_tool_path(tool_name)
        exists = os.path.isfile(tool_path)
        
        if not exists:
            error_msg = f"Tool not found: {tool_path}"
            print(f"[ERROR] {error_msg}")
            self.errors.append(error_msg)
            db.add_error(self.scan_id, error_msg)
        
        return exists
    
    def run_command(self, command, tool_name, timeout=1800):
        """
        Execute a subprocess command with error handling.
        
        Args:
            command (list): Command and arguments as list
            tool_name (str): Name of the tool (for logging)
            timeout (int): Maximum execution time in seconds (default: 30 min)
            
        Returns:
            tuple: (success: bool, output: str, error: str)
        """
        print(f"\n[{tool_name.upper()}] Executing: {' '.join(command)}")
        
        try:
            # Use CREATE_NO_WINDOW flag on Windows to hide console
            creationflags = 0
            if platform.system() == "Windows":
                creationflags = subprocess.CREATE_NO_WINDOW
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=creationflags
            )
            
            stdout, stderr = process.communicate(timeout=timeout)
            
            if process.returncode == 0:
                print(f"[{tool_name.upper()}] Completed successfully")
                return True, stdout, stderr
            else:
                error_msg = f"{tool_name} exited with code {process.returncode}: {stderr}"
                print(f"[{tool_name.upper()}] {error_msg}")
                self.errors.append(error_msg)
                db.add_error(self.scan_id, error_msg)
                return False, stdout, stderr
                
        except subprocess.TimeoutExpired:
            process.kill()
            error_msg = f"{tool_name} timed out after {timeout} seconds"
            print(f"[{tool_name.upper()}] {error_msg}")
            self.errors.append(error_msg)
            db.add_error(self.scan_id, error_msg)
            return False, "", error_msg
            
        except FileNotFoundError:
            error_msg = f"{tool_name} binary not found"
            print(f"[{tool_name.upper()}] {error_msg}")
            self.errors.append(error_msg)
            db.add_error(self.scan_id, error_msg)
            return False, "", error_msg
            
        except Exception as e:
            error_msg = f"{tool_name} error: {str(e)}"
            print(f"[{tool_name.upper()}] {error_msg}")
            self.errors.append(error_msg)
            db.add_error(self.scan_id, error_msg)
            return False, "", str(e)
    
    def parse_json_lines(self, output):
        """
        Parse JSON Lines (JSONL) output format used by ProjectDiscovery tools.
        
        Args:
            output (str): Raw output containing one JSON object per line
            
        Returns:
            list: List of parsed JSON objects
        """
        results = []
        
        if not output:
            return results
        
        for line in output.strip().split('\n'):
            line = line.strip()
            if not line:
                continue
            
            try:
                # Try to parse as JSON
                data = json.loads(line)
                results.append(data)
            except json.JSONDecodeError as e:
                # Not valid JSON, might be plain text output
                # For tools that output plain hostnames
                if line and not line.startswith('[') and not line.startswith('{'):
                    results.append({"host": line})
                else:
                    print(f"[WARN] Failed to parse JSON line: {line[:100]}...")
        
        return results
    
    # ==================== STAGE 1: SUBFINDER ====================
    
    def run_subfinder(self):
        """
        Run Subfinder for passive subdomain enumeration.
        
        Returns:
            bool: True if successful, False otherwise
        """
        db.update_tool_progress(self.scan_id, "subfinder", "running")
        
        if not self.check_tool_exists("subfinder"):
            db.update_tool_progress(self.scan_id, "subfinder", "failed")
            return False
        
        tool_path = self.get_tool_path("subfinder")
        output_file = os.path.join(self.temp_dir, "subdomains.json")
        
        # Subfinder command with JSON output
        command = [
            tool_path,
            "-d", self.target_domain,
            "-json",
            "-o", output_file,
            "-silent"
        ]
        
        success, stdout, stderr = self.run_command(command, "subfinder", timeout=600)
        
        if success or os.path.exists(output_file):
            # Parse output file if exists
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r', encoding='utf-8') as f:
                        content = f.read()
                    
                    parsed = self.parse_json_lines(content)
                    
                    for item in parsed:
                        if isinstance(item, dict):
                            host = item.get("host", item.get("subdomain", ""))
                        else:
                            host = str(item)
                        
                        if host and host not in self.subdomains:
                            self.subdomains.append(host)
                            
                except Exception as e:
                    print(f"[SUBFINDER] Error reading output file: {e}")
            
            # Also parse stdout in case output wasn't written to file
            if stdout:
                parsed = self.parse_json_lines(stdout)
                for item in parsed:
                    if isinstance(item, dict):
                        host = item.get("host", item.get("subdomain", ""))
                    else:
                        host = str(item)
                    
                    if host and host not in self.subdomains:
                        self.subdomains.append(host)
        
        # Always include the main domain
        if self.target_domain not in self.subdomains:
            self.subdomains.append(self.target_domain)
        
        # Store results in database
        db.store_subdomains(self.scan_id, self.subdomains)
        
        print(f"[SUBFINDER] Found {len(self.subdomains)} subdomains")
        
        if self.subdomains:
            db.update_tool_progress(self.scan_id, "subfinder", "completed")
            return True
        else:
            db.update_tool_progress(self.scan_id, "subfinder", "completed")
            return True  # Not a failure, just no additional subdomains found
    
    # ==================== STAGE 2: NAABU ====================
    
    def run_naabu(self):
        """
        Run Naabu for deep port scanning on discovered subdomains.
        Uses -top-ports 1000 for comprehensive coverage.
        
        Returns:
            bool: True if successful, False otherwise
        """
        db.update_tool_progress(self.scan_id, "naabu", "running")
        
        if not self.check_tool_exists("naabu"):
            db.update_tool_progress(self.scan_id, "naabu", "failed")
            return False
        
        if not self.subdomains:
            print("[NAABU] No subdomains to scan")
            db.update_tool_progress(self.scan_id, "naabu", "completed")
            return True
        
        tool_path = self.get_tool_path("naabu")
        
        # Write subdomains to input file
        input_file = os.path.join(self.temp_dir, "subdomains_list.txt")
        output_file = os.path.join(self.temp_dir, "ports.json")
        
        with open(input_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.subdomains))
        
        # Naabu command with top 1000 ports for deep scanning
        command = [
            tool_path,
            "-list", input_file,
            "-top-ports", "1000",  # CRITICAL: Deep port scanning
            "-json",
            "-o", output_file,
            "-silent"
        ]
        
        success, stdout, stderr = self.run_command(command, "naabu", timeout=1200)
        
        # Parse results
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                parsed = self.parse_json_lines(content)
                
                for item in parsed:
                    if isinstance(item, dict):
                        port_data = {
                            "host": item.get("host", item.get("ip", "")),
                            "port": item.get("port", 0),
                            "protocol": item.get("protocol", "tcp")
                        }
                        if port_data["host"] and port_data["port"]:
                            self.ports.append(port_data)
                            
            except Exception as e:
                print(f"[NAABU] Error reading output file: {e}")
        
        # Also parse stdout
        if stdout:
            parsed = self.parse_json_lines(stdout)
            for item in parsed:
                if isinstance(item, dict):
                    port_data = {
                        "host": item.get("host", item.get("ip", "")),
                        "port": item.get("port", 0),
                        "protocol": item.get("protocol", "tcp")
                    }
                    if port_data["host"] and port_data["port"]:
                        # Avoid duplicates
                        exists = any(
                            p["host"] == port_data["host"] and p["port"] == port_data["port"]
                            for p in self.ports
                        )
                        if not exists:
                            self.ports.append(port_data)
        
        # Store results
        db.store_ports(self.scan_id, self.ports)
        
        print(f"[NAABU] Found {len(self.ports)} open ports")
        db.update_tool_progress(self.scan_id, "naabu", "completed")
        
        return True
    
    # ==================== STAGE 3: HTTPX ====================
    
    def run_httpx(self):
        """
        Run HTTPX to filter for live web servers from port scan results.
        
        Returns:
            bool: True if successful, False otherwise
        """
        db.update_tool_progress(self.scan_id, "httpx", "running")
        
        if not self.check_tool_exists("httpx"):
            db.update_tool_progress(self.scan_id, "httpx", "failed")
            return False
        
        tool_path = self.get_tool_path("httpx")
        
        # Prepare targets: host:port combinations
        targets = []
        
        # Add all subdomains (default HTTP/HTTPS ports)
        for subdomain in self.subdomains:
            targets.append(subdomain)
        
        # Add host:port from Naabu results
        for port_data in self.ports:
            host = port_data.get("host", "")
            port = port_data.get("port", 0)
            
            if host and port:
                # Add host:port format for non-standard ports
                if port not in [80, 443]:
                    targets.append(f"{host}:{port}")
        
        if not targets:
            print("[HTTPX] No targets to probe")
            db.update_tool_progress(self.scan_id, "httpx", "completed")
            return True
        
        # Remove duplicates
        targets = list(set(targets))
        
        # Write targets to input file
        input_file = os.path.join(self.temp_dir, "httpx_targets.txt")
        output_file = os.path.join(self.temp_dir, "live_hosts.json")
        
        with open(input_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(targets))
        
        # HTTPX command
        command = [
            tool_path,
            "-list", input_file,
            "-json",
            "-o", output_file,
            "-silent",
            "-follow-redirects",
            "-status-code",
            "-title",
            "-tech-detect",
            "-timeout", "10"
        ]
        
        success, stdout, stderr = self.run_command(command, "httpx", timeout=900)
        
        # Parse results
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                parsed = self.parse_json_lines(content)
                
                for item in parsed:
                    if isinstance(item, dict):
                        url = item.get("url", "")
                        if url and url not in self.live_hosts:
                            self.live_hosts.append(url)
                            
            except Exception as e:
                print(f"[HTTPX] Error reading output file: {e}")
        
        # Also parse stdout
        if stdout:
            parsed = self.parse_json_lines(stdout)
            for item in parsed:
                if isinstance(item, dict):
                    url = item.get("url", "")
                    if url and url not in self.live_hosts:
                        self.live_hosts.append(url)
        
        # Store results
        db.store_live_hosts(self.scan_id, self.live_hosts)
        
        print(f"[HTTPX] Found {len(self.live_hosts)} live web hosts")
        db.update_tool_progress(self.scan_id, "httpx", "completed")
        
        return True
    
    # ==================== STAGE 4: NUCLEI ====================
    
    def run_nuclei(self):
        """
        Run Nuclei vulnerability scanner on live hosts.
        Uses -severity low,medium,high,critical for comprehensive scanning.
        
        Returns:
            bool: True if successful, False otherwise
        """
        db.update_tool_progress(self.scan_id, "nuclei", "running")
        
        if not self.check_tool_exists("nuclei"):
            db.update_tool_progress(self.scan_id, "nuclei", "failed")
            return False
        
        if not self.live_hosts:
            print("[NUCLEI] No live hosts to scan")
            db.update_tool_progress(self.scan_id, "nuclei", "completed")
            return True
        
        tool_path = self.get_tool_path("nuclei")
        
        # Write live hosts to input file
        input_file = os.path.join(self.temp_dir, "live_hosts.txt")
        output_file = os.path.join(self.temp_dir, "vulnerabilities.json")
        
        with open(input_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(self.live_hosts))
        
        # Nuclei command - TOP OF THE LINE scanning with all severity levels
        command = [
            tool_path,
            "-list", input_file,
            "-severity", "low,medium,high,critical",  # CRITICAL: All severity levels
            "-json-export", output_file,
            "-silent",
            "-nc",  # No color (cleaner output)
            "-stats"  # Show progress statistics
        ]
        
        success, stdout, stderr = self.run_command(command, "nuclei", timeout=3600)
        
        # Parse results
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Nuclei JSON export is newline-delimited JSON
                parsed = self.parse_json_lines(content)
                
                for item in parsed:
                    if isinstance(item, dict):
                        vulnerability = self.normalize_nuclei_output(item)
                        if vulnerability:
                            self.vulnerabilities.append(vulnerability)
                            
            except Exception as e:
                print(f"[NUCLEI] Error reading output file: {e}")
        
        # Also try parsing stdout for real-time results
        if stdout:
            parsed = self.parse_json_lines(stdout)
            for item in parsed:
                if isinstance(item, dict):
                    vulnerability = self.normalize_nuclei_output(item)
                    if vulnerability:
                        # Avoid duplicates based on template-id and host
                        exists = any(
                            v.get("template_id") == vulnerability.get("template_id") and
                            v.get("host") == vulnerability.get("host")
                            for v in self.vulnerabilities
                        )
                        if not exists:
                            self.vulnerabilities.append(vulnerability)
        
        # Store results
        db.store_vulnerabilities(self.scan_id, self.vulnerabilities)
        
        print(f"[NUCLEI] Found {len(self.vulnerabilities)} vulnerabilities")
        db.update_tool_progress(self.scan_id, "nuclei", "completed")
        
        return True
    
    def normalize_nuclei_output(self, item):
        """
        Normalize Nuclei JSON output to a consistent format.
        
        Args:
            item (dict): Raw Nuclei JSON output
            
        Returns:
            dict: Normalized vulnerability data
        """
        if not item:
            return None
        
        # Extract template info
        info = item.get("info", {})
        
        vulnerability = {
            "template_id": item.get("template-id", item.get("templateID", "unknown")),
            "template_name": info.get("name", "Unknown Vulnerability"),
            "severity": info.get("severity", "info"),
            "host": item.get("host", item.get("matched-at", "")),
            "matched_at": item.get("matched-at", item.get("matched", "")),
            "type": item.get("type", "http"),
            "description": info.get("description", ""),
            "reference": info.get("reference", []),
            "tags": info.get("tags", []),
            "timestamp": item.get("timestamp", datetime.utcnow().isoformat()),
            "matcher_name": item.get("matcher-name", ""),
            "extracted_results": item.get("extracted-results", []),
            "curl_command": item.get("curl-command", ""),
            "raw": item  # Store original for debugging
        }
        
        return vulnerability
    
    # ==================== SCAN ORCHESTRATION ====================
    
    def run_full_scan(self):
        """
        Execute the complete Deep Scan pipeline.
        
        Runs all 4 stages in sequence:
        1. Subfinder (Asset Discovery)
        2. Naabu (Port Scanning)
        3. HTTPX (Live Host Detection)
        4. Nuclei (Vulnerability Scanning)
        
        Returns:
            bool: True if scan completed (even with partial results), False on critical failure
        """
        self.is_running = True
        start_time = time.time()
        
        print("\n" + "="*60)
        print(f"[ARES] Starting Deep Scan for: {self.target_domain}")
        print(f"[ARES] Scan ID: {self.scan_id}")
        print("="*60 + "\n")
        
        # Update scan status
        db.update_scan_status(self.scan_id, "running")
        
        try:
            # Stage 1: Subfinder
            print("\n[STAGE 1/4] Asset Discovery (Subfinder)")
            print("-" * 40)
            self.run_subfinder()
            
            # Stage 2: Naabu
            print("\n[STAGE 2/4] Port Scanning (Naabu)")
            print("-" * 40)
            self.run_naabu()
            
            # Stage 3: HTTPX
            print("\n[STAGE 3/4] Live Host Detection (HTTPX)")
            print("-" * 40)
            self.run_httpx()
            
            # Stage 4: Nuclei
            print("\n[STAGE 4/4] Vulnerability Scanning (Nuclei)")
            print("-" * 40)
            self.run_nuclei()
            
            # Calculate scan duration
            duration = time.time() - start_time
            
            # Mark scan as completed
            db.update_scan_status(self.scan_id, "completed")
            
            print("\n" + "="*60)
            print(f"[ARES] Deep Scan Completed!")
            print(f"[ARES] Duration: {duration:.2f} seconds")
            print(f"[ARES] Results:")
            print(f"       - Subdomains: {len(self.subdomains)}")
            print(f"       - Open Ports: {len(self.ports)}")
            print(f"       - Live Hosts: {len(self.live_hosts)}")
            print(f"       - Vulnerabilities: {len(self.vulnerabilities)}")
            print("="*60 + "\n")
            
            self.is_running = False
            return True
            
        except Exception as e:
            error_msg = f"Critical scan error: {str(e)}"
            print(f"\n[ARES] {error_msg}")
            self.errors.append(error_msg)
            db.add_error(self.scan_id, error_msg)
            db.update_scan_status(self.scan_id, "failed")
            self.is_running = False
            return False
        
        finally:
            # Cleanup temp files
            self.cleanup()
    
    def cleanup(self):
        """Clean up temporary files created during the scan."""
        try:
            import shutil
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                print(f"[ARES] Cleaned up temp directory: {self.temp_dir}")
        except Exception as e:
            print(f"[ARES] Warning: Could not clean temp directory: {e}")
    
    def get_results(self):
        """
        Get the current scan results.
        
        Returns:
            dict: Current scan results
        """
        return {
            "scan_id": self.scan_id,
            "target_domain": self.target_domain,
            "subdomains": self.subdomains,
            "ports": self.ports,
            "live_hosts": self.live_hosts,
            "vulnerabilities": self.vulnerabilities,
            "errors": self.errors,
            "is_running": self.is_running
        }


# ==================== CONVENIENCE FUNCTIONS ====================

def start_scan(target_domain):
    """
    Start a new scan for a target domain.
    
    Args:
        target_domain (str): The domain to scan
        
    Returns:
        tuple: (scan_id, scanner_instance)
    """
    # Create scan record in database
    scan_id = db.create_scan(target_domain)
    
    # Create scanner instance
    scanner = Scanner(scan_id, target_domain)
    
    return scan_id, scanner


def run_scan_async(scan_id, target_domain):
    """
    Run a scan asynchronously (for use with threading).
    
    Args:
        scan_id (str): The scan ID
        target_domain (str): The domain to scan
        
    Returns:
        bool: True if successful, False otherwise
    """
    scanner = Scanner(scan_id, target_domain)
    return scanner.run_full_scan()


def get_scan_status(scan_id):
    """
    Get the current status of a scan.
    
    Args:
        scan_id (str): The scan ID
        
    Returns:
        dict: Scan status and progress
    """
    scan = db.get_scan(scan_id)
    
    if not scan:
        return None
    
    return {
        "scan_id": scan_id,
        "target_domain": scan.get("target_domain"),
        "status": scan.get("status"),
        "progress": scan.get("progress"),
        "stats": scan.get("stats"),
        "created_at": scan.get("created_at"),
        "completed_at": scan.get("completed_at")
    }


# ==================== CLI EXECUTION ====================

if __name__ == "__main__":
    """
    Allow running scanner directly from command line.
    Usage: python scanner.py example.com
    """
    if len(sys.argv) < 2:
        print("Usage: python scanner.py <target_domain>")
        print("Example: python scanner.py example.com")
        sys.exit(1)
    
    target = sys.argv[1]
    print(f"\n[ARES] Starting scan for: {target}")
    
    scan_id, scanner = start_scan(target)
    print(f"[ARES] Scan ID: {scan_id}")
    
    success = scanner.run_full_scan()
    
    if success:
        results = scanner.get_results()
        print("\n[ARES] Final Results:")
        print(json.dumps({
            "subdomains_count": len(results["subdomains"]),
            "ports_count": len(results["ports"]),
            "live_hosts_count": len(results["live_hosts"]),
            "vulnerabilities_count": len(results["vulnerabilities"])
        }, indent=2))
    else:
        print("\n[ARES] Scan completed with errors.")
        sys.exit(1)
