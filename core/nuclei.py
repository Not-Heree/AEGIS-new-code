# core/nuclei.py
"""
Nuclei Vulnerability Scanner Module
===================================
Windows-safe implementation with:
- Real-time streaming output (prevents pipe buffer deadlock)
- Auto-remediation generation
- Severity breakdown
- CVE/CVSS extraction
"""

import subprocess
import os
import json
import platform
import threading
import tempfile
from datetime import datetime
from typing import List, Dict, Any, Optional

from config import Config


# =============================================================================
# CONFIGURATION
# =============================================================================

IS_WINDOWS: bool = platform.system() == "Windows"


# =============================================================================
# HELPER FUNCTIONS (WINDOWS-SAFE STREAMING)
# =============================================================================

def _run_command_streaming(cmd_list: List[str], label: str = "NUCLEI") -> str:
    """
    Execute command with real-time streaming output.
    Windows-safe: Uses Popen to prevent pipe buffer deadlock.
    """
    try:
        print(f"[{label}] Starting: {os.path.basename(cmd_list[0])}")
        
        process = subprocess.Popen(
            cmd_list,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1
        )
        
        stdout_lines: List[str] = []
        
        def read_stderr():
            """Read stderr in background thread."""
            for line in process.stderr:
                line = line.strip()
                if line:
                    # Print important messages
                    if any(x in line for x in ["[WRN]", "[ERR]", "[FTL]", "[INF]", "templates"]):
                        print(f"[{label}] {line}")
        
        # Start stderr reader thread
        stderr_thread = threading.Thread(target=read_stderr, daemon=True)
        stderr_thread.start()
        
        # Read stdout in main thread
        for line in process.stdout:
            stdout_lines.append(line)
        
        process.wait()
        stderr_thread.join(timeout=5)
        
        print(f"[{label}] Completed (exit code: {process.returncode})")
        return "".join(stdout_lines)
        
    except FileNotFoundError:
        print(f"[{label}] ERROR: Tool not found at {cmd_list[0]}")
        return ""
    except Exception as e:
        print(f"[{label}] ERROR: {e}")
        return ""


def _write_targets_file(filepath: str, targets: List[str]) -> None:
    """Write targets to file with UTF-8 encoding (no BOM)."""
    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(targets))


# =============================================================================
# MAIN SCANNER FUNCTION
# =============================================================================

def run_nuclei(targets: List[str], template_type: str = "all") -> Dict[str, Any]:
    """
    Run Nuclei vulnerability scanner with Windows-safe streaming.
    
    Args:
        targets: List of URLs or hosts to scan
        template_type: Type of templates to use
            - "all": All templates (default)
            - "cves": CVE templates only
            - "exposures": Exposure templates
            - "misconfigs": Misconfiguration templates
            - "technologies": Tech detection
    
    Returns:
        dict with success, vulnerabilities, count, severity_breakdown
    """
    if not targets:
        print("[NUCLEI] No targets provided")
        return {"success": False, "error": "No targets", "vulnerabilities": []}

    print(f"\n{'='*50}")
    print(f"[NUCLEI] Starting vulnerability scan")
    print(f"{'='*50}")
    print(f"[NUCLEI] Targets: {len(targets)}")
    print(f"[NUCLEI] Template type: {template_type}")
    print(f"[NUCLEI] Severity filter: {Config.NUCLEI_SEVERITY}")

    temp_file = None
    try:
        # Write targets to temp file
        temp_file = os.path.join(tempfile.gettempdir(), f"nuclei_targets_{os.getpid()}.txt")
        
        # Ensure targets have protocol
        processed_targets: List[str] = []
        for target in targets:
            target = target.strip()
            if not target:
                continue
            if not target.startswith("http"):
                processed_targets.append(f"https://{target}")
                processed_targets.append(f"http://{target}")
            else:
                processed_targets.append(target)
        
        _write_targets_file(temp_file, processed_targets)
        print(f"[NUCLEI] Targets written to: {temp_file}")
        print(f"[NUCLEI] Total URLs to scan: {len(processed_targets)}")

        # Build nuclei command
        cmd: List[str] = [
            Config.NUCLEI_PATH,
            "-list", temp_file,
            "-jsonl",
            "-silent",
            "-severity", Config.NUCLEI_SEVERITY,
            "-timeout", "10",
            "-retries", str(getattr(Config, 'NUCLEI_RETRIES', 1)),
            "-no-color",
            "-stats"
        ]

        # Add rate limit if configured
        if hasattr(Config, 'NUCLEI_RATE_LIMIT'):
            cmd.extend(["-rate-limit", str(Config.NUCLEI_RATE_LIMIT)])

        # Add template filters based on type
        if template_type == "cves":
            cmd.extend(["-tags", "cve"])
        elif template_type == "exposures":
            cmd.extend(["-tags", "exposure,config"])
        elif template_type == "misconfigs":
            cmd.extend(["-tags", "misconfig,security-misconfiguration"])
        elif template_type == "technologies":
            cmd.extend(["-tags", "tech"])
        # "all" uses default templates

        print(f"[NUCLEI] Running scan...")

        # Run nuclei with streaming (Windows-safe)
        output: str = _run_command_streaming(cmd, "NUCLEI")

        print(f"[NUCLEI] Raw output: {len(output)} bytes, {len(output.splitlines())} lines")

        # Parse output
        vulnerabilities: List[Dict[str, Any]] = []
        severity_count = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                info = data.get("info", {})
                severity = info.get("severity", "info").lower()

                # Extract URL from various sources
                url = data.get("matched-at", "")
                if not url:
                    curl_cmd = data.get("curl-command", "")
                    if curl_cmd:
                        parts = curl_cmd.split(" ")
                        for part in parts:
                            if part.startswith("http"):
                                url = part.strip("'\"")
                                break
                if not url:
                    url = data.get("host", "")

                vuln = {
                    "template_id": data.get("template-id", ""),
                    "name": info.get("name", data.get("name", "")),
                    "severity": severity,
                    "description": info.get("description", ""),
                    "host": data.get("host", ""),
                    "url": url,
                    "matched_at": data.get("matched-at", ""),
                    "matcher_name": data.get("matcher-name", ""),
                    "tags": info.get("tags", []),
                    "reference": info.get("reference", []),
                    "cve_id": _extract_cve(info),
                    "cvss_score": _extract_cvss(info),
                    "cwe_id": info.get("classification", {}).get("cwe-id", []),
                    "remediation": _get_remediation(data),
                    "curl_command": data.get("curl-command", ""),
                    "extracted_results": data.get("extracted-results", []),
                    "found_at": datetime.utcnow().isoformat()
                }
                vulnerabilities.append(vuln)

                if severity in severity_count:
                    severity_count[severity] += 1

                # Real-time feedback
                print(f"    [FOUND] [{severity.upper()}] {vuln['name']} @ {vuln['host']}")

            except json.JSONDecodeError:
                pass

        print(f"\n[NUCLEI] Scan complete!")
        print(f"[NUCLEI] Total vulnerabilities: {len(vulnerabilities)}")
        print(f"[NUCLEI] Breakdown: Critical={severity_count['critical']}, High={severity_count['high']}, Medium={severity_count['medium']}, Low={severity_count['low']}, Info={severity_count['info']}")

        return {
            "success": True,
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities),
            "severity_breakdown": severity_count
        }

    except subprocess.TimeoutExpired:
        print(f"[NUCLEI] Timeout after {Config.SCAN_TIMEOUT}s")
        return {
            "success": False,
            "error": "Scan timeout",
            "vulnerabilities": []
        }

    except FileNotFoundError:
        error = f"Nuclei not found at {Config.NUCLEI_PATH}"
        print(f"[NUCLEI] ERROR: {error}")
        return {
            "success": False,
            "error": error,
            "vulnerabilities": []
        }

    except Exception as e:
        print(f"[NUCLEI] ERROR: {e}")
        return {
            "success": False,
            "error": str(e),
            "vulnerabilities": []
        }

    finally:
        # Cleanup temp file
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except Exception:
                pass


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _extract_cve(info: Dict[str, Any]) -> Optional[str]:
    """Extract CVE ID from vulnerability info."""
    classification = info.get("classification", {})
    cve_id = classification.get("cve-id", [])
    if cve_id:
        return cve_id[0] if isinstance(cve_id, list) else cve_id
    
    # Check in tags
    tags = info.get("tags", [])
    for tag in tags:
        if isinstance(tag, str) and tag.upper().startswith("CVE-"):
            return tag.upper()
    
    return None


def _extract_cvss(info: Dict[str, Any]) -> Optional[float]:
    """Extract CVSS score from vulnerability info."""
    classification = info.get("classification", {})
    cvss_score = classification.get("cvss-score", None)
    if cvss_score:
        try:
            return float(cvss_score)
        except (ValueError, TypeError):
            pass
    
    cvss_metrics = classification.get("cvss-metrics", "")
    if cvss_metrics:
        try:
            parts = str(cvss_metrics).split("/")
            for part in parts:
                clean = part.replace(".", "").replace("-", "")
                if clean.isdigit():
                    return float(part)
        except Exception:
            pass
    
    return None


def _get_remediation(entry: Dict[str, Any]) -> Dict[str, str]:
    """Generate remediation advice based on vulnerability."""
    info = entry.get("info", {})
    remediation = info.get("remediation", "")
    severity = info.get("severity", "info").lower()
    
    if remediation:
        return {
            "description": remediation,
            "priority": _get_priority(severity),
            "source": "nuclei-template"
        }
    
    template_id = entry.get("template-id", "")
    
    return {
        "description": _generate_remediation(template_id, severity),
        "priority": _get_priority(severity),
        "source": "auto-generated"
    }


def _get_priority(severity: str) -> str:
    """Map severity to priority."""
    priorities = {
        "critical": "immediate",
        "high": "short_term",
        "medium": "medium_term",
        "low": "long_term",
        "info": "informational"
    }
    return priorities.get(severity.lower(), "medium_term")


def _generate_remediation(template_id: str, severity: str) -> str:
    """Generate basic remediation based on template type."""
    template_lower = template_id.lower()
    
    remediations = {
        "xss": "Implement input validation and output encoding. Use Content-Security-Policy headers.",
        "sqli": "Use parameterized queries and prepared statements. Implement input validation.",
        "sql-injection": "Use parameterized queries and prepared statements. Implement input validation.",
        "ssrf": "Validate and sanitize user-supplied URLs. Implement allowlists for external resources.",
        "lfi": "Validate file paths and implement proper access controls. Use allowlists for file access.",
        "rce": "Patch the affected component immediately. Implement input validation and sandboxing.",
        "exposed": "Remove or restrict access to sensitive endpoints. Implement authentication.",
        "default-login": "Change default credentials immediately. Implement strong password policies.",
        "default-cred": "Change default credentials immediately. Implement strong password policies.",
        "cve-": "Apply the vendor security patch. Check vendor advisory for specific remediation steps.",
        "misconfig": "Review and harden configuration settings according to security best practices.",
        "disclosure": "Restrict access to sensitive information. Review information exposure points.",
        "takeover": "Verify domain ownership and DNS configuration. Remove dangling DNS records.",
        "open-redirect": "Validate and sanitize redirect URLs. Use allowlists for redirect destinations.",
        "cors": "Configure CORS headers properly. Restrict allowed origins.",
        "crlf": "Sanitize user input to remove CR/LF characters. Validate headers.",
        "xxe": "Disable external entity processing in XML parsers. Use less complex data formats.",
    }
    
    for key, remedy in remediations.items():
        if key in template_lower:
            return remedy
    
    severity_remediation = {
        "critical": "Investigate and remediate immediately. This is a critical security issue.",
        "high": "Prioritize remediation within 7 days. Review system for potential exploitation.",
        "medium": "Schedule remediation within 30 days. Monitor for any suspicious activity.",
        "low": "Plan remediation within 90 days as part of regular maintenance.",
        "info": "Review for potential security improvement opportunities."
    }
    
    return severity_remediation.get(severity, "Review and remediate according to security policies.")


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def run_nuclei_quick(targets: List[str]) -> Dict[str, Any]:
    """Run a quick scan with exposure/config checks."""
    return run_nuclei(targets, template_type="exposures")


def run_nuclei_cve(targets: List[str]) -> Dict[str, Any]:
    """Run CVE-focused scan."""
    return run_nuclei(targets, template_type="cves")


def run_nuclei_full(targets: List[str]) -> Dict[str, Any]:
    """Run full comprehensive scan."""
    return run_nuclei(targets, template_type="all")


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  NUCLEI SCANNER - Standalone Test")
    print("=" * 60)
    
    target = input("Enter target URL or domain: ").strip()
    if target:
        print(f"\nTesting with: {target}")
        result = run_nuclei_quick([target])
        
        print(f"\n{'='*60}")
        print(f"SUCCESS: {result['success']}")
        print(f"FOUND: {result.get('count', 0)} vulnerabilities")
        print(f"BREAKDOWN: {result.get('severity_breakdown', {})}")
        
        if result.get('vulnerabilities'):
            print(f"\n--- Top 5 Findings ---")
            for v in result['vulnerabilities'][:5]:
                print(f"[{v['severity'].upper()}] {v['name']}")
                print(f"  URL: {v['url']}")
                print(f"  Fix: {v['remediation'].get('description', 'N/A')[:80]}...")
                print()