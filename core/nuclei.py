"""
Nuclei Vulnerability Scanner Module
===================================
Windows-safe implementation with:
- Real-time streaming output (prevents pipe buffer deadlock)
- Auto-remediation generation
- Severity breakdown
- CVE/CVSS extraction
- Partial result detection on crash
- Intelligence-driven scanning support:
  - custom_template: single template path for CVE verification
  - custom_templates: multiple template paths for batched verification
  - custom_tags: technology-targeted scanning
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
from utils.logger import logger

IS_WINDOWS: bool = platform.system() == "Windows"


# =============================================================================
# HELPER FUNCTIONS (WINDOWS-SAFE STREAMING)
# =============================================================================

def _run_command_streaming(
    cmd_list: List[str],
    label: str = "NUCLEI"
) -> tuple:
    """
    Execute command with real-time streaming output.
    Windows-safe: Uses Popen to prevent pipe buffer deadlock.

    Returns:
        tuple: (output_string, exit_code)
    """
    try:
        logger.info(
            "[%s] Starting: %s",
            label, os.path.basename(cmd_list[0])
        )

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
                if line and any(
                    x in line
                    for x in [
                        "[WRN]", "[ERR]", "[FTL]",
                        "[INF]", "templates"
                    ]
                ):
                    logger.debug("[%s] %s", label, line)

        stderr_thread = threading.Thread(
            target=read_stderr, daemon=True
        )
        stderr_thread.start()

        for line in process.stdout:
            stdout_lines.append(line)

        process.wait()
        stderr_thread.join(timeout=5)

        exit_code = process.returncode
        logger.info(
            "[%s] Completed (exit code: %d)",
            label, exit_code
        )
        return "".join(stdout_lines), exit_code

    except FileNotFoundError:
        logger.error(
            "[%s] Tool not found at %s", label, cmd_list[0]
        )
        return "", -1

    except Exception as e:
        logger.error(
            "[%s] Error: %s", label, e, exc_info=True
        )
        return "", -1


def _write_targets_file(
    filepath: str,
    targets: List[str]
) -> None:
    """Write targets to file with UTF-8 encoding (no BOM)."""
    with open(
        filepath, "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write("\n".join(targets))


def _empty_result(error: str = "", success: bool = False) -> Dict[str, Any]:
    """Return a standard empty result dict."""
    return {
        "success": success,
        "partial": False,
        "error": error,
        "vulnerabilities": [],
        "count": 0,
        "severity_breakdown": {
            "critical": 0, "high": 0, "medium": 0,
            "low": 0, "info": 0
        }
    }


# =============================================================================
# MAIN SCANNER FUNCTION
# =============================================================================

def run_nuclei(
    targets: List[str],
    template_type: str = "all",
    custom_template: str = None,
    custom_templates: List[str] = None,
    custom_tags: List[str] = None,
    severity_override: str = None
) -> Dict[str, Any]:
    """
    Run Nuclei vulnerability scanner with Windows-safe streaming.

    Args:
        targets: List of hosts/URLs to scan
        template_type: "all", "cves", "exposures", "misconfigs", "technologies"
        custom_template: Single template path for targeted CVE verification
        custom_templates: Multiple template paths for batched CVE verification
        custom_tags: Technology-targeted scan tags (e.g., ["wordpress", "wp"])

    Returns:
        dict with:
            success: bool
            partial: bool — True if Nuclei crashed mid-scan
            vulnerabilities: list of vuln dicts
            count: int
            severity_breakdown: dict
    """
    if not targets:
        logger.warning("Nuclei: No targets provided")
        return _empty_result("No targets")

    # Determine scan mode for logging
    if custom_templates:
        mode = f"batched-cve ({len(custom_templates)} templates)"
    elif custom_template:
        mode = f"targeted-cve ({os.path.basename(custom_template)})"
    elif custom_tags:
        mode = f"tech-targeted (tags: {','.join(custom_tags)})"
    else:
        mode = f"broad ({template_type})"

    logger.info("=" * 50)
    logger.info("Nuclei scan starting [%s]", mode)
    logger.info(
        "Targets: %d | Severity: %s",
        len(targets), severity_override or Config.NUCLEI_SEVERITY
    )

    temp_file = None
    try:
        # ── Write targets to temp file ───────────────────
        temp_file = os.path.join(
            tempfile.gettempdir(),
            f"nuclei_targets_{os.getpid()}.txt"
        )

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
        logger.debug(
            "Targets written to: %s (%d URLs)",
            temp_file, len(processed_targets)
        )

        # ── Resolve severity filter ─────────────────────
        effective_severity = severity_override or Config.NUCLEI_SEVERITY

        # ── Build nuclei command ─────────────────────────
        cmd: List[str] = [
            Config.NUCLEI_PATH,
            "-list", temp_file,
            "-jsonl",
            "-silent",
            "-timeout", "10",
            "-retries", str(
                getattr(Config, 'NUCLEI_RETRIES', 1)
            ),
            "-no-color",
            "-stats"
        ]

        # ── Template selection (priority order) ──────────

        # Priority 1: Multiple specific templates (batched CVE verification)
        if custom_templates:
            valid_templates = [
                t for t in custom_templates
                if os.path.exists(t)
            ]
            if not valid_templates:
                logger.warning(
                    "No valid templates found in batch of %d",
                    len(custom_templates)
                )
                return _empty_result("No valid templates found")

            for t in valid_templates:
                cmd.extend(["-t", t])
            logger.info(
                "  Using %d specific templates",
                len(valid_templates)
            )

        # Priority 2: Single specific template (single CVE verification)
        elif custom_template:
            if os.path.exists(custom_template):
                cmd.extend(["-t", custom_template])
                logger.info(
                    "  Using template: %s",
                    os.path.basename(custom_template)
                )
            else:
                logger.warning(
                    "Template not found: %s — aborting scan",
                    custom_template
                )
                return _empty_result(
                    f"Template not found: {custom_template}"
                )

        # Priority 3: Technology-targeted tags
        elif custom_tags:
            cmd.extend(["-tags", ",".join(custom_tags)])
            cmd.extend(["-severity", effective_severity])   # ← CHANGED
            logger.info(
                "  Using tech tags: %s",
                ",".join(custom_tags)
            )

        # Priority 4: Standard scan by template type
        else:
            cmd.extend(["-severity", effective_severity])   # ← CHANGED

            if template_type == "cves":
                cmd.extend(["-tags", "cve"])
            elif template_type == "exposures":
                cmd.extend(["-tags", "exposure,config"])
            elif template_type == "misconfigs":
                cmd.extend([
                    "-tags",
                    "misconfig,security-misconfiguration"
                ])
            elif template_type == "technologies":
                cmd.extend(["-tags", "tech"])

        # Rate limiting
        if hasattr(Config, 'NUCLEI_RATE_LIMIT'):
            cmd.extend([
                "-rate-limit",
                str(Config.NUCLEI_RATE_LIMIT)
            ])

        logger.info("Nuclei scan running...")

        # ── Run nuclei with streaming ────────────────────
        output, exit_code = _run_command_streaming(
            cmd, "NUCLEI"
        )

        logger.debug(
            "Raw output: %d bytes, %d lines",
            len(output), len(output.splitlines())
        )

        # ── Parse output ─────────────────────────────────
        vulnerabilities: List[Dict[str, Any]] = []
        severity_count = {
            "critical": 0, "high": 0, "medium": 0,
            "low": 0, "info": 0
        }

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                info = data.get("info", {})
                severity = info.get(
                    "severity", "info"
                ).lower()

                # Extract URL from multiple sources
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
                    "template_id": data.get(
                        "template-id", ""
                    ),
                    "name": info.get(
                        "name", data.get("name", "")
                    ),
                    "severity": severity,
                    "description": info.get(
                        "description", ""
                    ),
                    "host": data.get("host", ""),
                    "url": url,
                    "matched_at": data.get(
                        "matched-at", ""
                    ),
                    "matcher_name": data.get(
                        "matcher-name", ""
                    ),
                    "tags": info.get("tags", []),
                    "reference": info.get("reference", []),
                    "cve_id": _extract_cve(info),
                    "cvss_score": _extract_cvss(info),
                    "cwe_id": info.get(
                        "classification", {}
                    ).get("cwe-id", []),
                    "remediation": _get_remediation(data),
                    "curl_command": data.get(
                        "curl-command", ""
                    ),
                    "extracted_results": data.get(
                        "extracted-results", []
                    ),
                    "found_at": datetime.utcnow().isoformat()
                }
                vulnerabilities.append(vuln)

                if severity in severity_count:
                    severity_count[severity] += 1

                logger.info(
                    "  Found [%s] %s @ %s",
                    severity.upper(),
                    vuln['name'],
                    vuln['host']
                )

            except json.JSONDecodeError:
                pass

        # ── Log summary ──────────────────────────────────
        logger.info(
            "Nuclei scan complete [%s]: %d vulnerabilities",
            mode, len(vulnerabilities)
        )
        logger.info(
            "Breakdown: Critical=%d, High=%d, "
            "Medium=%d, Low=%d, Info=%d",
            severity_count['critical'],
            severity_count['high'],
            severity_count['medium'],
            severity_count['low'],
            severity_count['info']
        )

        # ── Detect partial results ───────────────────────
        if exit_code != 0 and len(vulnerabilities) == 0:
            logger.error(
                "Nuclei crashed (exit code %d) — no results",
                exit_code
            )
            result = _empty_result(
                f"Nuclei exited with code {exit_code}. "
                f"No vulnerabilities found."
            )
            result["severity_breakdown"] = severity_count
            return result

        if exit_code != 0 and len(vulnerabilities) > 0:
            warning = (
                f"Nuclei exited abnormally "
                f"(code {exit_code}). "
                f"Found {len(vulnerabilities)} "
                f"vulnerabilities before crash. "
                f"Results may be incomplete."
            )
            logger.warning(warning)
            return {
                "success": True,
                "partial": True,
                "warning": warning,
                "vulnerabilities": vulnerabilities,
                "count": len(vulnerabilities),
                "severity_breakdown": severity_count
            }

        # Normal successful completion
        return {
            "success": True,
            "partial": False,
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities),
            "severity_breakdown": severity_count
        }

    except subprocess.TimeoutExpired:
        logger.error(
            "Nuclei timeout after %ds", Config.SCAN_TIMEOUT
        )
        return _empty_result("Scan timeout")

    except FileNotFoundError:
        logger.error(
            "Nuclei not found at %s", Config.NUCLEI_PATH
        )
        return _empty_result(
            f"Nuclei not found at {Config.NUCLEI_PATH}"
        )

    except Exception as e:
        logger.error("Nuclei error: %s", e, exc_info=True)
        return _empty_result(str(e))

    finally:
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except Exception:
                pass


# =============================================================================
# CVE / CVSS EXTRACTION
# =============================================================================

def _extract_cve(info: Dict[str, Any]) -> Optional[str]:
    """Extract CVE ID from vulnerability info."""
    classification = info.get("classification", {})
    cve_id = classification.get("cve-id", [])
    if cve_id:
        return cve_id[0] if isinstance(cve_id, list) else cve_id

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


# =============================================================================
# REMEDIATION GENERATION
# =============================================================================

def _get_remediation(
    entry: Dict[str, Any]
) -> Dict[str, str]:
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
        "description": _generate_remediation(
            template_id, severity
        ),
        "priority": _get_priority(severity),
        "source": "auto-generated"
    }


def _get_priority(severity: str) -> str:
    """Map severity to remediation priority."""
    priorities = {
        "critical": "immediate",
        "high": "short_term",
        "medium": "medium_term",
        "low": "long_term",
        "info": "informational"
    }
    return priorities.get(severity.lower(), "medium_term")


def _generate_remediation(
    template_id: str,
    severity: str
) -> str:
    """Generate basic remediation based on template type."""
    template_lower = template_id.lower()

    remediations = {
        "xss": (
            "Implement input validation and output encoding. "
            "Use Content-Security-Policy headers."
        ),
        "sqli": (
            "Use parameterized queries and prepared "
            "statements. Implement input validation."
        ),
        "sql-injection": (
            "Use parameterized queries and prepared "
            "statements. Implement input validation."
        ),
        "ssrf": (
            "Validate and sanitize user-supplied URLs. "
            "Implement allowlists for external resources."
        ),
        "lfi": (
            "Validate file paths and implement proper "
            "access controls. Use allowlists for file access."
        ),
        "rce": (
            "Patch the affected component immediately. "
            "Implement input validation and sandboxing."
        ),
        "exposed": (
            "Remove or restrict access to sensitive "
            "endpoints. Implement authentication."
        ),
        "default-login": (
            "Change default credentials immediately. "
            "Implement strong password policies."
        ),
        "default-cred": (
            "Change default credentials immediately. "
            "Implement strong password policies."
        ),
        "cve-": (
            "Apply the vendor security patch. Check vendor "
            "advisory for specific remediation steps."
        ),
        "misconfig": (
            "Review and harden configuration settings "
            "according to security best practices."
        ),
        "disclosure": (
            "Restrict access to sensitive information. "
            "Review information exposure points."
        ),
        "takeover": (
            "Verify domain ownership and DNS configuration. "
            "Remove dangling DNS records."
        ),
        "open-redirect": (
            "Validate and sanitize redirect URLs. "
            "Use allowlists for redirect destinations."
        ),
        "cors": (
            "Configure CORS headers properly. "
            "Restrict allowed origins."
        ),
        "crlf": (
            "Sanitize user input to remove CR/LF "
            "characters. Validate headers."
        ),
        "xxe": (
            "Disable external entity processing in XML "
            "parsers. Use less complex data formats."
        ),
    }

    for key, remedy in remediations.items():
        if key in template_lower:
            return remedy

    severity_remediation = {
        "critical": (
            "Investigate and remediate immediately. "
            "This is a critical security issue."
        ),
        "high": (
            "Prioritize remediation within 7 days. "
            "Review system for potential exploitation."
        ),
        "medium": (
            "Schedule remediation within 30 days. "
            "Monitor for any suspicious activity."
        ),
        "low": (
            "Plan remediation within 90 days as part "
            "of regular maintenance."
        ),
        "info": (
            "Review for potential security improvement "
            "opportunities."
        )
    }

    return severity_remediation.get(
        severity,
        "Review and remediate according to security policies."
    )