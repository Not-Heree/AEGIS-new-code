"""
Nuclei Vulnerability Scanner Module
===================================
Windows-safe implementation with:
- Real-time streaming output (prevents pipe buffer deadlock)
- Auto-remediation generation
- Severity breakdown
- CVE/CVSS extraction
- Partial result detection on crash or timeout
- Intelligence-driven scanning support:
  - custom_template: single template path for CVE verification
  - custom_templates: multiple template paths for batched verification
  - custom_tags: technology-targeted scanning

Performance controls (from Config):
  - NUCLEI_CONCURRENCY: Nuclei's -c and -bulk-size flags.
    Controls how many templates and hosts are processed in
    parallel within a single Nuclei process.
  - NUCLEI_TIMEOUT: Max seconds per Nuclei invocation.
    Process is killed if exceeded; partial results preserved.
  - NUCLEI_RATE_LIMIT: Max requests per second (-rate-limit).
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
    label: str = "NUCLEI",
    timeout: int = None
) -> tuple:
    """
    Execute command with real-time streaming output.
    Windows-safe: Uses Popen to prevent pipe buffer deadlock.

    Args:
        cmd_list: Command and arguments as list
        label:    Label for log messages
        timeout:  Max seconds before killing the process.
                  None = no timeout.

    Returns:
        tuple: (output_string, exit_code)
               exit_code -1 = process error
               exit_code -2 = killed by timeout
    """
    try:
        logger.info(
            "[%s] Starting: %s",
            label, os.path.basename(cmd_list[0])
        )
        if timeout:
            logger.info(
                "[%s] Timeout: %d seconds", label, timeout
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
        timed_out = False
        timer = None

        # ── Timeout watchdog ─────────────────────────────
        if timeout and timeout > 0:
            def _kill_on_timeout():
                nonlocal timed_out
                timed_out = True
                logger.warning(
                    "[%s] TIMEOUT after %ds — killing "
                    "process (partial results preserved)",
                    label, timeout
                )
                try:
                    process.kill()
                except Exception:
                    pass

            timer = threading.Timer(
                timeout, _kill_on_timeout
            )
            timer.daemon = True
            timer.start()

        # ── Read stderr in background ────────────────────
        def read_stderr():
            """Read stderr in background thread."""
            try:
                for line in process.stderr:
                    line = line.strip()
                    if line and any(
                        x in line
                        for x in [
                            "[WRN]", "[ERR]", "[FTL]",
                            "[INF]", "templates"
                        ]
                    ):
                        logger.debug(
                            "[%s] %s", label, line
                        )
            except Exception:
                pass

        stderr_thread = threading.Thread(
            target=read_stderr, daemon=True
        )
        stderr_thread.start()

        # ── Read stdout (main thread) ────────────────────
        try:
            for line in process.stdout:
                stdout_lines.append(line)
        except Exception:
            # Process was killed by timeout mid-read
            pass

        process.wait()
        stderr_thread.join(timeout=5)

        # ── Cancel timer if process finished naturally ───
        if timer:
            timer.cancel()

        if timed_out:
            logger.warning(
                "[%s] Process killed by timeout. "
                "Captured %d lines of output before kill.",
                label, len(stdout_lines)
            )
            return "".join(stdout_lines), -2

        exit_code = process.returncode
        logger.info(
            "[%s] Completed (exit code: %d)",
            label, exit_code
        )
        return "".join(stdout_lines), exit_code

    except FileNotFoundError:
        logger.error(
            "[%s] Tool not found at %s",
            label, cmd_list[0]
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
    """Write targets to file with UTF-8 encoding."""
    with open(
        filepath, "w", encoding="utf-8", newline="\n"
    ) as f:
        f.write("\n".join(targets))


def _empty_result(
    error: str = "",
    success: bool = False
) -> Dict[str, Any]:
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


def _merge_nuclei_results(
    results: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Combine multiple Nuclei batch results into one result dict."""
    merged_vulns: List[Dict[str, Any]] = []
    severity_breakdown = {
        "critical": 0, "high": 0, "medium": 0,
        "low": 0, "info": 0
    }
    partial = False
    warnings: List[str] = []
    errors: List[str] = []
    success = False

    for result in results:
        if not result:
            continue
        if result.get("success"):
            success = True
        if result.get("partial"):
            partial = True
        if result.get("warning"):
            warnings.append(result["warning"])
        if result.get("error"):
            errors.append(result["error"])
        merged_vulns.extend(result.get("vulnerabilities", []))

        for severity, count in result.get("severity_breakdown", {}).items():
            if severity in severity_breakdown:
                severity_breakdown[severity] += count

    merged = {
        "success": success,
        "partial": partial,
        "vulnerabilities": merged_vulns,
        "count": len(merged_vulns),
        "severity_breakdown": severity_breakdown
    }
    if warnings:
        merged["warning"] = " | ".join(warnings)
    if errors and not success:
        merged["error"] = " | ".join(errors)
    return merged


# =============================================================================
# MAIN SCANNER FUNCTION
# =============================================================================

def _run_nuclei_single(
    targets: List[str],
    template_type: str = "all",
    custom_template: str = None,
    custom_templates: List[str] = None,
    custom_tags: List[str] = None,
    severity_override: str = None,
    expand_http_schemes: bool = True
) -> Dict[str, Any]:
    """
    Run Nuclei vulnerability scanner with Windows-safe streaming.

    Performance is controlled by two Config values:
      - NUCLEI_CONCURRENCY: Passed to Nuclei as -c (template
        threads) and -bulk-size (hosts per batch). Controls
        internal parallelism. Higher = faster but more RAM.
      - NUCLEI_TIMEOUT: Max seconds this Nuclei process may
        run. If exceeded, the process is killed and any
        vulnerabilities found before the kill are returned
        as partial results.

    Args:
        targets: List of hosts/URLs to scan
        template_type: "all", "cves", "exposures", etc.
        custom_template: Single template path
        custom_templates: Multiple template paths
        custom_tags: Technology-targeted scan tags
        severity_override: Override severity filter

    Returns:
        dict with success, partial, vulnerabilities,
        count, severity_breakdown
    """
    if not targets:
        logger.warning("Nuclei: No targets provided")
        return _empty_result("No targets")

    # ── Read performance config ──────────────────────────
    concurrency = getattr(Config, 'NUCLEI_CONCURRENCY', 25)
    nuclei_timeout = getattr(Config, 'NUCLEI_TIMEOUT', 600)

    # Determine scan mode for logging
    if custom_templates:
        mode = (
            f"batched-cve "
            f"({len(custom_templates)} templates)"
        )
    elif custom_template:
        mode = (
            f"targeted-cve "
            f"({os.path.basename(custom_template)})"
        )
    elif custom_tags:
        mode = (
            f"tech-targeted "
            f"(tags: {','.join(custom_tags)})"
        )
    else:
        mode = f"broad ({template_type})"

    logger.info("=" * 50)
    logger.info("Nuclei scan starting [%s]", mode)
    logger.info(
        "Targets: %d | Severity: %s | "
        "Concurrency: %d | Timeout: %ds",
        len(targets),
        severity_override or Config.NUCLEI_SEVERITY,
        concurrency,
        nuclei_timeout
    )

    temp_file = None
    try:
        # ── Write targets to temp file ───────────────
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            suffix=".txt",
            prefix="nuclei_targets_",
            delete=False
        ) as temp_handle:
            temp_file = temp_handle.name

        # Ensure targets have protocol
        processed_targets: List[str] = []
        for target in targets:
            target = str(target).strip()
            if not target:
                continue
            if (
                expand_http_schemes
                and not target.startswith(("http://", "https://"))
            ):
                processed_targets.append(
                    f"https://{target}"
                )
                processed_targets.append(
                    f"http://{target}"
                )
            else:
                processed_targets.append(target)

        processed_targets = list(dict.fromkeys(processed_targets))

        _write_targets_file(
            temp_file, processed_targets
        )
        logger.debug(
            "Targets written to: %s (%d URLs)",
            temp_file, len(processed_targets)
        )

        # ── Resolve severity filter ──────────────────
        effective_severity = (
            severity_override or Config.NUCLEI_SEVERITY
        )

        # ── Build nuclei command ─────────────────────
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
            "-stats",
            # ── Performance: concurrency controls ────
            "-c", str(concurrency),
            "-bulk-size", str(concurrency),
        ]

        # ── Template selection (priority order) ──────

        # Priority 1: Multiple specific templates
        if custom_templates:
            valid_templates = [
                t for t in custom_templates
                if os.path.exists(t)
            ]
            if not valid_templates:
                logger.warning(
                    "No valid templates found in "
                    "batch of %d",
                    len(custom_templates)
                )
                return _empty_result(
                    "No valid templates found"
                )

            for t in valid_templates:
                cmd.extend(["-t", t])
            logger.info(
                "  Using %d specific templates",
                len(valid_templates)
            )

        # Priority 2: Single specific template
        elif custom_template:
            if os.path.exists(custom_template):
                cmd.extend(["-t", custom_template])
                logger.info(
                    "  Using template: %s",
                    os.path.basename(custom_template)
                )
            else:
                logger.warning(
                    "Template not found: %s",
                    custom_template
                )
                return _empty_result(
                    f"Template not found: "
                    f"{custom_template}"
                )

        # Priority 3: Technology-targeted tags
        elif custom_tags:
            cmd.extend([
                "-tags", ",".join(custom_tags)
            ])
            cmd.extend([
                "-severity", effective_severity
            ])
            logger.info(
                "  Using tech tags: %s",
                ",".join(custom_tags)
            )

        # Priority 4: Standard scan
        else:
            cmd.extend([
                "-severity", effective_severity
            ])

            if template_type == "cves":
                cmd.extend(["-tags", "cve"])
            elif template_type == "exposures":
                cmd.extend([
                    "-tags", "exposure,config"
                ])
            elif template_type == "misconfigs":
                cmd.extend([
                    "-tags",
                    "misconfig,"
                    "security-misconfiguration"
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

        # ── Run nuclei with streaming + timeout ──────
        output, exit_code = _run_command_streaming(
            cmd, "NUCLEI", timeout=nuclei_timeout
        )

        logger.debug(
            "Raw output: %d bytes, %d lines",
            len(output), len(output.splitlines())
        )

        # ── Parse output ─────────────────────────────
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

                # Extract URL
                url = data.get("matched-at", "")
                if not url:
                    curl_cmd = data.get(
                        "curl-command", ""
                    )
                    if curl_cmd:
                        parts = curl_cmd.split(" ")
                        for part in parts:
                            if part.startswith("http"):
                                url = part.strip("'\"")
                                break
                if not url:
                    url = data.get("host", "")

                # Extract base CWE ID from Nuclei
                nuclei_cwe = info.get(
                    "classification", {}
                ).get("cwe-id", [])
                
                # Map to CWE using vuln name/template/tags if needed
                template_id = data.get("template-id", "")
                vuln_name = info.get(
                    "name", data.get("name", "")
                )
                tags = info.get("tags", [])
                
                mapped_cwe = _map_vuln_to_cwe(
                    vuln_name, template_id, tags,
                    existing_cwe=nuclei_cwe
                )
                
                vuln = {
                    "template_id": template_id,
                    "name": vuln_name,
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
                    "tags": tags,
                    "reference": info.get(
                        "reference", []
                    ),
                    "cve_id": _extract_cve(info),
                    "cvss_score": _extract_cvss(info),
                    "cwe_id": mapped_cwe,  # Now includes mapped CWEs
                    "remediation": _get_remediation(
                        data
                    ),
                    "curl_command": data.get(
                        "curl-command", ""
                    ),
                    "extracted_results": data.get(
                        "extracted-results", []
                    ),
                    "found_at": (
                        datetime.utcnow().isoformat()
                    ),
                    
                    # ── Store template info for better remediation ──
                    "template_info": {
                        "author": info.get("author", []),
                        "severity": info.get("severity", ""),
                        "tags": tags,
                        "description": info.get("description", ""),
                        "remediation": info.get("remediation", ""),
                        "classification": info.get("classification", {})
                    }
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

        # ── Log summary ──────────────────────────────
        logger.info(
            "Nuclei scan complete [%s]: "
            "%d vulnerabilities",
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

        # ── Handle timeout (exit_code -2) ────────────
        if exit_code == -2:
            if vulnerabilities:
                warning = (
                    f"Nuclei timed out after "
                    f"{nuclei_timeout}s. "
                    f"Found {len(vulnerabilities)} "
                    f"vulnerabilities before timeout. "
                    f"Results are partial — increase "
                    f"NUCLEI_TIMEOUT or reduce targets."
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
            else:
                logger.error(
                    "Nuclei timed out after %ds "
                    "with no results",
                    nuclei_timeout
                )
                return _empty_result(
                    f"Nuclei timed out after "
                    f"{nuclei_timeout}s. "
                    f"No vulnerabilities found. "
                    f"Increase NUCLEI_TIMEOUT or "
                    f"reduce NUCLEI_CONCURRENCY."
                )

        # ── Handle crash (nonzero exit, not timeout) ─
        if exit_code != 0 and not vulnerabilities:
            logger.error(
                "Nuclei crashed (exit code %d) "
                "— no results", exit_code
            )
            result = _empty_result(
                f"Nuclei exited with code {exit_code}."
                f" No vulnerabilities found."
            )
            result["severity_breakdown"] = (
                severity_count
            )
            return result

        if exit_code != 0 and vulnerabilities:
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

        # ── Normal success ───────────────────────────
        return {
            "success": True,
            "partial": False,
            "vulnerabilities": vulnerabilities,
            "count": len(vulnerabilities),
            "severity_breakdown": severity_count
        }

    except FileNotFoundError:
        logger.error(
            "Nuclei not found at %s",
            Config.NUCLEI_PATH
        )
        return _empty_result(
            f"Nuclei not found at {Config.NUCLEI_PATH}"
        )

    except Exception as e:
        logger.error(
            "Nuclei error: %s", e, exc_info=True
        )
        return _empty_result(str(e))

    finally:
        if temp_file and os.path.exists(temp_file):
            try:
                os.remove(temp_file)
            except Exception:
                pass


def run_nuclei(
    targets: List[str],
    template_type: str = "all",
    custom_template: str = None,
    custom_templates: List[str] = None,
    custom_tags: List[str] = None,
    severity_override: str = None,
    expand_http_schemes: bool = True
) -> Dict[str, Any]:
    """Run Nuclei, chunking large target lists into safer batches."""
    if not targets:
        logger.warning("Nuclei: No targets provided")
        return _empty_result("No targets")

    deduped_targets: List[str] = []
    seen_targets = set()
    for target in targets:
        target = str(target).strip()
        if not target or target in seen_targets:
            continue
        seen_targets.add(target)
        deduped_targets.append(target)

    batch_size = max(
        1,
        getattr(Config, "NUCLEI_BATCH_SIZE", len(deduped_targets))
    )
    if len(deduped_targets) <= batch_size:
        return _run_nuclei_single(
            deduped_targets,
            template_type=template_type,
            custom_template=custom_template,
            custom_templates=custom_templates,
            custom_tags=custom_tags,
            severity_override=severity_override,
            expand_http_schemes=expand_http_schemes
        )

    logger.info(
        "Nuclei batching enabled: %d targets split into chunks of %d",
        len(deduped_targets),
        batch_size
    )
    batch_results: List[Dict[str, Any]] = []
    for offset in range(0, len(deduped_targets), batch_size):
        batch = deduped_targets[offset:offset + batch_size]
        logger.info(
            "Running Nuclei batch %d-%d of %d targets",
            offset + 1,
            offset + len(batch),
            len(deduped_targets)
        )
        batch_results.append(
            _run_nuclei_single(
                batch,
                template_type=template_type,
                custom_template=custom_template,
                custom_templates=custom_templates,
                custom_tags=custom_tags,
                severity_override=severity_override,
                expand_http_schemes=expand_http_schemes
            )
        )

    return _merge_nuclei_results(batch_results)


# =============================================================================
# CVE / CVSS EXTRACTION
# =============================================================================

def _extract_cve(
    info: Dict[str, Any]
) -> Optional[str]:
    """Extract CVE ID from vulnerability info."""
    classification = info.get("classification", {})
    cve_id = classification.get("cve-id", [])
    if cve_id:
        return (
            cve_id[0]
            if isinstance(cve_id, list)
            else cve_id
        )

    tags = info.get("tags", [])
    for tag in tags:
        if (isinstance(tag, str)
                and tag.upper().startswith("CVE-")):
            return tag.upper()

    return None


def _map_vuln_to_cwe(
    vuln_name: str,
    template_id: str,
    tags: List[str],
    existing_cwe: List[str] = None
) -> List[str]:
    """
    Map vulnerability name, template ID, and tags to CWE IDs.
    
    If CWE IDs are already provided by Nuclei, return them.
    Otherwise, map based on vulnerability characteristics.
    
    Args:
        vuln_name: Vulnerability name
        template_id: Nuclei template ID
        tags: Vulnerability tags
        existing_cwe: CWE IDs from Nuclei (if any)
    
    Returns:
        List of CWE IDs
    """
    # If CWE IDs already provided by Nuclei, return them
    if existing_cwe and len(existing_cwe) > 0:
        return existing_cwe
    
    vuln_name_lower = vuln_name.lower()
    template_lower = template_id.lower()
    tags_lower = [t.lower() for t in (tags or [])]
    
    # ── SSL/TLS / Weak Cryptography ──
    if any(x in vuln_name_lower for x in ["weak cipher", "cipher suite", "ssl", "tls"]):
        return ["CWE-327-WEAK", "CWE-757"]
    if any(x in template_lower for x in ["ssl-weak", "tls-weak", "cipher"]):
        return ["CWE-327-WEAK", "CWE-757"]
    
    # ── Broken/Risky Cryptography ──
    if any(x in vuln_name_lower for x in ["broken crypto", "risky algorithm", "md5", "sha1", "des"]):
        return ["CWE-327"]
    
    # ── Inadequate Encryption ──
    if any(x in vuln_name_lower for x in ["inadequate encrypt", "weak encrypt", "no encryption"]):
        return ["CWE-326"]
    
    # ── Authentication Issues ──
    if any(x in vuln_name_lower for x in ["weak password", "default cred", "hardcoded cred"]):
        return ["CWE-521"]
    if any(x in vuln_name_lower for x in ["missing auth", "no auth required"]):
        return ["CWE-287"]
    
    # ── SQL Injection ──
    if any(x in vuln_name_lower for x in ["sql inject", "sqli"]):
        return ["CWE-89"]
    if any(x in template_lower for x in ["sql-inject", "sqli"]):
        return ["CWE-89"]
    
    # ── Cross-Site Scripting ──
    if any(x in vuln_name_lower for x in ["xss", "cross-site script"]):
        return ["CWE-79"]
    if any(x in template_lower for x in ["xss", "cross-site"]):
        return ["CWE-79"]
    
    # ── Path Traversal ──
    if any(x in vuln_name_lower for x in ["path traversal", "directory traversal", "lfi"]):
        return ["CWE-22"]
    
    # ── Information Disclosure ──
    if any(x in vuln_name_lower for x in ["exposed .git", "git exposed", "directory listing", "source disclosure"]):
        return ["CWE-548"]
    if any(x in vuln_name_lower for x in ["sensitive data", "exposed env", ".env exposed"]):
        return ["CWE-434"]
    
    # ── CORS/Access Control ──
    if any(x in vuln_name_lower for x in ["cors", "cross-origin"]):
        return ["CWE-346"]
    if any(x in vuln_name_lower for x in ["access control", "authorization", "broken access"]):
        return ["CWE-284"]
    
    # ── Default Credentials ──
    if any(x in vuln_name_lower for x in ["default", "factory default", "unchanged password"]):
        return ["CWE-798"]
    
    # ── Open Redirect ──
    if any(x in vuln_name_lower for x in ["open redirect", "unvalidated redirect"]):
        return ["CWE-601"]
    
    # ── Deserialization ──
    if any(x in vuln_name_lower for x in ["deserialization", "unsafe deserialize"]):
        return ["CWE-502"]
    
    # ── XML External Entity ──
    if any(x in vuln_name_lower for x in ["xxe", "xml external"]):
        return ["CWE-611"]
    
    # No mapping found
    return []


def _extract_cvss(
    info: Dict[str, Any]
) -> Optional[float]:
    """Extract CVSS score from vulnerability info."""
    classification = info.get("classification", {})
    cvss_score = classification.get(
        "cvss-score", None
    )
    if cvss_score:
        try:
            return float(cvss_score)
        except (ValueError, TypeError):
            pass

    cvss_metrics = classification.get(
        "cvss-metrics", ""
    )
    if cvss_metrics:
        try:
            parts = str(cvss_metrics).split("/")
            for part in parts:
                clean = (
                    part.replace(".", "")
                    .replace("-", "")
                )
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
    """Generate remediation advice."""
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
    return priorities.get(
        severity.lower(), "medium_term"
    )


def _generate_remediation(
    template_id: str,
    severity: str
) -> str:
    """Generate basic remediation based on template."""
    template_lower = template_id.lower()

    remediations = {
        "xss": (
            "Implement input validation and output "
            "encoding. Use Content-Security-Policy "
            "headers."
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
            "Validate and sanitize user-supplied "
            "URLs. Implement allowlists for "
            "external resources."
        ),
        "lfi": (
            "Validate file paths and implement "
            "proper access controls. Use allowlists "
            "for file access."
        ),
        "rce": (
            "Patch the affected component "
            "immediately. Implement input validation "
            "and sandboxing."
        ),
        "exposed": (
            "Remove or restrict access to sensitive "
            "endpoints. Implement authentication."
        ),
        "default-login": (
            "Change default credentials "
            "immediately. Implement strong password "
            "policies."
        ),
        "default-cred": (
            "Change default credentials "
            "immediately. Implement strong password "
            "policies."
        ),
        "cve-": (
            "Apply the vendor security patch. Check "
            "vendor advisory for specific "
            "remediation steps."
        ),
        "misconfig": (
            "Review and harden configuration "
            "settings according to security best "
            "practices."
        ),
        "disclosure": (
            "Restrict access to sensitive "
            "information. Review information "
            "exposure points."
        ),
        "takeover": (
            "Verify domain ownership and DNS "
            "configuration. Remove dangling DNS "
            "records."
        ),
        "open-redirect": (
            "Validate and sanitize redirect URLs. "
            "Use allowlists for redirect "
            "destinations."
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
            "Disable external entity processing "
            "in XML parsers. Use less complex data "
            "formats."
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
            "Review system for potential "
            "exploitation."
        ),
        "medium": (
            "Schedule remediation within 30 days. "
            "Monitor for any suspicious activity."
        ),
        "low": (
            "Plan remediation within 90 days as "
            "part of regular maintenance."
        ),
        "info": (
            "Review for potential security "
            "improvement opportunities."
        )
    }

    return severity_remediation.get(
        severity,
        "Review and remediate according to "
        "security policies."
    )
