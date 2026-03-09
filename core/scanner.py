from datetime import datetime
from database.targets_db import update_target_stats, update_last_scan
from database.subdomains_db import (
    add_subdomains_bulk, mark_all_subdomains_old, get_subdomains_by_target
)
from database.ports_db import add_ports_bulk, mark_all_ports_old
from database.http_assets_db import (
    add_http_asset, mark_all_http_assets_old
)
from database.vulns_db import add_vulnerability, mark_all_vulns_old
from database.scans_db import (
    create_scan_with_domain, complete_scan, fail_scan,
    update_scan_progress
)
from core.subfinder import scan_subdomains
from core.naabu import run_naabu
from core.httpx_runner import run_httpx
from core.nuclei import run_nuclei
from core.change_detector import detect_changes
from core.risk_scorer import calculate_risk_score

from core.change_detector import detect_changes_with_snapshot
def run_full_scan(target_id, domain, scan_id=None):
    """
    Execute the complete EASM scan pipeline.

    Args:
        target_id: MongoDB target document ID (string)
        domain:    Root domain to scan (string)
        scan_id:   Pre-created scan ID (string, optional)

    Returns:
        dict with success, scan_id, results
    """

    # Create scan record if not provided
    if scan_id is None:
        scan = create_scan_with_domain(target_id, domain, "full")
        scan_id = scan["scan_id"]

    print("=" * 60)
    print(f"[SCAN] Starting full scan — ID: {scan_id}")
    print(f"[SCAN] Target: {domain}")
    print("=" * 60)

    # Initialize result containers
    phases_completed = []
    phases_failed = []
    subs_result = {"success": False, "subdomains": []}
    subdomain_list = []
    ports_result = {"success": False, "ports_found": {}}
    http_result = {"success": False, "http_assets": []}
    vuln_result = {"success": False, "vulnerabilities": []}
    changes_summary = {"total_changes": 0}
    risk_score = 0

    try:
        # ── Mark existing assets as old ──────────────────────────
        mark_all_subdomains_old(target_id)
        mark_all_ports_old(target_id)
        mark_all_http_assets_old(target_id)
        mark_all_vulns_old(target_id)

         # ══════════════════════════════════════════════════════════
        from database.subdomains_db import get_subdomains_by_target
        from database.ports_db import get_ports_by_target
        from database.vulns_db import get_vulns_by_target

        before_state = {
            "subdomains": set(
                s["subdomain"] for s in get_subdomains_by_target(target_id)
            ),
            "ports": set(
                f"{p['host']}:{p['port']}" for p in get_ports_by_target(target_id)
            ),
            "vulns": {
                f"{v.get('template_id', '')}||{v.get('host', '')}": v
                for v in get_vulns_by_target(target_id)
            }
        }

        # ═════════════════════════════════════════════════════════
        # PHASE 1: SUBDOMAIN DISCOVERY
        # ═════════════════════════════════════════════════════════
        _progress(scan_id, "subdomain_discovery", 5,
                  f"Discovering subdomains for {domain}...")
        try:
            subs_result = scan_subdomains(domain)
            subdomain_list = subs_result.get("subdomains", [])

            if subs_result.get("success") and subdomain_list:
                # Uses DB layer — stores both target_id AND target_domain
                add_subdomains_bulk(target_id, domain, subdomain_list)

            phases_completed.append("subdomain_discovery")
            print(f"[SCAN] Phase 1 ✅ {len(subdomain_list)} subdomains")

        except Exception as e:
            phases_failed.append({"phase": "subdomain_discovery", "error": str(e)})
            print(f"[SCAN] Phase 1 ❌ {e}")

        # ═════════════════════════════════════════════════════════
        # PHASE 2: PORT SCANNING
        # ═════════════════════════════════════════════════════════
        _progress(scan_id, "port_scanning", 20,
                  f"Scanning ports on {len(subdomain_list)} hosts...")
        try:
            if subdomain_list:
                ports_result = run_naabu(subdomain_list)

                if ports_result.get("success"):
                    for host, ports in ports_result["ports_found"].items():
                        # Uses DB layer — dedup + stores target_domain
                        add_ports_bulk(target_id, domain, "", host, ports)

                phases_completed.append("port_scanning")
                print(f"[SCAN] Phase 2 ✅ {ports_result.get('total_ports', 0)} ports")
            else:
                phases_completed.append("port_scanning")
                print("[SCAN] Phase 2 ⏭ Skipped (no subdomains)")

        except Exception as e:
            phases_failed.append({"phase": "port_scanning", "error": str(e)})
            print(f"[SCAN] Phase 2 ❌ {e}")

        # ═════════════════════════════════════════════════════════
        # PHASE 3: HTTP FINGERPRINTING
        # ═════════════════════════════════════════════════════════
        _progress(scan_id, "http_fingerprinting", 40,
                  f"Probing HTTP on {len(subdomain_list)} hosts...")
        try:
            if subdomain_list:
                http_result = run_httpx(subdomain_list)

                if http_result.get("success"):
                    for asset in http_result["http_assets"]:
                        # Uses DB layer — dedup + stores target_domain
                        add_http_asset(
                            target_id, domain, "",
                            asset.get("url", ""),
                            asset.get("host", ""),
                            asset.get("port", 0),
                            asset.get("status_code", 0),
                            asset.get("title", ""),
                            asset.get("web_server", ""),
                            asset.get("tech", []),
                            asset.get("content_length", 0)
                        )

                phases_completed.append("http_fingerprinting")
                print(f"[SCAN] Phase 3 ✅ {http_result.get('count', 0)} HTTP assets")
            else:
                phases_completed.append("http_fingerprinting")
                print("[SCAN] Phase 3 ⏭ Skipped")

        except Exception as e:
            phases_failed.append({"phase": "http_fingerprinting", "error": str(e)})
            print(f"[SCAN] Phase 3 ❌ {e}")

        # ═════════════════════════════════════════════════════════
        # PHASE 4: VULNERABILITY SCANNING
        # ═════════════════════════════════════════════════════════
        _progress(scan_id, "vuln_scanning", 55,
                  f"Running Nuclei on {len(subdomain_list)} hosts...")
        try:
            if subdomain_list:
                vuln_result = run_nuclei(subdomain_list)

                if vuln_result.get("success"):
                    for v in vuln_result["vulnerabilities"]:
                        # Uses DB layer — DEDUP + stores ALL fields
                        add_vulnerability(
                            target_id=target_id,
                            target_domain=domain,
                            subdomain_id="",
                            host=v.get("host", ""),
                            url=v.get("url", v.get("matched_at", "")),
                            template_id=v.get("template_id", ""),
                            name=v.get("name", ""),
                            severity=v.get("severity", "info"),
                            cve_id=v.get("cve_id"),
                            description=v.get("description", ""),
                            matched_at=v.get("matched_at", ""),
                            reference=v.get("reference", []),
                            tags=v.get("tags", []),
                            cvss_score=v.get("cvss_score"),
                            cwe_id=v.get("cwe_id", []),
                            remediation=v.get("remediation", {}),
                            curl_command=v.get("curl_command", ""),
                            extracted_results=v.get("extracted_results", [])
                        )

                phases_completed.append("vuln_scanning")
                print(f"[SCAN] Phase 4 ✅ {vuln_result.get('count', 0)} vulns")
            else:
                phases_completed.append("vuln_scanning")
                print("[SCAN] Phase 4 ⏭ Skipped")

        except Exception as e:
            phases_failed.append({"phase": "vuln_scanning", "error": str(e)})
            print(f"[SCAN] Phase 4 ❌ {e}")

        # ═════════════════════════════════════════════════════════
        # PHASE 5: CHANGE DETECTION (WAS DEAD CODE — NOW ALIVE)
        # ═════════════════════════════════════════════════════════
        _progress(scan_id, "change_detection", 85,
                  "Comparing with previous state...")
        try:
            changes_summary = detect_changes(
                target_id, domain, scan_id,
                before_state,
                subs_result, ports_result, vuln_result
            )
            phases_completed.append("change_detection")
            print(f"[SCAN] Phase 5 ✅ {changes_summary.get('total_changes', 0)} changes")

        except Exception as e:
            phases_failed.append({"phase": "change_detection", "error": str(e)})
            print(f"[SCAN] Phase 5 ❌ {e}")

        # ═════════════════════════════════════════════════════════
        # PHASE 6: RISK SCORING (WAS DEAD CODE — NOW ALIVE)
        # ═════════════════════════════════════════════════════════
        _progress(scan_id, "risk_scoring", 93,
                  "Calculating risk score...")
        try:
            risk_score = calculate_risk_score(target_id)
            phases_completed.append("risk_scoring")
            print(f"[SCAN] Phase 6 ✅ Risk score: {risk_score}/100")

        except Exception as e:
            phases_failed.append({"phase": "risk_scoring", "error": str(e)})
            print(f"[SCAN] Phase 6 ❌ {e}")

        # ═════════════════════════════════════════════════════════
        # FINALIZE
        # ═════════════════════════════════════════════════════════

        subdomain_count = len(subdomain_list)
        port_count = sum(
            len(p) for p in ports_result.get("ports_found", {}).values()
        )
        http_count = len(http_result.get("http_assets", []))
        vuln_count = len(vuln_result.get("vulnerabilities", []))

        # Update target stats
        update_target_stats(target_id, {
            "total_subdomains": subdomain_count,
            "total_ports": port_count,
            "total_http_assets": http_count,
            "total_vulns": vuln_count,
            "risk_score": risk_score
        })
        update_last_scan(target_id)

        # Build results
        results = {
            "subdomains_found": subdomain_count,
            "ports_found": port_count,
            "http_assets_found": http_count,
            "vulns_found": vuln_count,
            "changes_detected": changes_summary.get("total_changes", 0),
            "risk_score": risk_score,
            "phases_completed": phases_completed,
            "phases_failed": phases_failed,
        }

        # Complete scan record
        complete_scan(scan_id, results)

        _progress(scan_id, "done", 100, "Scan completed")

        status = "completed" if not phases_failed else "partial"

        print("=" * 60)
        print(f"[SCAN] {'✅' if status == 'completed' else '⚠️'} "
              f"Scan {status}")
        print(f"[SCAN] Subs: {subdomain_count} | Ports: {port_count} "
              f"| HTTP: {http_count} | Vulns: {vuln_count}")
        print(f"[SCAN] Changes: {changes_summary.get('total_changes', 0)} "
              f"| Risk: {risk_score}/100")
        print("=" * 60)

        return {
            "success": True,
            "status": status,
            "scan_id": scan_id,
            "results": results
        }

    except Exception as e:
        print(f"[SCAN] ❌ Fatal error: {e}")
        fail_scan(scan_id, str(e))
        return {
            "success": False,
            "status": "failed",
            "scan_id": scan_id,
            "error": str(e)
        }


def _progress(scan_id, phase, percent, detail=""):
    """Write progress to DB (non-fatal if fails)."""
    try:
        update_scan_progress(scan_id, {
            "current_phase": phase,
            "phase_detail": detail,
            "progress_percent": percent,
        })
    except Exception:
        pass