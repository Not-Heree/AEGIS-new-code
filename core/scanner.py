from datetime import datetime
from database.targets_db import update_target_stats, update_last_scan
from database.subdomains_db import add_subdomains_bulk, mark_all_subdomains_old, get_subdomains_by_target
from database.ports_db import add_ports_bulk, mark_all_ports_old
from database.http_assets_db import add_http_asset, mark_all_http_assets_old, get_http_asset_count
from database.vulns_db import add_vulnerability, mark_all_vulns_old
from database.scans_db import create_scan, complete_scan, fail_scan
from database.changes_db import add_change
from core.subfinder import run_subfinder
from core.naabu import run_naabu
from core.httpx_runner import run_httpx
from core.nuclei import run_nuclei
from core.change_detector import detect_changes
from core.risk_scorer import calculate_risk_score
from config import Config


def run_full_scan(target_id, root_domain):
    """Orchestrate a full EASM scan: subdomains → ports → HTTP → vulns → changes → risk."""

    # Create scan record
    scan = create_scan(target_id, "full")
    scan_id = scan["scan_id"]

    print("=" * 60)
    print(f"[SCAN] Starting full scan - ID: {scan_id}")
    print(f"[SCAN] Target: {root_domain}")
    print("=" * 60)

    try:
        # ─── Mark existing assets as old ─────────────────────────────

        mark_all_subdomains_old(target_id)
        mark_all_ports_old(target_id)
        mark_all_http_assets_old(target_id)
        mark_all_vulns_old(target_id)
        print("[SCAN] Marked existing assets as old")

        # ─── Phase 1: Subdomain Discovery ───────────────────────────

        print("[SCAN] Phase 1: Discovering subdomains...")
        subs_result = run_subfinder(root_domain)
        subdomain_list = subs_result.get("subdomains", [])

        if subs_result.get("success"):
            add_subdomains_bulk(target_id, subdomain_list)
        print(f"[SCAN] Added {len(subdomain_list)} subdomains")

        # ─── Phase 2: Port Scanning ─────────────────────────────────

        if subdomain_list:
            print("[SCAN] Phase 2: Scanning open ports...")
            ports_result = run_naabu(subdomain_list)

            if ports_result.get("success"):
                for host, ports in ports_result["ports_found"].items():
                    add_ports_bulk(target_id, "", host, ports)
            print(f"[SCAN] Added {ports_result.get('total_ports', 0)} ports")
        else:
            print("[SCAN] Skipping Naabu (no subdomains)")
            ports_result = {"success": False, "ports_found": {}}

        # ─── Phase 3: HTTP Fingerprinting ────────────────────────────

        if subdomain_list:
            print("[SCAN] Phase 3: HTTP fingerprinting...")
            http_result = run_httpx(subdomain_list)

            if http_result.get("success"):
                for asset in http_result["http_assets"]:
                    add_http_asset(
                        target_id, "",
                        asset.get("url", ""),
                        asset.get("host", ""),
                        asset.get("port", 0),
                        asset.get("status_code", 0),
                        asset.get("title", ""),
                        asset.get("web_server", ""),
                        asset.get("tech", [])
                    )
            print(f"[SCAN] Added {http_result.get('count', 0)} HTTP assets")
        else:
            print("[SCAN] Skipping HTTPX (no subdomains)")
            http_result = {"success": False, "http_assets": []}

        # ─── Phase 4: Vulnerability Scanning ─────────────────────────

        if subdomain_list:
            print("[SCAN] Phase 4: Vulnerability scanning...")
            vuln_result = run_nuclei(subdomain_list)

            if vuln_result.get("success"):
                for vuln in vuln_result["vulnerabilities"]:
                    add_vulnerability(
                        target_id, "",
                        vuln.get("host", ""),
                        vuln.get("url", ""),
                        vuln.get("template_id", ""),
                        vuln.get("name", ""),
                        vuln.get("severity", "info")
                    )
            print(f"[SCAN] Added {vuln_result.get('count', 0)} vulnerabilities")
        else:
            print("[SCAN] Skipping Nuclei (no subdomains)")
            vuln_result = {"success": False, "vulnerabilities": []}

        # ─── Phase 5: Detect Changes ─────────────────────────────────

        print("[SCAN] Phase 5: Detecting changes...")
        changes_summary = detect_changes(
            target_id, scan_id, subs_result, ports_result, vuln_result
        )
        print(f"[SCAN] Detected {changes_summary.get('total_changes', 0)} changes")

        # ─── Phase 6: Risk Score ─────────────────────────────────────

        print("[SCAN] Phase 6: Calculating risk score...")
        risk_score = calculate_risk_score(target_id)

        # ─── Update Target Stats ─────────────────────────────────────

        subdomain_count = len(subdomain_list)
        port_count = sum(len(p) for p in ports_result.get("ports_found", {}).values())
        http_count = len(http_result.get("http_assets", []))
        vuln_count = len(vuln_result.get("vulnerabilities", []))

        update_target_stats(target_id, {
            "total_subdomains": subdomain_count,
            "total_ports": port_count,
            "total_http_assets": http_count,
            "total_vulns": vuln_count,
            "risk_score": risk_score
        })
        update_last_scan(target_id)
        print("[SCAN] Updated target statistics")

        # ─── Complete Scan ───────────────────────────────────────────

        results = {
            "subdomains_found": subdomain_count,
            "ports_found": port_count,
            "http_assets_found": http_count,
            "vulns_found": vuln_count,
            "changes_detected": changes_summary.get("total_changes", 0),
            "risk_score": risk_score
        }
        complete_scan(scan_id, results)

        print("=" * 60)
        print(f"[SCAN] ✅ Scan completed successfully!")
        print(f"[SCAN] Subdomains: {subdomain_count} | Ports: {port_count}")
        print(f"[SCAN] HTTP Assets: {http_count} | Vulns: {vuln_count}")
        print(f"[SCAN] Changes: {changes_summary.get('total_changes', 0)} | Risk: {risk_score}/100")
        print("=" * 60)

        return {
            "success": True,
            "scan_id": scan_id,
            "results": results
        }

    except Exception as e:
        print(f"[SCAN] ❌ Scan failed: {e}")
        fail_scan(scan_id, str(e))
        return {
            "success": False,
            "scan_id": scan_id,
            "error": str(e)
        }
