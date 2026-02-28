from database.subdomains_db import get_subdomains_by_target
from database.ports_db import get_ports_by_target
from database.vulns_db import get_vulns_by_target
from database.changes_db import add_change


def detect_changes(target_id, scan_id, new_subdomains_result, new_ports_result, new_vulns_result):
    """Compare current scan results with previous data to detect attack surface changes."""
    try:
        new_sub_count = 0
        removed_sub_count = 0
        new_port_count = 0
        new_vuln_count = 0

        # ─── Subdomain Changes ───────────────────────────────────────

        # Get existing subdomains from DB
        existing_subs = get_subdomains_by_target(target_id)
        old_subs = set(s["subdomain"] for s in existing_subs)

        # Get new subdomains from scan result
        new_subs = set(new_subdomains_result.get("subdomains", []))

        # Detect new subdomains
        added_subs = new_subs - old_subs
        for sub in added_subs:
            add_change(
                target_id, "new_subdomain", "medium",
                {"subdomain": sub, "message": "New subdomain discovered"},
                scan_id
            )
            new_sub_count += 1

        # Detect removed subdomains
        removed_subs = old_subs - new_subs
        for sub in removed_subs:
            add_change(
                target_id, "subdomain_removed", "info",
                {"subdomain": sub, "message": "Subdomain no longer resolving"},
                scan_id
            )
            removed_sub_count += 1

        # ─── Port Changes ────────────────────────────────────────────

        # Get existing ports from DB as "host:port" set
        existing_ports = get_ports_by_target(target_id)
        old_ports_set = set(
            f"{p['host']}:{p['port']}" for p in existing_ports
        )

        # Build "host:port" set from new scan results
        new_ports_set = set()
        ports_found = new_ports_result.get("ports_found", {})
        for host, ports in ports_found.items():
            for port in ports:
                new_ports_set.add(f"{host}:{port}")

        # Detect new ports
        added_ports = new_ports_set - old_ports_set
        for hp in added_ports:
            add_change(
                target_id, "new_port", "medium",
                {"host_port": hp, "message": "New open port detected"},
                scan_id
            )
            new_port_count += 1

        # ─── Vulnerability Changes ───────────────────────────────────

        vulns_list = new_vulns_result.get("vulnerabilities", [])
        for vuln in vulns_list:
            # Determine change severity based on vuln severity
            vuln_severity = vuln.get("severity", "").lower()
            if vuln_severity in ("critical", "high"):
                change_severity = "high"
            else:
                change_severity = "medium"

            add_change(
                target_id, "new_vulnerability", change_severity,
                {
                    "name": vuln.get("name", ""),
                    "host": vuln.get("host", ""),
                    "severity": vuln.get("severity", ""),
                    "message": "New vulnerability found"
                },
                scan_id
            )
            new_vuln_count += 1

        # ─── Summary ─────────────────────────────────────────────────

        total = new_sub_count + removed_sub_count + new_port_count + new_vuln_count
        print(f"[CHANGES] Detected {total} changes")

        return {
            "new_subdomains": new_sub_count,
            "removed_subdomains": removed_sub_count,
            "new_ports": new_port_count,
            "new_vulns": new_vuln_count,
            "total_changes": total
        }

    except Exception as e:
        print(f"[CHANGES] Error detecting changes: {e}")
        return {
            "new_subdomains": 0,
            "removed_subdomains": 0,
            "new_ports": 0,
            "new_vulns": 0,
            "total_changes": 0
        }
