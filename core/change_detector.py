
from database.subdomains_db import get_subdomains_by_target
from database.ports_db import get_ports_by_target
from database.vulns_db import get_vulns_by_target
from database.changes_db import add_change

HIGH_SEVERITY_PORTS = {
    22, 23, 445, 1433, 3306, 3389, 5432, 5900,
    6379, 9200, 27017, 2082, 2083
}


def detect_changes(target_id, target_domain, scan_id,
                   new_subdomains_result, new_ports_result,
                   new_vulns_result):
    """
    Compare scan results against DB state.
    Now requires target_domain for storing changes with correct field.
    """
    try:
        changes = {
            "new_subdomains": 0, "removed_subdomains": 0,
            "new_ports": 0, "removed_ports": 0,
            "new_vulns": 0, "resolved_vulns": 0,
            "total_changes": 0
        }

        # ── Subdomain changes ───────────────────────────────
        existing_subs = get_subdomains_by_target(target_id)
        old_subs = set(s["subdomain"] for s in existing_subs)
        new_subs = set(new_subdomains_result.get("subdomains", []))

        for sub in (new_subs - old_subs):
            add_change(target_id, target_domain,
                      "new_subdomain", "medium",
                      {"subdomain": sub,
                       "message": f"New subdomain: {sub}"},
                      scan_id)
            changes["new_subdomains"] += 1

        for sub in (old_subs - new_subs):
            add_change(target_id, target_domain,
                      "subdomain_removed", "info",
                      {"subdomain": sub,
                       "message": f"Subdomain gone: {sub}"},
                      scan_id)
            changes["removed_subdomains"] += 1

        # ── Port changes (FIX #2: detects removed ports) ────
        existing_ports = get_ports_by_target(target_id)
        old_ports_set = set(
            f"{p['host']}:{p['port']}" for p in existing_ports
        )

        new_ports_set = set()
        for host, ports in new_ports_result.get("ports_found", {}).items():
            for port in ports:
                new_ports_set.add(f"{host}:{port}")

        for hp in (new_ports_set - old_ports_set):
            port_num = int(hp.split(":")[-1]) if ":" in hp else 0
            severity = "high" if port_num in HIGH_SEVERITY_PORTS else "medium"
            add_change(target_id, target_domain,
                      "new_port", severity,
                      {"host_port": hp,
                       "message": f"New open port: {hp}"},
                      scan_id)
            changes["new_ports"] += 1

        for hp in (old_ports_set - new_ports_set):
            add_change(target_id, target_domain,
                      "port_closed", "info",
                      {"host_port": hp,
                       "message": f"Port closed: {hp}"},
                      scan_id)
            changes["removed_ports"] += 1

        # ── Vuln changes (FIX #1 and #3) ────────────────────
        existing_vulns = get_vulns_by_target(target_id)
        old_vuln_keys = {}
        for v in existing_vulns:
            key = f"{v.get('template_id', '')}||{v.get('host', '')}"
            old_vuln_keys[key] = v

        new_vuln_keys = {}
        for v in new_vulns_result.get("vulnerabilities", []):
            key = f"{v.get('template_id', '')}||{v.get('host', '')}"
            new_vuln_keys[key] = v

        # Truly new vulns only
        for key in (set(new_vuln_keys) - set(old_vuln_keys)):
            v = new_vuln_keys[key]
            sev = v.get("severity", "info").lower()
            change_sev = "high" if sev in ("critical", "high") else "medium"
            add_change(target_id, target_domain,
                      "new_vulnerability", change_sev,
                      {"name": v.get("name", ""),
                       "host": v.get("host", ""),
                       "severity": sev,
                       "template_id": v.get("template_id", ""),
                       "message": f"New {sev} vuln: {v.get('name', '')}"},
                      scan_id)
            changes["new_vulns"] += 1

        # Resolved vulns
        for key in (set(old_vuln_keys) - set(new_vuln_keys)):
            v = old_vuln_keys[key]
            if v.get("status") == "resolved":
                continue
            add_change(target_id, target_domain,
                      "vulnerability_resolved", "info",
                      {"name": v.get("name", ""),
                       "host": v.get("host", ""),
                       "message": f"Resolved: {v.get('name', '')}"},
                      scan_id)
            changes["resolved_vulns"] += 1

        changes["total_changes"] = sum(
            changes[k] for k in changes if k != "total_changes"
        )

        print(f"[CHANGES] {changes['total_changes']} total: "
              f"+{changes['new_subdomains']}/-{changes['removed_subdomains']} subs, "
              f"+{changes['new_ports']}/-{changes['removed_ports']} ports, "
              f"+{changes['new_vulns']}/-{changes['resolved_vulns']} vulns")

        return changes

    except Exception as e:
        print(f"[CHANGES] Error: {e}")
        return {"total_changes": 0}


def detect_changes_with_snapshot(target_id, target_domain, scan_id,
                               before_state,
                               new_subs_result, new_ports_result,
                               new_vulns_result):
    """
    Compare scan results against a pre-computed snapshot.
    """
    try:
        changes = {
            "new_subdomains": 0, "removed_subdomains": 0,
            "new_ports": 0, "removed_ports": 0,
            "new_vulns": 0, "resolved_vulns": 0,
            "total_changes": 0
        }

        # ── Subdomain changes ───────────────────────────────
        old_subs = before_state["subdomains"]
        new_subs = set(new_subs_result.get("subdomains", []))

        for sub in (new_subs - old_subs):
            add_change(target_id, target_domain,
                      "new_subdomain", "medium",
                      {"subdomain": sub,
                       "message": f"New subdomain: {sub}"},
                      scan_id)
            changes["new_subdomains"] += 1

        for sub in (old_subs - new_subs):
            add_change(target_id, target_domain,
                      "subdomain_removed", "info",
                      {"subdomain": sub,
                       "message": f"Subdomain gone: {sub}"},
                      scan_id)
            changes["removed_subdomains"] += 1

        # ── Port changes ──────────────────────────────────
        old_ports = before_state["ports"]
        new_ports = set()
        for host, ports in new_ports_result.get("ports_found", {}).items():
            for port in ports:
                new_ports.add(f"{host}:{port}")

        for hp in (new_ports - old_ports):
            port_num = int(hp.split(":")[-1]) if ":" in hp else 0
            severity = "high" if port_num in HIGH_SEVERITY_PORTS else "medium"
            add_change(target_id, target_domain,
                      "new_port", severity,
                      {"host_port": hp,
                       "message": f"New open port: {hp}"},
                      scan_id)
            changes["new_ports"] += 1

        for hp in (old_ports - new_ports):
            add_change(target_id, target_domain,
                      "port_closed", "info",
                      {"host_port": hp,
                       "message": f"Port closed: {hp}"},
                      scan_id)
            changes["removed_ports"] += 1

        # ── Vuln changes ──────────────────────────────────
        old_vulns = before_state["vulns"]
        new_vulns = {}
        for v in new_vulns_result.get("vulnerabilities", []):
            key = f"{v.get('template_id', '')}||{v.get('host', '')}"
            new_vulns[key] = v

        for key in (set(new_vulns) - set(old_vulns)):
            v = new_vulns[key]
            sev = v.get("severity", "info").lower()
            change_sev = "high" if sev in ("critical", "high") else "medium"
            add_change(target_id, target_domain,
                      "new_vulnerability", change_sev,
                      {"name": v.get("name", ""),
                       "host": v.get("host", ""),
                       "severity": sev,
                       "template_id": v.get("template_id", ""),
                       "message": f"New {sev} vuln: {v.get('name', '')}"},
                      scan_id)
            changes["new_vulns"] += 1

        for key in (set(old_vulns) - set(new_vulns)):
            v = old_vulns[key]
            if v.get("status") == "resolved":
                continue
            add_change(target_id, target_domain,
                      "vulnerability_resolved", "info",
                      {"name": v.get("name", ""),
                       "host": v.get("host", ""),
                       "message": f"Resolved: {v.get('name', '')}"},
                      scan_id)
            changes["resolved_vulns"] += 1

        changes["total_changes"] = sum(
            changes[k] for k in changes if k != "total_changes"
        )

        print(f"[CHANGES] {changes['total_changes']} total: "
              f"+{changes['new_subdomains']}/-{changes['removed_subdomains']} subs, "
              f"+{changes['new_ports']}/-{changes['removed_ports']} ports, "
              f"+{changes['new_vulns']}/-{changes['resolved_vulns']} vulns")

        return changes

    except Exception as e:
        print(f"[CHANGES] Error: {e}")
        return {"total_changes": 0}