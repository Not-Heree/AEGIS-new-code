"""
Change Detector Module
======================
Compares scan results against previous state to detect changes
in the attack surface.

Detects:
  - New/removed subdomains
  - New/closed ports (with high-severity port flagging)
  - New/resolved vulnerabilities
  - New email discoveries and breach detections

Uses set difference operations for efficient comparison.
Each change is recorded to the changes collection with
severity, details, and scan ID for audit trail.

Two modes:
  - detect_changes(): Compares against live DB state
  - detect_changes_with_snapshot(): Compares against
    pre-computed snapshot (more accurate during scans)
"""

from database.subdomains_db import get_subdomains_by_target
from database.ports_db import get_ports_by_target
from database.vulns_db import get_vulns_by_target
from database.changes_db import add_change
from database.emails_db import get_emails_by_target

# Ports that are dangerous to have exposed on the internet
HIGH_SEVERITY_PORTS = {
    22,     # SSH
    23,     # Telnet
    445,    # SMB (ransomware vector)
    1433,   # MSSQL
    3306,   # MySQL
    3389,   # RDP (huge attack target)
    5432,   # PostgreSQL
    5900,   # VNC
    6379,   # Redis
    9200,   # Elasticsearch
    27017,  # MongoDB
    2082,   # cPanel
    2083    # cPanel SSL
}


def detect_changes(target_id, target_domain, scan_id,
                   new_subdomains_result, new_ports_result,
                   new_vulns_result):
    """
    Compare scan results against DB state.

    Args:
        target_id: Target document ObjectId string
        target_domain: Domain string for storing changes
        scan_id: Current scan ID for audit trail
        new_subdomains_result: Dict with "subdomains" list
        new_ports_result: Dict with "ports_found" mapping
        new_vulns_result: Dict with "vulnerabilities" list

    Returns:
        Dict with change counts and total_changes
    """
    try:
        changes = {
            "new_subdomains": 0,
            "removed_subdomains": 0,
            "new_ports": 0,
            "removed_ports": 0,
            "new_vulns": 0,
            "resolved_vulns": 0,
            "new_emails": 0,
            "new_breached_emails": 0,
            "total_changes": 0
        }

        # ── Subdomain changes ───────────────────────────
        existing_subs = get_subdomains_by_target(target_id)
        old_subs = set(s["subdomain"] for s in existing_subs)
        new_subs = set(
            new_subdomains_result.get("subdomains", [])
        )

        for sub in (new_subs - old_subs):
            add_change(
                target_id, target_domain,
                "new_subdomain", "medium",
                {
                    "subdomain": sub,
                    "message": f"New subdomain: {sub}"
                },
                scan_id
            )
            changes["new_subdomains"] += 1

        for sub in (old_subs - new_subs):
            add_change(
                target_id, target_domain,
                "subdomain_removed", "info",
                {
                    "subdomain": sub,
                    "message": f"Subdomain gone: {sub}"
                },
                scan_id
            )
            changes["removed_subdomains"] += 1

        # ── Port changes ────────────────────────────────
        existing_ports = get_ports_by_target(target_id)
        old_ports_set = set(
            f"{p['host']}:{p['port']}"
            for p in existing_ports
        )

        new_ports_set = set()
        for host, ports in new_ports_result.get(
            "ports_found", {}
        ).items():
            for port in ports:
                new_ports_set.add(f"{host}:{port}")

        for hp in (new_ports_set - old_ports_set):
            port_num = (
                int(hp.split(":")[-1]) if ":" in hp
                else 0
            )
            severity = (
                "high" if port_num in HIGH_SEVERITY_PORTS
                else "medium"
            )
            add_change(
                target_id, target_domain,
                "new_port", severity,
                {
                    "host_port": hp,
                    "message": f"New open port: {hp}"
                },
                scan_id
            )
            changes["new_ports"] += 1

        for hp in (old_ports_set - new_ports_set):
            add_change(
                target_id, target_domain,
                "port_closed", "info",
                {
                    "host_port": hp,
                    "message": f"Port closed: {hp}"
                },
                scan_id
            )
            changes["removed_ports"] += 1

        # ── Vulnerability changes ───────────────────────
        existing_vulns = get_vulns_by_target(target_id)
        old_vuln_keys = {}
        for v in existing_vulns:
            key = (
                f"{v.get('template_id', '')}||"
                f"{v.get('host', '')}"
            )
            old_vuln_keys[key] = v

        new_vuln_keys = {}
        for v in new_vulns_result.get("vulnerabilities", []):
            key = (
                f"{v.get('template_id', '')}||"
                f"{v.get('host', '')}"
            )
            new_vuln_keys[key] = v

        # Truly new vulns only
        for key in (set(new_vuln_keys) - set(old_vuln_keys)):
            v = new_vuln_keys[key]
            sev = v.get("severity", "info").lower()
            change_sev = (
                "high" if sev in ("critical", "high")
                else "medium"
            )
            add_change(
                target_id, target_domain,
                "new_vulnerability", change_sev,
                {
                    "name": v.get("name", ""),
                    "host": v.get("host", ""),
                    "severity": sev,
                    "template_id": v.get("template_id", ""),
                    "message": (
                        f"New {sev} vuln: "
                        f"{v.get('name', '')}"
                    )
                },
                scan_id
            )
            changes["new_vulns"] += 1

        # Resolved vulns
        for key in (set(old_vuln_keys) - set(new_vuln_keys)):
            v = old_vuln_keys[key]
            if v.get("status") == "resolved":
                continue
            add_change(
                target_id, target_domain,
                "vulnerability_resolved", "info",
                {
                    "name": v.get("name", ""),
                    "host": v.get("host", ""),
                    "message": (
                        f"Resolved: {v.get('name', '')}"
                    )
                },
                scan_id
            )
            changes["resolved_vulns"] += 1

        # ── Email changes ───────────────────────────────
        try:
            existing_emails = get_emails_by_target(target_id)

            for email_doc in existing_emails:
                is_new = email_doc.get("is_new", False)
                is_breached = (
                    email_doc.get("breach_status") == "breached"
                )

                if is_breached and is_new:
                    # New breached email — high severity
                    breach_count = email_doc.get(
                        "breach_count", 0
                    )
                    password_leaked = email_doc.get(
                        "password_leaked", False
                    )
                    add_change(
                        target_id, target_domain,
                        "email_breached", "high",
                        {
                            "email": email_doc.get(
                                "email", ""
                            ),
                            "breach_count": breach_count,
                            "password_leaked": password_leaked,
                            "message": (
                                f"Breached email found: "
                                f"{email_doc.get('email', '')} "
                                f"({breach_count} breaches"
                                f"{', PASSWORD LEAKED' if password_leaked else ''})"
                            )
                        },
                        scan_id
                    )
                    changes["new_breached_emails"] += 1

                elif is_new:
                    # New clean/unchecked email — medium severity
                    add_change(
                        target_id, target_domain,
                        "new_email", "medium",
                        {
                            "email": email_doc.get(
                                "email", ""
                            ),
                            "sources": email_doc.get(
                                "sources", []
                            ),
                            "message": (
                                f"New email discovered: "
                                f"{email_doc.get('email', '')}"
                            )
                        },
                        scan_id
                    )
                    changes["new_emails"] += 1

        except Exception as e:
            print(f"[CHANGES] Email change detection error: {e}")

        # ── Calculate total ─────────────────────────────
        changes["total_changes"] = sum(
            changes[k] for k in changes
            if k != "total_changes"
        )

        # ── Print summary ───────────────────────────────
        email_changes = (
            changes.get("new_emails", 0) +
            changes.get("new_breached_emails", 0)
        )
        print(
            f"[CHANGES] {changes['total_changes']} total: "
            f"+{changes['new_subdomains']}/"
            f"-{changes['removed_subdomains']} subs, "
            f"+{changes['new_ports']}/"
            f"-{changes['removed_ports']} ports, "
            f"+{changes['new_vulns']}/"
            f"-{changes['resolved_vulns']} vulns, "
            f"+{email_changes} emails"
        )

        return changes

    except Exception as e:
        print(f"[CHANGES] Error: {e}")
        return {"total_changes": 0}


def detect_changes_with_snapshot(target_id, target_domain,
                                 scan_id, before_state,
                                 new_subs_result,
                                 new_ports_result,
                                 new_vulns_result):
    """
    Compare scan results against a pre-computed snapshot.

    More accurate than detect_changes() during scans because
    the snapshot was taken before the scan modified the DB.

    Args:
        target_id: Target document ObjectId string
        target_domain: Domain string
        scan_id: Current scan ID
        before_state: Dict with sets of old subdomains,
                      ports, and vuln keys
        new_subs_result: Dict with "subdomains" list
        new_ports_result: Dict with "ports_found" mapping
        new_vulns_result: Dict with "vulnerabilities" list

    Returns:
        Dict with change counts and total_changes
    """
    try:
        changes = {
            "new_subdomains": 0,
            "removed_subdomains": 0,
            "new_ports": 0,
            "removed_ports": 0,
            "new_vulns": 0,
            "resolved_vulns": 0,
            "new_emails": 0,
            "new_breached_emails": 0,
            "total_changes": 0
        }

        # ── Subdomain changes ───────────────────────────
        old_subs = before_state["subdomains"]
        new_subs = set(
            new_subs_result.get("subdomains", [])
        )

        for sub in (new_subs - old_subs):
            add_change(
                target_id, target_domain,
                "new_subdomain", "medium",
                {
                    "subdomain": sub,
                    "message": f"New subdomain: {sub}"
                },
                scan_id
            )
            changes["new_subdomains"] += 1

        for sub in (old_subs - new_subs):
            add_change(
                target_id, target_domain,
                "subdomain_removed", "info",
                {
                    "subdomain": sub,
                    "message": f"Subdomain gone: {sub}"
                },
                scan_id
            )
            changes["removed_subdomains"] += 1

        # ── Port changes ────────────────────────────────
        old_ports = before_state["ports"]
        new_ports = set()
        for host, ports in new_ports_result.get(
            "ports_found", {}
        ).items():
            for port in ports:
                new_ports.add(f"{host}:{port}")

        for hp in (new_ports - old_ports):
            port_num = (
                int(hp.split(":")[-1]) if ":" in hp
                else 0
            )
            severity = (
                "high" if port_num in HIGH_SEVERITY_PORTS
                else "medium"
            )
            add_change(
                target_id, target_domain,
                "new_port", severity,
                {
                    "host_port": hp,
                    "message": f"New open port: {hp}"
                },
                scan_id
            )
            changes["new_ports"] += 1

        for hp in (old_ports - new_ports):
            add_change(
                target_id, target_domain,
                "port_closed", "info",
                {
                    "host_port": hp,
                    "message": f"Port closed: {hp}"
                },
                scan_id
            )
            changes["removed_ports"] += 1

        # ── Vulnerability changes ───────────────────────
        old_vulns = before_state["vulns"]
        new_vulns = {}
        for v in new_vulns_result.get("vulnerabilities", []):
            key = (
                f"{v.get('template_id', '')}||"
                f"{v.get('host', '')}"
            )
            new_vulns[key] = v

        for key in (set(new_vulns) - set(old_vulns)):
            v = new_vulns[key]
            sev = v.get("severity", "info").lower()
            change_sev = (
                "high" if sev in ("critical", "high")
                else "medium"
            )
            add_change(
                target_id, target_domain,
                "new_vulnerability", change_sev,
                {
                    "name": v.get("name", ""),
                    "host": v.get("host", ""),
                    "severity": sev,
                    "template_id": v.get("template_id", ""),
                    "message": (
                        f"New {sev} vuln: "
                        f"{v.get('name', '')}"
                    )
                },
                scan_id
            )
            changes["new_vulns"] += 1

        for key in (set(old_vulns) - set(new_vulns)):
            v = old_vulns[key]
            if v.get("status") == "resolved":
                continue
            add_change(
                target_id, target_domain,
                "vulnerability_resolved", "info",
                {
                    "name": v.get("name", ""),
                    "host": v.get("host", ""),
                    "message": (
                        f"Resolved: {v.get('name', '')}"
                    )
                },
                scan_id
            )
            changes["resolved_vulns"] += 1

        # ── Email changes ───────────────────────────────
        try:
            existing_emails = get_emails_by_target(target_id)

            for email_doc in existing_emails:
                is_new = email_doc.get("is_new", False)
                is_breached = (
                    email_doc.get("breach_status") == "breached"
                )

                if is_breached and is_new:
                    breach_count = email_doc.get(
                        "breach_count", 0
                    )
                    password_leaked = email_doc.get(
                        "password_leaked", False
                    )
                    add_change(
                        target_id, target_domain,
                        "email_breached", "high",
                        {
                            "email": email_doc.get(
                                "email", ""
                            ),
                            "breach_count": breach_count,
                            "password_leaked": password_leaked,
                            "message": (
                                f"Breached email found: "
                                f"{email_doc.get('email', '')} "
                                f"({breach_count} breaches"
                                f"{', PASSWORD LEAKED' if password_leaked else ''})"
                            )
                        },
                        scan_id
                    )
                    changes["new_breached_emails"] += 1

                elif is_new:
                    add_change(
                        target_id, target_domain,
                        "new_email", "medium",
                        {
                            "email": email_doc.get(
                                "email", ""
                            ),
                            "sources": email_doc.get(
                                "sources", []
                            ),
                            "message": (
                                f"New email discovered: "
                                f"{email_doc.get('email', '')}"
                            )
                        },
                        scan_id
                    )
                    changes["new_emails"] += 1

        except Exception as e:
            print(f"[CHANGES] Email change detection error: {e}")

        # ── Calculate total ─────────────────────────────
        changes["total_changes"] = sum(
            changes[k] for k in changes
            if k != "total_changes"
        )

        # ── Print summary ───────────────────────────────
        email_changes = (
            changes.get("new_emails", 0) +
            changes.get("new_breached_emails", 0)
        )
        print(
            f"[CHANGES] {changes['total_changes']} total: "
            f"+{changes['new_subdomains']}/"
            f"-{changes['removed_subdomains']} subs, "
            f"+{changes['new_ports']}/"
            f"-{changes['removed_ports']} ports, "
            f"+{changes['new_vulns']}/"
            f"-{changes['resolved_vulns']} vulns, "
            f"+{email_changes} emails"
        )

        return changes

    except Exception as e:
        print(f"[CHANGES] Error: {e}")
        return {"total_changes": 0}