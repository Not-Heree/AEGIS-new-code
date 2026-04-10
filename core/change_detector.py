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

from database.changes_db import add_change
from database.emails_db import get_emails_by_target
from utils.logger import logger

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


def detect_changes_with_snapshot(target_id, target_domain,
                                 scan_id, before_state,
                                 new_subs_result,
                                 new_ports_result,
                                 new_vulns_result,
                                 new_whois_result=None):
    """
    Compare scan results against a pre-computed snapshot.
    Skips change detection on first scan (empty before_state).
    """
    changes = {
        "new_subdomains": 0,
        "removed_subdomains": 0,
        "new_ports": 0,
        "removed_ports": 0,
        "new_vulns": 0,
        "resolved_vulns": 0,
        "new_emails": 0,
        "new_breached_emails": 0,
        "whois_changes": 0,
        "total_changes": 0
    }

    try:
        is_first_scan = (
            not before_state.get("subdomains")
            and not before_state.get("ports")
            and not before_state.get("vulns")
        )

        if is_first_scan:
            logger.info("First scan — skipping change detection")
            _detect_email_changes(
                target_id, target_domain, scan_id, changes
            )
            changes["total_changes"] = sum(
                v for k, v in changes.items()
                if k != "total_changes"
            )
            return changes

        # Subdomain changes
        _detect_subdomain_changes(
            target_id, target_domain, scan_id,
            before_state["subdomains"],
            set(new_subs_result.get("subdomains", [])),
            changes
        )

        # Port changes
        new_ports = set()
        for host, ports in new_ports_result.get(
            "ports_found", {}
        ).items():
            for port in ports:
                new_ports.add(f"{host}:{port}")

        _detect_port_changes(
            target_id, target_domain, scan_id,
            before_state["ports"], new_ports, changes
        )

        # Vulnerability changes
        new_vulns = {}
        for v in new_vulns_result.get("vulnerabilities", []):
            key = (
                f"{v.get('template_id', '')}||"
                f"{v.get('host', '')}"
            )
            new_vulns[key] = v

        _detect_vuln_changes(
            target_id, target_domain, scan_id,
            before_state["vulns"], new_vulns, changes
        )

        # Email changes
        _detect_email_changes(
            target_id, target_domain, scan_id, changes
        )

        # WHOIS changes
        if new_whois_result:
            _detect_whois_changes(
                target_id, target_domain, scan_id,
                before_state.get("whois", {}),
                new_whois_result, changes
            )

        changes["total_changes"] = sum(
            v for k, v in changes.items()
            if k != "total_changes"
        )

        logger.info(
            "Changes: %d total — +%d/-%d subs, "
            "+%d/-%d ports, +%d/-%d vulns",
            changes["total_changes"],
            changes["new_subdomains"],
            changes["removed_subdomains"],
            changes["new_ports"],
            changes["removed_ports"],
            changes["new_vulns"],
            changes["resolved_vulns"]
        )

        return changes

    except Exception as e:
        logger.error("Change detection failed: %s", e)
        return changes


def _detect_subdomain_changes(target_id, domain, scan_id,
                               old_subs, new_subs, changes):
    for sub in (new_subs - old_subs):
        add_change(
            target_id, domain, "new_subdomain", "medium",
            {"subdomain": sub, "message": f"New subdomain: {sub}"},
            scan_id
        )
        changes["new_subdomains"] += 1

    for sub in (old_subs - new_subs):
        add_change(
            target_id, domain, "subdomain_removed", "info",
            {"subdomain": sub, "message": f"Subdomain gone: {sub}"},
            scan_id
        )
        changes["removed_subdomains"] += 1


def _detect_port_changes(target_id, domain, scan_id,
                          old_ports, new_ports, changes):
    for hp in (new_ports - old_ports):
        port_num = int(hp.split(":")[-1]) if ":" in hp else 0
        severity = (
            "high" if port_num in HIGH_SEVERITY_PORTS
            else "medium"
        )
        add_change(
            target_id, domain, "new_port", severity,
            {"host_port": hp, "message": f"New open port: {hp}"},
            scan_id
        )
        changes["new_ports"] += 1

    for hp in (old_ports - new_ports):
        add_change(
            target_id, domain, "port_closed", "info",
            {"host_port": hp, "message": f"Port closed: {hp}"},
            scan_id
        )
        changes["removed_ports"] += 1


def _detect_vuln_changes(target_id, domain, scan_id,
                          old_vulns, new_vulns, changes):
    for key in (set(new_vulns) - set(old_vulns)):
        v = new_vulns[key]
        sev = v.get("severity", "info").lower()
        change_sev = (
            "high" if sev in ("critical", "high")
            else "medium"
        )
        add_change(
            target_id, domain, "new_vulnerability", change_sev,
            {
                "name": v.get("name", ""),
                "host": v.get("host", ""),
                "severity": sev,
                "template_id": v.get("template_id", ""),
                "message": f"New {sev} vuln: {v.get('name', '')}"
            },
            scan_id
        )
        changes["new_vulns"] += 1

    for key in (set(old_vulns) - set(new_vulns)):
        v = old_vulns[key]
        if v.get("status") == "resolved":
            continue
        add_change(
            target_id, domain, "vulnerability_resolved", "info",
            {
                "name": v.get("name", ""),
                "host": v.get("host", ""),
                "message": f"Resolved: {v.get('name', '')}"
            },
            scan_id
        )
        changes["resolved_vulns"] += 1


def _detect_email_changes(target_id, domain, scan_id, changes):
    try:
        for email_doc in get_emails_by_target(target_id):
            if not email_doc.get("is_new", False):
                continue

            is_breached = (
                email_doc.get("breach_status") == "breached"
            )
            email_addr = email_doc.get("email", "")

            if is_breached:
                breach_count = email_doc.get("breach_count", 0)
                pw_leaked = email_doc.get(
                    "password_leaked", False
                )
                add_change(
                    target_id, domain,
                    "email_breached", "high",
                    {
                        "email": email_addr,
                        "breach_count": breach_count,
                        "password_leaked": pw_leaked,
                        "message": (
                            f"Breached email: {email_addr} "
                            f"({breach_count} breaches"
                            f"{', PASSWORD LEAKED' if pw_leaked else ''})"
                        )
                    },
                    scan_id
                )
                changes["new_breached_emails"] += 1
            else:
                add_change(
                    target_id, domain, "new_email", "medium",
                    {
                        "email": email_addr,
                        "sources": email_doc.get("sources", []),
                        "message": f"New email: {email_addr}"
                    },
                    scan_id
                )
                changes["new_emails"] += 1

    except Exception as e:
        logger.error("Email change detection failed: %s", e)


def _detect_whois_changes(target_id, domain, scan_id,
                           old_whois, new_whois, changes):
    if not new_whois.get("success") or not old_whois:
        return

    try:
        # Nameserver change
        old_ns = set(old_whois.get("nameservers", []))
        new_ns = set(new_whois.get("nameservers", []))
        if old_ns and new_ns and old_ns != new_ns:
            add_change(
                target_id, domain,
                "whois_nameserver_change", "high",
                {
                    "old_nameservers": sorted(old_ns),
                    "new_nameservers": sorted(new_ns),
                    "message": (
                        f"Nameservers changed: "
                        f"{sorted(old_ns)} → {sorted(new_ns)}"
                    )
                },
                scan_id
            )
            changes["whois_changes"] += 1

        # Registrar change
        old_reg = old_whois.get("registrar")
        new_reg = new_whois.get("registrar")
        if old_reg and new_reg and old_reg != new_reg:
            add_change(
                target_id, domain,
                "whois_registrar_change", "critical",
                {
                    "old_registrar": old_reg,
                    "new_registrar": new_reg,
                    "message": (
                        f"Registrar changed: "
                        f"'{old_reg}' → '{new_reg}'"
                    )
                },
                scan_id
            )
            changes["whois_changes"] += 1

        # DNSSEC toggled
        old_dnssec = old_whois.get("dnssec", False)
        new_dnssec = new_whois.get("dnssec", False)
        if old_dnssec and not new_dnssec:
            add_change(
                target_id, domain,
                "whois_dnssec_removed", "high",
                {"message": "DNSSEC disabled"},
                scan_id
            )
            changes["whois_changes"] += 1
        elif not old_dnssec and new_dnssec:
            add_change(
                target_id, domain,
                "whois_dnssec_added", "info",
                {"message": "DNSSEC enabled"},
                scan_id
            )
            changes["whois_changes"] += 1

    except Exception as e:
        logger.error("WHOIS change detection failed: %s", e)