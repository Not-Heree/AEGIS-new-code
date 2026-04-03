"""
EASM Scan Pipeline Orchestrator
================================
Executes the complete scanning pipeline in sequence:

    Phase 0: Passive Recon (Shodan + Censys)
    Phase 1: Subdomain Discovery (Subfinder + crt.sh + merge passive)
    Phase 2: Port Scanning (Naabu — skips hosts covered by passive)
    Phase 3: HTTP Fingerprinting (HTTPX)
    Phase 4: Vulnerability Scanning (Nuclei + Shodan CVEs)
    Phase 5: Change Detection (diff against pre-scan snapshot)
    Phase 6: Risk Scoring (vulns + exposure + email breaches)

Design principles:
    - Each phase is wrapped in its own try/except
    - If one phase fails, others still run
    - Failed phases tracked in phases_failed list
    - Pre-scan snapshot enables accurate change detection
    - Passive recon data merged with active scan results
    - Progress tracked in DB for frontend polling
"""
import os
from datetime import datetime
from database.targets_db import update_target_stats, update_last_scan
from database.subdomains_db import (
    add_subdomains_bulk, mark_all_subdomains_old,
    get_subdomains_by_target
)
from database.ports_db import (
    add_ports_bulk, mark_all_ports_old, get_ports_by_target
)
from database.http_assets_db import (
    add_http_asset, mark_all_http_assets_old
)
from database.vulns_db import (
    add_vulnerability, mark_all_vulns_old, get_vulns_by_target
)
from database.emails_db import mark_all_emails_old
from database.scans_db import (
    create_scan_with_domain, complete_scan, fail_scan,
    update_scan_progress
)
from database.passive_recon_db import (
    save_shodan_results, save_censys_results,
    save_whois_results, get_whois_data
)
from core.subfinder import scan_subdomains, save_certificates
from core.naabu import run_naabu
from core.httpx_runner import run_httpx
from core.nuclei import run_nuclei
from core.change_detector import detect_changes_with_snapshot
from core.risk_scorer import calculate_risk_score
from utils.logger import logger


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

    if scan_id is None:
        scan = create_scan_with_domain(target_id, domain, "full")
        scan_id = scan["scan_id"]

    logger.info("=" * 60)
    logger.info("Starting full scan — ID: %s", scan_id)
    logger.info("Target: %s", domain)
    logger.info("=" * 60)

    # ── Initialize result containers ─────────────────────
    phases_completed = []
    phases_failed = []
    subs_result = {"success": False, "subdomains": []}
    subdomain_list = []
    ports_result = {"success": False, "ports_found": {}}
    http_result = {"success": False, "http_assets": []}
    vuln_result = {"success": False, "vulnerabilities": []}
    changes_summary = {"total_changes": 0}
    risk_score = 0
    vuln_scan_partial = False

    shodan_result = {
        "success": False, "subdomains": [],
        "ports_by_host": {}, "vulnerabilities": []
    }
    censys_result = {
        "success": False, "subdomains": [],
        "ports_by_host": {}, "services": []
    }
    whois_result = {
        "success": False, "registrar": None,
        "nameservers": [], "risk_flags": []
    }
    try:
        # ── Mark existing assets as old ──────────────────
        mark_all_subdomains_old(target_id)
        mark_all_ports_old(target_id)
        mark_all_http_assets_old(target_id)
        mark_all_vulns_old(target_id)
        mark_all_emails_old(target_id)

        # ── Pre-scan snapshot for change detection ───────
        before_state = {
            "subdomains": set(
                s["subdomain"]
                for s in get_subdomains_by_target(target_id)
            ),
            "ports": set(
                f"{p['host']}:{p['port']}"
                for p in get_ports_by_target(target_id)
            ),
            "vulns": {
                f"{v.get('template_id', '')}||"
                f"{v.get('host', '')}": v
                for v in get_vulns_by_target(target_id)
            },
            "whois": get_whois_data(domain)
        }

        # ═════════════════════════════════════════════════
        # PHASE 0: PASSIVE RECON (SHODAN + CENSYS)
        # ═════════════════════════════════════════════════
        _progress(
            scan_id, "passive_recon", 2,
            f"Running passive recon on {domain}..."
        )

        try:
            # ── Shodan ────────────────────────────────
            from core.shodan_recon import (
                run_passive_recon as shodan_recon,
                is_available as shodan_available
            )

            if shodan_available():
                _progress(
                    scan_id, "passive_recon", 3,
                    "Querying Shodan..."
                )
                shodan_result = shodan_recon(domain)

                if shodan_result.get("success"):
                    shodan_subs = shodan_result.get(
                        "subdomains", []
                    )
                    if shodan_subs:
                        add_subdomains_bulk(
                            target_id, domain,
                            shodan_subs, source="shodan"
                        )

                    for host, ports in shodan_result.get(
                        "ports_by_host", {}
                    ).items():
                        add_ports_bulk(
                            target_id, domain, "", host, ports,
                            source="shodan"
                        )

                    # We no longer add Shodan vulnerabilities directly to the DB here.
                    # We rely on Nuclei (Phase 4) to actively scan all discovered hosts 
                    # and verify if vulnerabilities are truly exploitable.

                    s = shodan_result.get("stats", {})
                    logger.info(
                        "Phase 0a: Shodan — %d subs, "
                        "%d ports, %d CVEs",
                        s.get('subdomains_found', 0),
                        s.get('unique_ports', 0),
                        s.get('unique_vulns', 0)
                    )

                    # ──── NEW: Save full Shodan intelligence ────
                    save_shodan_results(
                        target_id, domain, shodan_result
                    )
                else:
                    logger.warning(
                        "Phase 0a: Shodan — %s",
                        shodan_result.get('error', 'No data')
                    )
            else:
                logger.info(
                    "Phase 0a: Shodan not configured — skipping"
                )

            # ── Censys ────────────────────────────────
            from core.censys_recon import (
                run_passive_recon as censys_recon,
                is_available as censys_available
            )

            if censys_available():
                _progress(
                    scan_id, "passive_recon", 5,
                    "Querying Censys..."
                )
                censys_result = censys_recon(domain)

                if censys_result.get("success"):
                    censys_subs = censys_result.get(
                        "subdomains", []
                    )
                    if censys_subs:
                        add_subdomains_bulk(
                            target_id, domain,
                            censys_subs, source="censys"
                        )

                    for host, ports in censys_result.get(
                        "ports_by_host", {}
                    ).items():
                        add_ports_bulk(
                            target_id, domain, "", host, ports,
                            source="censys"
                        )

                    c = censys_result.get("stats", {})
                    logger.info(
                        "Phase 0b: Censys — %d subs, "
                        "%d ports, %d services",
                        c.get('total_subdomains', 0),
                        c.get('unique_ports', 0),
                        c.get('total_services', 0)
                    )

                    # ──── NEW: Save full Censys intelligence ────
                    save_censys_results(
                        target_id, domain, censys_result
                    )
                else:
                    logger.warning(
                        "Phase 0b: Censys — %s",
                        censys_result.get('error', 'No data')
                    )
            else:
                logger.info(
                    "Phase 0b: Censys not configured — skipping"
                )

            # ── WHOIS ─────────────────────────────────
            from core.whois_lookup import (
                run_whois_recon as whois_recon,
                is_available as whois_available
            )

            if whois_available():
                _progress(
                    scan_id, "passive_recon", 7,
                    "Querying WHOIS..."
                )
                whois_result = whois_recon(domain)

                if whois_result.get("success"):
                    save_whois_results(
                        target_id, domain, whois_result
                    )

                    w_stats = whois_result.get("stats", {})
                    logger.info(
                        "Phase 0c: WHOIS — registrar=%s, "
                        "%d nameservers, %d risk flags",
                        whois_result.get("registrar", "N/A"),
                        w_stats.get("nameserver_count", 0),
                        w_stats.get("risk_flags_count", 0)
                    )
                else:
                    logger.warning(
                        "Phase 0c: WHOIS — %s",
                        whois_result.get("error", "No data")
                    )
            else:
                logger.info(
                    "Phase 0c: WHOIS not available — "
                    "install python-whois"
                )

            phases_completed.append("passive_recon")

        except Exception as e:
            phases_failed.append({
                "phase": "passive_recon", "error": str(e)
            })
            logger.error("Phase 0 failed: %s", e, exc_info=True)

        # ═════════════════════════════════════════════════
        # PHASE 1: SUBDOMAIN DISCOVERY
        # ═════════════════════════════════════════════════
        _progress(
            scan_id, "subdomain_discovery", 10,
            f"Discovering subdomains for {domain}..."
        )

        try:
            subs_result = scan_subdomains(domain)
            subdomain_list = subs_result.get("subdomains", [])

            # Merge with passive recon subdomains
            passive_subs = set()
            passive_subs.update(
                shodan_result.get("subdomains", [])
            )
            passive_subs.update(
                censys_result.get("subdomains", [])
            )

            if passive_subs:
                active_count = len(subdomain_list)
                merged = set(subdomain_list)
                merged.update(passive_subs)
                subdomain_list = sorted(merged)
                logger.info(
                    "Merged: %d active + %d passive = "
                    "%d total subdomains",
                    active_count, len(passive_subs),
                    len(subdomain_list)
                )

            if subs_result.get("success") and subdomain_list:
                add_subdomains_bulk(
                    target_id, domain, subdomain_list,
                    source="subfinder"
                )
                
                # ── NEW: Save certificate data ────
                certs = subs_result.get("certificates", [])
                if certs:
                    save_certificates(domain, certs)

            phases_completed.append("subdomain_discovery")
            logger.info(
                "Phase 1 complete: %d subdomains",
                len(subdomain_list)
            )

        except Exception as e:
            phases_failed.append({
                "phase": "subdomain_discovery",
                "error": str(e)
            })
            logger.error("Phase 1 failed: %s", e, exc_info=True)

        # ═════════════════════════════════════════════════
        # PHASE 2: PORT SCANNING
        # ═════════════════════════════════════════════════
        _progress(
            scan_id, "port_scanning", 25,
            f"Scanning ports on {len(subdomain_list)} hosts..."
        )

        try:
            if subdomain_list:
                shodan_hosts = set(
                    shodan_result.get(
                        "ports_by_host", {}
                    ).keys()
                )
                censys_hosts = set(
                    censys_result.get(
                        "ports_by_host", {}
                    ).keys()
                )
                passive_hosts = shodan_hosts | censys_hosts

                hosts_needing_scan = [
                    h for h in subdomain_list
                    if h not in passive_hosts
                ]

                if hosts_needing_scan:
                    logger.info(
                        "Passive covered %d hosts "
                        "(Shodan: %d, Censys: %d), "
                        "Naabu scanning %d",
                        len(passive_hosts),
                        len(shodan_hosts),
                        len(censys_hosts),
                        len(hosts_needing_scan)
                    )
                    ports_result = run_naabu(hosts_needing_scan)

                    # ── NEW: Save Naabu ports with source ────
                    # Save BEFORE the merge overwrites ports_result
                    if ports_result.get("success"):
                        for host, ports in ports_result.get(
                            "ports_found", {}
                        ).items():
                            add_ports_bulk(
                                target_id, domain, "",
                                host, ports, source="naabu"
                            )
                else:
                    logger.info(
                        "Passive covered all %d hosts "
                        "— skipping Naabu",
                        len(passive_hosts)
                    )
                    ports_result = {
                        "success": True,
                        "ports_found": {},
                        "total_ports": 0
                    }

                # Merge all port sources
                merged_ports = dict(
                    shodan_result.get("ports_by_host", {})
                )

                for host, ports in censys_result.get(
                    "ports_by_host", {}
                ).items():
                    if host in merged_ports:
                        existing = set(merged_ports[host])
                        existing.update(ports)
                        merged_ports[host] = sorted(existing)
                    else:
                        merged_ports[host] = sorted(ports)

                for host, ports in ports_result.get(
                    "ports_found", {}
                ).items():
                    if host in merged_ports:
                        existing = set(merged_ports[host])
                        existing.update(ports)
                        merged_ports[host] = sorted(existing)
                    else:
                        merged_ports[host] = sorted(ports)

                ports_result["ports_found"] = merged_ports
                ports_result["total_ports"] = sum(
                    len(p) for p in merged_ports.values()
                )

                if ports_result.get("success") or passive_hosts:
                    for host, ports in merged_ports.items():
                        add_ports_bulk(
                            target_id, domain, "", host, ports,
                            source="scan"
                        )

                phases_completed.append("port_scanning")
                logger.info(
                    "Phase 2 complete: %d ports "
                    "(Passive: %d hosts, Naabu: %d hosts)",
                    ports_result.get('total_ports', 0),
                    len(passive_hosts),
                    len(hosts_needing_scan)
                )
            else:
                phases_completed.append("port_scanning")
                logger.info("Phase 2 skipped: no subdomains")

        except Exception as e:
            phases_failed.append({
                "phase": "port_scanning", "error": str(e)
            })
            logger.error("Phase 2 failed: %s", e, exc_info=True)

        # ═════════════════════════════════════════════════
        # PHASE 3: HTTP FINGERPRINTING
        # ═════════════════════════════════════════════════
        _progress(
            scan_id, "http_fingerprinting", 45,
            f"Probing HTTP on {len(subdomain_list)} hosts..."
        )

        try:
            if subdomain_list:
                http_result = run_httpx(subdomain_list)

                if http_result.get("success"):
                    for asset in http_result["http_assets"]:
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
                logger.info(
                    "Phase 3 complete: %d HTTP assets",
                    http_result.get('count', 0)
                )
            else:
                phases_completed.append("http_fingerprinting")
                logger.info("Phase 3 skipped: no subdomains")

        except Exception as e:
            phases_failed.append({
                "phase": "http_fingerprinting",
                "error": str(e)
            })
            logger.error("Phase 3 failed: %s", e, exc_info=True)

                 # ═════════════════════════════════════════════════
        # PHASE 4: VULNERABILITY SCANNING (INTELLIGENCE-DRIVEN v2)
        # ═════════════════════════════════════════════════
        _progress(
            scan_id, "vuln_scanning", 55,
            "Building intelligent scan plan..."
        )

        try:
            if subdomain_list:
                from core.smart_scanner import build_scan_plan
                from collections import defaultdict

                # ── Build targeted scan plan (now with port data) ─
                scan_plan = build_scan_plan(
                    shodan_result, censys_result,
                    http_result, subdomain_list,
                    ports_data=ports_result.get("ports_found", {})
                )

                all_vulns = []

                # ══════════════════════════════════════════
                # TIER 1A: Batched CVE Verification
                # ══════════════════════════════════════════
                cve_scans = scan_plan.get("tier1_cve_scans", [])
                if cve_scans:
                    _progress(
                        scan_id, "vuln_scanning", 57,
                        f"Tier 1A: Verifying "
                        f"{len(cve_scans)} Shodan CVEs..."
                    )

                    host_cves = defaultdict(list)
                    for scan_item in cve_scans:
                        target_url = scan_item.get(
                            "target_url", scan_item["host"]
                        )
                        host_cves[target_url].append(scan_item)

                    logger.info(
                        "Phase 4 Tier 1A: %d CVEs across %d hosts",
                        len(cve_scans), len(host_cves)
                    )

                    for target_url, items in host_cves.items():
                        templates = [
                            item["template"]
                            for item in items
                            if os.path.exists(item["template"])
                        ]
                        cve_ids = [
                            item["cve_id"] for item in items
                        ]

                        if not templates:
                            continue

                        logger.info(
                            "  Scanning %s for %d CVEs: %s",
                            target_url, len(cve_ids),
                            ", ".join(cve_ids)
                        )

                        targeted_result = run_nuclei(
                            [target_url],
                            custom_templates=templates
                        )

                        if (targeted_result.get("success")
                                and targeted_result.get(
                                    "vulnerabilities")):
                            for v in targeted_result[
                                "vulnerabilities"
                            ]:
                                v["verification_source"] = (
                                    "shodan_cve_confirmed"
                                )
                                v["confidence"] = "high"
                                all_vulns.append(v)
                                logger.info(
                                    "  CONFIRMED: %s",
                                    v.get("template_id", "")
                                )

                        confirmed_templates = set(
                            v.get("template_id", "")
                            for v in targeted_result.get(
                                "vulnerabilities", []
                            )
                        )
                        for cve in cve_ids:
                            template_name = os.path.basename(
                                [i["template"]
                                 for i in items
                                 if i["cve_id"] == cve][0]
                            ).replace(".yaml", "")
                            if template_name not in (
                                confirmed_templates
                            ):
                                logger.info(
                                    "  NOT CONFIRMED: %s "
                                    "(stale/patched)", cve
                                )

                # ══════════════════════════════════════════
                # TIER 1B: Tech-Targeted Scans
                # ══════════════════════════════════════════
                tech_targets = scan_plan.get(
                    "tier1_tech_tags", {}
                )
                if tech_targets:
                    _progress(
                        scan_id, "vuln_scanning", 62,
                        f"Tier 1B: Tech-targeted scan on "
                        f"{len(tech_targets)} hosts..."
                    )

                    tag_groups = {}
                    for host, tags in tech_targets.items():
                        tag_key = ",".join(sorted(tags))
                        if tag_key not in tag_groups:
                            tag_groups[tag_key] = []
                        tag_groups[tag_key].append(host)

                    for tags_str, hosts in tag_groups.items():
                        tags_list = tags_str.split(",")
                        logger.info(
                            "  Tier 1B: %d hosts with "
                            "tags [%s]",
                            len(hosts), tags_str
                        )

                        targeted_result = run_nuclei(
                            hosts, custom_tags=tags_list
                        )

                        if targeted_result.get("success"):
                            for v in targeted_result.get(
                                "vulnerabilities", []
                            ):
                                v["verification_source"] = (
                                    "tech_targeted"
                                )
                                v["confidence"] = "medium"
                                all_vulns.append(v)

                # ══════════════════════════════════════════
                # TIER 2A: Port-Informed Scans
                # ══════════════════════════════════════════
                port_targets = scan_plan.get(
                    "tier2a_port_tags", {}
                )
                if port_targets:
                    _progress(
                        scan_id, "vuln_scanning", 68,
                        f"Tier 2A: Port-targeted scan on "
                        f"{len(port_targets)} hosts..."
                    )

                    tag_groups = {}
                    for host, tags in port_targets.items():
                        tag_key = ",".join(sorted(tags))
                        if tag_key not in tag_groups:
                            tag_groups[tag_key] = []
                        tag_groups[tag_key].append(host)

                    for tags_str, hosts in tag_groups.items():
                        tags_list = tags_str.split(",")
                        logger.info(
                            "  Tier 2A: %d hosts with "
                            "port-tags [%s]",
                            len(hosts), tags_str
                        )

                        targeted_result = run_nuclei(
                            hosts, custom_tags=tags_list
                        )

                        if targeted_result.get("success"):
                            for v in targeted_result.get(
                                "vulnerabilities", []
                            ):
                                v["verification_source"] = (
                                    "port_targeted"
                                )
                                v["confidence"] = "medium"
                                all_vulns.append(v)

                # ══════════════════════════════════════════
                # TIER 2B: Header-Mined Scans
                # ══════════════════════════════════════════
                header_targets = scan_plan.get(
                    "tier2b_header_tags", {}
                )
                if header_targets:
                    _progress(
                        scan_id, "vuln_scanning", 73,
                        f"Tier 2B: Header-informed scan on "
                        f"{len(header_targets)} hosts..."
                    )

                    tag_groups = {}
                    for host, tags in header_targets.items():
                        tag_key = ",".join(sorted(tags))
                        if tag_key not in tag_groups:
                            tag_groups[tag_key] = []
                        tag_groups[tag_key].append(host)

                    for tags_str, hosts in tag_groups.items():
                        tags_list = tags_str.split(",")
                        logger.info(
                            "  Tier 2B: %d hosts with "
                            "header-tags [%s]",
                            len(hosts), tags_str
                        )

                        targeted_result = run_nuclei(
                            hosts, custom_tags=tags_list
                        )

                        if targeted_result.get("success"):
                            for v in targeted_result.get(
                                "vulnerabilities", []
                            ):
                                v["verification_source"] = (
                                    "header_targeted"
                                )
                                v["confidence"] = "medium"
                                all_vulns.append(v)

                # ══════════════════════════════════════════
                # TIER 2C: Catch-All — Web Hosts Only,
                #          Critical + High Severity ONLY
                # ══════════════════════════════════════════
                catchall_hosts = scan_plan.get(
                    "tier2c_catchall", []
                )
                if catchall_hosts:
                    _progress(
                        scan_id, "vuln_scanning", 78,
                        f"Tier 2C: Broad scan on "
                        f"{len(catchall_hosts)} unknown "
                        f"web hosts (critical+high only)..."
                    )
                    logger.info(
                        "  Tier 2C: %d hosts, "
                        "critical+high only",
                        len(catchall_hosts)
                    )

                    broad_result = run_nuclei(
                        catchall_hosts,
                        severity_override="critical,high"
                    )

                    if broad_result.get("success"):
                        for v in broad_result.get(
                            "vulnerabilities", []
                        ):
                            v["verification_source"] = (
                                "broad_scan"
                            )
                            v["confidence"] = "standard"
                            all_vulns.append(v)

                    if broad_result.get("partial"):
                        vuln_scan_partial = True

                # ══════════════════════════════════════════
                # TIER 2C-NET: Non-Web Hosts —
                #              Network Protocol Templates
                # ══════════════════════════════════════════
                non_web_hosts = scan_plan.get(
                    "tier2c_non_web", []
                )
                if non_web_hosts:
                    _progress(
                        scan_id, "vuln_scanning", 83,
                        f"Tier 2C-NET: Network scan on "
                        f"{len(non_web_hosts)} non-web hosts..."
                    )
                    logger.info(
                        "  Tier 2C-NET: %d non-web hosts",
                        len(non_web_hosts)
                    )

                    network_result = run_nuclei(
                        non_web_hosts,
                        custom_tags=[
                            "network", "ssh", "ftp", "dns",
                            "smtp", "snmp", "rdp", "vnc",
                            "default-login", "mysql", "postgres",
                            "mssql", "redis", "mongodb",
                            "memcached", "ldap"
                        ]
                    )

                    if network_result.get("success"):
                        for v in network_result.get(
                            "vulnerabilities", []
                        ):
                            v["verification_source"] = (
                                "network_scan"
                            )
                            v["confidence"] = "standard"
                            all_vulns.append(v)

                    if network_result.get("partial"):
                        vuln_scan_partial = True

                # ── Build final vuln_result ──────────────
                severity_count = {
                    "critical": 0, "high": 0, "medium": 0,
                    "low": 0, "info": 0
                }
                for v in all_vulns:
                    sev = v.get(
                        "severity", "info"
                    ).lower()
                    if sev in severity_count:
                        severity_count[sev] += 1

                vuln_result = {
                    "success": True,
                    "partial": vuln_scan_partial,
                    "vulnerabilities": all_vulns,
                    "count": len(all_vulns),
                    "scan_plan_stats": scan_plan.get(
                        "stats", {}
                    ),
                    "severity_breakdown": severity_count
                }

                # Save all vulns to DB
                for v in all_vulns:
                    add_vulnerability(
                        target_id=target_id,
                        target_domain=domain,
                        subdomain_id="",
                        host=v.get("host", ""),
                        url=v.get(
                            "url",
                            v.get("matched_at", "")
                        ),
                        template_id=v.get(
                            "template_id", ""
                        ),
                        name=v.get("name", ""),
                        severity=v.get(
                            "severity", "info"
                        ),
                        cve_id=v.get("cve_id"),
                        description=v.get(
                            "description", ""
                        ),
                        matched_at=v.get(
                            "matched_at", ""
                        ),
                        reference=v.get(
                            "reference", []
                        ),
                        tags=v.get("tags", []),
                        cvss_score=v.get("cvss_score"),
                        cwe_id=v.get("cwe_id", []),
                        remediation=v.get(
                            "remediation", {}
                        ),
                        curl_command=v.get(
                            "curl_command", ""
                        ),
                        extracted_results=v.get(
                            "extracted_results", []
                        )
                    )

                if not vuln_scan_partial:
                    phases_completed.append("vuln_scanning")

                logger.info(
                    "Phase 4 complete: %d vulns "
                    "(1A: %d confirmed, 1B: %d tech, "
                    "2A: %d port, 2B: %d header, "
                    "2C: %d broad, 2C-NET: %d network)",
                    len(all_vulns),
                    sum(1 for v in all_vulns
                        if v.get("confidence") == "high"),
                    sum(1 for v in all_vulns
                        if v.get("verification_source")
                        == "tech_targeted"),
                    sum(1 for v in all_vulns
                        if v.get("verification_source")
                        == "port_targeted"),
                    sum(1 for v in all_vulns
                        if v.get("verification_source")
                        == "header_targeted"),
                    sum(1 for v in all_vulns
                        if v.get("verification_source")
                        == "broad_scan"),
                    sum(1 for v in all_vulns
                        if v.get("verification_source")
                        == "network_scan"),
                )
            else:
                phases_completed.append("vuln_scanning")
                logger.info(
                    "Phase 4 skipped: no subdomains"
                )

        except Exception as e:
            phases_failed.append({
                "phase": "vuln_scanning",
                "error": str(e)
            })
            logger.error(
                "Phase 4 failed: %s", e, exc_info=True
            )
        # ═════════════════════════════════════════════════
        # PHASE 5: CHANGE DETECTION                        
        # ═════════════════════════════════════════════════   
        _progress(                                        
            scan_id, "change_detection", 85,
            "Comparing with previous state..."
        )

        try:
            vuln_data_for_changes = vuln_result
            if vuln_scan_partial:
                logger.warning(
                    "Phase 5: Skipping vuln change detection "
                    "(partial scan results)"
                )
                vuln_data_for_changes = {
                    "vulnerabilities": [],
                    "success": False
                }

            changes_summary = detect_changes_with_snapshot(
                target_id, domain, scan_id,
                before_state,
                subs_result, ports_result,
                vuln_data_for_changes,
                new_whois_result=whois_result
            )
            phases_completed.append("change_detection")
            logger.info(
                "Phase 5 complete: %d changes",
                changes_summary.get('total_changes', 0)
            )

        except Exception as e:
            phases_failed.append({
                "phase": "change_detection",
                "error": str(e)
            })
            logger.error("Phase 5 failed: %s", e, exc_info=True)

        # ═════════════════════════════════════════════════
        # PHASE 6: RISK SCORING                           
        # ═════════════════════════════════════════════════  
        _progress(                                       
            scan_id, "risk_scoring", 93,
            "Calculating risk score..."
        )

        try:
            risk_score = calculate_risk_score(target_id)
            phases_completed.append("risk_scoring")
            logger.info(
                "Phase 6 complete: Risk score %d/100",
                risk_score
            )

        except Exception as e:
            phases_failed.append({
                "phase": "risk_scoring", "error": str(e)
            })
            logger.error("Phase 6 failed: %s", e, exc_info=True)

        # ═════════════════════════════════════════════════
        # FINALIZE
        # ═════════════════════════════════════════════════
        subdomain_count = len(subdomain_list)
        port_count = sum(
            len(p)
            for p in ports_result.get(
                "ports_found", {}
            ).values()
        )
        http_count = len(
            http_result.get("http_assets", [])
        )
        vuln_count = len(
            vuln_result.get("vulnerabilities", [])
        )
        shodan_vuln_count = len(
            shodan_result.get("vulnerabilities", [])
        )
        censys_service_count = len(
            censys_result.get("services", [])
        )

        update_target_stats(target_id, {
            "total_subdomains": subdomain_count,
            "total_ports": port_count,
            "total_http_assets": http_count,
            "total_vulns": vuln_count,
            "risk_score": risk_score
        })
        update_last_scan(target_id)

        results = {
            "subdomains_found": subdomain_count,
            "ports_found": port_count,
            "http_assets_found": http_count,
            "vulns_found": vuln_count,
            "shodan_vulns": shodan_vuln_count,
            "changes_detected": changes_summary.get(
                "total_changes", 0
            ),
            "risk_score": risk_score,
            "phases_completed": phases_completed,
            "phases_failed": phases_failed,
            "passive_recon": {
                "shodan": {
                    "subdomains": len(
                        shodan_result.get("subdomains", [])
                    ),
                    "ports": len(
                        shodan_result.get(
                            "ports_by_host", {}
                        )
                    ),
                    "vulns": shodan_vuln_count
                },
                "censys": {
                    "subdomains": len(
                        censys_result.get("subdomains", [])
                    ),
                    "ports": len(
                        censys_result.get(
                            "ports_by_host", {}
                        )
                    ),
                    "services": censys_service_count
                },
                "whois": {
                    "registrar": whois_result.get(
                        "registrar"
                    ),
                    "risk_flags": len(
                        whois_result.get(
                            "risk_flags", []
                        )
                    ),
                    "dnssec": whois_result.get(
                        "dnssec", False
                    ),
                    "days_until_expiry": whois_result.get(
                        "days_until_expiry"
                    )
                }
            }
        }

        complete_scan(scan_id, results)
        _progress(scan_id, "done", 100, "Scan completed")

        status = (
            "completed" if not phases_failed
            else "partial"
        )

        logger.info("=" * 60)
        logger.info("Scan %s for %s", status, domain)
        logger.info(
            "Subs: %d | Ports: %d | HTTP: %d | Vulns: %d",
            subdomain_count, port_count,
            http_count, vuln_count
        )
        logger.info(
            "Passive: %d Shodan CVEs, %d Censys services",
            shodan_vuln_count, censys_service_count
        )
        logger.info(
            "Changes: %d | Risk: %d/100",
            changes_summary.get('total_changes', 0),
            risk_score
        )
        logger.info("=" * 60)

        return {
            "success": True,
            "status": status,
            "scan_id": scan_id,
            "results": results
        }

    except Exception as e:
        logger.error(
            "Fatal scan error for %s: %s",
            domain, e, exc_info=True
        )
        fail_scan(scan_id, str(e))
        return {
            "success": False,
            "status": "failed",
            "scan_id": scan_id,
            "error": str(e)
        }


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

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


def _cvss_to_severity(cvss_score):
    """Convert CVSS score to severity string."""
    if cvss_score is None:
        return "info"
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 0.1:
            return "low"
        else:
            return "info"
    except (ValueError, TypeError):
        return "info"


def _cvss_to_priority(cvss_score):
    """Convert CVSS score to remediation priority."""
    if cvss_score is None:
        return "medium_term"
    try:
        score = float(cvss_score)
        if score >= 9.0:
            return "immediate"
        elif score >= 7.0:
            return "short_term"
        elif score >= 4.0:
            return "medium_term"
        else:
            return "long_term"
    except (ValueError, TypeError):
        return "medium_term"