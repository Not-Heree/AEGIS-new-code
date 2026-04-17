"""
EASM Scan Pipeline Orchestrator
================================
Executes the complete scanning pipeline in sequence:

    Phase 0: Passive Recon (Shodan + Censys + WHOIS)
    Phase 1: Subdomain Discovery (Subfinder + Amass + crt.sh + merge)
    Phase 2: Port Scanning (Naabu — skips hosts covered by passive)
    Phase 3: HTTP Fingerprinting (HTTPX)
    Phase 3.5: Parameter Discovery (Arjun — opt-in, active)
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

Resumability:
    - Each completed phase is checkpointed to MongoDB
    - On resume, completed phases are skipped
    - Phase outputs are reloaded from DB for downstream phases
    - mark_all_*_old() is skipped on resume to preserve data integrity

Performance:
    - Tier 1A CVE scans are batched by template set
    - Tiers 1B/2A/2B already batch by tag groups
    - Nuclei auto-splits large target lists via NUCLEI_BATCH_SIZE
"""
import os
from datetime import datetime
from collections import defaultdict
from database.targets_db import update_target_stats, update_last_scan
from database.subdomains_db import (
    add_subdomains_bulk, mark_all_subdomains_old,
    get_subdomains_by_target, get_subdomains_by_source
)
from database.ports_db import (
    add_ports_bulk, mark_all_ports_old,
    get_ports_by_target, get_ports_by_source
)
from database.http_assets_db import (
    add_http_asset, mark_all_http_assets_old,
    get_http_assets_by_target
)
from database.vulns_db import (
    add_vulnerability, mark_all_vulns_old, get_vulns_by_target
)
from database.emails_db import mark_all_emails_old
from database.scans_db import (
    create_scan_with_domain, complete_scan, fail_scan,
    update_scan_progress, mark_phase_completed,
    get_completed_phases
)
from database.passive_recon_db import (
    save_shodan_results, save_censys_results,
    save_whois_results, get_whois_data,
    get_passive_recon
)
from core.subfinder import scan_subdomains, save_certificates
from core.naabu import run_naabu
from core.httpx_runner import run_httpx
from core.nuclei import run_nuclei
from core.change_detector import detect_changes_with_snapshot
from core.risk_scorer import calculate_risk_score
from core.smart_scanner import NETWORK_SCAN_TAGS
from config import Config
from database.endpoints_db import (
    add_endpoints_bulk, mark_all_endpoints_old
)
from utils.logger import logger
from utils.cancellation import register_target, is_cancelled, cleanup_signal
from utils.websocket import (
    emit_scan_progress, emit_scan_completed, emit_scan_error
)

# Internal mapping for frontend phase numbers
PHASE_MAP = {
    "passive_recon": 0,
    "subdomain_discovery": 1,
    "port_scanning": 2,
    "http_fingerprinting": 3,
    "parameter_discovery": 3.5,
    "vuln_scanning": 4,
    "change_detection": 5,
    "risk_scoring": 6,
    "done": 7
}


# =========================================================================
# RESUMABILITY: DATA RELOAD FROM DB
# =========================================================================

def _reload_from_db(target_id, domain, completed_phases):
    """
    Reload outputs of completed phases from MongoDB.

    When resuming a scan, later phases need data that was produced
    by earlier (already-completed) phases. Since those phases won't
    re-run, we reconstruct their output variables from what was
    persisted to the database.

    Args:
        target_id:        Target document ObjectId string
        domain:           Root domain string
        completed_phases: List of phase names already completed

    Returns:
        Tuple of (shodan_result, censys_result, whois_result,
                  subdomain_list, subs_result, ports_result,
                  http_result)
    """
    # Defaults (same as fresh scan)
    shodan_result = {
        "success": False, "subdomains": [],
        "ports_by_host": {}, "vulnerabilities": [],
        "hosts": [], "services": [], "stats": {}
    }
    censys_result = {
        "success": False, "subdomains": [],
        "ports_by_host": {}, "services": [],
        "hosts": [], "stats": {}
    }
    whois_result = {"success": False}
    subdomain_list = []
    subs_result = {"success": False, "subdomains": []}
    ports_result = {
        "success": False, "ports_found": {}, "total_ports": 0
    }
    http_result = {
        "success": False, "http_assets": [], "count": 0
    }

    # ── Reload Phase 0: Passive Recon ────────────────────
    if "passive_recon" in completed_phases:
        logger.info("[RESUME] Reloading Phase 0 data from DB...")

        # Shodan
        shodan_docs = get_passive_recon(domain, "shodan")
        if shodan_docs:
            doc = shodan_docs[0]
            shodan_subs = get_subdomains_by_source(
                target_id, "shodan"
            )
            sub_list = [s["subdomain"] for s in shodan_subs]

            shodan_ports = get_ports_by_source(
                target_id, "shodan"
            )
            pbh = {}
            for p in shodan_ports:
                host = p.get("host", "")
                port = p.get("port")
                if host and port is not None:
                    if host not in pbh:
                        pbh[host] = []
                    if port not in pbh[host]:
                        pbh[host].append(port)

            shodan_result = {
                "success": True,
                "subdomains": sub_list,
                "ports_by_host": pbh,
                "vulnerabilities": doc.get(
                    "vulnerabilities", []
                ),
                "hosts": doc.get("hosts", []),
                "services": doc.get("services", []),
                "stats": doc.get("stats", {}),
            }
            logger.info(
                "[RESUME]   Shodan: %d subs, %d hosts "
                "with ports, %d CVEs",
                len(sub_list), len(pbh),
                len(doc.get("vulnerabilities", []))
            )

        # Censys
        censys_docs = get_passive_recon(domain, "censys")
        if censys_docs:
            doc = censys_docs[0]
            censys_subs = get_subdomains_by_source(
                target_id, "censys"
            )
            sub_list = [s["subdomain"] for s in censys_subs]

            censys_ports = get_ports_by_source(
                target_id, "censys"
            )
            pbh = {}
            for p in censys_ports:
                host = p.get("host", "")
                port = p.get("port")
                if host and port is not None:
                    if host not in pbh:
                        pbh[host] = []
                    if port not in pbh[host]:
                        pbh[host].append(port)

            censys_result = {
                "success": True,
                "subdomains": sub_list,
                "ports_by_host": pbh,
                "vulnerabilities": [],
                "hosts": doc.get("hosts", []),
                "services": doc.get("services", []),
                "stats": doc.get("stats", {}),
            }
            logger.info(
                "[RESUME]   Censys: %d subs, "
                "%d hosts with ports",
                len(sub_list), len(pbh)
            )

        # WHOIS
        whois_data = get_whois_data(domain)
        if whois_data and whois_data.get("registrar"):
            whois_result = {"success": True, **whois_data}
            logger.info(
                "[RESUME]   WHOIS: registrar=%s",
                whois_data.get("registrar", "N/A")
            )

    # ── Reload Phase 1: Subdomain Discovery ──────────────
    if "subdomain_discovery" in completed_phases:
        stored_subs = get_subdomains_by_target(target_id)
        subdomain_list = [s["subdomain"] for s in stored_subs]
        subs_result = {
            "success": True,
            "subdomains": subdomain_list,
            "count": len(subdomain_list)
        }
        logger.info(
            "[RESUME] Reloaded Phase 1: %d subdomains",
            len(subdomain_list)
        )

    # ── Reload Phase 2: Port Scanning ────────────────────
    if "port_scanning" in completed_phases:
        stored_ports = get_ports_by_target(target_id)
        pbh = {}
        for p in stored_ports:
            host = p.get("host", "")
            port = p.get("port")
            if host and port is not None:
                if host not in pbh:
                    pbh[host] = []
                if port not in pbh[host]:
                    pbh[host].append(port)

        ports_result = {
            "success": True,
            "ports_found": pbh,
            "total_ports": sum(
                len(v) for v in pbh.values()
            )
        }
        logger.info(
            "[RESUME] Reloaded Phase 2: %d ports "
            "across %d hosts",
            ports_result["total_ports"], len(pbh)
        )

    # ── Reload Phase 3: HTTP Fingerprinting ──────────────
    if "http_fingerprinting" in completed_phases:
        stored_http = get_http_assets_by_target(target_id)
        http_result = {
            "success": True,
            "http_assets": stored_http,
            "count": len(stored_http)
        }
        logger.info(
            "[RESUME] Reloaded Phase 3: %d HTTP assets",
            len(stored_http)
        )

    return (
        shodan_result, censys_result, whois_result,
        subdomain_list, subs_result, ports_result,
        http_result
    )


def _build_http_target_map(http_result):
    """Map host -> discovered HTTP URLs from HTTPX results."""
    target_map = defaultdict(list)

    for asset in http_result.get("http_assets", []):
        host = str(asset.get("host", "")).strip()
        url = str(asset.get("url", "")).strip()
        if host and url and url not in target_map[host]:
            target_map[host].append(url)

    return target_map


def _preferred_targets_for_hosts(hosts, http_target_map):
    """Use discovered URLs for web scans and fall back to raw hosts."""
    targets = []
    seen = set()

    for host in hosts:
        preferred = http_target_map.get(host) or [host]
        for target in preferred:
            if target and target not in seen:
                seen.add(target)
                targets.append(target)

    return targets


def _persist_vulnerability_batch(
    target_id, domain, vulnerabilities, all_vulns, persisted_keys
):
    """Persist a vulnerability batch immediately and keep memory deduped."""
    for v in vulnerabilities:
        dedupe_key = (
            f"{v.get('template_id', '')}||"
            f"{v.get('host', '')}"
        )
        if dedupe_key in persisted_keys:
            continue

        persisted_keys.add(dedupe_key)
        all_vulns.append(v)
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
            cvss_score=v.get(
                "cvss_score"
            ),
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




# =========================================================================
# VULNERABILITY TIER HELPERS
# =========================================================================

def _run_tag_tier_scan(
    tier_name, tag_targets, http_target_map,
    source_label, target_id, domain,
    all_vulns, persisted_vuln_keys
):
    """
    Run a tag-grouped Nuclei scan for a single intelligence tier.

    Tiers 1B, 2A, and 2B all share the same pattern:
      1. Group hosts by their sorted tag-set key
      2. For each unique tag-set, run Nuclei on those hosts
      3. Persist annotated findings to the DB

    Args:
        tier_name:          Human-readable tier label (e.g. "Tier 1B")
        tag_targets:        Dict of {host: [tags]} from the scan plan
        http_target_map:    Dict of {host: preferred_http_url}
        source_label:       Value to set on verification_source field
        target_id:          MongoDB target document ID
        domain:             Root domain string
        all_vulns:          Shared list to collect all vulns
        persisted_vuln_keys: Shared set to deduplicate persisted vulns

    Returns:
        True if any batch returned a partial result, False otherwise
    """
    had_partial = False

    # Group hosts that share the same tag-set into one Nuclei call
    tag_groups = {}
    for host, tags in tag_targets.items():
        tag_key = ",".join(sorted(tags))
        if tag_key not in tag_groups:
            tag_groups[tag_key] = []
        tag_groups[tag_key].append(host)

    for tags_str, hosts in tag_groups.items():
        tags_list = tags_str.split(",")
        scan_targets = _preferred_targets_for_hosts(
            hosts, http_target_map
        )
        logger.info(
            "  %s: %d hosts with tags [%s]",
            tier_name, len(hosts), tags_str
        )

        result = run_nuclei(scan_targets, custom_tags=tags_list)

        if result.get("partial"):
            had_partial = True

        if result.get("success"):
            annotated = []
            for v in result.get("vulnerabilities", []):
                v["verification_source"] = source_label
                v["confidence"] = "medium"
                annotated.append(v)
            _persist_vulnerability_batch(
                target_id, domain, annotated,
                all_vulns, persisted_vuln_keys
            )

    return had_partial


def _run_simple_tier_scan(
    tier_name, hosts, http_target_map,
    source_label, target_id, domain,
    all_vulns, persisted_vuln_keys,
    custom_tags=None, severity_override=None,
    expand_http_schemes=True, confidence="standard"
):
    """
    Run a simple (non-tag-grouped) Nuclei scan for a tier.

    Used for Tier 2C (Broad) and Tier 2C-NET (Network).

    Args:
        tier_name:          Human-readable label
        hosts:              List of host strings
        http_target_map:    Dict of {host: preferred_url} or None (for raw IPs)
        source_label:       verification_source value
        target_id:          MongoDB ID
        domain:             Root domain
        all_vulns:          Shared vuln list
        persisted_vuln_keys: Shared dedupe set
        custom_tags:        Optional list of Nuclei tags
        severity_override:  Optional Nuclei severity string
        expand_http_schemes: Whether to add http/https prefixes
        confidence:         confidence score ("standard", "medium", etc)

    Returns:
        True if partial, False otherwise
    """
    if not hosts:
        return False

    scan_targets = hosts
    if http_target_map:
        scan_targets = _preferred_targets_for_hosts(
            hosts, http_target_map
        )

    logger.info(
        "  %s: %d targets", tier_name, len(scan_targets)
    )

    result = run_nuclei(
        scan_targets,
        custom_tags=custom_tags,
        severity_override=severity_override,
        expand_http_schemes=expand_http_schemes
    )

    if result.get("success"):
        annotated = []
        for v in result.get("vulnerabilities", []):
            v["verification_source"] = source_label
            v["confidence"] = confidence
            annotated.append(v)
        _persist_vulnerability_batch(
            target_id, domain, annotated,
            all_vulns, persisted_vuln_keys
        )

    return result.get("partial", False)


# =========================================================================
# MAIN SCAN PIPELINE
# =========================================================================

def run_full_scan(target_id, domain, scan_id=None):
    """
    Execute the complete EASM scan pipeline.

    Supports resumability: if scan_id points to a scan with
    completed phases, those phases are skipped and their
    outputs are reloaded from the database.

    Args:
        target_id: MongoDB target document ID (string)
        domain:    Root domain to scan (string)
        scan_id:   Pre-created scan ID (string, optional)

    Returns:
        dict with success, scan_id, results
    """

    if scan_id is None:
        scan = create_scan_with_domain(
            target_id, domain, "full"
        )
        scan_id = scan["scan_id"]

    logger.info("=" * 60)
    logger.info("Starting full scan — ID: %s", scan_id)
    logger.info("Target: %s", domain)
    logger.info("=" * 60)

    # Register for cancellation monitoring
    register_target(domain)

    # ── Check for resumable phases ───────────────────────
    completed_phases_db = get_completed_phases(scan_id)
    is_resuming = len(completed_phases_db) > 0

    if is_resuming:
        logger.info("=" * 60)
        logger.info(
            "RESUMING SCAN — Completed phases: %s",
            completed_phases_db
        )
        logger.info("=" * 60)

    # ── Initialize result containers ─────────────────────
    phases_completed = completed_phases_db.copy()
    phases_failed = []
    vuln_scan_partial = False

    subs_result = {"success": False, "subdomains": []}
    subdomain_list = []
    ports_result = {"success": False, "ports_found": {}}
    http_result = {"success": False, "http_assets": []}
    vuln_result = {"success": False, "vulnerabilities": []}
    changes_summary = {"total_changes": 0}
    risk_score = 0

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

    # ── Reload data from DB if resuming ──────────────────
    if is_resuming:
        (shodan_result, censys_result, whois_result,
         subdomain_list, subs_result, ports_result,
         http_result) = _reload_from_db(
            target_id, domain, completed_phases_db
        )

    try:
        # ── Mark existing assets as old ──────────────────
        # ONLY on fresh scans — resume needs existing data
        if not is_resuming:
            mark_all_subdomains_old(target_id)
            mark_all_ports_old(target_id)
            mark_all_http_assets_old(target_id)
            mark_all_vulns_old(target_id)
            mark_all_emails_old(target_id)
            mark_all_endpoints_old(target_id)

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
        # PHASE 0: PASSIVE RECON (SHODAN + CENSYS + WHOIS)
        # ═════════════════════════════════════════════════
        if "passive_recon" not in completed_phases_db:
            if is_cancelled(domain):
                logger.warning(f"[ABORT] Scan cancelled for {domain} before Phase 0")
                return {"success": False, "status": "cancelled"}

            _progress(
                scan_id, "passive_recon", 2,
                f"Running passive recon on {domain}..."
            )

            try:
                # ── Shodan ────────────────────────────
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
                                target_id, domain, "",
                                host, ports, source="shodan"
                            )

                        s = shodan_result.get("stats", {})
                        logger.info(
                            "Phase 0a: Shodan — %d subs, "
                            "%d ports, %d CVEs",
                            s.get('subdomains_found', 0),
                            s.get('unique_ports', 0),
                            s.get('unique_vulns', 0)
                        )

                        save_shodan_results(
                            target_id, domain, shodan_result
                        )
                    else:
                        logger.warning(
                            "Phase 0a: Shodan — %s",
                            shodan_result.get(
                                'error', 'No data'
                            )
                        )
                else:
                    logger.info(
                        "Phase 0a: Shodan not configured "
                        "— skipping"
                    )

                # ── Censys ────────────────────────────
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
                                target_id, domain, "",
                                host, ports, source="censys"
                            )

                        c = censys_result.get("stats", {})
                        logger.info(
                            "Phase 0b: Censys — %d subs, "
                            "%d ports, %d services",
                            c.get('total_subdomains', 0),
                            c.get('unique_ports', 0),
                            c.get('total_services', 0)
                        )

                        save_censys_results(
                            target_id, domain, censys_result
                        )
                    else:
                        logger.warning(
                            "Phase 0b: Censys — %s",
                            censys_result.get(
                                'error', 'No data'
                            )
                        )
                else:
                    logger.info(
                        "Phase 0b: Censys not configured "
                        "— skipping"
                    )

                # ── WHOIS ─────────────────────────────
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
                        w_stats = whois_result.get(
                            "stats", {}
                        )
                        logger.info(
                            "Phase 0c: WHOIS — "
                            "registrar=%s, "
                            "%d nameservers, "
                            "%d risk flags",
                            whois_result.get(
                                "registrar", "N/A"
                            ),
                            w_stats.get(
                                "nameserver_count", 0
                            ),
                            w_stats.get(
                                "risk_flags_count", 0
                            )
                        )
                    else:
                        logger.warning(
                            "Phase 0c: WHOIS — %s",
                            whois_result.get(
                                "error", "No data"
                            )
                        )
                else:
                    logger.info(
                        "Phase 0c: WHOIS not available "
                        "— install python-whois"
                    )

                phases_completed.append("passive_recon")
                mark_phase_completed(
                    scan_id, "passive_recon"
                )

            except Exception as e:
                phases_failed.append({
                    "phase": "passive_recon",
                    "error": str(e)
                })
                logger.error(
                    "Phase 0 failed: %s", e, exc_info=True
                )
        else:
            logger.info(
                "[RESUME] Skipping Phase 0: passive_recon "
                "(already completed)"
            )

        # ═════════════════════════════════════════════════
        # PHASE 1: SUBDOMAIN DISCOVERY
        # ═════════════════════════════════════════════════
        if "subdomain_discovery" not in completed_phases_db:
            _progress(
                scan_id, "subdomain_discovery", 10,
                f"Discovering subdomains for {domain}..."
            )

            try:
                # ── Parallel: Subfinder + Amass ───────
                # Both are passive OSINT tools querying
                # independent sources. Running in parallel
                # cuts Phase 1 time by 30-60 seconds.
                from concurrent.futures import (
                    ThreadPoolExecutor, as_completed,
                )

                amass_subs = set()
                amass_is_ready = False

                try:
                    from core.amass import (
                        run_amass,
                        is_available as amass_available,
                    )
                    amass_is_ready = amass_available()
                except Exception:
                    amass_is_ready = False

                if amass_is_ready:
                    logger.info(
                        "Phase 1: Running Subfinder + Amass "
                        "in parallel..."
                    )
                    _progress(
                        scan_id, "subdomain_discovery", 12,
                        "Running Subfinder + Amass in "
                        "parallel..."
                    )

                    with ThreadPoolExecutor(
                        max_workers=2
                    ) as pool:
                        sf_future = pool.submit(
                            scan_subdomains, domain
                        )
                        am_future = pool.submit(
                            run_amass, domain
                        )

                        subs_result = sf_future.result()
                        amass_result = am_future.result()

                    subfinder_subs = set(
                        subs_result.get("subdomains", [])
                    )

                    if amass_result.get("success"):
                        amass_subs = set(
                            amass_result.get(
                                "subdomains", []
                            )
                        )
                        logger.info(
                            "Phase 1: Amass found %d "
                            "subdomains",
                            len(amass_subs)
                        )
                    else:
                        logger.warning(
                            "Phase 1: Amass failed — %s",
                            amass_result.get(
                                "error", "unknown"
                            )
                        )
                else:
                    # Amass not available — run Subfinder
                    # only (original behaviour)
                    logger.info(
                        "Phase 1: Amass not installed "
                        "— running Subfinder only"
                    )
                    subs_result = scan_subdomains(domain)
                    subfinder_subs = set(
                        subs_result.get("subdomains", [])
                    )

                # ── Merge: Subfinder + Amass + Passive ─
                passive_subs = set()
                passive_subs.update(
                    shodan_result.get("subdomains", [])
                )
                passive_subs.update(
                    censys_result.get("subdomains", [])
                )

                # Three-way merge with source tagging
                all_subs = (
                    subfinder_subs | amass_subs | passive_subs
                )
                subdomain_list = sorted(all_subs)

                # Determine overlap for confidence scoring
                both_tools = subfinder_subs & amass_subs
                only_subfinder = (
                    subfinder_subs - amass_subs - passive_subs
                )
                only_amass = (
                    amass_subs - subfinder_subs - passive_subs
                )

                logger.info(
                    "Phase 1 merge: %d subfinder, "
                    "%d amass, %d passive, "
                    "%d merged (both tools), "
                    "%d total unique",
                    len(subfinder_subs),
                    len(amass_subs),
                    len(passive_subs),
                    len(both_tools),
                    len(subdomain_list),
                )

                # Persist with source attribution
                if subdomain_list:
                    # Subdomains found by both tools
                    # (highest confidence)
                    if both_tools:
                        add_subdomains_bulk(
                            target_id, domain,
                            sorted(both_tools),
                            source="merged"
                        )

                    # Subfinder-only
                    if only_subfinder:
                        add_subdomains_bulk(
                            target_id, domain,
                            sorted(only_subfinder),
                            source="subfinder"
                        )

                    # Amass-only
                    if only_amass:
                        add_subdomains_bulk(
                            target_id, domain,
                            sorted(only_amass),
                            source="amass"
                        )

                    # Passive-only subs
                    # (already persisted in Phase 0)

                subs_result = {
                    "success": True,
                    "subdomains": subdomain_list,
                    "count": len(subdomain_list),
                }

                if subs_result.get("success"):
                    certs = subs_result.get(
                        "certificates", []
                    )
                    if certs:
                        save_certificates(domain, certs)

                phases_completed.append(
                    "subdomain_discovery"
                )
                mark_phase_completed(
                    scan_id, "subdomain_discovery"
                )
                logger.info(
                    "Phase 1 complete: %d subdomains",
                    len(subdomain_list)
                )

            except Exception as e:
                phases_failed.append({
                    "phase": "subdomain_discovery",
                    "error": str(e)
                })
                logger.error(
                    "Phase 1 failed: %s", e, exc_info=True
                )
        else:
            logger.info(
                "[RESUME] Skipping Phase 1: "
                "subdomain_discovery "
                "(already completed — "
                "%d subdomains loaded)",
                len(subdomain_list)
            )

        # ═════════════════════════════════════════════════
        # PHASE 2: PORT SCANNING
        # ═════════════════════════════════════════════════
        if "port_scanning" not in completed_phases_db:
            _progress(
                scan_id, "port_scanning", 25,
                f"Scanning ports on "
                f"{len(subdomain_list)} hosts..."
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
                    passive_hosts = (
                        shodan_hosts | censys_hosts
                    )

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
                        ports_result = run_naabu(
                            hosts_needing_scan
                        )

                        if ports_result.get("success"):
                            for host, ports in (
                                ports_result.get(
                                    "ports_found", {}
                                ).items()
                            ):
                                add_ports_bulk(
                                    target_id, domain, "",
                                    host, ports,
                                    source="naabu"
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
                        shodan_result.get(
                            "ports_by_host", {}
                        )
                    )

                    for host, ports in censys_result.get(
                        "ports_by_host", {}
                    ).items():
                        if host in merged_ports:
                            existing = set(
                                merged_ports[host]
                            )
                            existing.update(ports)
                            merged_ports[host] = sorted(
                                existing
                            )
                        else:
                            merged_ports[host] = sorted(
                                ports
                            )

                    for host, ports in ports_result.get(
                        "ports_found", {}
                    ).items():
                        if host in merged_ports:
                            existing = set(
                                merged_ports[host]
                            )
                            existing.update(ports)
                            merged_ports[host] = sorted(
                                existing
                            )
                        else:
                            merged_ports[host] = sorted(
                                ports
                            )

                    ports_result["ports_found"] = (
                        merged_ports
                    )
                    ports_result["total_ports"] = sum(
                        len(p)
                        for p in merged_ports.values()
                    )

                    if (ports_result.get("success")
                            or passive_hosts):
                        for host, ports in (
                            merged_ports.items()
                        ):
                            add_ports_bulk(
                                target_id, domain, "",
                                host, ports, source="scan"
                            )

                    phases_completed.append("port_scanning")
                    mark_phase_completed(
                        scan_id, "port_scanning"
                    )
                    logger.info(
                        "Phase 2 complete: %d ports "
                        "(Passive: %d hosts, "
                        "Naabu: %d hosts)",
                        ports_result.get(
                            'total_ports', 0
                        ),
                        len(passive_hosts),
                        len(hosts_needing_scan)
                    )
                else:
                    phases_completed.append("port_scanning")
                    mark_phase_completed(
                        scan_id, "port_scanning"
                    )
                    logger.info(
                        "Phase 2 skipped: no subdomains"
                    )

            except Exception as e:
                phases_failed.append({
                    "phase": "port_scanning",
                    "error": str(e)
                })
                logger.error(
                    "Phase 2 failed: %s", e, exc_info=True
                )
        else:
            logger.info(
                "[RESUME] Skipping Phase 2: port_scanning "
                "(already completed — %d ports loaded)",
                ports_result.get("total_ports", 0)
            )

        # ═════════════════════════════════════════════════
        # PHASE 3: HTTP FINGERPRINTING
        # ═════════════════════════════════════════════════
        if "http_fingerprinting" not in completed_phases_db:
            _progress(
                scan_id, "http_fingerprinting", 45,
                f"Probing HTTP on "
                f"{len(subdomain_list)} hosts..."
            )

            try:
                if subdomain_list:
                    http_result = run_httpx(subdomain_list)

                    if http_result.get("success"):
                        for asset in http_result[
                            "http_assets"
                        ]:
                            add_http_asset(
                                target_id, domain, "",
                                asset.get("url", ""),
                                asset.get("host", ""),
                                asset.get("port", 0),
                                asset.get(
                                    "status_code", 0
                                ),
                                asset.get("title", ""),
                                asset.get(
                                    "web_server", ""
                                ),
                                asset.get("tech", []),
                                asset.get(
                                    "content_length", 0
                                )
                            )

                    phases_completed.append(
                        "http_fingerprinting"
                    )
                    mark_phase_completed(
                        scan_id, "http_fingerprinting"
                    )
                    logger.info(
                        "Phase 3 complete: %d HTTP assets",
                        http_result.get('count', 0)
                    )
                else:
                    phases_completed.append(
                        "http_fingerprinting"
                    )
                    mark_phase_completed(
                        scan_id, "http_fingerprinting"
                    )
                    logger.info(
                        "Phase 3 skipped: no subdomains"
                    )

            except Exception as e:
                phases_failed.append({
                    "phase": "http_fingerprinting",
                    "error": str(e)
                })
                logger.error(
                    "Phase 3 failed: %s", e, exc_info=True
                )
        else:
            logger.info(
                "[RESUME] Skipping Phase 3: "
                "http_fingerprinting "
                "(already completed — %d assets loaded)",
                http_result.get("count", 0)
            )
        # ═════════════════════════════════════════════════
        # PHASE 3.5: PARAMETER DISCOVERY (ARJUN)
        #            Opt-in — only runs if enabled
        # ═════════════════════════════════════════════════
        if "parameter_discovery" not in completed_phases_db:
            # Check opt-in gate — default is disabled
            # because Arjun is an active/intrusive tool
            enable_param_disc = Config.RUN_ARJUN
            param_rate_limit = Config.ARJUN_RATE_LIMIT
            try:
                from database.targets_db import get_target
                target_doc = get_target(target_id)
                if target_doc:
                    scan_cfg = target_doc.get(
                        "scan_config", {}
                    )
                    if "enable_parameter_discovery" in scan_cfg:
                        enable_param_disc = (
                            Config.RUN_ARJUN and
                            scan_cfg.get(
                                "enable_parameter_discovery",
                                False
                            )
                        )
                    param_rate_limit = scan_cfg.get(
                        "parameter_discovery_rate_limit",
                        param_rate_limit
                    )
            except Exception:
                pass

            if enable_param_disc:
                _progress(
                    scan_id, "parameter_discovery", 50,
                    "Discovering hidden HTTP parameters..."
                )

                try:
                    from core.arjun_runner import (
                        run_arjun,
                        is_available as arjun_available,
                    )

                    if arjun_available():
                        arjun_result = run_arjun(
                            http_result,
                            rate_limit=param_rate_limit,
                            domain=domain,
                        )

                        if arjun_result.get("success"):
                            endpoints = arjun_result.get(
                                "endpoints", []
                            )
                            if endpoints:
                                add_endpoints_bulk(
                                    target_id, domain,
                                    endpoints,
                                )
                            logger.info(
                                "Phase 3.5 complete: "
                                "%d endpoints with "
                                "hidden parameters",
                                len(endpoints)
                            )
                        else:
                            logger.warning(
                                "Phase 3.5: Arjun "
                                "failed — %s",
                                arjun_result.get(
                                    "error", "unknown"
                                )
                            )
                    else:
                        logger.info(
                            "Phase 3.5: Arjun not "
                            "installed — skipping"
                        )

                    phases_completed.append(
                        "parameter_discovery"
                    )
                    mark_phase_completed(
                        scan_id, "parameter_discovery"
                    )

                except Exception as e:
                    phases_failed.append({
                        "phase": "parameter_discovery",
                        "error": str(e)
                    })
                    logger.error(
                        "Phase 3.5 failed: %s",
                        e, exc_info=True
                    )
            else:
                # Disabled — skip silently, no checkpoint
                # needed (Phase 4 proceeds normally)
                logger.info(
                    "Phase 3.5: Parameter discovery "
                    "disabled — skipping"
                )
                phases_completed.append(
                    "parameter_discovery"
                )
                mark_phase_completed(
                    scan_id, "parameter_discovery"
                )
        else:
            logger.info(
                "[RESUME] Skipping Phase 3.5: "
                "parameter_discovery "
                "(already completed)"
            )

        # ═════════════════════════════════════════════════
        # PHASE 4: VULNERABILITY SCANNING
        #          (INTELLIGENCE-DRIVEN v2 + BATCHED)
        # ═════════════════════════════════════════════════
        if "vuln_scanning" not in completed_phases_db:
            _progress(
                scan_id, "vuln_scanning", 55,
                "Building intelligent scan plan..."
            )

            try:
                if subdomain_list:
                    from core.smart_scanner import (
                        build_scan_plan
                    )

                    scan_plan = build_scan_plan(
                        shodan_result, censys_result,
                        http_result, subdomain_list,
                        ports_data=ports_result.get(
                            "ports_found", {}
                        )
                    )

                    all_vulns = []
                    persisted_vuln_keys = set()
                    http_target_map = _build_http_target_map(
                        http_result
                    )

                    # ══════════════════════════════════════
                    # TIER 1A: Batched CVE Verification
                    #   Groups targets by template set so
                    #   hosts sharing CVEs are scanned in
                    #   a single Nuclei call.
                    # ══════════════════════════════════════
                    cve_scans = scan_plan.get(
                        "tier1_cve_scans", []
                    )
                    if cve_scans:
                        _progress(
                            scan_id, "vuln_scanning", 57,
                            f"Tier 1A: Verifying "
                            f"{len(cve_scans)} "
                            f"Shodan CVEs..."
                        )

                        # Collect per-host CVE items
                        host_cves = defaultdict(list)
                        for scan_item in cve_scans:
                            target_url = scan_item.get(
                                "target_url",
                                scan_item["host"]
                            )
                            host_cves[target_url].append(
                                scan_item
                            )

                        logger.info(
                            "Phase 4 Tier 1A: %d CVEs "
                            "across %d hosts",
                            len(cve_scans),
                            len(host_cves)
                        )

                        # Group by identical template sets
                        template_groups = {}
                        for target_url, items in (
                            host_cves.items()
                        ):
                            templates = tuple(sorted([
                                item["template"]
                                for item in items
                                if os.path.exists(
                                    item["template"]
                                )
                            ]))

                            if not templates:
                                continue

                            if templates not in (
                                template_groups
                            ):
                                template_groups[
                                    templates
                                ] = {
                                    "hosts": [],
                                    "cve_ids": set(),
                                    "items": []
                                }

                            grp = template_groups[templates]
                            grp["hosts"].append(target_url)
                            grp["items"].extend(items)
                            grp["cve_ids"].update(
                                item["cve_id"]
                                for item in items
                            )

                        # Scan each template group
                        for templates_tuple, grp in (
                            template_groups.items()
                        ):
                            batch_hosts = grp["hosts"]
                            batch_cves = sorted(
                                grp["cve_ids"]
                            )
                            templates_list = list(
                                templates_tuple
                            )

                            logger.info(
                                "  Tier 1A batch: "
                                "%d hosts, %d CVEs, "
                                "%d templates",
                                len(batch_hosts),
                                len(batch_cves),
                                len(templates_list)
                            )

                            targeted_result = run_nuclei(
                                batch_hosts,
                                custom_templates=(
                                    templates_list
                                )
                            )

                            if targeted_result.get("partial"):
                                vuln_scan_partial = True

                            if (
                                targeted_result.get("success")
                                and targeted_result.get("vulnerabilities")
                            ):
                                annotated_vulns = []
                                for v in targeted_result[
                                    "vulnerabilities"
                                ]:
                                    v[
                                        "verification_source"
                                    ] = "shodan_cve_confirmed"
                                    v["confidence"] = "high"
                                    annotated_vulns.append(v)
                                    logger.info(
                                        "  CONFIRMED: "
                                        "%s @ %s",
                                        v.get(
                                            "template_id",
                                            ""
                                        ),
                                        v.get("host", "")
                                    )
                                _persist_vulnerability_batch(
                                    target_id,
                                    domain,
                                    annotated_vulns,
                                    all_vulns,
                                    persisted_vuln_keys
                                )

                            # Log unconfirmed CVEs
                            confirmed = set(
                                v.get("template_id", "")
                                for v in
                                targeted_result.get(
                                    "vulnerabilities", []
                                )
                            )
                            for cve in batch_cves:
                                tname = os.path.basename(
                                    [
                                        i["template"]
                                        for i in
                                        grp["items"]
                                        if i["cve_id"]
                                        == cve
                                    ][0]
                                ).replace(".yaml", "")
                                if tname not in confirmed:
                                    logger.debug(
                                        "  NOT CONFIRMED:"
                                        " %s "
                                        "(stale/patched)",
                                        cve
                                    )

                    # ══════════════════════════════════════
                    # TIER 1B: Tech-Targeted Scans
                    # ══════════════════════════════════════
                    tech_targets = scan_plan.get(
                        "tier1_tech_tags", {}
                    )
                    if tech_targets:
                        _progress(
                            scan_id, "vuln_scanning", 62,
                            f"Tier 1B: Tech-targeted scan on "
                            f"{len(tech_targets)} hosts..."
                        )
                        if _run_tag_tier_scan(
                            "Tier 1B", tech_targets,
                            http_target_map, "tech_targeted",
                            target_id, domain,
                            all_vulns, persisted_vuln_keys
                        ):
                            vuln_scan_partial = True


                    # ══════════════════════════════════════
                    # TIER 2A: Port-Informed Scans
                    # ══════════════════════════════════════
                    port_targets = scan_plan.get(
                        "tier2a_port_tags", {}
                    )
                    if port_targets:
                        _progress(
                            scan_id, "vuln_scanning", 68,
                            f"Tier 2A: Port-targeted scan on "
                            f"{len(port_targets)} hosts..."
                        )
                        if _run_tag_tier_scan(
                            "Tier 2A", port_targets,
                            http_target_map, "port_targeted",
                            target_id, domain,
                            all_vulns, persisted_vuln_keys
                        ):
                            vuln_scan_partial = True



                    # ══════════════════════════════════════
                    # TIER 2B: Header-Mined Scans
                    # ══════════════════════════════════════
                    header_targets = scan_plan.get(
                        "tier2b_header_tags", {}
                    )
                    if header_targets:
                        _progress(
                            scan_id, "vuln_scanning", 73,
                            f"Tier 2B: Header-informed scan on "
                            f"{len(header_targets)} hosts..."
                        )
                        if _run_tag_tier_scan(
                            "Tier 2B", header_targets,
                            http_target_map, "header_targeted",
                            target_id, domain,
                            all_vulns, persisted_vuln_keys
                        ):
                            vuln_scan_partial = True

                    # ══════════════════════════════════════
                    # TIER 2C: Catch-All — Web Hosts Only
                    # ══════════════════════════════════════
                    catchall_hosts = scan_plan.get(
                        "tier2c_catchall", []
                    )
                    if catchall_hosts:
                        _progress(
                            scan_id, "vuln_scanning", 78,
                            f"Tier 2C: Broad scan on {len(catchall_hosts)} unknown web hosts..."
                        )
                        if _run_simple_tier_scan(
                            "Tier 2C", catchall_hosts, http_target_map,
                            "broad_scan", target_id, domain,
                            all_vulns, persisted_vuln_keys,
                            severity_override=Config.NUCLEI_TIER2C_SEVERITY
                        ):
                            vuln_scan_partial = True

                    # ══════════════════════════════════════
                    # TIER 2C-NET: Non-Web Hosts
                    # ══════════════════════════════════════
                    non_web_hosts = scan_plan.get(
                        "tier2c_non_web", []
                    )
                    if non_web_hosts:
                        _progress(
                            scan_id, "vuln_scanning", 83,
                            f"Tier 2C-NET: Network scan on {len(non_web_hosts)} non-web hosts..."
                        )
                        if _run_simple_tier_scan(
                            "Tier 2C-NET", non_web_hosts, None,
                            "network_scan", target_id, domain,
                            all_vulns, persisted_vuln_keys,
                            custom_tags=NETWORK_SCAN_TAGS,
                            expand_http_schemes=False
                        ):
                            vuln_scan_partial = True


                    # ── Build final vuln_result ───────────
                    severity_count = {
                        "critical": 0, "high": 0,
                        "medium": 0, "low": 0, "info": 0
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
                        "severity_breakdown": (
                            severity_count
                        )
                    }

                    if not vuln_scan_partial:
                        phases_completed.append(
                            "vuln_scanning"
                        )
                        mark_phase_completed(
                            scan_id, "vuln_scanning"
                        )

                    logger.info(
                        "Phase 4 complete: %d vulns "
                        "(1A: %d confirmed, "
                        "1B: %d tech, "
                        "2A: %d port, "
                        "2B: %d header, "
                        "2C: %d broad, "
                        "2C-NET: %d network)",
                        len(all_vulns),
                        sum(
                            1 for v in all_vulns
                            if v.get("confidence")
                            == "high"
                        ),
                        sum(
                            1 for v in all_vulns
                            if v.get(
                                "verification_source"
                            ) == "tech_targeted"
                        ),
                        sum(
                            1 for v in all_vulns
                            if v.get(
                                "verification_source"
                            ) == "port_targeted"
                        ),
                        sum(
                            1 for v in all_vulns
                            if v.get(
                                "verification_source"
                            ) == "header_targeted"
                        ),
                        sum(
                            1 for v in all_vulns
                            if v.get(
                                "verification_source"
                            ) == "broad_scan"
                        ),
                        sum(
                            1 for v in all_vulns
                            if v.get(
                                "verification_source"
                            ) == "network_scan"
                        ),
                    )
                else:
                    phases_completed.append(
                        "vuln_scanning"
                    )
                    mark_phase_completed(
                        scan_id, "vuln_scanning"
                    )
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
        else:
            logger.info(
                "[RESUME] Skipping Phase 4: vuln_scanning "
                "(already completed)"
            )

        # ═════════════════════════════════════════════════
        # PHASE 5: CHANGE DETECTION
        # ═════════════════════════════════════════════════
        if "change_detection" not in completed_phases_db:
            _progress(
                scan_id, "change_detection", 85,
                "Comparing with previous state..."
            )

            try:
                vuln_data_for_changes = vuln_result
                if vuln_scan_partial:
                    logger.warning(
                        "Phase 5: Skipping vuln change "
                        "detection (partial scan results)"
                    )
                    vuln_data_for_changes = {
                        "vulnerabilities": [],
                        "success": False
                    }

                changes_summary = (
                    detect_changes_with_snapshot(
                        target_id, domain, scan_id,
                        before_state,
                        subs_result, ports_result,
                        vuln_data_for_changes,
                        new_whois_result=whois_result
                    )
                )
                phases_completed.append(
                    "change_detection"
                )
                mark_phase_completed(
                    scan_id, "change_detection"
                )
                logger.info(
                    "Phase 5 complete: %d changes",
                    changes_summary.get(
                        'total_changes', 0
                    )
                )

            except Exception as e:
                phases_failed.append({
                    "phase": "change_detection",
                    "error": str(e)
                })
                logger.error(
                    "Phase 5 failed: %s", e, exc_info=True
                )
        else:
            logger.info(
                "[RESUME] Skipping Phase 5: "
                "change_detection (already completed)"
            )

        # ═════════════════════════════════════════════════
        # PHASE 6: RISK SCORING
        # ═════════════════════════════════════════════════
        if "risk_scoring" not in completed_phases_db:
            _progress(
                scan_id, "risk_scoring", 93,
                "Calculating risk score..."
            )

            try:
                risk_score = calculate_risk_score(
                    target_id
                )
                phases_completed.append("risk_scoring")
                mark_phase_completed(
                    scan_id, "risk_scoring"
                )
                logger.info(
                    "Phase 6 complete: Risk score %d/100",
                    risk_score
                )

            except Exception as e:
                phases_failed.append({
                    "phase": "risk_scoring",
                    "error": str(e)
                })
                logger.error(
                    "Phase 6 failed: %s", e, exc_info=True
                )
        else:
            # Recalculate if any scoring-relevant phase
            # was re-run during this resume
            recalc_phases = {
                "vuln_scanning", "port_scanning",
                "http_fingerprinting"
            }
            reran = recalc_phases - set(
                completed_phases_db
            )
            if reran:
                logger.info(
                    "[RESUME] Recalculating risk score "
                    "(phases %s were re-run)", reran
                )
                try:
                    risk_score = calculate_risk_score(
                        target_id
                    )
                    logger.info(
                        "Risk score recalculated: "
                        "%d/100", risk_score
                    )
                except Exception as e:
                    logger.error(
                        "Risk recalculation failed: %s",
                        e
                    )
            else:
                logger.info(
                    "[RESUME] Skipping Phase 6: "
                    "risk_scoring (already completed)"
                )

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
            "resumed": is_resuming,
            "passive_recon": {
                "shodan": {
                    "subdomains": len(
                        shodan_result.get(
                            "subdomains", []
                        )
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
                        censys_result.get(
                            "subdomains", []
                        )
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
                    "days_until_expiry": (
                        whois_result.get(
                            "days_until_expiry"
                        )
                    )
                }
            }
        }

        complete_scan(scan_id, results)
        _progress(scan_id, "done", 100, "Scan completed")
        
        # Final WebSocket announcement
        emit_scan_completed(scan_id, {
            "subdomains": subdomain_count,
            "ports": port_count,
            "vulns": vuln_count,
            "risk": risk_score
        })

        status = (
            "completed" if not phases_failed
            else "partial"
        )

        logger.info("=" * 60)
        logger.info("Scan %s for %s", status, domain)
        if is_resuming:
            logger.info(
                "  (Resumed — skipped: %s)",
                completed_phases_db
            )
        logger.info(
            "Subs: %d | Ports: %d | HTTP: %d | "
            "Vulns: %d",
            subdomain_count, port_count,
            http_count, vuln_count
        )
        logger.info(
            "Passive: %d Shodan CVEs, "
            "%d Censys services",
            shodan_vuln_count, censys_service_count
        )
        logger.info(
            "Changes: %d | Risk: %d/100",
            changes_summary.get('total_changes', 0),
            risk_score
        )
        logger.info("=" * 60)

        cleanup_signal(domain)
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
        emit_scan_error(scan_id, "fatal", str(e))
        return {
            "success": False,
            "status": "failed",
            "scan_id": scan_id,
            "error": str(e)
        }


# =========================================================================
# HELPER FUNCTIONS
# =========================================================================

def _progress(scan_id, phase, percent, detail=""):
    """Write progress to DB and emit WebSocket event."""
    try:
        update_scan_progress(scan_id, {
            "current_phase": phase,
            "phase_detail": detail,
            "progress_percent": percent,
        })
        
        # Also emit real-time update
        phase_num = PHASE_MAP.get(phase, 0)
        emit_scan_progress(
            scan_id=scan_id,
            phase_name=phase,
            phase_number=phase_num,
            progress_percent=percent,
            message=detail
        )
    except Exception as e:
        logger.error(f"Error updating progress: {e}")

