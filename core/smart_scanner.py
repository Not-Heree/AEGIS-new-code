"""
Intelligence-Driven Vulnerability Scanner v2
=============================================
Cross-references ALL available recon data to build TARGETED scans.

Six-tier approach:
  Tier 1A: Specific CVE template → specific host (Shodan verification)
  Tier 1B: Tech-targeted tags → hosts with known tech (HTTPX/Censys intel)
  Tier 2A: Port-informed tags → hosts with known service ports (Naabu/Shodan)
  Tier 2B: Header-mined tags → hosts with server/title clues (HTTPX headers)
  Tier 2C: Critical+High only → remaining web hosts (reduced catch-all)
  Tier 2C-NET: Network protocol templates → non-web hosts only

Port philosophy:
  PORT_TO_NUCLEI_TAGS contains ONLY service-specific ports where the port
  number definitively identifies the software (3306=MySQL, 6379=Redis).
  
  Ambiguous web ports (80, 443, 8080) are in WEB_PORTS only — used for
  web-vs-non-web classification but NOT for tag generation, because
  port 443 could be Apache, nginx, IIS, Node, Go, or anything else.
"""

import os
import re
from typing import List, Dict, Any, Set, Optional
from config import Config
from utils.logger import logger


# =============================================================================
# NETWORK SCAN TAGS (used by Tier 2C-NET in scanner.py)
# =============================================================================
#
# These tags define which Nuclei template categories are used when scanning
# non-web hosts (hosts with no HTTP service confirmed by HTTPX).
# Centralised here so they're findable, changeable in one place, and
# importable by the pipeline orchestrator.

NETWORK_SCAN_TAGS = [
    "network", "ssh", "ftp", "dns", "smtp", "snmp",
    "rdp", "vnc", "default-login", "mysql",
    "postgres", "mssql", "redis", "mongodb",
    "memcached", "ldap",
]


# =============================================================================
# CVE TEMPLATE INDEX (Built Once, Reused)
# =============================================================================

_TEMPLATE_INDEX = None


def _build_template_index() -> Dict[str, str]:
    """
    Build a one-time index of all CVE templates in the
    nuclei-templates directory. ~8000 files indexed in <1 second.
    """
    global _TEMPLATE_INDEX
    if _TEMPLATE_INDEX is not None:
        return _TEMPLATE_INDEX

    home = os.path.expanduser("~")
    userprofile = os.getenv("USERPROFILE", home)

    base_dirs = [
        Config.NUCLEI_TEMPLATES_PATH,
        os.path.join(home, "nuclei-templates"),
        os.path.join(userprofile, "nuclei-templates"),
    ]

    _TEMPLATE_INDEX = {}

    for base in base_dirs:
        if not base or not os.path.exists(base):
            continue

        for root, dirs, files in os.walk(base):
            for f in files:
                if f.upper().startswith("CVE-") and f.endswith(".yaml"):
                    cve_id = f.replace(".yaml", "").upper()
                    if cve_id not in _TEMPLATE_INDEX:
                        _TEMPLATE_INDEX[cve_id] = os.path.join(root, f)

    logger.info(
        "Indexed %d CVE templates from nuclei-templates",
        len(_TEMPLATE_INDEX)
    )
    return _TEMPLATE_INDEX


def find_nuclei_template_for_cve(cve_id: str) -> Optional[str]:
    """
    Find Nuclei template for a CVE using pre-built index.
    First call builds the index (~0.5s), subsequent calls are instant.
    """
    if not cve_id:
        return None

    index = _build_template_index()
    return index.get(cve_id.upper().strip())


# =============================================================================
# TECH → NUCLEI TAG MAPPING (used by Tier 1B)
# =============================================================================

TECH_TO_NUCLEI_TAGS = {
    # Web Servers
    "apache": ["apache"],
    "nginx": ["nginx"],
    "iis": ["iis"],
    "tomcat": ["tomcat"],
    "lighttpd": ["lighttpd"],

    # CMS
    "wordpress": ["wordpress", "wp"],
    "joomla": ["joomla"],
    "drupal": ["drupal"],
    "magento": ["magento"],
    "ghost": ["ghost"],
    "strapi": ["strapi"],
    "directus": ["directus"],
    "opencart": ["opencart"],
    "prestashop": ["prestashop"],

    # Frameworks
    "laravel": ["laravel"],
    "django": ["django"],
    "flask": ["flask"],
    "spring": ["spring", "springboot"],
    "ruby on rails": ["rails"],

    # Panels, Auth, & Containers
    "grafana": ["grafana"],
    "jenkins": ["jenkins"],
    "gitlab": ["gitlab"],
    "jira": ["jira", "atlassian"],
    "confluence": ["confluence", "atlassian"],
    "kibana": ["kibana", "elastic"],
    "elasticsearch": ["elasticsearch", "elastic"],
    "phpmyadmin": ["phpmyadmin"],
    "webmin": ["webmin"],
    "cpanel": ["cpanel"],
    "docker": ["docker"],
    "kubernetes": ["kubernetes", "k8s"],
    "keycloak": ["keycloak"],
    "auth0": ["auth0"],
    "okta": ["okta"],

    # Languages
    "php": ["php"],
    "asp.net": ["aspnet"],
    "node.js": ["nodejs"],

    # Infrastructure & Gateway
    "citrix": ["citrix"],
    "fortinet": ["fortinet", "fortigate"],
    "sonicwall": ["sonicwall"],
    "paloalto": ["paloalto"],
    "f5": ["f5", "bigip"],
    "vmware": ["vmware", "vcenter", "esxi"],
    "hashicorp vault": ["vault"],
    "traefik": ["traefik"],
    "envoy": ["envoy"],
    "kong": ["kong"],

    # Cloud & Storage
    "amazon s3": ["aws", "s3"],
    "azure blob": ["azure", "storage"],
    "google cloud storage": ["gcp", "bucket"],

    # Databases (Web Interface/API)
    "mongodb": ["mongodb"],
    "redis": ["redis"],
    "couchdb": ["couchdb"],
    "influxdb": ["influxdb"],

    # Mail & Collaboration
    "exchange": ["exchange"],
    "zimbra": ["zimbra"],
    "nextcloud": ["nextcloud"],
    "owncloud": ["owncloud"],
    "mattermost": ["mattermost"],
}


def map_tech_to_tags(tech_list: List[str]) -> Set[str]:
    """
    Convert HTTPX technology detections to Nuclei template tags.
    Uses word-boundary matching to prevent false associations.

    Examples:
        ["WordPress 6.1"] → {"wordpress", "wp"}
        ["Apache 2.4.49"] → {"apache"}
        ["Cisco Expressway"] → set()  (NOT {"express", "nodejs"})
    """
    tags = set()

    for tech in tech_list:
        tech_lower = tech.lower().strip()
        if not tech_lower:
            continue

        # Extract base product name: "Apache 2.4.49" → "apache"
        tech_base = re.split(r'[\s/]', tech_lower)[0]

        # Exact match on base name first (fastest, most accurate)
        if tech_base in TECH_TO_NUCLEI_TAGS:
            tags.update(TECH_TO_NUCLEI_TAGS[tech_base])
            continue

        # Word-boundary match for multi-word tech names
        for key, nuclei_tags in TECH_TO_NUCLEI_TAGS.items():
            pattern = r'(?:^|[\s/])' + re.escape(key) + r'(?:$|[\s/])'
            if re.search(pattern, tech_lower):
                tags.update(nuclei_tags)

    return tags


# =============================================================================
# PORT → NUCLEI TAG MAPPING (used by Tier 2A)
# =============================================================================

# SERVICE-SPECIFIC PORTS ONLY.
# These ports definitively identify the running service.
# Port 3306 is ALWAYS MySQL. Port 6379 is ALWAYS Redis.
#
# DELIBERATELY EXCLUDED: 80, 443, 8080, 8443, 8888
# These are generic web ports — port 443 could be Apache, nginx,
# IIS, Node, Go, Python, or literally anything else.
# They belong in WEB_PORTS (for classification) not here (for targeting).

PORT_TO_NUCLEI_TAGS = {
    # Databases — port = definitive service
    3306:  ["mysql"],
    5432:  ["postgres"],
    1433:  ["mssql"],
    27017: ["mongodb"],
    6379:  ["redis"],
    9200:  ["elasticsearch", "elastic"],
    5984:  ["couchdb"],
    11211: ["memcached"],

    # Mail — port = definitive protocol
    25:    ["smtp"],
    465:   ["smtp", "ssl"],
    587:   ["smtp"],
    143:   ["imap"],
    993:   ["imap", "ssl"],
    110:   ["pop3"],

    # Infrastructure — port = definitive protocol
    21:    ["ftp"],
    22:    ["ssh"],
    23:    ["telnet"],
    53:    ["dns"],
    161:   ["snmp"],
    389:   ["ldap"],
    636:   ["ldap", "ssl"],

    # Remote Access — port = definitive protocol
    3389:  ["rdp"],
    5900:  ["vnc"],

    # DevOps / Panels — port strongly implies specific software
    2375:  ["docker"],
    2376:  ["docker"],
    9090:  ["prometheus"],
    3000:  ["grafana"],
    8081:  ["nexus"],
    5601:  ["kibana", "elastic"],
    9000:  ["sonarqube"],
    8500:  ["consul"],
    2379:  ["etcd"],
    10250: ["kubernetes"],
    6443:  ["kubernetes"],
    8161:  ["activemq"],
    15672: ["rabbitmq"],
    4848:  ["glassfish"],
    7001:  ["weblogic"],
    9043:  ["websphere"],
    9060:  ["websphere"],
}

# AMBIGUOUS WEB PORTS.
# Used ONLY for web-vs-non-web host classification (Tier 2C vs Tier 2C-NET).
# NOT used for Nuclei tag generation.
# A host with port 443 open goes to Tier 2C (broad web scan),
# NOT Tier 2A (targeted service scan).
WEB_PORTS = {
    80, 443, 8080, 8443, 8000, 8888,
    # DevOps ports that also serve web UIs
    # (these are in PORT_TO_NUCLEI_TAGS too, but listed here
    #  so host_has_web_service() catches them)
    3000, 5000, 5601, 9090, 9200, 8081, 8500,
    7443, 4443, 2083, 2087, 8161, 15672,
    4848, 7001, 9043, 9060,
}


# =============================================================================
# HTTP INTEL MINING — Server Header + Title Clues (used by Tier 2B)
# =============================================================================

# Maps Server header substrings → Nuclei tags.
# These are technologies that HTTPX -tech-detect often MISSES
# because Wappalyzer doesn't have signatures for them.
SERVER_SIGNATURES = {
    # Python servers (HTTPX rarely detects these as "Python")
    "gunicorn":     ["python"],
    "uvicorn":      ["python"],
    "werkzeug":     ["python", "flask"],
    "waitress":     ["python"],
    "daphne":       ["python", "django"],
    "cheroot":      ["python"],
    "twisted":      ["python"],
    "runway":       ["python"],

    # Java servers (beyond Tomcat)
    "jetty":        ["java"],
    "wildfly":      ["java"],
    "weblogic":     ["oracle", "weblogic"],
    "websphere":    ["ibm"],
    "glassfish":    ["java", "glassfish"],
    "payara":       ["java"],
    "resin":        ["java"],

    # .NET
    "kestrel":      ["aspnet"],

    # Nginx variants
    "openresty":    ["nginx", "openresty"],
    "tengine":      ["nginx"],

    # Other web servers
    "litespeed":    ["litespeed"],
    "caddy":        ["caddy"],
    "traefik":      ["traefik"],
    "envoy":        ["envoy"],
    "haproxy":      ["haproxy"],

    # Specific products
    "cloudflare":   ["cloudflare"],
    "sucuri":       ["waf"],
    "barracuda":    ["waf"],
    "imperva":      ["waf"],
}

# Maps page title keywords → Nuclei tags.
# Catches panels/apps that HTTPX tech-detect missed.
TITLE_HINTS = {
    "login":        ["default-login", "login"],
    "sign in":      ["default-login", "login"],
    "admin":        ["panel", "admin"],
    "dashboard":    ["panel"],
    "webmail":      ["mail"],
    "roundcube":    ["roundcube", "mail"],
    "phpmyadmin":   ["phpmyadmin", "php"],
    "cpanel":       ["cpanel"],
    "plesk":        ["plesk"],
    "grafana":      ["grafana"],
    "jenkins":      ["jenkins"],
    "gitlab":       ["gitlab"],
    "kibana":       ["kibana", "elastic"],
    "portainer":    ["docker"],
    "proxmox":      ["proxmox"],
    "sonarqube":    ["sonarqube"],
    "nexus":        ["nexus"],
    "artifactory":  ["artifactory"],
    "minio":        ["minio"],
    "consul":       ["consul"],
    "vault":        ["hashicorp"],
    "argo":         ["argocd"],
    "rancher":      ["rancher", "kubernetes"],
    "traefik":      ["traefik"],
    "swagger":      ["api"],
    "api doc":      ["api"],
}


def mine_http_intel(
    http_assets: List[Dict[str, Any]]
) -> Dict[str, Set[str]]:
    """
    Extract technology hints from HTTP response data that
    HTTPX's -tech-detect might have missed.

    Mines from:
      - web_server field (Server header): gunicorn → python
      - title field (page title): "Login" → default-login
      - status_code: 401 → default-login templates

    Args:
        http_assets: List of asset dicts from run_httpx()

    Returns:
        {hostname: {tag1, tag2, ...}}
    """
    host_tags: Dict[str, Set[str]] = {}

    for asset in http_assets:
        host = asset.get("host", "")
        if not host:
            continue

        tags: Set[str] = set()

        # ── Mine from Server header ──────────────────────
        web_server = str(asset.get("web_server", "")).lower()
        if web_server:
            for signature, sig_tags in SERVER_SIGNATURES.items():
                if signature in web_server:
                    tags.update(sig_tags)

        # ── Mine from page title ─────────────────────────
        title = str(asset.get("title", "")).lower()
        if title:
            for keyword, keyword_tags in TITLE_HINTS.items():
                if keyword in title:
                    tags.update(keyword_tags)

        # ── Mine from status code ────────────────────────
        status = asset.get("status_code", 0)
        if status == 401:
            tags.add("default-login")
        elif status == 403:
            tags.add("waf")

        if tags and host:
            if host not in host_tags:
                host_tags[host] = set()
            host_tags[host].update(tags)

    return host_tags


def get_port_based_tags(
    host: str,
    ports_data: Dict[str, Any]
) -> Set[str]:
    """
    Given a host and the merged ports dict, return relevant
    Nuclei tags based on what service-specific ports are open.

    Only uses PORT_TO_NUCLEI_TAGS (definitive service ports).
    Ambiguous web ports (80, 443, 8080) are deliberately excluded
    and handled by Tier 2C classification instead.

    Args:
        host: Hostname or IP
        ports_data: {host: [port1, port2, ...]} from merged scan results

    Returns:
        Set of Nuclei tag strings
    """
    tags: Set[str] = set()
    host_ports = ports_data.get(host, [])

    for port in host_ports:
        try:
            port_int = int(port)
        except (ValueError, TypeError):
            continue

        if port_int in PORT_TO_NUCLEI_TAGS:
            tags.update(PORT_TO_NUCLEI_TAGS[port_int])

    return tags


def host_has_web_service(
    host: str,
    ports_data: Dict[str, Any],
    http_assets: List[Dict[str, Any]]
) -> bool:
    """
    Determine if a host is running any web service.
    Used to decide between Tier 2C (web) and Tier 2C-NET (non-web).

    Checks:
      1. Does the host have any known web ports open? (WEB_PORTS set)
      2. Did HTTPX get any HTTP response from it?

    Args:
        host: Hostname or IP
        ports_data: {host: [port1, port2, ...]}
        http_assets: List of asset dicts from HTTPX

    Returns:
        True if host has a web service
    """
    # Check ports
    host_ports = ports_data.get(host, [])
    for port in host_ports:
        try:
            if int(port) in WEB_PORTS:
                return True
        except (ValueError, TypeError):
            continue

    # Check if HTTPX got any response from this host
    for asset in http_assets:
        if asset.get("host", "") == host:
            return True

    return False


# =============================================================================
# HOST NORMALIZATION (IP ↔ Hostname)
# =============================================================================

def _normalize_hosts(host_set: set, shodan_result: dict) -> set:
    """
    Expand a set of hosts to include both IPs and hostnames
    using Shodan's existing data (no DNS lookups needed).

    This fixes the problem where Shodan reports CVEs by IP
    but subdomain_list contains hostnames — without this,
    lower tiers would re-scan hosts already covered.
    """
    expanded = set(host_set)

    for host_data in shodan_result.get("hosts", []):
        ip = host_data.get("ip", "")
        hostnames = host_data.get("hostnames", [])

        if ip in expanded:
            for hn in hostnames:
                expanded.add(hn.lower())

        for hn in hostnames:
            if hn.lower() in expanded:
                expanded.add(ip)

    return expanded


# =============================================================================
# BUILD TARGETED SCAN PLAN
# =============================================================================

def build_scan_plan(
    shodan_result: Dict[str, Any],
    censys_result: Dict[str, Any],
    http_result: Dict[str, Any],
    subdomain_list: List[str],
    ports_data: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Analyze ALL recon data and build an intelligent 6-tier scan plan.

    Tier assignment is strictly cascading — each host goes to the
    HIGHEST tier that has intelligence for it. A host is never
    scanned in multiple tiers.

    Cascade order:
      1A (CVE) → 1B (tech) → 2A (service port) → 2B (header) → 2C/2C-NET

    Args:
        shodan_result: Output from Shodan passive recon
        censys_result: Output from Censys passive recon
        http_result:   Output from HTTPX fingerprinting
        subdomain_list: All discovered subdomains
        ports_data:    Merged port data {host: [port1, port2, ...]}

    Returns:
        Structured plan dict with six tiers
    """
    if ports_data is None:
        ports_data = {}

    plan = {
        "tier1_cve_scans": [],       # Tier 1A: Specific CVE verification
        "tier1_tech_tags": {},       # Tier 1B: HTTPX/Censys tech-targeted
        "tier2a_port_tags": {},      # Tier 2A: Service-port-informed targeting
        "tier2b_header_tags": {},    # Tier 2B: Header-mined targeting
        "tier2c_catchall": [],       # Tier 2C: Web hosts, critical+high only
        "tier2c_non_web": [],        # Tier 2C-NET: Non-web, network templates
        "shodan_cves_found": [],
        "stats": {
            "shodan_cves_total": 0,
            "shodan_cves_with_templates": 0,
            "shodan_cves_without_templates": 0,
            "hosts_with_tech_intel": 0,
            "hosts_with_port_intel": 0,
            "hosts_with_header_intel": 0,
            "hosts_needing_broad_scan": 0,
            "non_web_hosts": 0,
        }
    }

    hosts_with_intel: Set[str] = set()

    # ═════════════════════════════════════════════════════
    # Step 1: Map Shodan CVEs to Nuclei templates (Tier 1A)
    # ═════════════════════════════════════════════════════
    shodan_vulns = shodan_result.get("vulnerabilities", [])
    plan["stats"]["shodan_cves_total"] = len(shodan_vulns)

    seen_cve_host: Set[str] = set()

    for vuln in shodan_vulns:
        cve_id = vuln.get("cve_id", "")
        host = vuln.get("host", vuln.get("ip", ""))

        if not cve_id or not host:
            continue

        dedup_key = f"{cve_id}:{host}"
        if dedup_key in seen_cve_host:
            continue
        seen_cve_host.add(dedup_key)

        template_path = find_nuclei_template_for_cve(cve_id)

        plan["shodan_cves_found"].append({
            "cve_id": cve_id,
            "host": host,
            "port": vuln.get("port", 0),
            "cvss": vuln.get("cvss"),
            "has_template": template_path is not None
        })

        if template_path:
            port = vuln.get("port", 80)
            protocol = "https" if port == 443 else "http"
            target_url = f"{protocol}://{host}:{port}"

            plan["tier1_cve_scans"].append({
                "host": host,
                "target_url": target_url,
                "template": template_path,
                "cve_id": cve_id,
                "cvss": vuln.get("cvss"),
                "port": port,
                "reason": f"Shodan reported {cve_id} "
                          f"(CVSS: {vuln.get('cvss', 'N/A')})"
            })
            hosts_with_intel.add(host)
            plan["stats"]["shodan_cves_with_templates"] += 1
        else:
            plan["stats"]["shodan_cves_without_templates"] += 1

    # ═════════════════════════════════════════════════════
    # Step 2: Map HTTPX tech to Nuclei tags (Tier 1B)
    # ═════════════════════════════════════════════════════
    for asset in http_result.get("http_assets", []):
        host = asset.get("host", "")
        tech = asset.get("tech", [])

        if not host or not tech:
            continue

        tags = map_tech_to_tags(tech)

        if tags:
            if host not in plan["tier1_tech_tags"]:
                plan["tier1_tech_tags"][host] = set()
            plan["tier1_tech_tags"][host].update(tags)
            hosts_with_intel.add(host)

    # ═════════════════════════════════════════════════════
    # Step 3: Map Censys software to tags (Tier 1B)
    # ═════════════════════════════════════════════════════
    for service in censys_result.get("services", []):
        host = service.get("hostname", "")
        software_list = service.get("software", [])

        if not host:
            continue

        for sw in software_list:
            if isinstance(sw, str):
                tags = map_tech_to_tags([sw])
                if tags:
                    if host not in plan["tier1_tech_tags"]:
                        plan["tier1_tech_tags"][host] = set()
                    plan["tier1_tech_tags"][host].update(tags)
                    hosts_with_intel.add(host)

    # Convert Tier 1B tag sets to sorted lists for serialization
    for host in plan["tier1_tech_tags"]:
        plan["tier1_tech_tags"][host] = sorted(
            plan["tier1_tech_tags"][host]
        )

    plan["stats"]["hosts_with_tech_intel"] = len(
        plan["tier1_tech_tags"]
    )

    # ═════════════════════════════════════════════════════
    # Step 4: Service-port-based intelligence (Tier 2A)
    # ═════════════════════════════════════════════════════
    # Only hosts NOT already covered by Tier 1A or 1B.
    # Only service-specific ports (NOT 80/443/8080).
    expanded_intel = _normalize_hosts(
        hosts_with_intel, shodan_result
    )

    remaining_hosts = [
        h for h in subdomain_list
        if h not in expanded_intel
    ]

    for host in remaining_hosts:
        port_tags = get_port_based_tags(host, ports_data)
        if port_tags:
            plan["tier2a_port_tags"][host] = sorted(port_tags)
            hosts_with_intel.add(host)

    plan["stats"]["hosts_with_port_intel"] = len(
        plan["tier2a_port_tags"]
    )

    # ═════════════════════════════════════════════════════
    # Step 5: HTTP header/title mining (Tier 2B)
    # ═════════════════════════════════════════════════════
    # Only hosts NOT covered by Tier 1A, 1B, or 2A.
    expanded_intel = _normalize_hosts(
        hosts_with_intel, shodan_result
    )

    http_assets = http_result.get("http_assets", [])
    header_intel = mine_http_intel(http_assets)

    for host, tags in header_intel.items():
        if host in expanded_intel:
            # Already covered by a higher tier — skip
            continue
        if tags:
            plan["tier2b_header_tags"][host] = sorted(tags)
            hosts_with_intel.add(host)

    plan["stats"]["hosts_with_header_intel"] = len(
        plan["tier2b_header_tags"]
    )

    # ═════════════════════════════════════════════════════
    # Step 6: Classify true remainders (Tier 2C / 2C-NET)
    # ═════════════════════════════════════════════════════
    expanded_intel = _normalize_hosts(
        hosts_with_intel, shodan_result
    )

    true_remainders = [
        h for h in subdomain_list
        if h not in expanded_intel
    ]

    for host in true_remainders:
        if host_has_web_service(host, ports_data, http_assets):
            plan["tier2c_catchall"].append(host)
        else:
            plan["tier2c_non_web"].append(host)

    plan["stats"]["hosts_needing_broad_scan"] = len(
        plan["tier2c_catchall"]
    )
    plan["stats"]["non_web_hosts"] = len(
        plan["tier2c_non_web"]
    )

    # ═════════════════════════════════════════════════════
    # Log the plan
    # ═════════════════════════════════════════════════════
    logger.info("=" * 60)
    logger.info("INTELLIGENT SCAN PLAN v2:")
    logger.info(
        "  Tier 1A: %d CVE verifications across %d hosts",
        len(plan["tier1_cve_scans"]),
        len(set(s["host"] for s in plan["tier1_cve_scans"]))
    )
    logger.info(
        "  Tier 1B: %d tech-targeted hosts",
        len(plan["tier1_tech_tags"])
    )
    logger.info(
        "  Tier 2A: %d port-informed hosts",
        len(plan["tier2a_port_tags"])
    )
    logger.info(
        "  Tier 2B: %d header-mined hosts",
        len(plan["tier2b_header_tags"])
    )
    logger.info(
        "  Tier 2C: %d catch-all web hosts (critical+high only)",
        len(plan["tier2c_catchall"])
    )
    logger.info(
        "  Tier 2C-NET: %d non-web hosts (network templates only)",
        len(plan["tier2c_non_web"])
    )
    logger.info(
        "  Shodan CVEs: %d total, %d with templates, %d without",
        plan["stats"]["shodan_cves_total"],
        plan["stats"]["shodan_cves_with_templates"],
        plan["stats"]["shodan_cves_without_templates"]
    )
    logger.info("=" * 60)

    return plan
