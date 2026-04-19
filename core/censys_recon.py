"""
Censys Passive Reconnaissance Module
=====================================
Uses Censys Search API v2 with PAT (Personal Access Token).

Authentication:
  - Primary:  CENSYS_PAT  (Personal Access Token - single token)
  - Fallback: CENSYS_API_ID + CENSYS_API_SECRET (old method)

Get your PAT from: https://search.censys.io/account
  → Click "API" tab
  → Copy your Personal Access Token

API Docs: https://search.censys.io/api
Free tier: 250 queries/month
"""

import requests
import base64
from datetime import datetime
from config import Config
from utils.logger import logger


# ── Censys API v2 Base URL ────────────────────────────────────────────────
CENSYS_API_BASE = "https://search.censys.io/api/v2"


def is_available():
    """
    Check if Censys credentials are configured.
    Used by the scanner to decide whether to run this phase.
    """
    return bool(Config.CENSYS_PAT) or (bool(Config.CENSYS_API_ID) and bool(Config.CENSYS_API_SECRET))


# =============================================================================
# AUTHENTICATION HELPER
# =============================================================================

def _get_auth_headers():
    """
    Build authentication headers for Censys API.

    Priority:
      1. PAT token (Bearer auth) — recommended
      2. API ID + Secret (Basic auth) — legacy fallback

    Returns:
        dict: Headers with Authorization, or None if no credentials
    """
    # ── Option 1: PAT Token (Recommended) ────────────────
    pat = Config.CENSYS_PAT

    if pat:
        logger.debug("[CENSYS] Using PAT authentication")
        return {
            "Authorization": f"Bearer {pat}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "AEGIS-EASM/1.0"
        }

    # ── Option 2: API ID + Secret Fallback ───────────────
    api_id = Config.CENSYS_API_ID
    api_secret = Config.CENSYS_API_SECRET

    if api_id and api_secret:
        logger.debug("[CENSYS] Using API ID + Secret authentication")
        # Censys Basic Auth = base64(api_id:api_secret)
        credentials = base64.b64encode(
            f"{api_id}:{api_secret}".encode()
        ).decode()
        return {
            "Authorization": f"Basic {credentials}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "AEGIS-EASM/1.0"
        }

    # ── No credentials ────────────────────────────────────
    logger.warning("[CENSYS] No credentials found")
    logger.warning(
        "[CENSYS] Set CENSYS_PAT in .env"
        " (get from https://search.censys.io/account)"
    )
    return None


# =============================================================================
# HOST SEARCH
# =============================================================================

def _search_hosts(domain, headers):
    """
    Search Censys for hosts associated with a domain.

    Uses Censys v2 /hosts/search endpoint.
    Query finds all IPs that have the domain in their
    certificate Subject Alternative Names (SANs).

    Args:
        domain: Target domain (e.g., "company.com")
        headers: Auth headers from _get_auth_headers()

    Returns:
        list of host dicts from Censys
    """
    try:
        query = f"parsed.names: {domain}"

        resp = requests.get(
            f"{CENSYS_API_BASE}/hosts/search",
            headers=headers,
            params={
                "q": query,
                "per_page": 50,        # max per page
                "virtual_hosts": "INCLUDE"
            },
            timeout=20
        )

        # ── Handle auth errors ────────────────────────────
        if resp.status_code == 401:
            logger.error(
                "[CENSYS] Authentication failed — "
                "check your CENSYS_PAT token"
            )
            return []

        if resp.status_code == 403:
            logger.error(
                "[CENSYS] Access forbidden — "
                "token may lack search permissions"
            )
            return []

        if resp.status_code == 429:
            logger.warning(
                "[CENSYS] Rate limited — "
                "free tier: 250 queries/month"
            )
            return []

        if resp.status_code == 422:
            logger.warning(
                "[CENSYS] Invalid query: %s", query
            )
            return []

        if resp.status_code != 200:
            logger.warning(
                "[CENSYS] Host search HTTP %d: %s",
                resp.status_code,
                resp.text[:200]
            )
            return []

        data = resp.json()
        hits = data.get("result", {}).get("hits", [])
        total = data.get("result", {}).get("total", 0)

        logger.info(
            "[CENSYS] Host search found %d results (total: %d)",
            len(hits), total
        )
        return hits

    except requests.Timeout:
        logger.warning("[CENSYS] Host search timed out")
        return []

    except Exception as e:
        logger.error("[CENSYS] Host search error: %s", e)
        return []


# =============================================================================
# HOST DETAILS
# =============================================================================

def _get_host_details(ip, headers):
    """
    Get detailed info for a specific IP from Censys.

    Args:
        ip: IP address string
        headers: Auth headers

    Returns:
        dict with host details, or {}
    """
    try:
        resp = requests.get(
            f"{CENSYS_API_BASE}/hosts/{ip}",
            headers=headers,
            timeout=15
        )

        if resp.status_code == 404:
            return {}

        if resp.status_code != 200:
            return {}

        return resp.json().get("result", {})

    except Exception as e:
        logger.debug("[CENSYS] Host detail error for %s: %s", ip, e)
        return {}


# =============================================================================
# CERTIFICATE SEARCH
# =============================================================================

def _search_certificates(domain, headers):
    """
    Search Censys certificate transparency logs for a domain.

    Finds subdomains exposed in SSL certificates.
    This is free intel — no active scanning.

    Args:
        domain: Target domain
        headers: Auth headers

    Returns:
        set of discovered subdomains
    """
    subdomains = set()

    try:
        resp = requests.get(
            f"{CENSYS_API_BASE}/certificates/search",
            headers=headers,
            params={
                "q": f"parsed.names: {domain}",
                "per_page": 100,
                "fields": "parsed.names"
            },
            timeout=20
        )

        if resp.status_code != 200:
            logger.debug(
                "[CENSYS] Cert search HTTP %d",
                resp.status_code
            )
            return subdomains

        data = resp.json()
        hits = data.get("result", {}).get("hits", [])

        for hit in hits:
            names = hit.get("parsed", {}).get("names", [])
            for name in names:
                name = name.lower().strip()
                # Filter wildcards and root-only entries
                if (
                    name.endswith(f".{domain}")
                    and "*" not in name
                    and name != domain
                ):
                    subdomains.add(name)

        logger.info(
            "[CENSYS] Cert search found %d subdomains",
            len(subdomains)
        )

    except requests.Timeout:
        logger.warning("[CENSYS] Cert search timed out")

    except Exception as e:
        logger.error("[CENSYS] Cert search error: %s", e)

    return subdomains


# =============================================================================
# PARSE HOST DATA
# =============================================================================

def _parse_host(hit):
    """
    Extract useful fields from a Censys host search result.

    Args:
        hit: Single host dict from Censys search results

    Returns:
        dict with normalized host data
    """
    ip = hit.get("ip", "")
    services = hit.get("services", [])

    # Extract open ports and service info
    open_ports = []
    service_list = []
    for svc in services:
        port = svc.get("port")
        transport = svc.get("transport_protocol", "TCP")
        service_name = svc.get("service_name", "unknown")
        banner = svc.get("banner", "")

        if port:
            open_ports.append(port)
            service_list.append({
                "port": port,
                "protocol": transport,
                "service": service_name,
                "banner": banner[:200] if banner else ""
            })

    # Extract labels/tags Censys assigned
    labels = hit.get("labels", [])

    # Extract autonomous system info
    as_info = hit.get("autonomous_system", {})

    # Extract location
    location = hit.get("location", {})

    # Extract names from matched services (subdomains/hostnames)
    matched_services = hit.get("matched_services", [])
    hostnames = []
    for ms in matched_services:
        tls = ms.get("tls", {})
        cert = tls.get("certificates", {})
        leaf = cert.get("leaf_data", {})
        names = leaf.get("names", [])
        hostnames.extend(names)

    return {
        "ip": ip,
        "open_ports": sorted(open_ports),
        "services": service_list,
        "labels": labels,
        "asn": as_info.get("asn", ""),
        "as_name": as_info.get("name", ""),
        "country": location.get("country", ""),
        "country_code": location.get("country_code", ""),
        "city": location.get("city", ""),
        "hostnames": list(set(hostnames)),
        "last_updated": hit.get("last_updated_at", "")
    }


# =============================================================================
# MAIN RECON FUNCTION
# =============================================================================

def run_passive_recon(domain):
    """
    Run full Censys passive reconnaissance on a domain.

    Collects:
      - IPs hosting domain-related services
      - Open ports and service banners
      - Subdomains from certificate transparency
      - ASN and geolocation data
      - CVEs Censys has detected on hosts

    Args:
        domain: Target domain (e.g., "company.com")

    Returns:
        dict with all collected intelligence
    """
    logger.info("[CENSYS] Starting passive recon for: %s", domain)

    # ── Check credentials first ───────────────────────────
    headers = _get_auth_headers()

    if not headers:
        return {
            "success": False,
            "error": (
                "No Censys credentials. "
                "Set CENSYS_PAT in .env file. "
                "Get token from: https://search.censys.io/account"
            ),
            "domain": domain,
            "hosts": [],
            "ips": [],
            "open_ports": [],
            "subdomains": [],
            "tech": [],
            "cves": []
        }

    # ── Phase 1: Host Search ──────────────────────────────
    logger.info("[CENSYS] Phase 1: Searching hosts...")
    hits = _search_hosts(domain, headers)

    # ── Phase 2: Parse Host Data ──────────────────────────
    hosts = []
    all_ips = []
    all_ports = set()
    all_technologies = set()
    all_cves = []
    all_hostnames = set()

    for hit in hits:
        parsed = _parse_host(hit)
        hosts.append(parsed)
        all_ips.append(parsed["ip"])
        all_ports.update(parsed["open_ports"])

        # Collect labels as "technologies"
        for label in parsed.get("labels", []):
            all_technologies.add(label)

        # Collect hostnames for subdomain intel
        for hostname in parsed.get("hostnames", []):
            if (
                hostname.endswith(f".{domain}")
                and hostname != domain
            ):
                all_hostnames.add(hostname)

    # ── Phase 3: Certificate Search ───────────────────────
    logger.info("[CENSYS] Phase 3: Searching certificates...")
    cert_subdomains = _search_certificates(domain, headers)
    all_hostnames.update(cert_subdomains)

    # ── Phase 4: Get CVEs for top hosts ───────────────────
    logger.info("[CENSYS] Phase 4: Fetching CVE data...")
    cve_limit = 5  # only check top 5 IPs (save API quota)

    for ip in all_ips[:cve_limit]:
        try:
            details = _get_host_details(ip, headers)
            services = details.get("services", [])

            for svc in services:
                vulns = svc.get("vulnerabilities", [])
                for vuln in vulns:
                    cve_id = vuln.get("cve_id", "")
                    if cve_id:
                        all_cves.append({
                            "ip": ip,
                            "cve_id": cve_id,
                            "severity": vuln.get(
                                "severity", "unknown"
                            ),
                            "cvss": vuln.get("cvss", 0),
                            "description": vuln.get(
                                "description", ""
                            )[:300]
                        })
        except Exception as e:
            logger.debug(
                "[CENSYS] CVE fetch error for %s: %s", ip, e
            )
            continue

    # ── Build Final Result ────────────────────────────────
    result = {
        "success": True,
        "domain": domain,

        # Host intelligence
        "hosts": hosts,
        "host_count": len(hosts),

        # IP list (flat, for other modules)
        "ips": all_ips,
        "ip_count": len(all_ips),

        # Port intelligence
        "open_ports": sorted(list(all_ports)),
        "port_count": len(all_ports),

        # Subdomain intelligence (from certs + host data)
        "subdomains": sorted(list(all_hostnames)),
        "subdomain_count": len(all_hostnames),

        # Technology/label intelligence
        "tech": sorted(list(all_technologies)),

        # CVE intelligence
        "cves": all_cves,
        "cve_count": len(all_cves),

        # Metadata
        "recon_at": datetime.utcnow().isoformat(),
        "auth_method": "PAT" if Config.CENSYS_PAT else "API_KEY"
    }

    # ── Summary Log ───────────────────────────────────────
    logger.info("[CENSYS] Recon complete for %s:", domain)
    logger.info("  Hosts:      %d", result["host_count"])
    logger.info("  IPs:        %d", result["ip_count"])
    logger.info("  Ports:      %d", result["port_count"])
    logger.info("  Subdomains: %d", result["subdomain_count"])
    logger.info("  CVEs:       %d", result["cve_count"])

    return result


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("  CENSYS RECON - Standalone Test")
    logger.info("=" * 60)

    # Quick credential check
    pat = Config.CENSYS_PAT
    api_id = Config.CENSYS_API_ID

    if pat:
        logger.info(f"[AUTH] Using PAT: {pat[:8]}...")
    elif api_id:
        logger.info(f"[AUTH] Using API ID: {api_id[:8]}...")
    else:
        logger.warning("[AUTH] No credentials found!")
        logger.warning("  Set CENSYS_PAT in your .env file")
        logger.warning("  Get token: https://search.censys.io/account")
        exit(1)

    domain = input("\nEnter domain to test: ").strip()
    if not domain:
        domain = "example.com"

    result = run_passive_recon(domain)

    logger.info("\n" + "=" * 60)
    logger.info(f"Results for {domain}:")
    logger.info(f"  Success:    {result['success']}")
    logger.info(f"  Hosts:      {result.get('host_count', 0)}")
    logger.info(f"  IPs:        {result.get('ip_count', 0)}")
    logger.info(f"  Ports:      {result.get('port_count', 0)}")
    logger.info(f"  Subdomains: {result.get('subdomain_count', 0)}")
    logger.info(f"  CVEs:       {result.get('cve_count', 0)}")
    logger.info(f"  Auth:       {result.get('auth_method', 'unknown')}")

    if result.get("ips"):
        logger.info("\n  IPs found:")
        for ip in result["ips"][:5]:
            logger.info(f"    - {ip}")

    if result.get("subdomains"):
        logger.info("\n  Subdomains found:")
        for sub in result["subdomains"][:5]:
            logger.info(f"    - {sub}")

    if result.get("cves"):
        logger.info("\n  CVEs found:")
        for cve in result["cves"][:5]:
            logger.info(f"    - {cve['ip']} → {cve['cve_id']} ({cve['severity']})")