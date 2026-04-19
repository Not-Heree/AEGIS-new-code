"""
Shodan Passive Reconnaissance Module
=====================================
Queries Shodan's database for intelligence about a target domain.
Zero traffic sent to the target — completely passive.

Provides:
  - Subdomain discovery (DNS records Shodan has seen)
  - Port & service data (from Shodan's internet-wide scans)
  - Banner information (service fingerprints)
  - Known vulnerabilities (CVEs mapped to services)
  - SSL certificate data

Designed to run as Phase 0 — before any active scanning.
Each function is independent — failure in one doesn't affect others.

Free tier: Limited queries. Get API key at https://account.shodan.io
"""

import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Set

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False
    logger.warning("[SHODAN] shodan library not installed. Run: pip install shodan")

from config import Config
from utils.logger import logger


# =============================================================================
# INITIALIZATION
# =============================================================================

_api = None


def _get_api():
    """Get or create Shodan API client. Validates key on first use."""
    global _api

    if not SHODAN_AVAILABLE:
        return None

    api_key = Config.SHODAN_API_KEY
    if not api_key:
        return None

    if _api is None:
        try:
            _api = shodan.Shodan(api_key)
            info = _api.info()
            print(
                f"[SHODAN] API connected — "
                f"Plan: {info.get('plan', 'unknown')}, "
                f"Credits: {info.get('query_credits', 0)} queries, "
                f"{info.get('scan_credits', 0)} scans"
            )
        except shodan.APIError as e:
            logger.error("[SHODAN] API key error: %s", e)
            _api = None
            return None
        except Exception as e:
            logger.error("[SHODAN] Connection error: %s", e)
            _api = None
            return None

    return _api


def is_available() -> bool:
    """Check if Shodan API is configured and accessible."""
    return _get_api() is not None


# =============================================================================
# SUBDOMAIN DISCOVERY
# =============================================================================

def discover_subdomains(domain: str) -> Dict[str, Any]:
    """
    Discover subdomains using Shodan's DNS data.

    Uses Shodan's domain info endpoint which returns
    all subdomains Shodan has seen in DNS records.

    Args:
        domain: Root domain (e.g., "example.com")

    Returns:
        Dict with subdomains list and count
    """
    api = _get_api()
    if not api:
        return {
            "success": False,
            "error": "Shodan API not available",
            "subdomains": [],
            "source": "shodan"
        }

    from utils.throttler import throttler
    throttler.wait_if_needed("shodan", Config.API_THROTTLE_SECONDS)

    logger.info("[SHODAN] Discovering subdomains for {domain}...")

    try:
        result = api.dns.domain_info(domain)

        subdomains = set()

        # Extract from domain info data
        for entry in result.get("data", []):
            subdomain = entry.get("subdomain", "")
            if subdomain:
                full = f"{subdomain}.{domain}".lower()
                subdomains.add(full)
            else:
                subdomains.add(domain.lower())

        # Extract from subdomains field if present
        for sub in result.get("subdomains", []):
            if sub:
                full = f"{sub}.{domain}".lower()
                subdomains.add(full)

        subdomains = sorted(subdomains)
        print(
            f"[SHODAN] Found {len(subdomains)} subdomains "
            f"via DNS data"
        )

        return {
            "success": True,
            "subdomains": subdomains,
            "count": len(subdomains),
            "source": "shodan"
        }

    except shodan.APIError as e:
        error_msg = str(e)
        if "access denied" in error_msg.lower():
            logger.warning("[SHODAN] DNS lookup requires paid plan (needs paid Shodan plan)")
        else:
            logger.error("[SHODAN] API error: %s", e)
        return {
            "success": False,
            "error": error_msg,
            "subdomains": [],
            "source": "shodan"
        }

    except Exception as e:
        logger.error("[SHODAN] Subdomain discovery error: %s", e, exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "subdomains": [],
            "source": "shodan"
        }


# =============================================================================
# HOST SEARCH BY DOMAIN
# =============================================================================

def search_domain(domain: str) -> Dict[str, Any]:
    """
    Search Shodan for all hosts associated with a domain.

    Uses the search query: hostname:domain
    Returns IPs, ports, services, banners, and CVEs.

    Args:
        domain: Target domain

    Returns:
        Dict with hosts, ports, services, and vulnerabilities
    """
    api = _get_api()
    if not api:
        return {
            "success": False,
            "error": "Shodan API not available",
            "hosts": [],
            "source": "shodan"
        }

    logger.info("[SHODAN] Searching for hosts matching {domain}...")

    try:
        query = f"hostname:{domain}"
        results = api.search(query)

        hosts = {}
        all_ports = {}
        all_vulns = []
        all_banners = []
        total_results = results.get("total", 0)

        logger.info("[SHODAN] Found %d results", total_results)

        for match in results.get("matches", []):
            ip = match.get("ip_str", "")
            port = match.get("port", 0)
            hostnames = match.get("hostnames", [])
            hostname = hostnames[0] if hostnames else ip

            # ── Build host record ─────────────────────
            if ip not in hosts:
                hosts[ip] = {
                    "ip": ip,
                    "hostnames": hostnames,
                    "hostname": hostname,
                    "os": match.get("os", ""),
                    "org": match.get("org", ""),
                    "isp": match.get("isp", ""),
                    "country": match.get(
                        "location", {}
                    ).get("country_name", ""),
                    "city": match.get(
                        "location", {}
                    ).get("city", ""),
                    "ports": [],
                    "vulns": [],
                    "last_update": match.get("timestamp", "")
                }

            # ── Port and service data ─────────────────
            service_info = {
                "port": port,
                "transport": match.get("transport", "tcp"),
                "product": match.get("product", ""),
                "version": match.get("version", ""),
                "banner": match.get("data", "")[:500],
                "module": match.get(
                    "_shodan", {}
                ).get("module", ""),
                "hostname": hostname
            }

            # Extract HTTP data if available
            http_data = match.get("http", {})
            if http_data:
                service_info["http_title"] = http_data.get(
                    "title", ""
                )
                service_info["http_server"] = http_data.get(
                    "server", ""
                )
                service_info["http_status"] = http_data.get(
                    "status", 0
                )

            # Extract SSL data if available
            ssl_data = match.get("ssl", {})
            if ssl_data:
                cert = ssl_data.get("cert", {})
                service_info["ssl_issuer"] = cert.get(
                    "issuer", {}
                ).get("O", "")
                service_info["ssl_subject"] = cert.get(
                    "subject", {}
                ).get("CN", "")
                service_info["ssl_expires"] = cert.get(
                    "expires", ""
                )

            if port not in hosts[ip]["ports"]:
                hosts[ip]["ports"].append(port)

            port_key = f"{hostname}:{port}"
            all_ports[port_key] = service_info
            all_banners.append(service_info)

            # ── Vulnerability data ────────────────────
            vulns = match.get("vulns", {})
            if vulns:
                for cve_id, vuln_info in vulns.items():
                    vuln_entry = {
                        "cve_id": cve_id,
                        "host": hostname,
                        "ip": ip,
                        "port": port,
                        "cvss": (
                            vuln_info.get("cvss", None)
                            if isinstance(vuln_info, dict)
                            else None
                        ),
                        "summary": (
                            vuln_info.get("summary", "")
                            if isinstance(vuln_info, dict)
                            else ""
                        ),
                        "source": "shodan",
                        "verified": (
                            vuln_info.get("verified", False)
                            if isinstance(vuln_info, dict)
                            else False
                        )
                    }
                    all_vulns.append(vuln_entry)
                    if cve_id not in hosts[ip]["vulns"]:
                        hosts[ip]["vulns"].append(cve_id)

        # ── Build port summary ────────────────────────
        ports_by_host = {}
        for port_key, service in all_ports.items():
            host = service.get("hostname", "")
            p = service.get("port", 0)
            if host not in ports_by_host:
                ports_by_host[host] = []
            if p not in ports_by_host[host]:
                ports_by_host[host].append(p)

        for host in ports_by_host:
            ports_by_host[host].sort()

        # ── Summary stats ─────────────────────────────
        unique_ips = len(hosts)
        unique_ports = len(set(
            s["port"] for s in all_banners
        ))
        unique_vulns = len(set(
            v["cve_id"] for v in all_vulns
        ))

        print(
            f"[SHODAN] Summary: {unique_ips} IPs, "
            f"{unique_ports} unique ports, "
            f"{unique_vulns} CVEs"
        )

        return {
            "success": True,
            "domain": domain,
            "total_results": total_results,
            "hosts": list(hosts.values()),
            "ports_by_host": ports_by_host,
            "services": all_banners,
            "vulnerabilities": all_vulns,
            "stats": {
                "unique_ips": unique_ips,
                "unique_ports": unique_ports,
                "unique_vulns": unique_vulns,
                "total_services": len(all_banners)
            },
            "source": "shodan"
        }

    except shodan.APIError as e:
        logger.error("[SHODAN] Search error: %s", e, exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "hosts": [],
            "source": "shodan"
        }

    except Exception as e:
        logger.error("[SHODAN] Search error: %s", e, exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "hosts": [],
            "source": "shodan"
        }


# =============================================================================
# UNIFIED PASSIVE RECON
# =============================================================================

def run_passive_recon(domain: str) -> Dict[str, Any]:
    """
    Run complete passive reconnaissance on a domain using Shodan.

    This is the main function called by scanner.py Phase 0.
    Combines subdomain discovery + host search into one result.

    Args:
        domain: Target domain (e.g., "example.com")

    Returns:
        Dict with all passive recon data
    """
    print(f"\n{'='*60}")
    print(f"[SHODAN] Starting passive recon for: {domain}")
    print(f"{'='*60}")

    if not is_available():
        logger.warning("[SHODAN] Not available — skipping passive recon")
        logger.warning("[SHODAN] Set SHODAN_API_KEY in .env to enable")
        return {
            "success": False,
            "error": "Shodan API not configured",
            "subdomains": [],
            "ports_by_host": {},
            "hosts": [],
            "vulnerabilities": [],
            "services": [],
            "stats": {
                "unique_ips": 0,
                "unique_ports": 0,
                "unique_vulns": 0,
                "total_services": 0,
                "subdomains_found": 0
            },
            "source": "shodan"
        }

    all_subdomains = set()

    # ── Step 1: Subdomain Discovery ───────────────────
    sub_result = discover_subdomains(domain)
    if sub_result.get("success"):
        all_subdomains.update(sub_result.get("subdomains", []))

    # Small delay to respect rate limits
    time.sleep(1)

    # ── Step 2: Host Search ───────────────────────────
    search_result = search_domain(domain)

    # Extract additional subdomains from search results
    if search_result.get("success"):
        for host in search_result.get("hosts", []):
            for hostname in host.get("hostnames", []):
                if hostname.endswith(domain):
                    all_subdomains.add(hostname.lower())

        # Extract from SSL certificates
        for service in search_result.get("services", []):
            ssl_subject = service.get("ssl_subject", "")
            if ssl_subject and ssl_subject.endswith(domain):
                all_subdomains.add(ssl_subject.lower())

    final_subdomains = sorted(all_subdomains)

    # ── Build combined result ─────────────────────────
    stats = search_result.get("stats", {})
    stats["subdomains_found"] = len(final_subdomains)

    print(f"\n[SHODAN] Passive recon complete:")
    logger.info("[SHODAN]   Subdomains: %d", len(final_subdomains))
    logger.info("[SHODAN]   IPs: %d", stats.get('unique_ips', 0))
    logger.info("[SHODAN]   Ports: %d", stats.get('unique_ports', 0))
    logger.info("[SHODAN]   CVEs: %d", stats.get('unique_vulns', 0))
    print(
        f"[SHODAN]   Services: "
        f"{stats.get('total_services', 0)}"
    )

    return {
        "success": True,
        "domain": domain,
        "subdomains": final_subdomains,
        "ports_by_host": search_result.get("ports_by_host", {}),
        "hosts": search_result.get("hosts", []),
        "vulnerabilities": search_result.get(
            "vulnerabilities", []
        ),
        "services": search_result.get("services", []),
        "stats": stats,
        "source": "shodan",
        "recon_at": datetime.utcnow().isoformat()
    }


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  SHODAN RECON — Standalone Test")
    print("=" * 60)

    if not is_available():
        print("\n Shodan API not configured")
        print("Set SHODAN_API_KEY in your .env file")
        print("Get a free key at: https://account.shodan.io")
    else:
        domain = input(
            "\nEnter domain (e.g., example.com): "
        ).strip()
        if domain:
            result = run_passive_recon(domain)

            print(f"\n{'='*60}")
            print(f"Domain: {result['domain']}")
            print(f"Success: {result['success']}")

            if result["success"]:
                print(
                    f"\nSubdomains "
                    f"({len(result['subdomains'])}):"
                )
                for sub in result["subdomains"][:10]:
                    print(f"  • {sub}")

                print(f"\nHosts ({len(result['hosts'])}):")
                for host in result["hosts"][:5]:
                    print(
                        f"  • {host['ip']} "
                        f"({host['hostname']}) — "
                        f"Ports: {host['ports']}"
                    )

                print(
                    f"\nVulnerabilities "
                    f"({len(result['vulnerabilities'])}):"
                )
                for vuln in result["vulnerabilities"][:5]:
                    print(
                        f"  • {vuln['cve_id']} on "
                        f"{vuln['host']}:{vuln['port']}"
                    )