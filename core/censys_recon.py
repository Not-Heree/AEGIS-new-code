"""
Censys Passive Reconnaissance Module
=====================================
Queries Censys database for intelligence about a target domain.
Zero traffic sent to the target — completely passive.

Provides:
  - Subdomain discovery via SSL certificate analysis
  - Host and service enumeration
  - Port and protocol data
  - TLS/SSL certificate details
  - Software and version detection

Censys excels at:
  - Finding subdomains hidden in SSL certificates
  - High-quality service fingerprinting
  - Discovering assets not in DNS records

Free tier: 250 queries/month.
Get credentials at: https://search.censys.io/account/api
"""

import time
from datetime import datetime
from typing import Dict, Any, List, Optional, Set

# Safe imports — handle SDK version differences
try:
    from censys.search import CensysHosts
    CENSYS_HOSTS_AVAILABLE = True
except ImportError:
    CENSYS_HOSTS_AVAILABLE = False

try:
    from censys.search import CensysCerts
    CENSYS_CERTS_AVAILABLE = True
except ImportError:
    CENSYS_CERTS_AVAILABLE = False

try:
    from censys.common.exceptions import (
        CensysUnauthorizedException,
        CensysRateLimitExceededException,
        CensysException
    )
except ImportError:
    # Fallback exception classes if SDK not installed
    CensysUnauthorizedException = Exception
    CensysRateLimitExceededException = Exception
    CensysException = Exception

CENSYS_AVAILABLE = CENSYS_HOSTS_AVAILABLE or CENSYS_CERTS_AVAILABLE

if not CENSYS_AVAILABLE:
    print(
        "[CENSYS] WARNING: censys library not installed. "
        "Run: pip install censys"
    )

from config import Config


# =============================================================================
# INITIALIZATION
# =============================================================================

_hosts_api = None
_certs_api = None


def _get_hosts_api():
    """Get or create Censys Hosts API client."""
    global _hosts_api

    if not CENSYS_HOSTS_AVAILABLE:
        return None

    api_id = Config.CENSYS_API_ID
    api_secret = Config.CENSYS_API_SECRET

    if not api_id or not api_secret:
        return None

    if _hosts_api is None:
        try:
            _hosts_api = CensysHosts(
                api_id=api_id,
                api_secret=api_secret
            )
            print("[CENSYS] Hosts API connected")
        except CensysUnauthorizedException:
            print("[CENSYS] Invalid API credentials")
            _hosts_api = None
            return None
        except Exception as e:
            print(f"[CENSYS] Hosts API connection error: {e}")
            _hosts_api = None
            return None

    return _hosts_api


def _get_certs_api():
    """Get or create Censys Certificates API client."""
    global _certs_api

    if not CENSYS_CERTS_AVAILABLE:
        return None

    api_id = Config.CENSYS_API_ID
    api_secret = Config.CENSYS_API_SECRET

    if not api_id or not api_secret:
        return None

    if _certs_api is None:
        try:
            _certs_api = CensysCerts(
                api_id=api_id,
                api_secret=api_secret
            )
            print("[CENSYS] Certs API connected")
        except CensysUnauthorizedException:
            print("[CENSYS] Invalid API credentials")
            _certs_api = None
            return None
        except Exception as e:
            print(f"[CENSYS] Certs API connection error: {e}")
            _certs_api = None
            return None

    return _certs_api


def is_available() -> bool:
    """Check if Censys API is configured and accessible."""
    return _get_hosts_api() is not None


# =============================================================================
# SUBDOMAIN DISCOVERY VIA CERTIFICATES
# =============================================================================

def discover_subdomains_via_certs(
    domain: str, max_results: int = 100
) -> Dict[str, Any]:
    """
    Discover subdomains by searching SSL/TLS certificates.

    Censys indexes every certificate it finds during internet-wide scans.
    By searching for certificates that mention our domain, we find
    subdomains that might not be in DNS records.

    This is one of the most powerful subdomain discovery techniques
    because:
    - Certificates are public (Certificate Transparency logs)
    - They often include internal/staging subdomains
    - Wildcard certs reveal domain patterns

    Args:
        domain: Root domain (e.g., "example.com")
        max_results: Maximum certificates to analyze

    Returns:
        Dict with discovered subdomains
    """
    if not CENSYS_CERTS_AVAILABLE:
        print(
            "[CENSYS] CensysCerts not available in "
            "installed SDK version"
        )
        return {
            "success": False,
            "error": (
                "CensysCerts not available — "
                "SDK version may not support certificate search"
            ),
            "subdomains": [],
            "certificates_analyzed": 0,
            "source": "censys_certs"
        }

    certs_api = _get_certs_api()
    if not certs_api:
        return {
            "success": False,
            "error": "Censys Certs API not available",
            "subdomains": [],
            "certificates_analyzed": 0,
            "source": "censys_certs"
        }

    print(f"[CENSYS] Searching certificates for {domain}...")

    try:
        subdomains = set()
        cert_count = 0

        query = f"names: {domain}"

        for cert in certs_api.search(
            query,
            per_page=50,
            pages=max(1, max_results // 50)
        ):
            cert_count += 1

            names = cert.get("names", [])
            for name in names:
                name = name.lower().strip()

                # Skip wildcards but note the base domain
                if name.startswith("*."):
                    base = name[2:]
                    if base.endswith(domain):
                        subdomains.add(base)
                    continue

                # Must belong to target domain
                if name.endswith(domain):
                    subdomains.add(name)

            if cert_count >= max_results:
                break

        final_subs = sorted(subdomains)
        print(
            f"[CENSYS] Analyzed {cert_count} certificates, "
            f"found {len(final_subs)} subdomains"
        )

        return {
            "success": True,
            "subdomains": final_subs,
            "count": len(final_subs),
            "certificates_analyzed": cert_count,
            "source": "censys_certs"
        }

    except CensysRateLimitExceededException:
        print("[CENSYS] Rate limit exceeded — try again later")
        return {
            "success": False,
            "error": "Rate limit exceeded",
            "subdomains": [],
            "certificates_analyzed": 0,
            "source": "censys_certs"
        }

    except CensysUnauthorizedException:
        print("[CENSYS] Authentication failed")
        return {
            "success": False,
            "error": "Authentication failed",
            "subdomains": [],
            "certificates_analyzed": 0,
            "source": "censys_certs"
        }

    except CensysException as e:
        print(f"[CENSYS] Cert search error: {e}")
        return {
            "success": False,
            "error": str(e),
            "subdomains": [],
            "certificates_analyzed": 0,
            "source": "censys_certs"
        }

    except Exception as e:
        print(f"[CENSYS] Cert search error: {e}")
        return {
            "success": False,
            "error": str(e),
            "subdomains": [],
            "certificates_analyzed": 0,
            "source": "censys_certs"
        }


# =============================================================================
# HOST SEARCH
# =============================================================================

def search_hosts(
    domain: str, max_results: int = 100
) -> Dict[str, Any]:
    """
    Search Censys for hosts associated with a domain.

    Returns detailed host information including:
    - IP addresses and hostnames
    - Open ports and protocols
    - Service fingerprints (software, versions)
    - TLS certificate details
    - Operating system detection

    Args:
        domain: Target domain
        max_results: Maximum hosts to return

    Returns:
        Dict with hosts, ports, services
    """
    hosts_api = _get_hosts_api()
    if not hosts_api:
        return {
            "success": False,
            "error": "Censys Hosts API not available",
            "hosts": [],
            "ports_by_host": {},
            "services": [],
            "stats": {},
            "source": "censys_hosts"
        }

    print(f"[CENSYS] Searching hosts for {domain}...")

    try:
        hosts = {}
        ports_by_host = {}
        all_services = []
        host_count = 0

        query = (
            f"services.tls.certificates.leaf.names: {domain}"
        )

        for host_data in hosts_api.search(
            query,
            per_page=50,
            pages=max(1, max_results // 50)
        ):
            host_count += 1
            ip = host_data.get("ip", "")

            if not ip:
                continue

            # ── Extract basic host info ───────────────
            host_info = {
                "ip": ip,
                "hostnames": [],
                "os": "",
                "ports": [],
                "services": [],
                "location": {},
                "autonomous_system": {},
                "last_updated": host_data.get(
                    "last_updated_at", ""
                ),
                "source": "censys"
            }

            # ── Extract services (ports) ──────────────
            services = host_data.get("services", [])
            for svc in services:
                port = svc.get("port", 0)
                transport = svc.get(
                    "transport_protocol", "TCP"
                ).lower()
                service_name = svc.get("service_name", "")
                extended_service = svc.get(
                    "extended_service_name", ""
                )

                service_info = {
                    "port": port,
                    "transport": transport,
                    "service_name": service_name,
                    "extended_service": extended_service,
                    "software": [],
                    "hostname": "",
                    "certificate": {}
                }

                # Extract software info
                sw = svc.get("software", [])
                if sw:
                    for s in sw:
                        product = s.get("product", "")
                        version = s.get("version", "")
                        if product:
                            sw_str = product
                            if version:
                                sw_str += f" {version}"
                            service_info["software"].append(
                                sw_str
                            )

                # Extract TLS/certificate info
                tls = svc.get("tls", {})
                if tls:
                    cert = tls.get("certificates", {})
                    leaf = cert.get("leaf", {})

                    if leaf:
                        names = leaf.get("names", [])
                        issuer = leaf.get("issuer", {})
                        subject = leaf.get("subject", {})
                        validity = leaf.get("validity", {})

                        # Handle issuer org
                        issuer_org_raw = issuer.get(
                            "organization", ""
                        )
                        if isinstance(issuer_org_raw, list):
                            issuer_org = (
                                issuer_org_raw[0]
                                if issuer_org_raw else ""
                            )
                        else:
                            issuer_org = issuer_org_raw

                        # Handle subject CN
                        subject_cn_raw = subject.get(
                            "common_name", ""
                        )
                        if isinstance(subject_cn_raw, list):
                            subject_cn = (
                                subject_cn_raw[0]
                                if subject_cn_raw else ""
                            )
                        else:
                            subject_cn = subject_cn_raw

                        service_info["certificate"] = {
                            "names": names,
                            "issuer_org": issuer_org,
                            "subject_cn": subject_cn,
                            "not_after": validity.get(
                                "end", ""
                            ),
                            "not_before": validity.get(
                                "start", ""
                            )
                        }

                        # Extract hostnames from cert
                        for name in names:
                            name = name.lower().strip()
                            if (not name.startswith("*.") and
                                    name.endswith(domain)):
                                if name not in host_info[
                                    "hostnames"
                                ]:
                                    host_info[
                                        "hostnames"
                                    ].append(name)
                                service_info[
                                    "hostname"
                                ] = name

                # Extract HTTP info
                http = svc.get("http", {})
                if http:
                    response = http.get("response", {})
                    service_info["http_status"] = response.get(
                        "status_code", 0
                    )
                    service_info["http_title"] = response.get(
                        "html_title", ""
                    )
                    headers = response.get("headers", {})
                    if headers:
                        server = headers.get("server", [])
                        if isinstance(server, list) and server:
                            service_info[
                                "http_server"
                            ] = server[0]
                        elif isinstance(server, str):
                            service_info[
                                "http_server"
                            ] = server

                if port not in host_info["ports"]:
                    host_info["ports"].append(port)

                host_info["services"].append(service_info)
                all_services.append(service_info)

            # Sort ports
            host_info["ports"].sort()

            # Extract location
            location = host_data.get("location", {})
            if location:
                host_info["location"] = {
                    "country": location.get("country", ""),
                    "city": location.get("city", ""),
                    "province": location.get("province", "")
                }

            # Extract AS info
            as_info = host_data.get(
                "autonomous_system", {}
            )
            if as_info:
                host_info["autonomous_system"] = {
                    "asn": as_info.get("asn", 0),
                    "name": as_info.get("name", ""),
                    "bgp_prefix": as_info.get(
                        "bgp_prefix", ""
                    )
                }

            # Extract OS
            os_info = host_data.get("operating_system", {})
            if os_info:
                product = os_info.get("product", "")
                version = os_info.get("version", "")
                host_info["os"] = (
                    f"{product} {version}".strip()
                )

            hosts[ip] = host_info

            # Build ports_by_host mapping
            for hostname in host_info["hostnames"]:
                if hostname not in ports_by_host:
                    ports_by_host[hostname] = []
                for port in host_info["ports"]:
                    if port not in ports_by_host[hostname]:
                        ports_by_host[hostname].append(port)

            # Also map IP to ports
            if ip not in ports_by_host:
                ports_by_host[ip] = []
            for port in host_info["ports"]:
                if port not in ports_by_host[ip]:
                    ports_by_host[ip].append(port)

            if host_count >= max_results:
                break

        # Sort all port lists
        for host in ports_by_host:
            ports_by_host[host].sort()

        # Stats
        unique_ips = len(hosts)
        unique_ports = len(set(
            s["port"] for s in all_services
        ))
        unique_hostnames = set()
        for h in hosts.values():
            unique_hostnames.update(h.get("hostnames", []))

        print(
            f"[CENSYS] Found {unique_ips} hosts, "
            f"{unique_ports} unique ports, "
            f"{len(unique_hostnames)} hostnames"
        )

        return {
            "success": True,
            "domain": domain,
            "hosts": list(hosts.values()),
            "ports_by_host": ports_by_host,
            "services": all_services,
            "stats": {
                "unique_ips": unique_ips,
                "unique_ports": unique_ports,
                "unique_hostnames": len(unique_hostnames),
                "total_services": len(all_services),
                "hosts_analyzed": host_count
            },
            "source": "censys_hosts"
        }

    except CensysRateLimitExceededException:
        print("[CENSYS] Rate limit exceeded")
        return {
            "success": False,
            "error": (
                "Rate limit exceeded — try again later"
            ),
            "hosts": [],
            "ports_by_host": {},
            "services": [],
            "stats": {},
            "source": "censys_hosts"
        }

    except CensysUnauthorizedException:
        print("[CENSYS] Authentication failed")
        return {
            "success": False,
            "error": (
                "Authentication failed — "
                "check API credentials"
            ),
            "hosts": [],
            "ports_by_host": {},
            "services": [],
            "stats": {},
            "source": "censys_hosts"
        }

    except CensysException as e:
        print(f"[CENSYS] Host search error: {e}")
        return {
            "success": False,
            "error": str(e),
            "hosts": [],
            "ports_by_host": {},
            "services": [],
            "stats": {},
            "source": "censys_hosts"
        }

    except Exception as e:
        print(f"[CENSYS] Host search error: {e}")
        return {
            "success": False,
            "error": str(e),
            "hosts": [],
            "ports_by_host": {},
            "services": [],
            "stats": {},
            "source": "censys_hosts"
        }


# =============================================================================
# SINGLE HOST LOOKUP
# =============================================================================

def lookup_host(ip: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed information about a specific IP from Censys.

    Args:
        ip: IP address to look up

    Returns:
        Dict with host details or None on failure
    """
    hosts_api = _get_hosts_api()
    if not hosts_api:
        return None

    try:
        host = hosts_api.view(ip)

        ports = []
        services = []
        hostnames = set()

        for svc in host.get("services", []):
            port = svc.get("port", 0)
            if port not in ports:
                ports.append(port)

            service_name = svc.get("service_name", "")
            software = svc.get("software", [])
            sw_str = ""
            if software:
                product = software[0].get("product", "")
                version = software[0].get("version", "")
                sw_str = f"{product} {version}".strip()

            services.append({
                "port": port,
                "service": service_name,
                "software": sw_str,
                "transport": svc.get(
                    "transport_protocol", "TCP"
                ).lower()
            })

            # Extract hostnames from TLS
            tls = svc.get("tls", {})
            if tls:
                cert = tls.get(
                    "certificates", {}
                ).get("leaf", {})
                for name in cert.get("names", []):
                    if not name.startswith("*."):
                        hostnames.add(name.lower())

        location = host.get("location", {})
        as_info = host.get("autonomous_system", {})

        return {
            "ip": ip,
            "hostnames": sorted(hostnames),
            "ports": sorted(ports),
            "services": services,
            "os": host.get(
                "operating_system", {}
            ).get("product", ""),
            "country": location.get("country", ""),
            "city": location.get("city", ""),
            "asn": as_info.get("asn", 0),
            "as_name": as_info.get("name", ""),
            "last_updated": host.get("last_updated_at", ""),
            "source": "censys"
        }

    except CensysException as e:
        print(f"[CENSYS] Host lookup error for {ip}: {e}")
        return None

    except Exception as e:
        print(f"[CENSYS] Host lookup error for {ip}: {e}")
        return None


# =============================================================================
# UNIFIED PASSIVE RECON
# =============================================================================

def run_passive_recon(domain: str) -> Dict[str, Any]:
    """
    Run complete passive reconnaissance using Censys.

    Combines certificate-based subdomain discovery with
    host search for ports and services.

    This is called by scanner.py Phase 0 alongside Shodan.

    Args:
        domain: Target domain (e.g., "example.com")

    Returns:
        Dict with all passive recon data
    """
    print(f"\n{'='*60}")
    print(f"[CENSYS] Starting passive recon for: {domain}")
    print(f"{'='*60}")

    if not is_available():
        print("[CENSYS] Not available — skipping")
        print(
            "[CENSYS] Set CENSYS_API_ID and "
            "CENSYS_API_SECRET in .env"
        )
        return {
            "success": False,
            "error": "Censys API not configured",
            "subdomains": [],
            "ports_by_host": {},
            "hosts": [],
            "services": [],
            "stats": {
                "subdomains_from_certs": 0,
                "subdomains_from_hosts": 0,
                "total_subdomains": 0,
                "unique_ips": 0,
                "unique_ports": 0,
                "total_services": 0,
                "certificates_analyzed": 0,
                "hosts_analyzed": 0
            },
            "source": "censys"
        }

    all_subdomains = set()

    # ── Step 1: Certificate-based subdomain discovery ─
    cert_result = discover_subdomains_via_certs(domain)
    cert_subs = set()
    if cert_result.get("success"):
        cert_subs = set(cert_result.get("subdomains", []))
        all_subdomains.update(cert_subs)

    # Small delay between API calls
    time.sleep(1)

    # ── Step 2: Host search ───────────────────────────
    host_result = search_hosts(domain)
    host_subs = set()
    if host_result.get("success"):
        # Extract hostnames from host data
        for host in host_result.get("hosts", []):
            for hostname in host.get("hostnames", []):
                if hostname.endswith(domain):
                    host_subs.add(hostname.lower())
                    all_subdomains.add(hostname.lower())

        # Extract from service certificates
        for service in host_result.get("services", []):
            cert = service.get("certificate", {})
            for name in cert.get("names", []):
                name = name.lower().strip()
                if (not name.startswith("*.") and
                        name.endswith(domain)):
                    all_subdomains.add(name)

    final_subdomains = sorted(all_subdomains)

    # ── Build combined stats ──────────────────────────
    host_stats = host_result.get("stats", {})
    stats = {
        "subdomains_from_certs": len(cert_subs),
        "subdomains_from_hosts": len(host_subs),
        "total_subdomains": len(final_subdomains),
        "unique_ips": host_stats.get("unique_ips", 0),
        "unique_ports": host_stats.get("unique_ports", 0),
        "total_services": host_stats.get(
            "total_services", 0
        ),
        "certificates_analyzed": cert_result.get(
            "certificates_analyzed", 0
        ),
        "hosts_analyzed": host_stats.get(
            "hosts_analyzed", 0
        )
    }

    print(f"\n[CENSYS] Passive recon complete:")
    print(
        f"[CENSYS]   Subdomains: {len(final_subdomains)} "
        f"({len(cert_subs)} from certs, "
        f"{len(host_subs)} from hosts)"
    )
    print(f"[CENSYS]   IPs: {stats['unique_ips']}")
    print(f"[CENSYS]   Ports: {stats['unique_ports']}")
    print(
        f"[CENSYS]   Services: {stats['total_services']}"
    )

    return {
        "success": True,
        "domain": domain,
        "subdomains": final_subdomains,
        "ports_by_host": host_result.get(
            "ports_by_host", {}
        ),
        "hosts": host_result.get("hosts", []),
        "services": host_result.get("services", []),
        "stats": stats,
        "source": "censys",
        "recon_at": datetime.utcnow().isoformat()
    }


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  CENSYS RECON — Standalone Test")
    print("=" * 60)

    if not is_available():
        print("\n❌ Censys API not configured")
        print(
            "Set CENSYS_API_ID and CENSYS_API_SECRET "
            "in .env"
        )
        print(
            "Get credentials at: "
            "https://search.censys.io/account/api"
        )
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
                for sub in result["subdomains"][:15]:
                    print(f"  • {sub}")
                if len(result["subdomains"]) > 15:
                    remaining = (
                        len(result["subdomains"]) - 15
                    )
                    print(f"  ... and {remaining} more")

                print(f"\nHosts ({len(result['hosts'])}):")
                for host in result["hosts"][:5]:
                    print(
                        f"  • {host['ip']} — "
                        f"Ports: {host['ports']} — "
                        f"Hostnames: "
                        f"{host.get('hostnames', [])}"
                    )

                print(f"\nStats:")
                for key, val in result["stats"].items():
                    print(f"  {key}: {val}")