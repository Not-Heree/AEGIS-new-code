# database/passive_recon_db.py
"""
Passive Recon Database Layer
=============================
Stores rich intelligence from Shodan & Censys that doesn't
fit into the simple subdomains/ports collections.

Stores:
  - Host details (IP, org, ISP, country, OS)
  - Service banners (product, version, banner text)
  - Shodan CVEs (unverified — for display + Nuclei targeting)
  - SSL certificate data
  - Censys software fingerprints
"""

from datetime import datetime
from bson import ObjectId
from database.connection import get_collection
from config import Config

PASSIVE_COLLECTION = "passive_recon"


def serialize_doc(doc):
    if doc is None:
        return None
    doc["_id"] = str(doc["_id"])
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            doc[key] = str(value)
        elif isinstance(value, datetime):
            doc[key] = value.isoformat()
    return doc


# ─── Save Full Passive Recon Results ─────────────────────────────────────

def save_shodan_results(target_id, target_domain, shodan_result):
    """
    Save complete Shodan recon data.

    Stores hosts, services, CVEs, and banners that would
    otherwise be thrown away after Phase 0.
    """
    try:
        collection = get_collection(PASSIVE_COLLECTION)

        doc = {
            "target_id": ObjectId(target_id),
            "target_domain": target_domain,
            "source": "shodan",
            "collected_at": datetime.utcnow(),

            # Host intelligence
            "hosts": shodan_result.get("hosts", []),

            # Service banners (product, version, banner text)
            "services": shodan_result.get("services", []),

            # Known CVEs mapped to services
            "vulnerabilities": shodan_result.get("vulnerabilities", []),

            # Summary stats
            "stats": shodan_result.get("stats", {}),
        }

        # Upsert: one Shodan record per domain (overwrite on re-scan)
        collection.update_one(
            {
                "target_domain": target_domain,
                "source": "shodan"
            },
            {"$set": doc},
            upsert=True
        )

        print(
            f"[PASSIVE_DB] Saved Shodan data for {target_domain}: "
            f"{len(doc['hosts'])} hosts, "
            f"{len(doc['vulnerabilities'])} CVEs, "
            f"{len(doc['services'])} services"
        )
        return True

    except Exception as e:
        print(f"[PASSIVE_DB] Error saving Shodan data: {e}")
        return False


def save_censys_results(target_id, target_domain, censys_result):
    """
    Save complete Censys recon data.

    Stores hosts, services, software versions, and
    certificate details.
    """
    try:
        collection = get_collection(PASSIVE_COLLECTION)

        doc = {
            "target_id": ObjectId(target_id),
            "target_domain": target_domain,
            "source": "censys",
            "collected_at": datetime.utcnow(),

            # Host intelligence
            "hosts": censys_result.get("hosts", []),

            # Service fingerprints
            "services": censys_result.get("services", []),

            # No CVEs from Censys (it doesn't report vulns)
            "vulnerabilities": [],

            # Summary stats
            "stats": censys_result.get("stats", {}),
        }

        collection.update_one(
            {
                "target_domain": target_domain,
                "source": "censys"
            },
            {"$set": doc},
            upsert=True
        )

        print(
            f"[PASSIVE_DB] Saved Censys data for {target_domain}: "
            f"{len(doc['hosts'])} hosts, "
            f"{len(doc['services'])} services"
        )
        return True

    except Exception as e:
        print(f"[PASSIVE_DB] Error saving Censys data: {e}")
        return False


# ─── Query Functions ─────────────────────────────────────────────────────

def get_passive_recon(target_domain, source=None):
    """
    Get passive recon data for a domain.

    Args:
        target_domain: Domain string
        source: Optional "shodan" or "censys" filter

    Returns:
        List of passive recon documents (one per source)
    """
    try:
        collection = get_collection(PASSIVE_COLLECTION)
        query = {"target_domain": target_domain}
        if source:
            query["source"] = source

        docs = list(collection.find(query))
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_shodan_vulns(target_domain):
    """
    Get Shodan-reported CVEs for a domain.

    Returns list of CVE dicts with:
        cve_id, host, ip, port, cvss, summary, source, verified
    """
    try:
        collection = get_collection(PASSIVE_COLLECTION)
        doc = collection.find_one({
            "target_domain": target_domain,
            "source": "shodan"
        })

        if not doc:
            return []

        return doc.get("vulnerabilities", [])
    except Exception:
        return []


def get_service_banners(target_domain):
    """
    Get all service banners from both Shodan and Censys.

    Merges and deduplicates by host:port.
    Returns rich service data including product, version, banner.
    """
    try:
        collection = get_collection(PASSIVE_COLLECTION)
        docs = list(collection.find({"target_domain": target_domain}))

        services_by_key = {}

        for doc in docs:
            source = doc.get("source", "unknown")
            for svc in doc.get("services", []):
                host = svc.get("hostname", svc.get("host", ""))
                port = svc.get("port", 0)
                key = f"{host}:{port}"

                if key not in services_by_key:
                    services_by_key[key] = {
                        "host": host,
                        "port": port,
                        "sources": [],
                        "product": "",
                        "version": "",
                        "banner": "",
                        "http_title": "",
                        "http_server": "",
                        "ssl_subject": "",
                        "ssl_issuer": "",
                        "ssl_expires": "",
                        "software": [],
                    }

                entry = services_by_key[key]
                if source not in entry["sources"]:
                    entry["sources"].append(source)

                # Merge data (prefer non-empty values)
                if svc.get("product") and not entry["product"]:
                    entry["product"] = svc["product"]
                if svc.get("version") and not entry["version"]:
                    entry["version"] = svc["version"]
                if svc.get("banner") and not entry["banner"]:
                    entry["banner"] = svc["banner"][:500]
                if svc.get("http_title") and not entry["http_title"]:
                    entry["http_title"] = svc["http_title"]
                if svc.get("http_server") and not entry["http_server"]:
                    entry["http_server"] = svc["http_server"]
                if svc.get("ssl_subject") and not entry["ssl_subject"]:
                    entry["ssl_subject"] = svc["ssl_subject"]
                if svc.get("ssl_issuer") and not entry["ssl_issuer"]:
                    entry["ssl_issuer"] = svc["ssl_issuer"]
                if svc.get("ssl_expires") and not entry["ssl_expires"]:
                    entry["ssl_expires"] = svc["ssl_expires"]

                # Censys software list
                for sw in svc.get("software", []):
                    if sw and sw not in entry["software"]:
                        entry["software"].append(sw)

        return sorted(
            services_by_key.values(),
            key=lambda x: (x["host"], x["port"])
        )
    except Exception as e:
        print(f"[PASSIVE_DB] Error getting banners: {e}")
        return []


def get_passive_summary(target_domain):
    """
    Get a summary of all passive recon data for dashboard cards.

    Returns:
        {
            "shodan": {
                "available": True/False,
                "hosts": 5,
                "services": 23,
                "cves": 8,
                "unique_ports": 15,
                "collected_at": "2024-..."
            },
            "censys": { ... },
            "combined": {
                "total_hosts": 7,
                "total_services": 30,
                "total_cves": 8,
                "unique_products": ["Apache", "nginx", ...]
            }
        }
    """
    try:
        collection = get_collection(PASSIVE_COLLECTION)
        docs = list(collection.find({"target_domain": target_domain}))

        result = {
            "shodan": {"available": False},
            "censys": {"available": False},
            "combined": {
                "total_hosts": 0,
                "total_services": 0,
                "total_cves": 0,
                "unique_products": [],
                "unique_cves": [],
            }
        }

        all_products = set()
        all_cves = set()
        all_hosts = set()

        for doc in docs:
            source = doc.get("source", "")
            stats = doc.get("stats", {})
            hosts = doc.get("hosts", [])
            services = doc.get("services", [])
            vulns = doc.get("vulnerabilities", [])

            source_summary = {
                "available": True,
                "hosts": len(hosts),
                "services": len(services),
                "cves": len(vulns),
                "unique_ports": stats.get("unique_ports", 0),
                "collected_at": doc.get("collected_at", ""),
            }

            if source == "shodan":
                source_summary["unique_ips"] = stats.get("unique_ips", 0)
                result["shodan"] = source_summary
            elif source == "censys":
                source_summary["certificates_analyzed"] = stats.get(
                    "certificates_analyzed", 0
                )
                result["censys"] = source_summary

            # Aggregate for combined stats
            for host in hosts:
                ip = host.get("ip", "")
                if ip:
                    all_hosts.add(ip)

            for svc in services:
                product = svc.get("product", "")
                if product:
                    all_products.add(product)
                # Censys software
                for sw in svc.get("software", []):
                    if sw:
                        all_products.add(sw)

            for vuln in vulns:
                cve = vuln.get("cve_id", "")
                if cve:
                    all_cves.add(cve)

        result["combined"]["total_hosts"] = len(all_hosts)
        result["combined"]["total_services"] = sum(
            len(doc.get("services", [])) for doc in docs
        )
        result["combined"]["total_cves"] = len(all_cves)
        result["combined"]["unique_products"] = sorted(all_products)[:20]
        result["combined"]["unique_cves"] = sorted(all_cves)

        return result

    except Exception as e:
        print(f"[PASSIVE_DB] Summary error: {e}")
        return {
            "shodan": {"available": False},
            "censys": {"available": False},
            "combined": {
                "total_hosts": 0,
                "total_services": 0,
                "total_cves": 0,
                "unique_products": [],
                "unique_cves": [],
            }
        }

# ─── WHOIS Data Storage & Queries ────────────────────────────────────────

def save_whois_results(target_id, target_domain, whois_result):
    """
    Save complete WHOIS recon data.

    Stores registration details, nameservers, DNSSEC status,
    and computed risk flags. One record per domain, overwritten
    on re-scan.

    Args:
        target_id: Target document ObjectId string
        target_domain: Domain string
        whois_result: Dict from run_whois_recon()

    Returns:
        True on success, False on error
    """
    try:
        collection = get_collection(PASSIVE_COLLECTION)

        doc = {
            "target_id": ObjectId(target_id),
            "target_domain": target_domain,
            "source": "whois",
            "collected_at": datetime.utcnow(),

            # Registration data
            "registrar": whois_result.get("registrar"),
            "creation_date": whois_result.get("creation_date"),
            "expiration_date": whois_result.get(
                "expiration_date"
            ),
            "updated_date": whois_result.get("updated_date"),
            "nameservers": whois_result.get("nameservers", []),
            "status": whois_result.get("status", []),
            "dnssec": whois_result.get("dnssec", False),

            # Registrant info
            "registrant_org": whois_result.get(
                "registrant_org"
            ),
            "registrant_country": whois_result.get(
                "registrant_country"
            ),
            "registrant_emails": whois_result.get(
                "registrant_emails", []
            ),
            "privacy_enabled": whois_result.get(
                "privacy_enabled", False
            ),

            # Computed fields
            "days_until_expiry": whois_result.get(
                "days_until_expiry"
            ),
            "domain_age_days": whois_result.get(
                "domain_age_days"
            ),
            "risk_flags": whois_result.get("risk_flags", []),

            # Empty arrays to match Shodan/Censys structure
            "hosts": [],
            "services": [],
            "vulnerabilities": [],

            "stats": whois_result.get("stats", {}),
        }

        collection.update_one(
            {
                "target_domain": target_domain,
                "source": "whois"
            },
            {"$set": doc},
            upsert=True
        )

        flag_count = len(doc["risk_flags"])
        print(
            f"[PASSIVE_DB] Saved WHOIS data for "
            f"{target_domain}: "
            f"registrar={doc['registrar']}, "
            f"{len(doc['nameservers'])} nameservers, "
            f"{flag_count} risk flags"
        )
        return True

    except Exception as e:
        print(f"[PASSIVE_DB] Error saving WHOIS data: {e}")
        return False


def get_whois_risk_flags(target_id):
    """
    Get WHOIS risk flags for risk scoring (Phase 6).

    Called by risk_scorer.py to add WHOIS-based risk
    to the overall score.

    Args:
        target_id: Target document ObjectId string

    Returns:
        List of risk flag dicts with severity and detail
    """
    try:
        collection = get_collection(PASSIVE_COLLECTION)
        doc = collection.find_one({
            "target_id": ObjectId(target_id),
            "source": "whois"
        })

        if not doc:
            return []

        return doc.get("risk_flags", [])

    except Exception as e:
        print(f"[PASSIVE_DB] Error getting WHOIS flags: {e}")
        return []


def get_whois_data(target_domain):
    """
    Get previous WHOIS snapshot for change detection.

    Called by scanner.py before Phase 0 to capture the
    previous state for comparison after the new lookup.

    Args:
        target_domain: Domain string

    Returns:
        Dict with WHOIS fields, or empty dict if none
    """
    try:
        collection = get_collection(PASSIVE_COLLECTION)
        doc = collection.find_one({
            "target_domain": target_domain,
            "source": "whois"
        })

        if not doc:
            return {}

        return {
            "registrar": doc.get("registrar"),
            "nameservers": doc.get("nameservers", []),
            "dnssec": doc.get("dnssec", False),
            "expiration_date": doc.get("expiration_date"),
            "status": doc.get("status", []),
            "registrant_org": doc.get("registrant_org"),
        }

    except Exception as e:
        print(
            f"[PASSIVE_DB] Error getting WHOIS data: {e}"
        )
        return {}

def delete_passive_recon_by_domain(target_domain):
    """Delete all passive recon data for a domain."""
    try:
        collection = get_collection(PASSIVE_COLLECTION)
        result = collection.delete_many({"target_domain": target_domain})
        return result.deleted_count
    except Exception:
        return 0
