# routes/passive_recon.py
"""
Passive Recon API Routes
========================
Serves Shodan, Censys, WHOIS & Certificate intelligence.
"""

from flask import Blueprint, jsonify
from database.passive_recon_db import (
    get_passive_recon,
    get_passive_summary,
    get_shodan_vulns,
    get_service_banners
)
from utils.sanitize import sanitize_domain

passive_bp = Blueprint(
    "passive_recon", __name__,
    url_prefix="/api/passive"
)


@passive_bp.route("/", methods=["GET"])
def passive_overview():
    """
    GET /api/passive/
    Returns passive recon summary across ALL targets.
    Merges Shodan, Censys, WHOIS AND Certificate data.
    """
    try:
        from database.connection import get_db
        from datetime import datetime as dt

        db = get_db()

        # ══════════════════════════════════════════
        # STEP 1: Process passive_recon collection
        # ══════════════════════════════════════════
        docs = list(db["passive_recon"].find())
        by_domain = {}

        for doc in docs:
            domain = doc.get("target_domain", "unknown")
            source = doc.get("source", "unknown")
            hosts = doc.get("hosts", [])
            services = doc.get("services", [])
            vulns = doc.get("vulnerabilities", [])
            stats = doc.get("stats", {})

            # ── Initialize domain entry ──
            if domain not in by_domain:
                by_domain[domain] = {
                    "domain": domain,
                    "shodan":       {"available": False},
                    "censys":       {"available": False},
                    "whois":        {"available": False},
                    "certificates": {"available": False},
                    "total_hosts": 0,
                    "total_services": 0,
                    "total_cves": 0,
                    "total_certs": 0,
                    "products": set(),
                    "cve_list": [],
                }

            entry = by_domain[domain]

            # ── Common source stats ──
            source_data = {
                "available": True,
                "hosts": len(hosts),
                "services": len(services),
                "cves": len(vulns),
                "unique_ports": stats.get("unique_ports", 0),
                "collected_at": doc.get("collected_at", ""),
            }

            # ── Route by source ──
            if source == "shodan":
                entry["shodan"] = source_data

            elif source == "censys":
                entry["censys"] = source_data

            elif source == "whois":
                # Normalize dates (python-whois returns
                # single datetime OR list of datetimes)
                creation = doc.get("creation_date")
                expiration = doc.get("expiration_date")

                for field_name, val in [
                    ("creation", creation),
                    ("expiration", expiration)
                ]:
                    if isinstance(val, dt):
                        if field_name == "creation":
                            creation = val.isoformat()
                        else:
                            expiration = val.isoformat()
                    elif isinstance(val, list) and val:
                        first = val[0]
                        iso = (first.isoformat()
                               if isinstance(first, dt)
                               else str(first))
                        if field_name == "creation":
                            creation = iso
                        else:
                            expiration = iso

                entry["whois"] = {
                    **source_data,
                    "registrar": doc.get(
                        "registrar", "Unknown"
                    ),
                    "creation_date": creation,
                    "expiration_date": expiration,
                    "days_until_expiry": doc.get(
                        "days_until_expiry"
                    ),
                    "risk_flags": doc.get(
                        "risk_flags", []
                    ),
                    "name_servers": doc.get(
                        "name_servers", []
                    ),
                }

            # ── Accumulate totals ──
            entry["total_hosts"] += len(hosts)
            entry["total_services"] += len(services)
            entry["total_cves"] += len(vulns)

            for svc in services:
                product = svc.get("product", "")
                if product:
                    entry["products"].add(product)
                for sw in svc.get("software", []):
                    if sw:
                        entry["products"].add(sw)

            for v in vulns:
                entry["cve_list"].append(v)

        # ══════════════════════════════════════════
        # STEP 2: Merge certificate data per domain
        # ══════════════════════════════════════════
        try:
            cert_pipeline = [
                {"$group": {
                    "_id": "$target_domain",
                    "total": {"$sum": 1},
                    "not_after_dates": {"$push": "$not_after"}
                }}
            ]
            cert_agg = list(
                db["certificates"].aggregate(cert_pipeline)
            )

            now = dt.utcnow()

            for group in cert_agg:
                cert_domain = group["_id"]
                cert_total = group["total"]
                dates = group.get("not_after_dates", [])

                expired = 0
                expiring = 0
                for d_val in dates:
                    if not d_val:
                        continue
                    try:
                        na_str = str(d_val).replace(
                            "+00:00", ""
                        ).replace("Z", "")
                        for fmt in [
                            "%Y-%m-%dT%H:%M:%S",
                            "%Y-%m-%dT%H:%M:%S.%f",
                            "%Y-%m-%d %H:%M:%S",
                        ]:
                            try:
                                exp_dt = dt.strptime(
                                    na_str, fmt
                                )
                                break
                            except ValueError:
                                continue
                        else:
                            continue

                        days_left = (exp_dt - now).days
                        if days_left < 0:
                            expired += 1
                        elif days_left <= 30:
                            expiring += 1
                    except Exception:
                        continue

                # Create domain entry if not exists
                if cert_domain not in by_domain:
                    by_domain[cert_domain] = {
                        "domain": cert_domain,
                        "shodan":       {"available": False},
                        "censys":       {"available": False},
                        "whois":        {"available": False},
                        "certificates": {"available": False},
                        "total_hosts": 0,
                        "total_services": 0,
                        "total_cves": 0,
                        "total_certs": 0,
                        "products": set(),
                        "cve_list": [],
                    }

                by_domain[cert_domain]["certificates"] = {
                    "available": True,
                    "total": cert_total,
                    "expired": expired,
                    "expiring_soon": expiring,
                }
                by_domain[cert_domain]["total_certs"] = (
                    cert_total
                )
        except Exception as cert_err:
            print(
                f"[passive_overview] Cert aggregation "
                f"error: {cert_err}"
            )

        # ══════════════════════════════════════════
        # STEP 3: Build response
        # ══════════════════════════════════════════
        domains_list = []
        global_whois_domains = 0
        global_whois_risks = 0

        for domain, data in by_domain.items():
            data["products"] = sorted(data["products"])[:10]
            data["cve_count_by_severity"] = {
                "critical": 0, "high": 0,
                "medium": 0, "low": 0
            }
            for v in data.get("cve_list", []):
                cvss = v.get("cvss")
                if cvss is not None:
                    try:
                        score = float(cvss)
                        if score >= 9.0:
                            data["cve_count_by_severity"][
                                "critical"
                            ] += 1
                        elif score >= 7.0:
                            data["cve_count_by_severity"][
                                "high"
                            ] += 1
                        elif score >= 4.0:
                            data["cve_count_by_severity"][
                                "medium"
                            ] += 1
                        else:
                            data["cve_count_by_severity"][
                                "low"
                            ] += 1
                    except (ValueError, TypeError):
                        pass

            # WHOIS global stats
            if data.get("whois", {}).get("available"):
                global_whois_domains += 1
                global_whois_risks += len(
                    data["whois"].get("risk_flags", [])
                )

            del data["cve_list"]
            domains_list.append(data)

        # Serialize datetimes
        for d in domains_list:
            for src in ["shodan", "censys", "whois"]:
                collected = d.get(src, {}).get(
                    "collected_at"
                )
                if isinstance(collected, dt):
                    d[src]["collected_at"] = (
                        collected.isoformat()
                    )

        # Global totals
        total_hosts = sum(
            d["total_hosts"] for d in domains_list
        )
        total_services = sum(
            d["total_services"] for d in domains_list
        )
        total_cves = sum(
            d["total_cves"] for d in domains_list
        )
        total_certs = sum(
            d["total_certs"] for d in domains_list
        )

        return jsonify({
            "success": True,
            "total_targets": len(domains_list),
            "total_hosts": total_hosts,
            "total_services": total_services,
            "total_cves": total_cves,
            "total_certificates": total_certs,
            "total_whois_domains": global_whois_domains,
            "total_whois_risks": global_whois_risks,
            "domains": domains_list
        })

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False, "error": str(e)
        }), 500


@passive_bp.route("/summary/<domain>", methods=["GET"])
def passive_summary(domain):
    try:
        domain = sanitize_domain(domain)
    except ValueError as e:
        return jsonify({
            "success": False, "error": str(e)
        }), 400
    summary = get_passive_summary(domain)
    return jsonify({"success": True, "domain": domain, **summary})


@passive_bp.route("/vulns/<domain>", methods=["GET"])
def passive_vulns(domain):
    try:
        domain = sanitize_domain(domain)
    except ValueError as e:
        return jsonify({
            "success": False, "error": str(e)
        }), 400

    vulns = get_shodan_vulns(domain)
    by_severity = {
        "critical": [], "high": [], "medium": [],
        "low": [], "unknown": []
    }
    for v in vulns:
        cvss = v.get("cvss")
        if cvss is not None:
            try:
                score = float(cvss)
                if score >= 9.0:     sev = "critical"
                elif score >= 7.0:   sev = "high"
                elif score >= 4.0:   sev = "medium"
                else:                sev = "low"
            except (ValueError, TypeError):
                sev = "unknown"
        else:
            sev = "unknown"
        v["derived_severity"] = sev
        by_severity[sev].append(v)

    return jsonify({
        "success": True,
        "domain": domain,
        "total_cves": len(vulns),
        "note": (
            "These CVEs are reported by Shodan based on "
            "service fingerprinting. They have NOT been "
            "actively verified."
        ),
        "by_severity": by_severity,
        "vulnerabilities": vulns
    })


@passive_bp.route("/services/<domain>", methods=["GET"])
def passive_services(domain):
    try:
        domain = sanitize_domain(domain)
    except ValueError as e:
        return jsonify({
            "success": False, "error": str(e)
        }), 400
    services = get_service_banners(domain)
    return jsonify({
        "success": True,
        "domain": domain,
        "total_services": len(services),
        "services": services
    })


@passive_bp.route("/hosts/<domain>", methods=["GET"])
def passive_hosts(domain):
    try:
        domain = sanitize_domain(domain)
    except ValueError as e:
        return jsonify({
            "success": False, "error": str(e)
        }), 400

    recon_data = get_passive_recon(domain)
    all_hosts = {}

    for doc in recon_data:
        source = doc.get("source", "unknown")
        for host in doc.get("hosts", []):
            ip = host.get("ip", "")
            if not ip:
                continue
            if ip not in all_hosts:
                all_hosts[ip] = {
                    "ip": ip, "hostnames": [],
                    "ports": [], "org": "", "isp": "",
                    "country": "", "city": "",
                    "os": "", "vulns": [], "sources": [],
                }
            entry = all_hosts[ip]
            if source not in entry["sources"]:
                entry["sources"].append(source)
            for h in host.get("hostnames", []):
                if h and h not in entry["hostnames"]:
                    entry["hostnames"].append(h)
            for p in host.get("ports", []):
                if p not in entry["ports"]:
                    entry["ports"].append(p)
            entry["ports"].sort()
            if host.get("org") and not entry["org"]:
                entry["org"] = host["org"]
            if host.get("isp") and not entry["isp"]:
                entry["isp"] = host["isp"]
            if host.get("country") and not entry["country"]:
                entry["country"] = host.get(
                    "country",
                    host.get("location", {}).get(
                        "country", ""
                    )
                )
            if host.get("city") and not entry["city"]:
                entry["city"] = host.get(
                    "city",
                    host.get("location", {}).get("city", "")
                )
            if host.get("os") and not entry["os"]:
                entry["os"] = host["os"]
            for v in host.get("vulns", []):
                if v not in entry["vulns"]:
                    entry["vulns"].append(v)

    hosts_list = sorted(
        all_hosts.values(),
        key=lambda x: len(x["vulns"]),
        reverse=True
    )
    return jsonify({
        "success": True,
        "domain": domain,
        "total_hosts": len(hosts_list),
        "hosts": hosts_list
    })


@passive_bp.route("/source/<source>", methods=["GET"])
def passive_by_source(source):
    valid_sources = ["shodan", "censys", "whois"]
    source = source.lower().strip()
    if source not in valid_sources:
        return jsonify({
            "success": False,
            "error": (
                f"Invalid source. "
                f"Use: {', '.join(valid_sources)}"
            )
        }), 400

    try:
        from database.connection import get_db
        from datetime import datetime as dt

        db = get_db()
        docs = list(
            db["passive_recon"].find({"source": source})
        )

        results = []
        total_hosts = 0
        total_services = 0
        total_vulns = 0

        for doc in docs:
            domain = doc.get("target_domain", "unknown")
            hosts = doc.get("hosts", [])
            services = doc.get("services", [])
            vulns = doc.get("vulnerabilities", [])
            collected = doc.get("collected_at", "")

            if isinstance(collected, dt):
                collected = collected.isoformat()

            entry = {
                "domain": domain,
                "collected_at": collected,
                "hosts_count": len(hosts),
                "services_count": len(services),
                "vulns_count": len(vulns),
            }

            clean_hosts = []
            for h in hosts:
                clean_hosts.append({
                    "ip": h.get("ip", ""),
                    "hostnames": h.get("hostnames", []),
                    "ports": sorted(h.get("ports", [])),
                    "org": h.get("org", ""),
                    "country": h.get(
                        "country",
                        h.get("location", {}).get(
                            "country", ""
                        )
                    ),
                    "city": h.get(
                        "city",
                        h.get("location", {}).get(
                            "city", ""
                        )
                    ),
                    "os": h.get("os", ""),
                    "vulns": h.get("vulns", [])
                })
            entry["hosts"] = clean_hosts

            clean_services = []
            for s in services:
                clean_services.append({
                    "host": s.get("host", ""),
                    "port": s.get("port", ""),
                    "product": s.get("product", ""),
                    "version": s.get("version", ""),
                    "transport": s.get("transport", "tcp")
                })
            entry["services"] = clean_services

            clean_vulns = []
            for v in vulns:
                clean_vulns.append({
                    "cve_id": v.get("cve_id", ""),
                    "cvss": v.get("cvss"),
                    "host": v.get(
                        "host", v.get("ip", "")
                    ),
                    "port": v.get("port", "")
                })
            entry["vulnerabilities"] = clean_vulns

            if source == "whois":
                for field in [
                    "creation_date", "expiration_date"
                ]:
                    val = doc.get(field)
                    if isinstance(val, dt):
                        entry[field] = val.isoformat()
                    elif isinstance(val, list) and val:
                        entry[field] = (
                            val[0].isoformat()
                            if isinstance(val[0], dt)
                            else str(val[0])
                        )
                    else:
                        entry[field] = val
                entry["registrar"] = doc.get(
                    "registrar", "Unknown"
                )
                entry["days_until_expiry"] = doc.get(
                    "days_until_expiry"
                )
                entry["risk_flags"] = doc.get(
                    "risk_flags", []
                )
                entry["name_servers"] = doc.get(
                    "name_servers", []
                )

            total_hosts += len(hosts)
            total_services += len(services)
            total_vulns += len(vulns)
            results.append(entry)

        return jsonify({
            "success": True,
            "source": source,
            "total_domains": len(results),
            "total_hosts": total_hosts,
            "total_services": total_services,
            "total_vulnerabilities": total_vulns,
            "results": results
        })

    except Exception as e:
        return jsonify({
            "success": False, "error": str(e)
        }), 500


@passive_bp.route("/certificates", methods=["GET"])
@passive_bp.route("/certificates/<domain>", methods=["GET"])
def passive_certificates(domain=None):
    """
    GET /api/passive/certificates
    GET /api/passive/certificates/<domain>
    """
    try:
        from database.connection import get_db
        from datetime import datetime as dt

        db = get_db()
        query = {}
        if domain:
            domain = sanitize_domain(domain)
            query["target_domain"] = domain

        certs = list(
            db["certificates"]
            .find(query)
            .sort("not_before", -1)
            .limit(200)
        )

        now = dt.utcnow()
        active = 0
        expired = 0
        expiring_soon = 0
        wildcard = 0
        issuers = {}
        cert_list = []

        for c in certs:
            not_after_raw = c.get("not_after")
            not_before_raw = c.get("not_before")
            status = "unknown"
            days_left = None

            if not_after_raw:
                try:
                    na_str = str(not_after_raw).replace(
                        "+00:00", ""
                    ).replace("Z", "")
                    exp_dt = None
                    for fmt in [
                        "%Y-%m-%dT%H:%M:%S",
                        "%Y-%m-%dT%H:%M:%S.%f",
                        "%Y-%m-%d %H:%M:%S",
                    ]:
                        try:
                            exp_dt = dt.strptime(na_str, fmt)
                            break
                        except ValueError:
                            continue

                    if exp_dt:
                        days_left = (exp_dt - now).days
                        if days_left < 0:
                            status = "expired"
                            expired += 1
                        elif days_left <= 30:
                            status = "expiring"
                            expiring_soon += 1
                        else:
                            status = "active"
                            active += 1
                    else:
                        status = "active"
                        active += 1
                except Exception:
                    status = "active"
                    active += 1
            else:
                status = "unknown"

            is_wc = c.get("is_wildcard", False)
            if is_wc:
                wildcard += 1

            org = c.get("issuer_org", "Unknown") or "Unknown"
            issuers[org] = issuers.get(org, 0) + 1

            cert_list.append({
                "domain": c.get("target_domain", ""),
                "common_name": c.get("common_name", ""),
                "san_domains": (
                    c.get("san_domains") or []
                )[:5],
                "san_count": len(
                    c.get("san_domains") or []
                ),
                "issuer_org": org,
                "issuer_name": c.get("issuer_name", ""),
                "not_before": (
                    str(not_before_raw)
                    if not_before_raw else None
                ),
                "not_after": (
                    str(not_after_raw)
                    if not_after_raw else None
                ),
                "days_left": days_left,
                "status": status,
                "is_wildcard": is_wc,
                "serial_number": c.get(
                    "serial_number", ""
                ),
                "crtsh_id": c.get("crtsh_id"),
            })

        risk_flags = []
        if expired > 0:
            risk_flags.append({
                "severity": "high",
                "detail": (
                    f"{expired} expired certificate(s) "
                    f"found in CT logs"
                )
            })
        if expiring_soon > 0:
            risk_flags.append({
                "severity": "medium",
                "detail": (
                    f"{expiring_soon} certificate(s) "
                    f"expiring within 30 days"
                )
            })
        if wildcard > 0:
            risk_flags.append({
                "severity": "low",
                "detail": (
                    f"{wildcard} wildcard certificate(s) "
                    f"detected"
                )
            })

        sorted_issuers = dict(sorted(
            issuers.items(),
            key=lambda x: x[1],
            reverse=True
        ))

        return jsonify({
            "success": True,
            "domain": domain,
            "total_certificates": len(cert_list),
            "summary": {
                "active": active,
                "expired": expired,
                "expiring_soon": expiring_soon,
                "wildcard": wildcard,
                "by_issuer": sorted_issuers
            },
            "risk_flags": risk_flags,
            "certificates": cert_list
        })

    except ValueError as e:
        return jsonify({
            "success": False, "error": str(e)
        }), 400
    except Exception as e:
        return jsonify({
            "success": False, "error": str(e)
        }), 500