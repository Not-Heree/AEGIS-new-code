# routes/passive_recon.py
"""
Passive Recon API Routes
========================
Serves Shodan & Censys intelligence data to the dashboard.
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
    """
    try:
        from database.connection import get_db
        
        db = get_db()
        docs = list(db["passive_recon"].find())
        
        by_domain = {}
        
        for doc in docs:
            domain = doc.get("target_domain", "unknown")
            source = doc.get("source", "unknown")
            stats = doc.get("stats", {})
            hosts = doc.get("hosts", [])
            services = doc.get("services", [])
            vulns = doc.get("vulnerabilities", [])
            
            if domain not in by_domain:
                by_domain[domain] = {
                    "domain": domain,
                    "shodan": {"available": False},
                    "censys": {"available": False},
                    "total_hosts": 0,
                    "total_services": 0,
                    "total_cves": 0,
                    "products": set(),
                    "cve_list": [],
                }
            
            entry = by_domain[domain]
            
            source_data = {
                "available": True,
                "hosts": len(hosts),
                "services": len(services),
                "cves": len(vulns),
                "unique_ports": stats.get("unique_ports", 0),
                "collected_at": doc.get("collected_at", ""),
            }
            
            if source == "shodan":
                entry["shodan"] = source_data
            elif source == "censys":
                entry["censys"] = source_data
            
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
        
        # Convert sets to lists for JSON
        domains_list = []
        for domain, data in by_domain.items():
            data["products"] = sorted(data["products"])[:10]
            data["cve_count_by_severity"] = {
                "critical": 0, "high": 0, "medium": 0, "low": 0
            }
            for v in data.get("cve_list", []):
                cvss = v.get("cvss")
                if cvss is not None:
                    try:
                        score = float(cvss)
                        if score >= 9.0:
                            data["cve_count_by_severity"]["critical"] += 1
                        elif score >= 7.0:
                            data["cve_count_by_severity"]["high"] += 1
                        elif score >= 4.0:
                            data["cve_count_by_severity"]["medium"] += 1
                        else:
                            data["cve_count_by_severity"]["low"] += 1
                    except (ValueError, TypeError):
                        pass
            del data["cve_list"]  # Don't send full list in overview
            domains_list.append(data)
        
        # Serialize collected_at datetimes
        from datetime import datetime as dt
        for d in domains_list:
            for src in ["shodan", "censys"]:
                if isinstance(d.get(src, {}).get("collected_at"), dt):
                    d[src]["collected_at"] = d[src]["collected_at"].isoformat()
        
        # Global totals
        total_hosts = sum(d["total_hosts"] for d in domains_list)
        total_services = sum(d["total_services"] for d in domains_list)
        total_cves = sum(d["total_cves"] for d in domains_list)
        
        return jsonify({
            "success": True,
            "total_targets": len(domains_list),
            "total_hosts": total_hosts,
            "total_services": total_services,
            "total_cves": total_cves,
            "domains": domains_list
        })
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
@passive_bp.route("/summary/<domain>", methods=["GET"])
def passive_summary(domain):
    """
    GET /api/passive/summary/<domain>
    
    Dashboard summary cards — returns counts and key stats
    for both Shodan and Censys.
    """
    try:
        domain = sanitize_domain(domain)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    
    summary = get_passive_summary(domain)
    
    return jsonify({
        "success": True,
        "domain": domain,
        **summary
    })


@passive_bp.route("/vulns/<domain>", methods=["GET"])
def passive_vulns(domain):
    """
    GET /api/passive/vulns/<domain>
    
    Returns Shodan-reported CVEs for a domain.
    These are UNVERIFIED — Shodan maps CVEs based on
    service banners, not active exploitation testing.
    """
    try:
        domain = sanitize_domain(domain)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    
    vulns = get_shodan_vulns(domain)
    
    # Group by severity for display
    by_severity = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "unknown": []
    }
    
    for v in vulns:
        cvss = v.get("cvss")
        if cvss is not None:
            try:
                score = float(cvss)
                if score >= 9.0:
                    sev = "critical"
                elif score >= 7.0:
                    sev = "high"
                elif score >= 4.0:
                    sev = "medium"
                else:
                    sev = "low"
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
            "actively verified. Use Nuclei to confirm."
        ),
        "by_severity": by_severity,
        "vulnerabilities": vulns
    })


@passive_bp.route("/services/<domain>", methods=["GET"])
def passive_services(domain):
    """
    GET /api/passive/services/<domain>
    
    Returns merged service banners from Shodan + Censys.
    Shows what software is running on each host:port.
    """
    try:
        domain = sanitize_domain(domain)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    
    services = get_service_banners(domain)
    
    return jsonify({
        "success": True,
        "domain": domain,
        "total_services": len(services),
        "services": services
    })


@passive_bp.route("/hosts/<domain>", methods=["GET"])
def passive_hosts(domain):
    """
    GET /api/passive/hosts/<domain>
    
    Returns detailed host data from Shodan + Censys.
    Includes IP, hostname, org, country, ports, OS.
    """
    try:
        domain = sanitize_domain(domain)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400
    
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
                    "ip": ip,
                    "hostnames": [],
                    "ports": [],
                    "org": "",
                    "isp": "",
                    "country": "",
                    "city": "",
                    "os": "",
                    "vulns": [],
                    "sources": [],
                }
            
            entry = all_hosts[ip]
            if source not in entry["sources"]:
                entry["sources"].append(source)
            
            # Merge hostnames
            for h in host.get("hostnames", []):
                if h and h not in entry["hostnames"]:
                    entry["hostnames"].append(h)
            
            # Merge ports
            for p in host.get("ports", []):
                if p not in entry["ports"]:
                    entry["ports"].append(p)
            entry["ports"].sort()
            
            # Take non-empty values
            if host.get("org") and not entry["org"]:
                entry["org"] = host["org"]
            if host.get("isp") and not entry["isp"]:
                entry["isp"] = host["isp"]
            if host.get("country") and not entry["country"]:
                entry["country"] = host.get(
                    "country",
                    host.get("location", {}).get("country", "")
                )
            if host.get("city") and not entry["city"]:
                entry["city"] = host.get(
                    "city",
                    host.get("location", {}).get("city", "")
                )
            if host.get("os") and not entry["os"]:
                entry["os"] = host["os"]
            
            # Merge vulns (Shodan only)
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