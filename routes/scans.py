# routes/scans.py

from flask import Blueprint, jsonify, request
from bson import ObjectId
from database.connection import get_db
from config import Config
from datetime import datetime

scans_bp = Blueprint("scans", __name__, url_prefix="/api/scans")


# ─── Helper Functions ────────────────────────────────────────────────────

def _serialize(doc):
    """Convert MongoDB document to JSON-safe dict."""
    if doc and "_id" in doc:
        doc["_id"] = str(doc["_id"])
    return doc


def _create_scan_record(domain, scan_type):
    """Create a new scan record in scan_history."""
    db = get_db()
    scan_record = {
        "target_domain": domain,
        "scan_type": scan_type,
        "status": "running",
        "started_at": datetime.utcnow(),
        "completed_at": None,
        "stats": {},
        "error": None
    }
    result = db[Config.SCANS_COLLECTION].insert_one(scan_record)
    return str(result.inserted_id)


def _update_scan_record(scan_id, status, stats=None, error=None):
    """Update scan record with results."""
    db = get_db()
    update = {
        "status": status,
        "completed_at": datetime.utcnow()
    }
    if stats:
        update["stats"] = stats
    if error:
        update["error"] = error

    db[Config.SCANS_COLLECTION].update_one(
        {"_id": ObjectId(scan_id)},
        {"$set": update}
    )


def _find_target(domain):
    """Find target by domain or root_domain."""
    db = get_db()
    target = db[Config.TARGETS_COLLECTION].find_one({"domain": domain})
    if not target:
        target = db[Config.TARGETS_COLLECTION].find_one({"root_domain": domain})
    return target


def _get_subdomains(domain):
    """Get subdomain list for a domain from DB."""
    db = get_db()
    subs = list(db[Config.SUBDOMAINS_COLLECTION].find(
        {"target_domain": domain},
        {"subdomain": 1, "_id": 0}
    ))
    return [s["subdomain"] for s in subs]


def _get_urls(domain):
    """Get URL list for a domain from DB."""
    db = get_db()
    http_assets = list(db[Config.HTTP_ASSETS_COLLECTION].find(
        {"target_domain": domain},
        {"url": 1, "_id": 0}
    ))
    return [a["url"] for a in http_assets if a.get("url")]


# ─── Scan Status ─────────────────────────────────────────────────────────

@scans_bp.route("/status", methods=["GET"])
def scan_status():
    """GET /api/scans/status - Module status and available scanners."""
    return jsonify({
        "success": True,
        "message": "Scans module ready",
        "status": "ready",
        "available_scans": [
            "full",
            "subdomains",
            "ports",
            "http",
            "vulns"
        ]
    })


# ─── Scan History ────────────────────────────────────────────────────────

@scans_bp.route("/history/<domain>", methods=["GET"])
def scan_history(domain):
    """GET /api/scans/history/<domain> - Get scan history for a domain."""
    try:
        db = get_db()
        history = list(db[Config.SCANS_COLLECTION].find(
            {"target_domain": domain}
        ).sort("started_at", -1).limit(20))

        for record in history:
            record["_id"] = str(record["_id"])

        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(history),
            "history": history
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Get Single Scan Status ──────────────────────────────────────────────

@scans_bp.route("/status/<scan_id>", methods=["GET"])
def get_scan_status(scan_id):
    """GET /api/scans/status/<scan_id> - Get status of a specific scan."""
    try:
        db = get_db()
        scan = db[Config.SCANS_COLLECTION].find_one(
            {"_id": ObjectId(scan_id)}
        )

        if not scan:
            return jsonify({
                "success": False,
                "error": "Scan not found"
            }), 404

        return jsonify({
            "success": True,
            "scan": _serialize(scan)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Subdomain Scan Only ─────────────────────────────────────────────────

@scans_bp.route("/subdomains/<domain>", methods=["POST"])
def subdomain_scan(domain):
    """POST /api/scans/subdomains/<domain> - Run subdomain enumeration."""
    try:
        from core.subfinder import scan_subdomains, save_subdomains

        # Check target exists
        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found. Add it first."
            }), 404

        print(f"\n[API] Starting subdomain scan for: {domain}")

        # Create scan record
        scan_id = _create_scan_record(domain, "subdomains")

        # Run scan
        result = scan_subdomains(domain)

        # Save to DB
        saved = 0
        if result.get("success") and result.get("subdomains"):
            saved = save_subdomains(domain, result["subdomains"])

        # Update scan record
        _update_scan_record(scan_id, "completed", stats={
            "subdomains_found": result.get("count", 0),
            "saved": saved,
            "sources": result.get("sources", {})
        })

        return jsonify({
            "success": True,
            "domain": domain,
            "scan_id": scan_id,
            "count": result.get("count", 0),
            "saved": saved,
            "sources": result.get("sources", {}),
            "subdomains": result.get("subdomains", [])[:100]
        })

    except Exception as e:
        print(f"[API] Subdomain scan error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Port Scan Only ──────────────────────────────────────────────────────

@scans_bp.route("/ports/<domain>", methods=["POST"])
def port_scan(domain):
    """POST /api/scans/ports/<domain> - Run port scanning."""
    try:
        from core.naabu import run_naabu

        db = get_db()

        # Check target exists
        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found."
            }), 404

        # Get subdomains
        subdomain_list = _get_subdomains(domain)
        if not subdomain_list:
            return jsonify({
                "success": False,
                "error": "No subdomains found. Run subdomain scan first."
            }), 400

        print(f"\n[API] Starting port scan for: {domain} ({len(subdomain_list)} hosts)")

        # Create scan record
        scan_id = _create_scan_record(domain, "ports")

        # Run scan
        result = run_naabu(subdomain_list)

        # Save to DB
        saved = 0
        if result.get("success"):
            for host, ports in result.get("ports_found", {}).items():
                for port in ports:
                    db[Config.PORTS_COLLECTION].update_one(
                        {"host": host, "port": port},
                        {"$set": {
                            "host": host,
                            "port": port,
                            "target_domain": domain,
                            "scanned_at": datetime.utcnow(),
                            "status": "open"
                        }},
                        upsert=True
                    )
                    saved += 1

        # Update scan record
        _update_scan_record(scan_id, "completed", stats={
            "hosts_scanned": len(subdomain_list),
            "ports_found": result.get("total_ports", 0),
            "saved": saved
        })

        return jsonify({
            "success": result.get("success", False),
            "domain": domain,
            "scan_id": scan_id,
            "hosts_scanned": len(subdomain_list),
            "ports_found": result.get("total_ports", 0),
            "saved": saved,
            "results": result.get("ports_found", {})
        })

    except Exception as e:
        print(f"[API] Port scan error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── HTTP Scan Only ──────────────────────────────────────────────────────

@scans_bp.route("/http/<domain>", methods=["POST"])
def http_scan(domain):
    """POST /api/scans/http/<domain> - Run HTTP probing."""
    try:
        from core.httpx_runner import run_httpx

        db = get_db()

        # Check target exists
        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found."
            }), 404

        # Get subdomains
        subdomain_list = _get_subdomains(domain)
        if not subdomain_list:
            return jsonify({
                "success": False,
                "error": "No subdomains found. Run subdomain scan first."
            }), 400

        print(f"\n[API] Starting HTTP probe for: {domain} ({len(subdomain_list)} hosts)")

        # Create scan record
        scan_id = _create_scan_record(domain, "http")

        # Run scan
        result = run_httpx(subdomain_list)

        # Save to DB
        saved = 0
        if result.get("success"):
            for asset in result.get("http_assets", []):
                url = asset.get("url", "")
                if url:
                    db[Config.HTTP_ASSETS_COLLECTION].update_one(
                        {"url": url},
                        {"$set": {
                            "url": url,
                            "host": asset.get("host", ""),
                            "status_code": asset.get("status_code", 0),
                            "title": asset.get("title", ""),
                            "web_server": asset.get("web_server", ""),
                            "technologies": asset.get("tech", []),
                            "content_length": asset.get("content_length", 0),
                            "port": asset.get("port", 0),
                            "target_domain": domain,
                            "scanned_at": datetime.utcnow()
                        }},
                        upsert=True
                    )
                    saved += 1

        # Update scan record
        _update_scan_record(scan_id, "completed", stats={
            "hosts_probed": len(subdomain_list),
            "http_assets_found": result.get("count", 0),
            "saved": saved
        })

        return jsonify({
            "success": result.get("success", False),
            "domain": domain,
            "scan_id": scan_id,
            "hosts_probed": len(subdomain_list),
            "http_assets_found": result.get("count", 0),
            "saved": saved,
            "http_assets": result.get("http_assets", [])[:100]
        })

    except Exception as e:
        print(f"[API] HTTP scan error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Vulnerability Scan Only ─────────────────────────────────────────────

@scans_bp.route("/vulns/<domain>", methods=["POST"])
def vuln_scan(domain):
    """POST /api/scans/vulns/<domain> - Run vulnerability scanning."""
    try:
        from core.nuclei import run_nuclei

        db = get_db()

        # Check target exists
        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found."
            }), 404

        # Get URLs
        urls = _get_urls(domain)

        # Fallback to subdomains
        if not urls:
            subdomain_list = _get_subdomains(domain)
            urls = [f"https://{s}" for s in subdomain_list]

        if not urls:
            return jsonify({
                "success": False,
                "error": "No URLs found. Run HTTP scan first."
            }), 400

        print(f"\n[API] Starting vuln scan for: {domain} ({len(urls)} URLs)")

        # Create scan record
        scan_id = _create_scan_record(domain, "vulns")

        # Run scan
        result = run_nuclei(urls)

        # Save to DB
        saved = 0
        severity_breakdown = {
            "critical": 0, "high": 0,
            "medium": 0, "low": 0, "info": 0
        }

        if result.get("success"):
            for vuln in result.get("vulnerabilities", []):
                db[Config.VULNS_COLLECTION].insert_one({
                    "template_id": vuln.get("template_id", ""),
                    "name": vuln.get("name", ""),
                    "severity": vuln.get("severity", "info"),
                    "description": vuln.get("description", ""),
                    "host": vuln.get("host", ""),
                    "url": vuln.get("url", ""),
                    "vulnerability": vuln.get("template_id", ""),
                    "reference": vuln.get("reference", []),
                    "target_domain": domain,
                    "found_at": datetime.utcnow()
                })
                saved += 1
                sev = vuln.get("severity", "info").lower()
                if sev in severity_breakdown:
                    severity_breakdown[sev] += 1

        # Update scan record
        _update_scan_record(scan_id, "completed", stats={
            "urls_scanned": len(urls),
            "vulns_found": result.get("count", 0),
            "saved": saved,
            "severity_breakdown": severity_breakdown
        })

        return jsonify({
            "success": result.get("success", False),
            "domain": domain,
            "scan_id": scan_id,
            "urls_scanned": len(urls),
            "vulns_found": result.get("count", 0),
            "saved": saved,
            "severity_breakdown": severity_breakdown,
            "vulnerabilities": result.get("vulnerabilities", [])[:100]
        })

    except Exception as e:
        print(f"[API] Vuln scan error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Full Scan (Complete Pipeline) ───────────────────────────────────────

@scans_bp.route("/full/<domain>", methods=["POST"])
def full_scan(domain):
    """POST /api/scans/full/<domain> - Run complete scan pipeline."""
    try:
        from core.subfinder import scan_subdomains, save_subdomains
        from core.naabu import run_naabu
        from core.httpx_runner import run_httpx
        from core.nuclei import run_nuclei

        db = get_db()

        # Check target exists
        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found. Add it first."
            }), 404

        print(f"\n{'='*50}")
        print(f"[FULL SCAN] Starting for: {domain}")
        print(f"{'='*50}")

        # Create scan record
        scan_id = _create_scan_record(domain, "full")

        results = {
            "subdomains": {"success": False, "count": 0},
            "ports": {"success": False, "count": 0},
            "http": {"success": False, "count": 0},
            "vulns": {"success": False, "count": 0}
        }

        # ─── Step 1: Subdomain Enumeration ─────────────────────────
        print(f"\n[STEP 1/4] Subdomain Enumeration")
        try:
            sub_result = scan_subdomains(domain)
            saved = 0
            if sub_result.get("success") and sub_result.get("subdomains"):
                saved = save_subdomains(domain, sub_result["subdomains"])
            results["subdomains"] = {
                "success": sub_result.get("success", False),
                "count": sub_result.get("count", 0),
                "saved": saved,
                "sources": sub_result.get("sources", {})
            }
        except Exception as e:
            print(f"  [ERROR] Subdomain scan failed: {e}")
            results["subdomains"]["error"] = str(e)

        # ─── Step 2: Port Scanning ─────────────────────────────────
        print(f"\n[STEP 2/4] Port Scanning")
        try:
            subdomain_list = _get_subdomains(domain)
            if subdomain_list:
                port_result = run_naabu(subdomain_list)
                saved = 0
                if port_result.get("success"):
                    for host, ports in port_result.get("ports_found", {}).items():
                        for port in ports:
                            db[Config.PORTS_COLLECTION].update_one(
                                {"host": host, "port": port},
                                {"$set": {
                                    "host": host,
                                    "port": port,
                                    "target_domain": domain,
                                    "scanned_at": datetime.utcnow(),
                                    "status": "open"
                                }},
                                upsert=True
                            )
                            saved += 1
                results["ports"] = {
                    "success": port_result.get("success", False),
                    "count": port_result.get("total_ports", 0),
                    "saved": saved
                }
            else:
                results["ports"]["error"] = "No subdomains to scan"
        except Exception as e:
            print(f"  [ERROR] Port scan failed: {e}")
            results["ports"]["error"] = str(e)

        # ─── Step 3: HTTP Probing ──────────────────────────────────
        print(f"\n[STEP 3/4] HTTP Probing")
        try:
            subdomain_list = _get_subdomains(domain)
            if subdomain_list:
                http_result = run_httpx(subdomain_list)
                saved = 0
                if http_result.get("success"):
                    for asset in http_result.get("http_assets", []):
                        url = asset.get("url", "")
                        if url:
                            db[Config.HTTP_ASSETS_COLLECTION].update_one(
                                {"url": url},
                                {"$set": {
                                    "url": url,
                                    "host": asset.get("host", ""),
                                    "status_code": asset.get("status_code", 0),
                                    "title": asset.get("title", ""),
                                    "web_server": asset.get("web_server", ""),
                                    "technologies": asset.get("tech", []),
                                    "target_domain": domain,
                                    "scanned_at": datetime.utcnow()
                                }},
                                upsert=True
                            )
                            saved += 1
                results["http"] = {
                    "success": http_result.get("success", False),
                    "count": http_result.get("count", 0),
                    "saved": saved
                }
            else:
                results["http"]["error"] = "No subdomains to probe"
        except Exception as e:
            print(f"  [ERROR] HTTP scan failed: {e}")
            results["http"]["error"] = str(e)

        # ─── Step 4: Vulnerability Scanning ────────────────────────
        print(f"\n[STEP 4/4] Vulnerability Scanning")
        try:
            urls = _get_urls(domain)
            if not urls:
                subdomain_list = _get_subdomains(domain)
                urls = [f"https://{s}" for s in subdomain_list]

            if urls:
                vuln_result = run_nuclei(urls)
                saved = 0
                if vuln_result.get("success"):
                    for vuln in vuln_result.get("vulnerabilities", []):
                        db[Config.VULNS_COLLECTION].insert_one({
                            "template_id": vuln.get("template_id", ""),
                            "name": vuln.get("name", ""),
                            "severity": vuln.get("severity", "info"),
                            "description": vuln.get("description", ""),
                            "host": vuln.get("host", ""),
                            "url": vuln.get("url", ""),
                            "target_domain": domain,
                            "found_at": datetime.utcnow()
                        })
                        saved += 1
                results["vulns"] = {
                    "success": vuln_result.get("success", False),
                    "count": vuln_result.get("count", 0),
                    "saved": saved
                }
            else:
                results["vulns"]["error"] = "No URLs to scan"
        except Exception as e:
            print(f"  [ERROR] Vuln scan failed: {e}")
            results["vulns"]["error"] = str(e)

        # ─── Update Target Stats ───────────────────────────────────
        db[Config.TARGETS_COLLECTION].update_one(
            {"domain": domain},
            {"$set": {
                "last_scanned": datetime.utcnow(),
                "total_subdomains": results["subdomains"].get("count", 0),
                "total_ports": results["ports"].get("count", 0),
                "total_http_assets": results["http"].get("count", 0),
                "total_vulns": results["vulns"].get("count", 0)
            }}
        )

        # ─── Update Scan Record ────────────────────────────────────
        _update_scan_record(scan_id, "completed", stats=results)

        print(f"\n{'='*50}")
        print(f"[FULL SCAN] Completed for: {domain}")
        print(f"  Subdomains: {results['subdomains'].get('count', 0)}")
        print(f"  Ports:      {results['ports'].get('count', 0)}")
        print(f"  HTTP:       {results['http'].get('count', 0)}")
        print(f"  Vulns:      {results['vulns'].get('count', 0)}")
        print(f"{'='*50}\n")

        return jsonify({
            "success": True,
            "domain": domain,
            "scan_id": scan_id,
            "status": "completed",
            "results": results
        })

    except Exception as e:
        print(f"[FULL SCAN] Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500