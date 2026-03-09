from flask import Blueprint, jsonify, request
from bson import ObjectId
from database.connection import get_db
from config import Config
from datetime import datetime

scans_bp = Blueprint("scans", __name__, url_prefix="/api/scans")


# ─── Helpers ─────────────────────────────────────────────────────────────

def _serialize(doc):
    """Convert MongoDB document to JSON-safe dict — handles ALL ObjectId and datetime fields."""
    if doc is None:
        return None

    from bson import ObjectId
    from datetime import datetime

    result = {}
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            result[key] = str(value)
        elif isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, list):
            result[key] = [
                str(v) if isinstance(v, ObjectId)
                else v.isoformat() if isinstance(v, datetime)
                else v
                for v in value
            ]
        elif isinstance(value, dict):
            result[key] = _serialize(value)
        else:
            result[key] = value
    return result


def _find_target(domain):
    db = get_db()
    target = db[Config.TARGETS_COLLECTION].find_one({"root_domain": domain})
    if not target:
        target = db[Config.TARGETS_COLLECTION].find_one({"domain": domain})
    return target


def _get_subdomains(domain):
    db = get_db()
    subs = list(db[Config.SUBDOMAINS_COLLECTION].find(
        {"target_domain": domain}, {"subdomain": 1, "_id": 0}
    ))
    return [s["subdomain"] for s in subs]


def _get_urls(domain):
    db = get_db()
    assets = list(db[Config.HTTP_ASSETS_COLLECTION].find(
        {"target_domain": domain}, {"url": 1, "_id": 0}
    ))
    return [a["url"] for a in assets if a.get("url")]


def _create_scan_record(target_id, domain, scan_type):
    db = get_db()
    doc = {
        "target_id": ObjectId(target_id) if target_id else None,
        "target_domain": domain,
        "scan_type": scan_type,
        "status": "running",
        "started_at": datetime.utcnow(),
        "completed_at": None,
        "stats": {},
        "error": None
    }
    result = db[Config.SCANS_COLLECTION].insert_one(doc)
    return str(result.inserted_id)


def _complete_scan_record(scan_id, status, stats=None, error=None):
    db = get_db()
    update = {"status": status, "completed_at": datetime.utcnow()}
    if stats:
        update["stats"] = stats
    if error:
        update["error"] = error
    db[Config.SCANS_COLLECTION].update_one(
        {"_id": ObjectId(scan_id)}, {"$set": update}
    )


# ─── Status & History ────────────────────────────────────────────────────

@scans_bp.route("/status", methods=["GET"])
def scan_status():
    return jsonify({
        "success": True, "status": "ready",
        "available_scans": ["full", "subdomains", "ports", "http", "vulns"]
    })


@scans_bp.route("/history/<domain>", methods=["GET"])
def scan_history(domain):
    try:
        db = get_db()
        history = list(db[Config.SCANS_COLLECTION].find(
            {"target_domain": domain}
        ).sort("started_at", -1).limit(20))

        # Serialize ALL fields properly
        serialized = [_serialize(r) for r in history]

        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(serialized),
            "history": serialized
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@scans_bp.route("/status/<scan_id>", methods=["GET"])
def get_scan_status(scan_id):
    try:
        db = get_db()
        scan = db[Config.SCANS_COLLECTION].find_one(
            {"_id": ObjectId(scan_id)})
        if not scan:
            return jsonify({"success": False, "error": "Not found"}), 404
        return jsonify({"success": True, "scan": _serialize(scan)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Subdomain Scan ──────────────────────────────────────────────────────

@scans_bp.route("/subdomains/<domain>", methods=["POST"])
def subdomain_scan(domain):
    try:
        from core.subfinder import scan_subdomains
        from database.subdomains_db import add_subdomains_bulk

        target = _find_target(domain)
        if not target:
            return jsonify({"success": False, "error": "Target not found"}), 404

        target_id = str(target["_id"])
        scan_id = _create_scan_record(target_id, domain, "subdomains")

        result = scan_subdomains(domain)
        saved = {"new": 0, "updated": 0}

        if result.get("success") and result.get("subdomains"):
            saved = add_subdomains_bulk(
                target_id, domain, result["subdomains"]
            )

        _complete_scan_record(scan_id, "completed", stats={
            "subdomains_found": result.get("count", 0),
            "new": saved.get("new", 0)
        })

        return jsonify({
            "success": True, "domain": domain, "scan_id": scan_id,
            "count": result.get("count", 0),
            "subdomains": result.get("subdomains", [])[:100]
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Port Scan ────────────────────────────────────────────────────────────

@scans_bp.route("/ports/<domain>", methods=["POST"])
def port_scan(domain):
    try:
        from core.naabu import run_naabu
        from database.ports_db import add_ports_bulk

        target = _find_target(domain)
        if not target:
            return jsonify({"success": False, "error": "Target not found"}), 404

        target_id = str(target["_id"])
        subdomain_list = _get_subdomains(domain)
        if not subdomain_list:
            return jsonify({"success": False,
                           "error": "No subdomains. Run subdomain scan first."}), 400

        scan_id = _create_scan_record(target_id, domain, "ports")
        result = run_naabu(subdomain_list)

        saved = 0
        if result.get("success"):
            for host, ports in result.get("ports_found", {}).items():
                r = add_ports_bulk(target_id, domain, "", host, ports)
                saved += r.get("new", 0) + r.get("updated", 0)

        _complete_scan_record(scan_id, "completed", stats={
            "ports_found": result.get("total_ports", 0), "saved": saved
        })

        return jsonify({
            "success": True, "domain": domain, "scan_id": scan_id,
            "ports_found": result.get("total_ports", 0),
            "results": result.get("ports_found", {})
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── HTTP Scan ────────────────────────────────────────────────────────────

@scans_bp.route("/http/<domain>", methods=["POST"])
def http_scan(domain):
    try:
        from core.httpx_runner import run_httpx
        from database.http_assets_db import add_http_asset

        target = _find_target(domain)
        if not target:
            return jsonify({"success": False, "error": "Target not found"}), 404

        target_id = str(target["_id"])
        subdomain_list = _get_subdomains(domain)
        if not subdomain_list:
            return jsonify({"success": False,
                           "error": "No subdomains."}), 400

        scan_id = _create_scan_record(target_id, domain, "http")
        result = run_httpx(subdomain_list)

        saved = 0
        if result.get("success"):
            for asset in result.get("http_assets", []):
                add_http_asset(
                    target_id, domain, "",
                    asset.get("url", ""), asset.get("host", ""),
                    asset.get("port", 0), asset.get("status_code", 0),
                    asset.get("title", ""), asset.get("web_server", ""),
                    asset.get("tech", []), asset.get("content_length", 0)
                )
                saved += 1

        _complete_scan_record(scan_id, "completed", stats={
            "http_assets_found": result.get("count", 0), "saved": saved
        })

        return jsonify({
            "success": True, "domain": domain, "scan_id": scan_id,
            "http_assets_found": result.get("count", 0)
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Vuln Scan ────────────────────────────────────────────────────────────

@scans_bp.route("/vulns/<domain>", methods=["POST"])
def vuln_scan(domain):
    try:
        from core.nuclei import run_nuclei
        from database.vulns_db import add_vulnerability

        target = _find_target(domain)
        if not target:
            return jsonify({"success": False, "error": "Target not found"}), 404

        target_id = str(target["_id"])
        urls = _get_urls(domain)
        if not urls:
            subdomain_list = _get_subdomains(domain)
            urls = [f"https://{s}" for s in subdomain_list]
        if not urls:
            return jsonify({"success": False, "error": "No targets."}), 400

        scan_id = _create_scan_record(target_id, domain, "vulns")
        result = run_nuclei(urls)

        saved = 0
        if result.get("success"):
            for v in result.get("vulnerabilities", []):
                # NOW stores ALL nuclei fields via DB layer with DEDUP
                add_vulnerability(
                    target_id=target_id,
                    target_domain=domain,
                    subdomain_id="",
                    host=v.get("host", ""),
                    url=v.get("url", v.get("matched_at", "")),
                    template_id=v.get("template_id", ""),
                    name=v.get("name", ""),
                    severity=v.get("severity", "info"),
                    cve_id=v.get("cve_id"),
                    description=v.get("description", ""),
                    matched_at=v.get("matched_at", ""),
                    reference=v.get("reference", []),
                    tags=v.get("tags", []),
                    cvss_score=v.get("cvss_score"),
                    cwe_id=v.get("cwe_id", []),
                    remediation=v.get("remediation", {}),
                    curl_command=v.get("curl_command", ""),
                    extracted_results=v.get("extracted_results", [])
                )
                saved += 1

        _complete_scan_record(scan_id, "completed", stats={
            "vulns_found": result.get("count", 0), "saved": saved,
            "severity_breakdown": result.get("severity_breakdown", {})
        })

        return jsonify({
            "success": True, "domain": domain, "scan_id": scan_id,
            "vulns_found": result.get("count", 0),
            "severity_breakdown": result.get("severity_breakdown", {})
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── FULL SCAN — Calls scanner.py ────────────────────────────────────────

@scans_bp.route("/full/<domain>", methods=["POST"])
def full_scan(domain):
    """
    Full scan pipeline.
    
    NOW calls core/scanner.py which:
      - Uses DB layer functions (dedup, target_domain)
      - Runs change detection
      - Runs risk scoring
      - Stores ALL vuln data from Nuclei
    """
    try:
        from core.scanner import run_full_scan
        from database.scans_db import create_scan_with_domain

        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found. Add it first."
            }), 404

        target_id = str(target["_id"])

        print(f"\n{'='*50}")
        print(f"[FULL SCAN] Starting for: {domain}")
        print(f"{'='*50}")

        # Create scan record
        scan = create_scan_with_domain(target_id, domain, "full")
        scan_id = scan["scan_id"]

        # Run unified scanner (does everything properly)
        result = run_full_scan(target_id, domain, scan_id)

        return jsonify(result)

    except Exception as e:
        print(f"[FULL SCAN] Error: {e}")
        return jsonify({"success": False, "error": str(e)}), 500