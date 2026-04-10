# routes/scans.py

import threading
from flask import Blueprint, jsonify, request
from bson import ObjectId
from database.connection import get_db
from config import Config
from datetime import datetime
from utils.sanitize import sanitize_domain, sanitize_object_id
from utils.logger import logger
from database.scans_db import (
    can_resume_scan, reset_scan_for_resume,
    get_completed_phases
)

scans_bp = Blueprint("scans", __name__, url_prefix="/api/scans")


# ─── Helpers (unchanged) ─────────────────────────────────────────────────

def _serialize(doc):
    if doc is None:
        return None
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


# ─── Background runners ──────────────────────────────────────────────────

def _run_scan_background(target_id, domain, scan_id):
    """Execute full scan in background thread."""
    try:
        from core.scanner import run_full_scan
        run_full_scan(target_id, domain, scan_id)
    except Exception as e:
        from database.scans_db import fail_scan
        fail_scan(scan_id, str(e))
        logger.error(
            "Background scan failed for %s: %s",
            domain, e, exc_info=True
        )


def _run_subdomain_background(scan_id, target_id, domain):
    """Execute subdomain scan in background thread."""
    try:
        from core.subfinder import scan_subdomains
        from database.subdomains_db import add_subdomains_bulk

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
        logger.info(
            "Subdomain scan complete for %s: %d found",
            domain, result.get("count", 0)
        )
    except Exception as e:
        _complete_scan_record(scan_id, "failed", error=str(e))
        logger.error(
            "Subdomain scan failed for %s: %s",
            domain, e, exc_info=True
        )


def _run_port_background(scan_id, target_id, domain, subdomain_list):
    """Execute port scan in background thread."""
    try:
        from core.naabu import run_naabu
        from database.ports_db import add_ports_bulk

        result = run_naabu(subdomain_list)

        saved = 0
        if result.get("success"):
            for host, ports in result.get("ports_found", {}).items():
                r = add_ports_bulk(target_id, domain, "", host, ports,
                source="naabu")
                saved += r.get("new", 0) + r.get("updated", 0)

        _complete_scan_record(scan_id, "completed", stats={
            "ports_found": result.get("total_ports", 0), "saved": saved
        })
        logger.info(
            "Port scan complete for %s: %d ports",
            domain, result.get("total_ports", 0)
        )
    except Exception as e:
        _complete_scan_record(scan_id, "failed", error=str(e))
        logger.error(
            "Port scan failed for %s: %s",
            domain, e, exc_info=True
        )


def _run_http_background(scan_id, target_id, domain, subdomain_list):
    """Execute HTTP scan in background thread."""
    try:
        from core.httpx_runner import run_httpx
        from database.http_assets_db import add_http_asset

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
        logger.info(
            "HTTP scan complete for %s: %d assets",
            domain, result.get("count", 0)
        )
    except Exception as e:
        _complete_scan_record(scan_id, "failed", error=str(e))
        logger.error(
            "HTTP scan failed for %s: %s",
            domain, e, exc_info=True
        )


def _run_vuln_background(scan_id, target_id, domain, urls):
    """Execute vulnerability scan in background thread."""
    try:
        from core.nuclei import run_nuclei
        from database.vulns_db import add_vulnerability

        result = run_nuclei(urls)

        saved = 0
        if result.get("success"):
            for v in result.get("vulnerabilities", []):
                add_vulnerability(
                    target_id=target_id, target_domain=domain,
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
        logger.info(
            "Vuln scan complete for %s: %d vulns",
            domain, result.get("count", 0)
        )
    except Exception as e:
        _complete_scan_record(scan_id, "failed", error=str(e))
        logger.error(
            "Vuln scan failed for %s: %s",
            domain, e, exc_info=True
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
        try:
            domain = sanitize_domain(domain)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        db = get_db()
        history = list(db[Config.SCANS_COLLECTION].find(
            {"target_domain": domain}
        ).sort("started_at", -1).limit(20))

        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(history),
            "history": [_serialize(r) for r in history]
        })
    except Exception as e:
        logger.error("Error loading scan history for %s: %s", domain, e)
        return jsonify({"success": False, "error": str(e)}), 500


@scans_bp.route("/status/<scan_id>", methods=["GET"])
def get_scan_status(scan_id):
    try:
        try:
            scan_id = sanitize_object_id(scan_id, "scan_id")
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        db = get_db()
        scan = db[Config.SCANS_COLLECTION].find_one({"_id": ObjectId(scan_id)})
        if not scan:
            return jsonify({"success": False, "error": "Not found"}), 404
        return jsonify({"success": True, "scan": _serialize(scan)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Subdomain Scan ──────────────────────────────────────────────────────

@scans_bp.route("/subdomains/<domain>", methods=["POST"])
def subdomain_scan(domain):
    """Kicks off subdomain scan in a background thread."""
    try:
        try:
            domain = sanitize_domain(domain)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        target = _find_target(domain)
        if not target:
            return jsonify({"success": False, "error": "Target not found"}), 404

        target_id = str(target["_id"])
        scan_id = _create_scan_record(target_id, domain, "subdomains")

        logger.info("Subdomain scan started for %s", domain)

        thread = threading.Thread(
            target=_run_subdomain_background,
            args=(scan_id, target_id, domain),
            name=f"scan-subdomains-{domain}",
            daemon=True
        )
        thread.start()

        return jsonify({
            "success": True,
            "message": f"Subdomain scan started for {domain}",
            "scan_id": scan_id,
            "status_url": f"/api/scans/status/{scan_id}"
        }), 202

    except Exception as e:
        logger.error("Subdomain scan error for %s: %s", domain, e, exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Port Scan ────────────────────────────────────────────────────────────

@scans_bp.route("/ports/<domain>", methods=["POST"])
def port_scan(domain):
    """Kicks off port scan in a background thread."""
    try:
        try:
            domain = sanitize_domain(domain)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        target = _find_target(domain)
        if not target:
            return jsonify({"success": False, "error": "Target not found"}), 404

        target_id = str(target["_id"])
        subdomain_list = _get_subdomains(domain)
        if not subdomain_list:
            return jsonify({"success": False,
                           "error": "No subdomains. Run subdomain scan first."}), 400

        scan_id = _create_scan_record(target_id, domain, "ports")
        logger.info("Port scan started for %s (%d hosts)", domain, len(subdomain_list))

        thread = threading.Thread(
            target=_run_port_background,
            args=(scan_id, target_id, domain, subdomain_list),
            name=f"scan-ports-{domain}",
            daemon=True
        )
        thread.start()

        return jsonify({
            "success": True,
            "message": f"Port scan started for {domain}",
            "scan_id": scan_id,
            "status_url": f"/api/scans/status/{scan_id}"
        }), 202

    except Exception as e:
        logger.error("Port scan error for %s: %s", domain, e, exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# ─── HTTP Scan ────────────────────────────────────────────────────────────

@scans_bp.route("/http/<domain>", methods=["POST"])
def http_scan(domain):
    """Kicks off HTTP scan in a background thread."""
    try:
        try:
            domain = sanitize_domain(domain)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        target = _find_target(domain)
        if not target:
            return jsonify({"success": False, "error": "Target not found"}), 404

        target_id = str(target["_id"])
        subdomain_list = _get_subdomains(domain)
        if not subdomain_list:
            return jsonify({"success": False, "error": "No subdomains."}), 400

        scan_id = _create_scan_record(target_id, domain, "http")
        logger.info("HTTP scan started for %s", domain)

        thread = threading.Thread(
            target=_run_http_background,
            args=(scan_id, target_id, domain, subdomain_list),
            name=f"scan-http-{domain}",
            daemon=True
        )
        thread.start()

        return jsonify({
            "success": True,
            "message": f"HTTP scan started for {domain}",
            "scan_id": scan_id,
            "status_url": f"/api/scans/status/{scan_id}"
        }), 202

    except Exception as e:
        logger.error("HTTP scan error for %s: %s", domain, e, exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Vuln Scan ────────────────────────────────────────────────────────────

@scans_bp.route("/vulns/<domain>", methods=["POST"])
def vuln_scan(domain):
    """Kicks off vulnerability scan in a background thread."""
    try:
        try:
            domain = sanitize_domain(domain)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

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
        logger.info("Vuln scan started for %s (%d URLs)", domain, len(urls))

        thread = threading.Thread(
            target=_run_vuln_background,
            args=(scan_id, target_id, domain, urls),
            name=f"scan-vulns-{domain}",
            daemon=True
        )
        thread.start()

        return jsonify({
            "success": True,
            "message": f"Vulnerability scan started for {domain}",
            "scan_id": scan_id,
            "status_url": f"/api/scans/status/{scan_id}"
        }), 202

    except Exception as e:
        logger.error("Vuln scan error for %s: %s", domain, e, exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# ─── FULL SCAN ────────────────────────────────────────────────────────────

@scans_bp.route("/full/<domain>", methods=["POST"])
def full_scan(domain):
    """Kicks off the full scan pipeline in a background thread.
    
    Auto-resumes failed scans with completed phases.
    Creates new scan if no resumable scan found.
    """
    from database.scans_db import (
        create_scan_with_domain, 
        get_failed_scan_with_completed_phases,
        reset_scan_for_resume
    )
    from core.scanner import run_full_scan

    try:
        domain = sanitize_domain(domain)
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

    target = _find_target(domain)
    if not target:
        return jsonify({
            "success": False,
            "error": f"Target '{domain}' not found. Add it first."
        }), 404

    target_id = str(target["_id"])

    db = get_db()
    running = db[Config.SCANS_COLLECTION].find_one({
        "target_domain": domain,
        "status": "running"
    })
    if running:
        return jsonify({
            "success": False,
            "error": f"Scan already running for {domain}",
            "scan_id": str(running["_id"])
        }), 409

    # ─── CHECK FOR AUTO-RESUME ─────────────────────────────────────
    resumable = get_failed_scan_with_completed_phases(domain)
    
    if resumable:
        # Auto-resume the failed scan
        scan_id = resumable["scan_id"]
        completed_phases = resumable["completed_phases"]
        
        logger.info("=" * 60)
        logger.info("AUTO-RESUME: Scan %s for %s", scan_id, domain)
        logger.info("  Previous attempt completed phases: %s", completed_phases)
        logger.info("  Resuming from phase: %s", 
                    completed_phases[-1] if completed_phases else "N/A")
        logger.info("=" * 60)
        
        # Reset the scan to resumable state
        reset_scan_for_resume(scan_id)
        
        # Start resume in background
        thread = threading.Thread(
            target=_run_scan_background,
            args=(target_id, domain, scan_id),
            name=f"scan-{domain}-resume",
            daemon=True
        )
        thread.start()
        
        return jsonify({
            "success": True,
            "message": f"Resuming failed scan for {domain}",
            "scan_id": scan_id,
            "resumed": True,
            "completed_phases": completed_phases,
            "status_url": f"/api/scans/status/{scan_id}"
        }), 202
    
    # ─── CREATE NEW SCAN ───────────────────────────────────────────
    scan = create_scan_with_domain(target_id, domain, "full")
    scan_id = scan["scan_id"]

    logger.info("=" * 60)
    logger.info("Full scan starting for: %s (scan_id: %s)",
                domain, scan_id)
    logger.info("=" * 60)

    thread = threading.Thread(
        target=_run_scan_background,
        args=(target_id, domain, scan_id),
        name=f"scan-{domain}",
        daemon=True
    )
    thread.start()

    return jsonify({
        "success": True,
        "message": f"Scan started for {domain}",
        "scan_id": scan_id,
        "resumed": False,
        "status_url": f"/api/scans/status/{scan_id}"
    }), 202