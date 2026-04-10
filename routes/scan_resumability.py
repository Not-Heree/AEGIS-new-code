"""
Scan Resumability Routes

Endpoints for resuming interrupted/failed scans from their last checkpoint.
"""

import threading
from flask import Blueprint, jsonify, request
from bson import ObjectId
from database.scans_db import (
    can_resume_scan, reset_scan_for_resume,
    get_completed_phases
)
from database.targets_db import get_target_by_id
from config import Config
from utils.sanitize import sanitize_object_id
from utils.logger import logger

resumability_bp = Blueprint(
    "resumability", __name__, url_prefix="/api/scans/resume"
)


@resumability_bp.route("/<scan_id>/check", methods=["GET"])
def check_resume_eligibility(scan_id):
    """
    Check if a scan can be resumed.
    
    Returns:
        {
            "can_resume": bool,
            "completed_phases": list,
            "error": str (if cannot resume)
        }
    """
    try:
        scan_id = sanitize_object_id(scan_id, "scan_id")
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

    result = can_resume_scan(scan_id)
    return jsonify(result), 200 if result.get("can_resume") else 400


@resumability_bp.route("/<scan_id>/now", methods=["POST"])
def resume_scan_now(scan_id):
    """
    Resume a failed/interrupted scan from its last checkpoint.
    
    Clears error state, re-marks as 'running', and restarts the scan
    from the phase after the last completed phase.
    """
    try:
        scan_id = sanitize_object_id(scan_id, "scan_id")
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

    # Check if resumable
    check = can_resume_scan(scan_id)
    if not check.get("can_resume"):
        return jsonify({
            "success": False,
            "error": check.get("error", "Cannot resume this scan")
        }), 400

    # Reset the scan to running state
    if not reset_scan_for_resume(scan_id):
        return jsonify({
            "success": False,
            "error": "Failed to reset scan for resume"
        }), 500

    # Get the scan document to find target info
    from database.connection import get_collection
    scan_doc = get_collection(Config.SCANS_COLLECTION).find_one(
        {"_id": ObjectId(scan_id)}
    )
    
    if not scan_doc:
        return jsonify({"success": False, "error": "Scan not found"}), 404

    target_id = str(scan_doc.get("target_id"))
    domain = scan_doc.get("target_domain")
    
    # Get target to verify it exists
    target = get_target_by_id(target_id)
    if not target:
        return jsonify({
            "success": False,
            "error": "Target not found"
        }), 404

    # Import the scanner
    from core.scanner import run_full_scan

    # Start the scan in background
    logger.info(
        "Resuming scan %s for %s (target: %s)",
        scan_id, domain, target_id
    )

    thread = threading.Thread(
        target=run_full_scan,
        args=(target_id, domain, scan_id),
        name=f"resume-{scan_id}",
        daemon=True
    )
    thread.start()

    return jsonify({
        "success": True,
        "message": f"Scan resuming from checkpoint",
        "scan_id": scan_id,
        "domain": domain,
        "completed_phases": check.get("completed_phases"),
        "status_url": f"/api/scans/status/{scan_id}"
    }), 202


@resumability_bp.route("/<scan_id>/phases", methods=["GET"])
def get_scan_phases(scan_id):
    """
    Get the list of phases already completed for a scan.
    Useful for understanding resume progress.
    """
    try:
        scan_id = sanitize_object_id(scan_id, "scan_id")
    except ValueError as e:
        return jsonify({"success": False, "error": str(e)}), 400

    completed = get_completed_phases(scan_id)
    
    all_phases = [
        "passive_recon",
        "subdomain_discovery",
        "port_scanning",
        "http_fingerprinting",
        "vuln_scanning",
        "change_detection",
        "risk_scoring"
    ]

    return jsonify({
        "success": True,
        "scan_id": scan_id,
        "completed_phases": completed,
        "all_phases": all_phases,
        "progress_percent": int(
            (len(completed) / len(all_phases)) * 100
        ) if all_phases else 0
    }), 200
