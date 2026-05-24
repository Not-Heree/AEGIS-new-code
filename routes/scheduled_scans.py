"""
Scheduled Scans Routes
======================
REST API for managing scheduled security scans.

Endpoints:
    GET    /api/schedules/              List all schedules
    POST   /api/schedules/              Create new schedule
    GET    /api/schedules/<schedule_id> Get schedule details
    PUT    /api/schedules/<schedule_id> Update schedule
    DELETE /api/schedules/<schedule_id> Delete schedule
"""

from flask import Blueprint, jsonify, request, render_template
from bson import ObjectId
from datetime import datetime

from database.connection import get_db
from database.scan_schedules_db import (
    create_schedule, get_schedule, get_schedules_for_target,
    update_schedule, delete_schedule, record_execution
)
from config import Config
from utils.logger import logger
from utils.sanitize import sanitize_domain, sanitize_object_id, sanitize_string

schedules_bp = Blueprint("schedules", __name__, url_prefix="/api/schedules")


# =============================================================================
# HELPERS
# =============================================================================

def _find_target(domain):
    """Find target by domain name"""
    db = get_db()
    target = db[Config.TARGETS_COLLECTION].find_one({"root_domain": domain})
    if not target:
        target = db[Config.TARGETS_COLLECTION].find_one({"domain": domain})
    return target


# =============================================================================
# LIST SCHEDULES
# =============================================================================

@schedules_bp.route("/", methods=["GET"])
def list_schedules():
    """GET /api/schedules/ — List all scheduled scans"""
    try:
        domain = request.args.get("domain")

        db = get_db()
        collection = db[Config.SCAN_SCHEDULES_COLLECTION]

        query = {}
        if domain:
            try:
                domain = sanitize_domain(domain)
                query["target_domain"] = domain
            except ValueError as e:
                return jsonify({"success": False, "error": str(e)}), 400

        schedules = list(collection.find(query).sort("created_at", -1))

        for s in schedules:
            s["_id"] = str(s["_id"])
            s["target_id"] = str(s["target_id"])
            if "created_at" in s:
                s["created_at"] = s["created_at"].isoformat()
            if "last_run" in s and s["last_run"]:
                s["last_run"] = s["last_run"].isoformat()
            if "next_run" in s and s["next_run"]:
                s["next_run"] = s["next_run"].isoformat()

        return jsonify({
            "success": True,
            "schedules": schedules,
            "total": len(schedules)
        })

    except Exception as e:
        logger.error(f"Error listing schedules: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# CREATE SCHEDULE
# =============================================================================

@schedules_bp.route("/", methods=["POST"])
def create_new_schedule():
    """POST /api/schedules/ — Create new scan schedule"""
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "success": False,
                "error": "No data provided"
            }), 400

        # Validate inputs
        try:
            domain = sanitize_domain(data.get("domain"))
            frequency = sanitize_string(data.get("frequency", "daily")).lower()
            time_of_day = sanitize_string(data.get("time_of_day", "00:00"))
            scan_type = sanitize_string(data.get("scan_type", "full")).lower()
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        # Validate frequency
        if frequency not in ["daily", "weekly", "monthly"]:
            return jsonify({
                "success": False,
                "error": "Frequency must be daily, weekly, or monthly"
            }), 400

        # Validate time format
        try:
            hours, minutes = map(int, time_of_day.split(':'))
            if not (0 <= hours < 24 and 0 <= minutes < 60):
                raise ValueError()
        except:
            return jsonify({
                "success": False,
                "error": "Invalid time format. Use HH:MM (24-hour)"
            }), 400

        # Find target
        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found"
            }), 404

        # Create schedule
        result = create_schedule(
            target_id=str(target["_id"]),
            target_domain=domain,
            frequency=frequency,
            time_of_day=time_of_day,
            enabled=data.get("enabled", True),
            scan_type=scan_type
        )

        if result["success"]:
            logger.info(f"Created schedule for {domain}: {frequency} at {time_of_day}")
            schedule = get_schedule(result["schedule_id"])
            return jsonify({
                "success": True,
                "message": f"Schedule created for {domain}",
                "schedule": schedule
            }), 201
        else:
            return jsonify(result), 500

    except Exception as e:
        logger.error(f"Error creating schedule: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# GET SCHEDULE
# =============================================================================

@schedules_bp.route("/<schedule_id>", methods=["GET"])
def get_schedule_detail(schedule_id):
    """GET /api/schedules/<schedule_id> — Get schedule details"""
    try:
        try:
            schedule_id = sanitize_object_id(schedule_id)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        schedule = get_schedule(schedule_id)

        if not schedule:
            return jsonify({
                "success": False,
                "error": "Schedule not found"
            }), 404

        return jsonify({
            "success": True,
            "schedule": schedule
        })

    except Exception as e:
        logger.error(f"Error getting schedule: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# UPDATE SCHEDULE
# =============================================================================

@schedules_bp.route("/<schedule_id>", methods=["PUT"])
def update_schedule_detail(schedule_id):
    """PUT /api/schedules/<schedule_id> — Update schedule"""
    try:
        try:
            schedule_id = sanitize_object_id(schedule_id)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        data = request.get_json()
        if not data:
            return jsonify({"success": False, "error": "No data provided"}), 400

        # Validate updatable fields
        updates = {}

        if "frequency" in data:
            frequency = sanitize_string(data["frequency"]).lower()
            if frequency not in ["daily", "weekly", "monthly"]:
                return jsonify({
                    "success": False,
                    "error": "Invalid frequency"
                }), 400
            updates["frequency"] = frequency

        if "time_of_day" in data:
            time_of_day = sanitize_string(data["time_of_day"])
            try:
                hours, minutes = map(int, time_of_day.split(':'))
                if not (0 <= hours < 24 and 0 <= minutes < 60):
                    raise ValueError()
            except:
                return jsonify({
                    "success": False,
                    "error": "Invalid time format"
                }), 400
            updates["time_of_day"] = time_of_day

        if "schedule_type" in data:
            scan_type = sanitize_string(data["scan_type"]).lower()
            if scan_type not in ["full", "passive"]:
                return jsonify({
                    "success": False,
                    "error": "Invalid scan_type"
                }), 400
            updates["scan_type"] = scan_type

        if "enabled" in data:
            updates["enabled"] = bool(data["enabled"])

        if "notes" in data:
            updates["notes"] = sanitize_string(data["notes"])

        if not updates:
            return jsonify({
                "success": False,
                "error": "No valid fields to update"
            }), 400

        result = update_schedule(schedule_id, **updates)

        if result["success"]:
            schedule = get_schedule(schedule_id)
            logger.info(f"Updated schedule {schedule_id}")
            return jsonify({
                "success": True,
                "message": "Schedule updated",
                "schedule": schedule
            })
        else:
            return jsonify(result), 500

    except Exception as e:
        logger.error(f"Error updating schedule: {e}", exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# DELETE SCHEDULE
# =============================================================================

@schedules_bp.route("/<schedule_id>", methods=["DELETE"])
def delete_schedule_detail(schedule_id):
    """DELETE /api/schedules/<schedule_id> — Delete schedule"""
    try:
        try:
            schedule_id = sanitize_object_id(schedule_id)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        schedule = get_schedule(schedule_id)
        if not schedule:
            return jsonify({
                "success": False,
                "error": "Schedule not found"
            }), 404

        result = delete_schedule(schedule_id)

        if result["success"]:
            logger.info(f"Deleted schedule {schedule_id}")
            return jsonify({
                "success": True,
                "message": f"Schedule for {schedule.get('target_domain')} deleted"
            })
        else:
            return jsonify(result), 500

    except Exception as e:
        logger.error(f"Error deleting schedule: {e}")
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# SCHEDULE MANAGEMENT UI
# =============================================================================

@schedules_bp.route("/manage", endpoint="manage_schedules")
def manage_schedules_ui():
    """Display schedule management UI"""
    try:
        db = get_db()
        targets = list(db[Config.TARGETS_COLLECTION].find().sort("root_domain", 1))

        for t in targets:
            t["_id"] = str(t["_id"])

        return render_template(
            "scheduled_scans.html",
            targets=targets,
            active_page="scheduled"
        )

    except Exception as e:
        logger.error(f"Error loading schedules UI: {e}", exc_info=True)
        return render_template("scheduled_scans.html", error=str(e))
