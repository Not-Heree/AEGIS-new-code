"""
Target Management Routes
========================
REST API for managing monitored domains.

Endpoints:
    GET    /api/targets/         List all targets
    POST   /api/targets/         Add new target + auto-harvest emails
    GET    /api/targets/<domain> Get single target
    PUT    /api/targets/<domain> Update target details
    DELETE /api/targets/<domain> Delete target + ALL related data
"""

import threading
from flask import Blueprint, jsonify, request
from bson import ObjectId
from database.connection import get_db
from config import Config
from datetime import datetime
from utils.sanitize import (
    sanitize_domain, sanitize_string,
    sanitize_string_optional
)
from utils.logger import logger

targets_bp = Blueprint("targets", __name__, url_prefix="/api/targets")


# =============================================================================
# HELPERS
# =============================================================================

def _find_target(domain):
    """
    Find target by domain name.

    Tries root_domain first (canonical field).
    Falls back to legacy "domain" field for backward compatibility.
    """
    db = get_db()
    target = db[Config.TARGETS_COLLECTION].find_one(
        {"root_domain": domain}
    )
    if not target:
        target = db[Config.TARGETS_COLLECTION].find_one(
            {"domain": domain}
        )
    return target


# =============================================================================
# BACKGROUND EMAIL HARVESTING
# =============================================================================

def _harvest_emails_background(target_id, domain):
    """Run email harvesting in a background thread."""
    # Import the lock from emails route
    try:
        from routes.emails import (
            _start_harvest, _end_harvest
        )
        if not _start_harvest(domain):
            logger.info(
                "Harvest already running for %s, "
                "skipping background harvest",
                domain
            )
            return
    except ImportError:
        pass

    try:
        from core.email_harvester import harvest_and_check
        from database.emails_db import add_emails_bulk

        logger.info(
            "Background email harvest started for %s",
            domain
        )

        harvest_result = harvest_and_check(domain)

        if harvest_result.get("success"):
            combined = harvest_result.get("combined", {})
            emails_data = combined.get("emails", [])

            if emails_data:
                saved = add_emails_bulk(
                    target_id, domain, emails_data
                )
                logger.info(
                    "Background harvest saved for %s: "
                    "%d new, %d updated",
                    domain,
                    saved.get('new', 0),
                    saved.get('updated', 0)
                )

            try:
                db = get_db()
                db[Config.TARGETS_COLLECTION].update_one(
                    {"_id": ObjectId(target_id)},
                    {"$set": {
                        "total_emails": combined.get(
                            "total_emails", 0
                        ),
                        "total_breached_emails": combined.get(
                            "total_breached", 0
                        )
                    }}
                )
            except Exception as e:
                logger.error(
                    "Error updating email stats for %s: %s",
                    domain, e
                )

        else:
            logger.warning(
                "Background harvest failed for %s: %s",
                domain,
                harvest_result.get('error', 'Unknown')
            )

    except Exception as e:
        logger.error(
            "Background harvest error for %s: %s",
            domain, e, exc_info=True
        )

    finally:
        try:
            from routes.emails import _end_harvest
            _end_harvest(domain)
        except ImportError:
            pass


# =============================================================================
# GET ALL TARGETS
# =============================================================================

@targets_bp.route("/", methods=["GET"])
def get_targets():
    """GET /api/targets/ — List all targets."""
    try:
        db = get_db()
        targets = list(db[Config.TARGETS_COLLECTION].find())

        for target in targets:
            target["_id"] = str(target["_id"])
            for key, value in target.items():
                if isinstance(value, datetime):
                    target[key] = value.isoformat()

        return jsonify({
            "success": True,
            "count": len(targets),
            "targets": targets
        })
    except Exception as e:
        logger.error("Error listing targets: %s", e)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# =============================================================================
# ADD NEW TARGET
# =============================================================================

@targets_bp.route("/", methods=["POST"])
def add_target():
    """
    POST /api/targets/ — Add a new target domain.

    Creates target with CANONICAL field names only:
        root_domain, created_at, last_scan_at

    Email harvesting runs in a background thread.
    """
    try:
        data = request.get_json()

        if not data:
            return jsonify({
                "success": False,
                "error": (
                    "No data provided. "
                    "Send: {\"domain\": \"example.com\"}"
                )
            }), 400

        try:
            domain = sanitize_domain(data.get("domain"))
            org_name = sanitize_string_optional(
                data.get("org_name", ""), "org_name"
            )
            description = sanitize_string_optional(
                data.get("description", ""), "description"
            )
        except ValueError as e:
            return jsonify({
                "success": False,
                "error": str(e)
            }), 400

        db = get_db()

        existing = db[Config.TARGETS_COLLECTION].find_one(
            {"root_domain": domain}
        )
        if not existing:
            existing = db[Config.TARGETS_COLLECTION].find_one(
                {"domain": domain}
            )
        if existing:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' already exists",
                "target_id": str(existing["_id"])
            }), 409

        target = {
            "root_domain": domain,
            "org_name": org_name,
            "description": description,
            "status": "active",
            "total_subdomains": 0,
            "total_ports": 0,
            "total_http_assets": 0,
            "total_vulns": 0,
            "total_emails": 0,
            "total_breached_emails": 0,
            "risk_score": 0,
            "created_at": datetime.utcnow(),
            "last_scan_at": None,
            "scan_count": 0,
        }

        result = db[Config.TARGETS_COLLECTION].insert_one(target)
        target_id = str(result.inserted_id)
        target["_id"] = target_id
        target["created_at"] = target["created_at"].isoformat()

        logger.info("Added new target: %s (id: %s)", domain, target_id)

        thread = threading.Thread(
            target=_harvest_emails_background,
            args=(target_id, domain),
            name=f"email-harvest-{domain}"
        )
        thread.daemon = True
        thread.start()

        logger.info(
            "Email harvesting thread started for %s", domain
        )

        return jsonify({
            "success": True,
            "message": (
                f"Target '{domain}' added successfully. "
                f"Email harvesting running in background."
            ),
            "target": target,
            "email_harvest": {
                "status": "running_in_background",
                "message": (
                    "Check the Emails page in a few minutes "
                    "for discovered emails and breach data."
                )
            }
        }), 201

    except Exception as e:
        logger.error("Error adding target: %s", e, exc_info=True)
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


# =============================================================================
# GET SINGLE TARGET
# =============================================================================

@targets_bp.route("/<domain>", methods=["GET"])
def get_target(domain):
    """GET /api/targets/<domain> — Get one target by domain name."""
    try:
        try:
            domain = sanitize_domain(domain)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found"
            }), 404

        target["_id"] = str(target["_id"])
        for key, value in target.items():
            if isinstance(value, datetime):
                target[key] = value.isoformat()

        return jsonify({"success": True, "target": target})

    except Exception as e:
        logger.error("Error getting target %s: %s", domain, e)
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# UPDATE TARGET
# =============================================================================

@targets_bp.route("/<domain>", methods=["PUT"])
def update_target(domain):
    """PUT /api/targets/<domain> — Update target details."""
    try:
        try:
            domain = sanitize_domain(domain)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        data = request.get_json()
        if not data:
            return jsonify({
                "success": False, "error": "No data provided"
            }), 400

        db = get_db()

        allowed_fields = ["org_name", "description", "status"]
        update_data = {}
        try:
            for field in allowed_fields:
                if field in data:
                    update_data[field] = sanitize_string(
                        data[field], field
                    )
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        if not update_data:
            return jsonify({
                "success": False,
                "error": f"No valid fields. Allowed: {allowed_fields}"
            }), 400

        result = db[Config.TARGETS_COLLECTION].update_one(
            {"root_domain": domain},
            {"$set": update_data}
        )

        if result.matched_count == 0:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found"
            }), 404

        logger.info(
            "Updated target %s: fields=%s",
            domain, list(update_data.keys())
        )

        return jsonify({
            "success": True,
            "message": f"Target '{domain}' updated",
            "updated_fields": list(update_data.keys())
        })

    except Exception as e:
        logger.error("Error updating target %s: %s", domain, e)
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# DELETE TARGET + ALL DATA
# =============================================================================

@targets_bp.route("/<domain>", methods=["DELETE"])
def delete_target(domain):
    """DELETE /api/targets/<domain> — Remove target and ALL related data."""
    try:
        try:
            domain = sanitize_domain(domain)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        db = get_db()
        target = _find_target(domain)
        if not target:
            return jsonify({"success": False, "error": "Not found"}), 404

        target_id = target["_id"]

        deleted = {}
        collections_to_clean = [
            (Config.SUBDOMAINS_COLLECTION, [
                {"target_domain": domain}, {"target_id": target_id}
            ]),
            (Config.PORTS_COLLECTION, [
                {"target_domain": domain}, {"target_id": target_id}
            ]),
            (Config.HTTP_ASSETS_COLLECTION, [
                {"target_domain": domain}, {"target_id": target_id}
            ]),
            (Config.VULNS_COLLECTION, [
                {"target_domain": domain}, {"target_id": target_id}
            ]),
            (Config.CHANGES_COLLECTION, [
                {"target_domain": domain}, {"target_id": target_id}
            ]),
            (Config.SCANS_COLLECTION, [
                {"target_domain": domain}, {"target_id": target_id}
            ]),
            (Config.EMAILS_COLLECTION, [
                {"target_domain": domain}, {"target_id": target_id}
            ]),
            ("passive_recon", [
                {"target_domain": domain}, {"target_id": target_id}
            ]),
        ]

        for coll_name, queries in collections_to_clean:
            count = 0
            for query in queries:
                count += db[coll_name].delete_many(query).deleted_count
            deleted[coll_name] = count

        db[Config.TARGETS_COLLECTION].delete_one({"_id": target_id})

        logger.info("Deleted target: %s", domain)
        logger.debug("Cascade cleanup: %s", deleted)

        return jsonify({
            "success": True,
            "message": f"'{domain}' and all data deleted",
            "deleted": deleted
        })

    except Exception as e:
        logger.error("Error deleting target %s: %s", domain, e)
        return jsonify({"success": False, "error": str(e)}), 500