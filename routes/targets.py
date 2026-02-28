# routes/targets.py

from flask import Blueprint, jsonify, request
from database.connection import get_db
from config import Config
from datetime import datetime

targets_bp = Blueprint("targets", __name__, url_prefix="/api/targets")


# ─── Get All Targets ─────────────────────────────────────────────────────

@targets_bp.route("/", methods=["GET"])
def get_targets():
    """GET /api/targets/ - List all targets."""
    try:
        db = get_db()
        targets = list(db[Config.TARGETS_COLLECTION].find())

        # Convert ObjectId to string
        for target in targets:
            target["_id"] = str(target["_id"])

        return jsonify({
            "success": True,
            "count": len(targets),
            "targets": targets
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Add New Target ──────────────────────────────────────────────────────

@targets_bp.route("/", methods=["POST"])
def add_target():
    """POST /api/targets/ - Add a new target domain."""
    try:
        data = request.get_json()

        # Validate input
        if not data or "domain" not in data:
            return jsonify({
                "success": False,
                "error": "domain is required. Send: {\"domain\": \"example.com\"}"
            }), 400

        domain = data["domain"].strip().lower()

        # Basic domain validation
        if not domain or "." not in domain:
            return jsonify({
                "success": False,
                "error": f"Invalid domain: '{domain}'"
            }), 400

        db = get_db()

        # Check if already exists
        existing = db[Config.TARGETS_COLLECTION].find_one({"root_domain": domain})
        if existing:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' already exists",
                "target_id": str(existing["_id"])
            }), 409

        # Build target document with all fields
        target = {
            "domain": domain,
            "root_domain": domain,
            "org_name": data.get("org_name", ""),
            "description": data.get("description", ""),
            "added_at": datetime.utcnow(),
            "status": "active",
            "last_scanned": None,
            "scan_count": 0,
            "risk_score": 0,
            "total_subdomains": 0,
            "total_ports": 0,
            "total_http_assets": 0,
            "total_vulns": 0
        }

        result = db[Config.TARGETS_COLLECTION].insert_one(target)
        target["_id"] = str(result.inserted_id)

        print(f"[TARGETS] Added new target: {domain}")

        return jsonify({
            "success": True,
            "message": f"Target '{domain}' added successfully",
            "target": target
        }), 201

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Get Single Target ───────────────────────────────────────────────────

@targets_bp.route("/<domain>", methods=["GET"])
def get_target(domain):
    """GET /api/targets/<domain> - Get one target by domain name."""
    try:
        db = get_db()
        target = db[Config.TARGETS_COLLECTION].find_one(
            {"root_domain": domain}
        )

        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found"
            }), 404

        target["_id"] = str(target["_id"])

        return jsonify({
            "success": True,
            "target": target
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Update Target ───────────────────────────────────────────────────────

@targets_bp.route("/<domain>", methods=["PUT"])
def update_target(domain):
    """PUT /api/targets/<domain> - Update target details."""
    try:
        data = request.get_json()
        if not data:
            return jsonify({
                "success": False,
                "error": "No data provided"
            }), 400

        db = get_db()

        # Only allow updating these fields
        allowed_fields = ["org_name", "description", "status"]
        update_data = {}
        for field in allowed_fields:
            if field in data:
                update_data[field] = data[field]

        if not update_data:
            return jsonify({
                "success": False,
                "error": f"No valid fields to update. Allowed: {allowed_fields}"
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

        print(f"[TARGETS] Updated target: {domain}")

        return jsonify({
            "success": True,
            "message": f"Target '{domain}' updated",
            "updated_fields": list(update_data.keys())
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Delete Target ───────────────────────────────────────────────────────

@targets_bp.route("/<domain>", methods=["DELETE"])
def delete_target(domain):
    """DELETE /api/targets/<domain> - Remove a target and all its data."""
    try:
        db = get_db()

        # Check if target exists
        target = db[Config.TARGETS_COLLECTION].find_one({"root_domain": domain})
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found"
            }), 404

        # Cascade delete — remove ALL data for this domain
        deleted_counts = {}

        deleted_counts["subdomains"] = db[Config.SUBDOMAINS_COLLECTION].delete_many(
            {"target_domain": domain}
        ).deleted_count

        deleted_counts["ports"] = db[Config.PORTS_COLLECTION].delete_many(
            {"target_domain": domain}
        ).deleted_count

        deleted_counts["http_assets"] = db[Config.HTTP_ASSETS_COLLECTION].delete_many(
            {"target_domain": domain}
        ).deleted_count

        deleted_counts["vulnerabilities"] = db[Config.VULNS_COLLECTION].delete_many(
            {"target_domain": domain}
        ).deleted_count

        deleted_counts["changes"] = db[Config.CHANGES_COLLECTION].delete_many(
            {"target_domain": domain}
        ).deleted_count

        deleted_counts["scans"] = db[Config.SCANS_COLLECTION].delete_many(
            {"target_domain": domain}
        ).deleted_count

        # Delete the target itself
        db[Config.TARGETS_COLLECTION].delete_one({"root_domain": domain})

        print(f"[TARGETS] Deleted target: {domain} (cascade)")

        return jsonify({
            "success": True,
            "message": f"Target '{domain}' and all associated data deleted",
            "deleted": deleted_counts
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500