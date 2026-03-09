# routes/changes.py

from flask import Blueprint, jsonify, request
from bson import ObjectId
from database.connection import get_db
from config import Config

changes_bp = Blueprint("changes", __name__, url_prefix="/api/changes")


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


def _serialize_list(docs):
    return [_serialize(doc) for doc in docs]


# ─── GET All Changes ─────────────────────────────────────────────────────

@changes_bp.route("/", methods=["GET"])
def get_all_changes():
    """GET /api/changes/ - List all changes"""
    try:
        db = get_db()
        changes = _serialize_list(
            db[Config.CHANGES_COLLECTION].find()
            .sort("detected_at", -1)
            .limit(100)
        )
        return jsonify({
            "success": True,
            "count": len(changes),
            "changes": changes
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── GET Changes by Domain ───────────────────────────────────────────────

@changes_bp.route("/<domain>", methods=["GET"])
def get_changes_by_domain(domain):
    """GET /api/changes/<domain> - Get changes for a domain"""
    try:
        db = get_db()
        changes = _serialize_list(
            db[Config.CHANGES_COLLECTION].find(
                {"target_domain": domain}
            ).sort("detected_at", -1).limit(50)
        )
        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(changes),
            "changes": changes
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── GET Unacknowledged Changes ──────────────────────────────────────────

@changes_bp.route("/unacknowledged/<domain>", methods=["GET"])
def get_unacknowledged(domain):
    """GET /api/changes/unacknowledged/<domain> - Unacknowledged changes"""
    try:
        db = get_db()
        changes = _serialize_list(
            db[Config.CHANGES_COLLECTION].find({
                "target_domain": domain,
                "acknowledged": {"$ne": True}
            }).sort("detected_at", -1)
        )
        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(changes),
            "changes": changes
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── PATCH Acknowledge Change ────────────────────────────────────────────

@changes_bp.route("/acknowledge/<change_id>", methods=["PATCH"])
def acknowledge_change(change_id):
    """PATCH /api/changes/acknowledge/<change_id> - Acknowledge a change"""
    try:
        db = get_db()
        result = db[Config.CHANGES_COLLECTION].update_one(
            {"_id": ObjectId(change_id)},
            {"$set": {"acknowledged": True}}
        )
        if result.matched_count == 0:
            return jsonify({
                "success": False,
                "error": "Change not found"
            }), 404

        return jsonify({
            "success": True,
            "message": "Change acknowledged"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── DELETE All Changes for Domain ──────────────────────────────────────

@changes_bp.route("/<domain>", methods=["DELETE"])
def delete_changes(domain):
    """DELETE /api/changes/<domain> - Delete all changes for domain"""
    try:
        db = get_db()
        result = db[Config.CHANGES_COLLECTION].delete_many(
            {"target_domain": domain}
        )
        return jsonify({
            "success": True,
            "message": f"Deleted {result.deleted_count} changes",
            "deleted_count": result.deleted_count
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500