# routes/assets.py

from flask import Blueprint, jsonify, request
from bson import ObjectId
from database.connection import get_db
from config import Config

assets_bp = Blueprint("assets", __name__, url_prefix="/api/assets")


def _serialize(doc):
    """Convert MongoDB document to JSON-safe dict."""
    if doc and "_id" in doc:
        doc["_id"] = str(doc["_id"])
    return doc


def _serialize_list(docs):
    """Convert list of MongoDB documents to JSON-safe list."""
    return [_serialize(doc) for doc in docs]


# ─── GET All HTTP Assets ─────────────────────────────────────────────────

@assets_bp.route("/", methods=["GET"])
def get_all_assets():
    """GET /api/assets/ - List all HTTP assets"""
    try:
        db = get_db()
        assets = _serialize_list(
            db[Config.HTTP_ASSETS_COLLECTION].find()
        )
        return jsonify({
            "success": True,
            "count": len(assets),
            "assets": assets
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── GET Assets by Domain ────────────────────────────────────────────────

@assets_bp.route("/<domain>", methods=["GET"])
def get_assets_by_domain(domain):
    """GET /api/assets/<domain> - Get HTTP assets for a domain"""
    try:
        db = get_db()
        assets = _serialize_list(
            db[Config.HTTP_ASSETS_COLLECTION].find(
                {"target_domain": domain}
            )
        )
        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(assets),
            "assets": assets
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── GET Asset Stats by Domain ───────────────────────────────────────────

@assets_bp.route("/stats/<domain>", methods=["GET"])
def get_asset_stats(domain):
    """GET /api/assets/stats/<domain> - Get HTTP asset statistics"""
    try:
        db = get_db()

        total = db[Config.HTTP_ASSETS_COLLECTION].count_documents(
            {"target_domain": domain}
        )

        # Count by status code
        pipeline = [
            {"$match": {"target_domain": domain}},
            {"$group": {
                "_id": "$status_code",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}}
        ]
        by_status = list(
            db[Config.HTTP_ASSETS_COLLECTION].aggregate(pipeline)
        )

        # Count by technology
        tech_pipeline = [
            {"$match": {"target_domain": domain}},
            {"$unwind": "$technologies"},
            {"$group": {
                "_id": "$technologies",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        by_tech = list(
            db[Config.HTTP_ASSETS_COLLECTION].aggregate(tech_pipeline)
        )

        return jsonify({
            "success": True,
            "domain": domain,
            "total": total,
            "by_status_code": by_status,
            "top_technologies": by_tech
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── DELETE Asset ────────────────────────────────────────────────────────

@assets_bp.route("/<asset_id>", methods=["DELETE"])
def delete_asset(asset_id):
    """DELETE /api/assets/<asset_id> - Delete an HTTP asset"""
    try:
        db = get_db()
        result = db[Config.HTTP_ASSETS_COLLECTION].delete_one(
            {"_id": ObjectId(asset_id)}
        )
        if result.deleted_count == 0:
            return jsonify({
                "success": False,
                "error": "Asset not found"
            }), 404

        return jsonify({
            "success": True,
            "message": "Asset deleted successfully"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500