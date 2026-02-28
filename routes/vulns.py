# routes/vulns.py

from flask import Blueprint, jsonify, request
from bson import ObjectId
from database.connection import get_db
from config import Config

vulns_bp = Blueprint("vulns", __name__, url_prefix="/api/vulns")


def _serialize(doc):
    """Convert MongoDB document to JSON-safe dict."""
    if doc and "_id" in doc:
        doc["_id"] = str(doc["_id"])
    return doc


def _serialize_list(docs):
    """Convert list of MongoDB documents to JSON-safe list."""
    return [_serialize(doc) for doc in docs]


# ─── GET All Vulnerabilities ─────────────────────────────────────────────

@vulns_bp.route("/", methods=["GET"])
def get_all_vulns():
    """GET /api/vulns/ - List all vulnerabilities"""
    try:
        db = get_db()
        vulns = _serialize_list(
            db[Config.VULNS_COLLECTION].find()
            .sort("severity", 1)
        )
        return jsonify({
            "success": True,
            "count": len(vulns),
            "vulnerabilities": vulns
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── GET Vulns by Domain ─────────────────────────────────────────────────

@vulns_bp.route("/<domain>", methods=["GET"])
def get_vulns_by_domain(domain):
    """GET /api/vulns/<domain> - Get vulnerabilities for a domain"""
    try:
        db = get_db()
        vulns = _serialize_list(
            db[Config.VULNS_COLLECTION].find(
                {"target_domain": domain}
            ).sort("severity", 1)
        )
        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(vulns),
            "vulnerabilities": vulns
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── GET Vulns by Severity ───────────────────────────────────────────────

@vulns_bp.route("/<domain>/severity/<severity>", methods=["GET"])
def get_vulns_by_severity(domain, severity):
    """GET /api/vulns/<domain>/severity/<severity>"""
    try:
        db = get_db()
        vulns = _serialize_list(
            db[Config.VULNS_COLLECTION].find({
                "target_domain": domain,
                "severity": severity.lower()
            })
        )
        return jsonify({
            "success": True,
            "domain": domain,
            "severity": severity,
            "count": len(vulns),
            "vulnerabilities": vulns
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── GET Vuln Stats ──────────────────────────────────────────────────────

@vulns_bp.route("/stats/<domain>", methods=["GET"])
def get_vuln_stats(domain):
    """GET /api/vulns/stats/<domain> - Vulnerability statistics"""
    try:
        db = get_db()

        # Count by severity
        severities = ["critical", "high", "medium", "low", "info"]
        breakdown = {}
        for sev in severities:
            breakdown[sev] = db[Config.VULNS_COLLECTION].count_documents({
                "target_domain": domain,
                "severity": sev
            })

        total = sum(breakdown.values())

        # Top vulnerability types
        pipeline = [
            {"$match": {"target_domain": domain}},
            {"$group": {
                "_id": "$vulnerability",
                "count": {"$sum": 1},
                "severity": {"$first": "$severity"}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        top_vulns = list(
            db[Config.VULNS_COLLECTION].aggregate(pipeline)
        )

        return jsonify({
            "success": True,
            "domain": domain,
            "total": total,
            "by_severity": breakdown,
            "top_vulnerabilities": top_vulns
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── DELETE Vuln ─────────────────────────────────────────────────────────

@vulns_bp.route("/<vuln_id>", methods=["DELETE"])
def delete_vuln(vuln_id):
    """DELETE /api/vulns/<vuln_id> - Delete a vulnerability"""
    try:
        db = get_db()
        result = db[Config.VULNS_COLLECTION].delete_one(
            {"_id": ObjectId(vuln_id)}
        )
        if result.deleted_count == 0:
            return jsonify({
                "success": False,
                "error": "Vulnerability not found"
            }), 404

        return jsonify({
            "success": True,
            "message": "Vulnerability deleted"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500