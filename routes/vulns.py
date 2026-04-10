# routes/vulns.py

from flask import Blueprint, jsonify, request, render_template
from bson import ObjectId
from database.connection import get_db
from config import Config
from core.cve_enricher import enrich_vulnerability, initialize as init_enricher
from utils.logger import logger
from utils.sanitize import (                              # ◄ NEW
    sanitize_domain, sanitize_object_id,                  # ◄ NEW
    sanitize_status, sanitize_severity                    # ◄ NEW
)                                                         # ◄ NEW

vulns_bp = Blueprint("vulns", __name__, url_prefix="/api/vulns")

# Initialize enricher on blueprint load
try:
    init_enricher()
except Exception as e:
    logger.warning(f"Enricher initialization skipped: {e}")


def _serialize(doc):
    """Convert MongoDB document to JSON-safe dict."""
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
        try:                                               # ◄ NEW
            domain = sanitize_domain(domain)               # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

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
        try:                                               # ◄ NEW
            domain = sanitize_domain(domain)               # ◄ NEW
            severity = sanitize_severity(severity)         # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        db = get_db()
        vulns = _serialize_list(
            db[Config.VULNS_COLLECTION].find({
                "target_domain": domain,
                "severity": severity
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
        try:                                               # ◄ NEW
            domain = sanitize_domain(domain)               # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        db = get_db()

        severities = ["critical", "high", "medium", "low", "info"]
        breakdown = {}
        for sev in severities:
            breakdown[sev] = db[Config.VULNS_COLLECTION].count_documents({
                "target_domain": domain,
                "severity": sev
            })

        total = sum(breakdown.values())

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


# ─── Update Vuln Status ─────────────────────────────────────────────────

@vulns_bp.route("/<vuln_id>/status", methods=["PATCH"])
def update_vuln_status(vuln_id):
    """PATCH /api/vulns/<vuln_id>/status — Mark as resolved/false_positive/open."""
    try:
        try:
            vuln_id = sanitize_object_id(
                vuln_id, "vuln_id"
            )
        except ValueError as e:
            return jsonify({
                "success": False, "error": str(e)
            }), 400

        data = request.get_json()
        if not data or "status" not in data:
            return jsonify({
                "success": False,
                "error": "status required. Options: open, resolved, false_positive"
            }), 400

        try:
            new_status = sanitize_status(
                data["status"],
                ("open", "resolved", "false_positive"),
                "status"
            )
        except ValueError as e:
            return jsonify({
                "success": False, "error": str(e)
            }), 400

        db = get_db()
        update_fields = {"status": new_status}
        if new_status == "resolved":
            from datetime import datetime
            update_fields["resolved_at"] = datetime.utcnow()
        elif new_status == "open":
            update_fields["resolved_at"] = None

        result = db[Config.VULNS_COLLECTION].update_one(
            {"_id": ObjectId(vuln_id)},
            {"$set": update_fields}
        )

        if result.matched_count == 0:
            return jsonify({"success": False, "error": "Vuln not found"}), 404

        # ═══════════════════════════════════════════════      # ◄ NEW SECTION
        # Recalculate risk score immediately
        # ═══════════════════════════════════════════════
        new_risk_score = None                                  # ◄ NEW
        try:                                                   # ◄ NEW
            vuln = db[Config.VULNS_COLLECTION].find_one(       # ◄ NEW
                {"_id": ObjectId(vuln_id)}                     # ◄ NEW
            )                                                  # ◄ NEW
            if vuln and vuln.get("target_id"):                 # ◄ NEW
                from core.risk_scorer import (                 # ◄ NEW
                    calculate_risk_score                       # ◄ NEW
                )                                              # ◄ NEW
                target_id_str = str(vuln["target_id"])         # ◄ NEW
                new_risk_score = calculate_risk_score(         # ◄ NEW
                    target_id_str                              # ◄ NEW
                )                                              # ◄ NEW
                                                               # ◄ NEW
                db[Config.TARGETS_COLLECTION].update_one(      # ◄ NEW
                    {"_id": vuln["target_id"]},                # ◄ NEW
                    {"$set": {"risk_score": new_risk_score}}   # ◄ NEW
                )                                              # ◄ NEW
                print(                                         # ◄ NEW
                    f"[VULNS] Risk score recalculated: "       # ◄ NEW
                    f"{new_risk_score}/100"                    # ◄ NEW
                )                                              # ◄ NEW
        except Exception as e:                                 # ◄ NEW
            print(                                             # ◄ NEW
                f"[VULNS] Risk recalc error: {e}"             # ◄ NEW
            )                                                  # ◄ NEW

        response = {                                           # ◄ CHANGED
            "success": True,
            "message": f"Vulnerability marked as {new_status}"
        }
        if new_risk_score is not None:                         # ◄ NEW
            response["new_risk_score"] = new_risk_score        # ◄ NEW

        return jsonify(response)

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# ─── GET Vuln Detail ────────────────────────────────────────────────────

@vulns_bp.route("/<vuln_id>/detail", methods=["GET"])
def get_vuln_detail(vuln_id):
    """GET /api/vulns/<vuln_id>/detail — Full vulnerability details."""
    try:
        try:                                               # ◄ NEW
            vuln_id = sanitize_object_id(                  # ◄ NEW
                vuln_id, "vuln_id"                         # ◄ NEW
            )                                              # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        db = get_db()
        vuln = db[Config.VULNS_COLLECTION].find_one(
            {"_id": ObjectId(vuln_id)}
        )
        if not vuln:
            return jsonify({"success": False, "error": "Not found"}), 404

        return jsonify({"success": True, "vulnerability": _serialize(vuln)})
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# HTML ROUTES (for rendering templates)
# =============================================================================

@vulns_bp.route("/<vuln_id>/show", methods=["GET"])
def show_vuln_detail(vuln_id):
    """
    Show detailed view of a single vulnerability with enrichment.
    
    ✅ Enrichment happens HERE, on-demand, not during storage
    
    GET /vulns/<vuln_id>/show
    """
    try:
        try:
            vuln_id = sanitize_object_id(vuln_id, "vuln_id")
        except ValueError as e:
            return f"Invalid vuln_id: {e}", 400

        db = get_db()
        vuln = db[Config.VULNS_COLLECTION].find_one({"_id": ObjectId(vuln_id)})
        
        if not vuln:
            return "Vulnerability not found", 404
        
        # ── ENRICHMENT: Compute on retrieval ────────────────
        logger.info(f"[VULN] Enriching {vuln.get('template_id')} for display...")
        
        try:
            enrichment = enrich_vulnerability(vuln)
            vuln['enrichment'] = enrichment
            logger.info(f"[VULN] Enrichment complete: Priority={enrichment.get('priority_label')}")
        except Exception as e:
            logger.error(f"[VULN] Enrichment failed: {e}", exc_info=True)
            # Continue without enrichment - don't break the page
            vuln['enrichment'] = None
        
        # Get target info
        if vuln.get('target_id'):
            try:
                target = db[Config.TARGETS_COLLECTION].find_one({'_id': ObjectId(vuln['target_id'])})
                vuln['target'] = target
            except Exception:
                vuln['target'] = None
        
        # Serialize the MongoDB document to make it JSON-safe for the template
        safe_vuln = _serialize(vuln)
        
        return render_template('vulnerability_detail.html', vuln=safe_vuln)
    
    except Exception as e:
        logger.error(f"[VULN] Error loading vulnerability {vuln_id}: {e}", exc_info=True)
        return f"Error loading vulnerability: {e}", 500

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500