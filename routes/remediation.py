"""
Remediation Routes
"""

from flask import Blueprint, jsonify, request, render_template
from bson import ObjectId
from datetime import datetime

from database.connection import get_db
from config import Config
from core.remediation_engine import (
    get_remediation_plan,
    get_single_remediation,
    update_remediation_status,
    get_remediation_summary_stats
)
from utils.logger import logger
from utils.sanitize import (                              # ◄ NEW
    sanitize_domain, sanitize_object_id,                  # ◄ NEW
    sanitize_status, sanitize_string                      # ◄ NEW
)                                                         # ◄ NEW

remediation_bp = Blueprint("remediation", __name__)


# =============================================================================
# HELPERS
# =============================================================================

def _find_target(domain):
    db = get_db()
    target = db[Config.TARGETS_COLLECTION].find_one({"root_domain": domain})
    if not target:
        target = db[Config.TARGETS_COLLECTION].find_one({"domain": domain})
    return target


def _serialize(doc):
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


# =============================================================================
# GUI PAGES
# =============================================================================

@remediation_bp.route("/remediation")
def remediation_page_no_domain():
    try:
        db = get_db()
        targets = list(db[Config.TARGETS_COLLECTION].find(
            {}, {"domain": 1, "root_domain": 1, "risk_score": 1, "total_vulns": 1}
        ))
        for t in targets:
            t["_id"] = str(t["_id"])

        return render_template(
            "remediation.html",
            active_page="remediation",
            domain=None,
            targets=targets
        )
    except Exception as e:
        return render_template(
            "remediation.html",
            active_page="remediation",
            domain=None,
            targets=[],
            error=str(e)
        )


@remediation_bp.route("/remediation/<domain>")
def remediation_page(domain):
    try:                                                   # ◄ NEW
        domain = sanitize_domain(domain)                   # ◄ NEW
    except ValueError:                                     # ◄ NEW
        return render_template(                            # ◄ NEW
            "remediation.html",                            # ◄ NEW
            active_page="remediation",                     # ◄ NEW
            domain=domain,                                 # ◄ NEW
            targets=[],                                    # ◄ NEW
            error=f"Invalid domain: '{domain}'"            # ◄ NEW
        )                                                  # ◄ NEW

    target = _find_target(domain)
    if not target:
        return render_template(
            "remediation.html",
            active_page="remediation",
            domain=domain,
            targets=[],
            error=f"Target '{domain}' not found"
        )

    return render_template(
        "remediation.html",
        active_page="remediation",
        domain=domain,
        target_id=str(target["_id"]),
        targets=[]
    )


# =============================================================================
# API ENDPOINTS
# =============================================================================

@remediation_bp.route("/api/remediation/<domain>", methods=["GET"])
def api_remediation_plan(domain):
    try:
        try:                                               # ◄ NEW
            domain = sanitize_domain(domain)               # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found"
            }), 404

        target_id = str(target["_id"])
        plan = get_remediation_plan(target_id, domain)

        if not plan.get("success"):
            return jsonify(plan), 500

        items = plan.get("remediation_items", [])

        severity_filter = request.args.get("severity")
        if severity_filter:
            try:                                           # ◄ NEW
                severity_filter = sanitize_string(         # ◄ NEW
                    severity_filter, "severity"            # ◄ NEW
                ).lower()                                  # ◄ NEW
            except ValueError:                             # ◄ NEW
                severity_filter = None                     # ◄ NEW

            if severity_filter:
                items = [
                    i for i in items
                    if i.get("severity", "").lower() == severity_filter
                ]

        status_filter = request.args.get("status")
        if status_filter:
            try:                                           # ◄ NEW
                status_filter = sanitize_string(           # ◄ NEW
                    status_filter, "status"                # ◄ NEW
                ).lower()                                  # ◄ NEW
            except ValueError:                             # ◄ NEW
                status_filter = None                       # ◄ NEW

            if status_filter:
                items = [
                    i for i in items
                    if i.get("status", "").lower() == status_filter
                ]

        limit = request.args.get("limit", type=int)
        if limit and limit > 0:
            items = items[:limit]

        plan["remediation_items"] = items
        plan["filtered_count"] = len(items)

        return jsonify(plan)

    except Exception as e:
        logger.error("[REMEDIATION API] Error: %s", e, exc_info=True)
        return jsonify({"success": False, "error": str(e)}), 500


@remediation_bp.route("/api/remediation/<domain>/summary", methods=["GET"])
def api_remediation_summary(domain):
    try:
        try:                                               # ◄ NEW
            domain = sanitize_domain(domain)               # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found"
            }), 404

        target_id = str(target["_id"])
        stats = get_remediation_summary_stats(target_id)

        return jsonify({
            "success": True,
            "domain": domain,
            "stats": stats
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@remediation_bp.route("/api/remediation/vuln/<vuln_id>", methods=["GET"])
def api_single_remediation(vuln_id):
    try:
        try:                                               # ◄ NEW
            vuln_id = sanitize_object_id(                  # ◄ NEW
                vuln_id, "vuln_id"                         # ◄ NEW
            )                                              # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        target_id = request.args.get("target_id")
        if not target_id:
            return jsonify({
                "success": False,
                "error": "target_id query parameter is required"
            }), 400

        try:                                               # ◄ NEW
            target_id = sanitize_object_id(                # ◄ NEW
                target_id, "target_id"                     # ◄ NEW
            )                                              # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        item = get_single_remediation(vuln_id, target_id)

        if not item:
            return jsonify({
                "success": False,
                "error": "Vulnerability not found"
            }), 404

        return jsonify({
            "success": True,
            "remediation": item
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@remediation_bp.route("/api/remediation/status/<vuln_id>", methods=["PATCH"])
def api_update_status(vuln_id):
    """
    PATCH /api/remediation/status/<vuln_id>
    Update vulnerability status from remediation page.
    Also recalculates risk score.
    """
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
                "error": "Request body must include 'status' field"
            }), 400

        try:
            new_status = sanitize_status(
                data["status"],
                ("open", "in_progress",
                 "resolved", "false_positive"),
                "status"
            )
        except ValueError as e:
            return jsonify({
                "success": False, "error": str(e)
            }), 400

        result = update_remediation_status(vuln_id, new_status)

        # ═══════════════════════════════════════════════      # ◄ NEW SECTION
        # Recalculate risk score after status change
        # ═══════════════════════════════════════════════
        if result.get("success"):                              # ◄ NEW
            try:                                               # ◄ NEW
                db = get_db()                                  # ◄ NEW
                vuln = db[Config.VULNS_COLLECTION].find_one(   # ◄ NEW
                    {"_id": ObjectId(vuln_id)}                 # ◄ NEW
                )                                              # ◄ NEW
                if vuln and vuln.get("target_id"):             # ◄ NEW
                    from core.risk_scorer import (             # ◄ NEW
                        calculate_risk_score                   # ◄ NEW
                    )                                          # ◄ NEW
                    new_score = calculate_risk_score(           # ◄ NEW
                        str(vuln["target_id"])                  # ◄ NEW
                    )                                          # ◄ NEW
                    db[Config.TARGETS_COLLECTION].update_one(  # ◄ NEW
                        {"_id": vuln["target_id"]},            # ◄ NEW
                        {"$set": {"risk_score": new_score}}    # ◄ NEW
                    )                                          # ◄ NEW
                    result["new_risk_score"] = new_score        # ◄ NEW
            except Exception as e:                             # ◄ NEW
                logger.warning("[REMEDIATION] Risk recalc error: %s", e)

        if result.get("success"):
            return jsonify(result)
        else:
            return jsonify(result), 400

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@remediation_bp.route("/api/remediation/<domain>/export", methods=["GET"])
def api_export_plan(domain):
    try:
        try:                                               # ◄ NEW
            domain = sanitize_domain(domain)               # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found"
            }), 404

        target_id = str(target["_id"])
        plan = get_remediation_plan(target_id, domain)

        if not plan.get("success"):
            return jsonify(plan), 500

        export = {
            "report_title": f"Remediation Plan — {domain}",
            "generated_at": datetime.utcnow().isoformat(),
            "target_domain": domain,
            "executive_summary": plan["summary"]["message"],
            "total_vulnerabilities": plan["summary"]["total_vulns"],
            "actively_exploited": plan["summary"]["kev_count"],
            "priority_breakdown": plan["priority_breakdown"],
            "items": []
        }

        for item in plan.get("remediation_items", []):
            export_item = {
                "rank": item.get("rank", 0),
                "name": item.get("name", ""),
                "severity": item.get("severity", ""),
                "priority_score": item.get("priority_score", 0),
                "priority_label": item.get("priority_label", ""),
                "host": item.get("host", ""),
                "cve_id": item.get("cve_id", ""),
                "is_actively_exploited": item.get("is_kev", False),
                "fix_by_date": item.get("fix_by_date", ""),
                "remediation_summary": item.get("remediation", {}).get("summary", ""),
                "remediation_steps": item.get("remediation", {}).get("detailed_steps", []),
                "patch_urls": item.get("patch_urls", []),
                "status": item.get("status", "open")
            }
            export["items"].append(export_item)

        return jsonify({
            "success": True,
            "export": export
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# REMEDIATION TRACKER UI
# =============================================================================

@remediation_bp.route("/remediation-tracker/<vuln_id>")
def remediation_tracker(vuln_id):
    """
    Display interactive remediation tracker for a specific vulnerability.

    Shows step-by-step remediation guidance with progress tracking capability.
    """
    try:
        try:
            vuln_id = sanitize_object_id(vuln_id)
        except ValueError as e:
            logger.warning(f"Invalid vuln_id format: {vuln_id}")
            return render_template("remediation_tracker.html",
                                 error="Invalid vulnerability ID")

        db = get_db()
        vuln = db[Config.VULNS_COLLECTION].find_one({"_id": ObjectId(vuln_id)})

        if not vuln:
            return render_template("remediation_tracker.html",
                                 error="Vulnerability not found")

        # Get remediation details
        remediation = get_single_remediation(vuln_id)

        return render_template(
            "remediation_tracker.html",
            vuln_name=vuln.get("name", "Unknown Vulnerability"),
            cve_id=vuln.get("cve_id", "N/A"),
            severity=vuln.get("severity", "MEDIUM").upper(),
            affected_endpoint=vuln.get("host", "N/A"),
            discovered_date=vuln.get("discovered_at", "Unknown"),
            remediation_plan=remediation.get("detailed_steps", []),
            resources=remediation.get("resources", []),
            deadline=remediation.get("fix_by_date", "7 days"),
            active_page="remediation"
        )

    except Exception as e:
        logger.error(f"Error loading remediation tracker: {e}", exc_info=True)
        return render_template("remediation_tracker.html",
                             error=f"Error loading remediation tracker: {str(e)}")
