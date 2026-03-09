"""
Remediation Routes — API Endpoints for Remediation Dashboard

Endpoints:
    GET  /api/remediation/<domain>              Full remediation plan
    GET  /api/remediation/<domain>/summary       Quick stats (for dashboard)
    GET  /api/remediation/vuln/<vuln_id>         Single vuln detail
    PATCH /api/remediation/status/<vuln_id>      Update vuln status
    GET  /remediation                            GUI page (template render)
    GET  /remediation/<domain>                   GUI page for specific domain
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


remediation_bp = Blueprint("remediation", __name__)


# =============================================================================
# HELPERS
# =============================================================================

def _find_target(domain):
    """Find target by domain or root_domain."""
    db = get_db()
    target = db[Config.TARGETS_COLLECTION].find_one({"root_domain": domain})
    if not target:
        target = db[Config.TARGETS_COLLECTION].find_one({"domain": domain})
    return target


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


# =============================================================================
# GUI PAGES
# =============================================================================

@remediation_bp.route("/remediation")
def remediation_page_no_domain():
    """
    GET /remediation — Remediation page without domain selected.
    Shows domain selector.
    """
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
    """
    GET /remediation/<domain> — Remediation page for a specific domain.
    The actual data is loaded via JavaScript calling the API endpoints.
    """
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
    """
    GET /api/remediation/<domain>

    Returns full remediation plan with:
        - Summary stats
        - Priority breakdown
        - All remediation items sorted by priority

    Query params:
        severity: Filter by severity (critical, high, medium, low, info)
        status: Filter by status (open, in_progress, resolved, false_positive)
        limit: Max items to return (default: all)
    """
    try:
        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found"
            }), 404

        target_id = str(target["_id"])

        # Generate remediation plan
        plan = get_remediation_plan(target_id, domain)

        if not plan.get("success"):
            return jsonify(plan), 500

        # Apply filters
        items = plan.get("remediation_items", [])

        severity_filter = request.args.get("severity")
        if severity_filter:
            items = [
                i for i in items
                if i.get("severity", "").lower() == severity_filter.lower()
            ]

        status_filter = request.args.get("status")
        if status_filter:
            items = [
                i for i in items
                if i.get("status", "").lower() == status_filter.lower()
            ]

        limit = request.args.get("limit", type=int)
        if limit and limit > 0:
            items = items[:limit]

        plan["remediation_items"] = items
        plan["filtered_count"] = len(items)

        return jsonify(plan)

    except Exception as e:
        print(f"[REMEDIATION API] Error: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@remediation_bp.route("/api/remediation/<domain>/summary", methods=["GET"])
def api_remediation_summary(domain):
    """
    GET /api/remediation/<domain>/summary

    Returns quick summary stats (no enrichment API calls).
    Fast endpoint for dashboard widgets.
    """
    try:
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
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@remediation_bp.route("/api/remediation/vuln/<vuln_id>", methods=["GET"])
def api_single_remediation(vuln_id):
    """
    GET /api/remediation/vuln/<vuln_id>

    Returns detailed remediation for a single vulnerability.
    Used when user clicks on a vuln card for full details.

    Query params:
        target_id: Required — the target this vuln belongs to
    """
    try:
        target_id = request.args.get("target_id")
        if not target_id:
            return jsonify({
                "success": False,
                "error": "target_id query parameter is required"
            }), 400

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
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@remediation_bp.route("/api/remediation/status/<vuln_id>", methods=["PATCH"])
def api_update_status(vuln_id):
    """
    PATCH /api/remediation/status/<vuln_id>

    Update vulnerability status from remediation page.

    Body JSON:
        {"status": "open|in_progress|resolved|false_positive"}
    """
    try:
        data = request.get_json()
        if not data or "status" not in data:
            return jsonify({
                "success": False,
                "error": "Request body must include 'status' field"
            }), 400

        new_status = data["status"]
        result = update_remediation_status(vuln_id, new_status)

        if result.get("success"):
            return jsonify(result)
        else:
            return jsonify(result), 400

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


@remediation_bp.route("/api/remediation/<domain>/export", methods=["GET"])
def api_export_plan(domain):
    """
    GET /api/remediation/<domain>/export

    Export remediation plan as a structured report.
    Can be used for PDF generation or management reporting.

    Query params:
        format: json (default) — more formats can be added later
    """
    try:
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

        # Build export document
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
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500