# routes/reports.py

import os
from datetime import datetime
from flask import Blueprint, jsonify, send_file
from bson import ObjectId
from database.connection import get_db
from reports.report_generator import generate_report
from reports.pdf_generator import generate_pdf

reports_bp = Blueprint("reports", __name__, url_prefix="/api/reports")


def _serialize(doc):
    """Convert MongoDB document to JSON-safe dict (handles all types)."""
    if doc is None:
        return None

    if isinstance(doc, list):
        return [_serialize(d) for d in doc]

    if isinstance(doc, dict):
        result = {}
        for key, value in doc.items():
            if isinstance(value, ObjectId):
                result[key] = str(value)
            elif isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, (dict, list)):
                result[key] = _serialize(value)
            else:
                result[key] = value
        return result

    if isinstance(doc, ObjectId):
        return str(doc)

    if isinstance(doc, datetime):
        return doc.isoformat()

    return doc


@reports_bp.route("/json/<domain>", methods=["GET"])
def get_report_json(domain):
    """GET /api/reports/json/<domain> - Get report data as JSON"""
    try:
        db = get_db()
        report_data = generate_report(domain, db)
        return jsonify({
            "success": True,
            "report": _serialize(report_data)
        })
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@reports_bp.route("/generate/<domain>", methods=["POST"])
def generate_report_endpoint(domain):
    """POST /api/reports/generate/<domain> - Generate PDF report"""
    try:
        db = get_db()
        report_data = generate_report(domain, db)
        pdf_path = generate_pdf(report_data)
        return jsonify({
            "success": True,
            "message": f"Report generated for {domain}",
            "file_path": pdf_path
        })
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@reports_bp.route("/download/<domain>", methods=["GET"])
def download_report(domain):
    """GET /api/reports/download/<domain> - Download PDF report"""
    try:
        safe_domain = domain.replace(".", "_")
        reports_dir = "generated_reports"

        if not os.path.exists(reports_dir):
            return jsonify({"success": False, "error": "No reports directory found"}), 404

        matching_files = [f for f in os.listdir(reports_dir) if f.startswith(f"report_{safe_domain}") and f.endswith(".pdf")]
        if not matching_files:
            return jsonify({"success": False, "error": f"No report found for {domain}"}), 404

        matching_files.sort(reverse=True)
        pdf_path = os.path.join(reports_dir, matching_files[0])
        return send_file(pdf_path, mimetype="application/pdf", as_attachment=True, download_name=f"easm_report_{safe_domain}.pdf")
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@reports_bp.route("/", methods=["GET"])
def list_reports():
    """GET /api/reports/ - List all generated reports"""
    try:
        reports_dir = "generated_reports"
        if not os.path.exists(reports_dir):
            return jsonify({"success": True, "count": 0, "reports": []})

        files = [f for f in os.listdir(reports_dir) if f.endswith(".pdf")]
        reports = []
        for f in files:
            filepath = os.path.join(reports_dir, f)
            reports.append({
                "filename": f,
                "size_kb": round(os.path.getsize(filepath) / 1024, 2),
                "created_at": datetime.fromtimestamp(os.path.getctime(filepath)).isoformat()
            })
        reports.sort(key=lambda x: x["created_at"], reverse=True)
        return jsonify({"success": True, "count": len(reports), "reports": reports})
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@reports_bp.route("/summary/<domain>", methods=["GET"])
def get_executive_summary(domain):
    """GET /api/reports/summary/<domain> - Get brief executive summary"""
    try:
        db = get_db()
        summary_data = get_executive_summary(domain, db)
        return jsonify({
            "success": True,
            "summary": _serialize(summary_data)
        })
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@reports_bp.route("/remediation/<domain>", methods=["GET"])
def get_remediation_report(domain):
    """GET /api/reports/remediation/<domain> - Get remediation plan"""
    try:
        db = get_db()
        remediation_data = get_remediation_report(domain, db)
        return jsonify({
            "success": True,
            "remediation": _serialize(remediation_data)
        })
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500