# routes/reports.py

import os
from datetime import datetime

from flask import Blueprint, jsonify, send_file

from database.connection import get_db
from reports.pdf_generator import generate_pdf
from reports.report_generator import generate_report
from utils.logger import logger

reports_bp = Blueprint("reports", __name__, url_prefix="/api/reports")


@reports_bp.route("/generate/<domain>", methods=["POST"])
def generate_report_endpoint(domain):
    """POST /api/reports/generate/<domain> - Generate full PDF report."""
    try:
        db = get_db()
        report_data = generate_report(domain, db)
        pdf_path = generate_pdf(report_data)
        return jsonify({
            "success": True,
            "message": f"Full report generated for {domain}",
            "file_path": pdf_path
        })
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@reports_bp.route("/download/<domain>", methods=["GET"])
def download_report(domain):
    """GET /api/reports/download/<domain> - Download latest full PDF report."""
    try:
        safe_domain = domain.replace(".", "_")
        reports_dir = "generated_reports"

        if not os.path.exists(reports_dir):
            return jsonify({
                "success": False,
                "error": "No reports directory found"
            }), 404

        matching_files = [
            f for f in os.listdir(reports_dir)
            if f.startswith(f"report_{safe_domain}") and f.endswith(".pdf")
        ]
        if not matching_files:
            return jsonify({
                "success": False,
                "error": f"No report found for {domain}"
            }), 404

        matching_files.sort(reverse=True)
        pdf_path = os.path.join(reports_dir, matching_files[0])
        return send_file(
            pdf_path,
            mimetype="application/pdf",
            as_attachment=True,
            download_name=f"easm_report_{safe_domain}.pdf"
        )
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500


@reports_bp.route("/", methods=["GET"])
def list_reports():
    """GET /api/reports/ - List generated PDF reports."""
    try:
        reports_dir = "generated_reports"
        if not os.path.exists(reports_dir):
            return jsonify({"success": True, "count": 0, "reports": []})

        files = [f for f in os.listdir(reports_dir) if f.endswith(".pdf")]
        reports = []
        for filename in files:
            filepath = os.path.join(reports_dir, filename)
            reports.append({
                "filename": filename,
                "size_kb": round(os.path.getsize(filepath) / 1024, 2),
                "created_at": datetime.fromtimestamp(
                    os.path.getctime(filepath)
                ).isoformat()
            })

        reports.sort(key=lambda item: item["created_at"], reverse=True)
        return jsonify({
            "success": True,
            "count": len(reports),
            "reports": reports
        })
    except Exception as error:
        return jsonify({"success": False, "error": str(error)}), 500
