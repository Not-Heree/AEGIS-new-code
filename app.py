"""
AEGIS - Web Application Module
==============================
This is the main Flask application for the AEGIS EASM dashboard.
It handles all HTTP routes including:
    - Landing page for submitting scan requests
    - Scan status polling API
    - Dashboard / Report views
    - PDF report generation

The actual scanning logic is delegated to scanner.py, which runs in a
background thread to avoid blocking the web UI.
"""

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    make_response
)
from scanner import step_1_subfinder, step_2_naabu, step_3_httpx, step_4_nuclei
from db import get_db
import threading
import re
from datetime import datetime
from typing import Dict, Any, Optional, List
import pdfkit


# =============================================================================
# APPLICATION INITIALIZATION
# =============================================================================
app: Flask = Flask(__name__)


# =============================================================================
# INPUT VALIDATION
# =============================================================================

def sanitize_domain(domain_input: str) -> Optional[str]:
    """
    Validates and sanitizes a user-provided domain string.

    This is a critical security function. We must ensure the input is a
    legitimate domain before passing it to subprocess calls to prevent
    command injection attacks.

    Args:
        domain_input: The raw domain string from the user form.

    Returns:
        A cleaned, lowercase domain string if valid.
        Returns None if the input is invalid or potentially malicious.

    Examples:
        >>> sanitize_domain("  Example.COM  ")
        'example.com'
        >>> sanitize_domain("https://example.com/path")
        'example.com'
        >>> sanitize_domain("; rm -rf /")
        None
    """
    if not domain_input:
        return None

    # Step 1: Strip whitespace and convert to lowercase.
    cleaned: str = domain_input.strip().lower()

    # Step 2: Remove common protocol prefixes.
    cleaned = cleaned.replace("http://", "").replace("https://", "")

    # Step 3: Remove trailing slashes and paths.
    cleaned = cleaned.split("/")[0]

    # Step 4: Validate against a regex pattern for valid domain characters.
    # A valid domain consists of alphanumeric characters, hyphens, and dots.
    # We explicitly disallow any special characters used in shell injection.
    domain_pattern: re.Pattern = re.compile(
        r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
    )

    if not domain_pattern.match(cleaned):
        print(f"[!] Invalid domain rejected: {domain_input}")
        return None

    return cleaned


# =============================================================================
# ROUTES
# =============================================================================

@app.route('/')
def index() -> str:
    """
    Renders the landing page with the scan input form.

    Returns:
        Rendered HTML for the index.html template.
    """
    return render_template('index.html')


@app.route('/history')
def history() -> str:
    """
    Renders the history page showing all previous scans.

    Returns:
        Rendered HTML for the history.html template with scan data.
    """
    scan_history: List[Dict[str, Any]] = get_db().get_all_scans()
    return render_template('history.html', history=scan_history)


@app.route('/scan', methods=['POST'])
def start_scan() -> str:
    """
    Handles the scan form submission.

    Validates the domain input, creates a new scan record in the database,
    and starts the scanning pipeline in a background thread.

    Returns:
        Rendered HTML for the scanning.html template (shows progress).
        Returns an error page if the domain is invalid.
    """
    raw_domain: str = request.form.get('domain', '')

    # Validate and sanitize the domain before doing anything else.
    # This is essential to prevent command injection via subprocess.
    domain: Optional[str] = sanitize_domain(raw_domain)
    if not domain:
        return render_template(
            'error.html',
            message="Invalid domain format. Please enter a valid domain like 'example.com'."
        ), 400

    # Create a new scan record in the database.
    db = get_db()
    scan_id: str = db.create_scan(domain)
    db.update_scan_status(scan_id, "initializing")

    # Spawn a background thread to run the scan.
    # This prevents the web UI from freezing during long scans.
    thread: threading.Thread = threading.Thread(
        target=run_full_scan,
        args=(domain, scan_id)
    )
    thread.start()

    return render_template('scanning.html', scan_id=scan_id, domain=domain)


@app.route('/report/<scan_id>')
def report(scan_id: str) -> str:
    """
    Renders the main dashboard/report for a completed scan.

    Args:
        scan_id: The MongoDB ObjectId string for the scan.

    Returns:
        Rendered HTML for the report.html template with all scan data.
        Returns a 404 error if the scan is not found.
    """
    scan_data: Optional[Dict[str, Any]] = get_db().get_scan_summary(scan_id)
    if not scan_data:
        return "Scan not found", 404

    return render_template(
        'report.html',
        scan=scan_data['scan'],
        assets=scan_data['assets'],
        vulnerabilities=scan_data['vulnerabilities'],
        statistics=scan_data['statistics']
    )


@app.route('/pdf/<scan_id>')
def download_pdf(scan_id: str):
    """
    Generates and returns a PDF report for download.

    Args:
        scan_id: The MongoDB ObjectId string for the scan.

    Returns:
        A PDF file as an attachment.
        Returns a 500 error if PDF generation fails (e.g., wkhtmltopdf not installed).
    """
    scan_data: Optional[Dict[str, Any]] = get_db().get_scan_summary(scan_id)
    if not scan_data:
        return "Scan not found", 404

    # Render an HTML template designed specifically for PDF output.
    html: str = render_template(
        'pdf_report.html',
        scan=scan_data['scan'],
        assets=scan_data['assets'],
        statistics=scan_data['statistics'],
        vulnerabilities=scan_data['vulnerabilities'],
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M")
    )

    # PDF generation options for clean output.
    options: Dict[str, Any] = {
        'page-size': 'A4',
        'margin-top': '0mm',
        'margin-right': '0mm',
        'margin-bottom': '0mm',
        'margin-left': '0mm',
        'encoding': "UTF-8",
        'no-outline': None
    }

    try:
        # pdfkit wraps wkhtmltopdf. The second arg (False) means output to memory.
        pdf: bytes = pdfkit.from_string(html, False, options=options)

        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = (
            f'attachment; filename=AEGIS_Report_{scan_data["scan"]["target_domain"]}.pdf'
        )
        return response
    except Exception as e:
        print(f"[!] PDF Generation Error: {e}")
        return f"Error generating PDF. Ensure wkhtmltopdf is installed. Details: {e}", 500


@app.route('/api/scan/<scan_id>/status')
def get_scan_status_api(scan_id: str):
    """
    API endpoint for polling scan status.

    The frontend JavaScript calls this endpoint periodically to update the
    progress bar and status message on the scanning page.

    Args:
        scan_id: The MongoDB ObjectId string for the scan.

    Returns:
        JSON object with status, current_phase, and progress percentage.
    """
    db = get_db()
    status_data: Optional[Dict[str, Any]] = db.get_scan_status(scan_id)

    if not status_data:
        return jsonify({"success": False, "error": "Scan not found"}), 404

    return jsonify({
        "success": True,
        "status": status_data['status'],
        "current_phase": status_data['current_phase'],
        "progress": status_data['progress_percent'],
        "message": f"Phase: {status_data['current_phase']}..."
    })


# =============================================================================
# BACKGROUND SCAN ORCHESTRATOR
# =============================================================================

def run_full_scan(target: str, scan_id: str) -> None:
    """
    Orchestrates the full "Sniper" scanning pipeline.

    This function is designed to run in a background thread. It calls each
    scanning step sequentially and updates the database with progress and
    results after each phase completes.

    Pipeline:
        1. Subfinder (Asset Discovery) -> Count for "Assets Found" card
        2. Naabu (Port Scan) -> Count for "Open Ports" card
        3. HTTPX (Web Probe) -> Live URLs
        4. Nuclei (Vuln Scan) -> Count for "Critical Issues" card

    Args:
        target: The validated domain to scan.
        scan_id: The database ID for this scan record.

    Returns:
        None. All results are written to the database.
    """
    print(f"[AEGIS] Starting scan for {target}")
    db = get_db()

    # Initialize scan status.
    db.update_scan_status(scan_id, "running", phase="starting", progress=0)

    try:
        # =====================================================================
        # PHASE 1: Asset Discovery (Subfinder)
        # =====================================================================
        db.update_scan_status(scan_id, "running", phase="subfinder", progress=10)
        subs: List[str] = step_1_subfinder(target)

        # Always include the root domain itself as an asset.
        if target not in subs:
            subs.append(target)

        if subs:
            db.add_assets_bulk(scan_id, subs)
        db.mark_phase_completed(scan_id, "subfinder")

        # =====================================================================
        # PHASE 2: Port Scanning (Naabu)
        # =====================================================================
        db.update_scan_status(scan_id, "running", phase="naabu", progress=30)
        ports: List[Dict[str, Any]] = []
        if subs:
            ports = step_2_naabu(subs)
            if ports:
                db.add_ports_bulk(scan_id, ports)
        db.mark_phase_completed(scan_id, "naabu")

        # =====================================================================
        # PHASE 3: Web Probing (HTTPX)
        # =====================================================================
        db.update_scan_status(scan_id, "running", phase="httpx", progress=60)
        live_urls: List[Dict[str, Any]] = []
        if ports:
            live_urls = step_3_httpx(ports)
            if live_urls:
                db.add_live_urls_bulk(scan_id, live_urls)
        db.mark_phase_completed(scan_id, "httpx")

        # =====================================================================
        # PHASE 4: Vulnerability Scanning (Nuclei)
        # =====================================================================
        db.update_scan_status(scan_id, "running", phase="nuclei", progress=80)
        vulns: List[Dict[str, Any]] = []
        if live_urls:
            vulns = step_4_nuclei(live_urls)
            if vulns:
                db.add_vulnerabilities_bulk(scan_id, vulns)
        db.mark_phase_completed(scan_id, "nuclei")

        # =====================================================================
        # SCAN COMPLETE
        # =====================================================================
        db.update_scan_status(scan_id, "completed", phase="done", progress=100)
        print(f"[AEGIS] Scan {scan_id} completed successfully.")

    except Exception as e:
        # Log the error and mark the scan as failed.
        print(f"[!] Scan failed: {e}")
        import traceback
        traceback.print_exc()
        db.add_scan_error(scan_id, str(e))
        db.update_scan_status(scan_id, "failed")


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

if __name__ == "__main__":
    # Run the Flask development server on port 5000.
    # debug=True enables hot-reloading and detailed error pages.
    app.run(debug=True, port=5000)
