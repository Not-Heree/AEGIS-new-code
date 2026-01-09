"""
ARES - Flask Application (app.py)
Web Application for External Attack Surface Management

This module provides:
- Web routes for the EASM dashboard
- Async scan execution using threading
- PDF report generation using pdfkit
- RESTful API endpoints for scan management
"""

import os
import io
import json
import threading
from datetime import datetime
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    jsonify,
    Response,
    flash,
    make_response
)

# Import project modules
from db import db, get_db
from scanner import Scanner, start_scan, run_scan_async, get_scan_status
from remediation import get_remediation, get_stats as get_remediation_stats

# Try to import pdfkit (optional - for PDF generation)
try:
    import pdfkit
    PDFKIT_AVAILABLE = True
except ImportError:
    PDFKIT_AVAILABLE = False
    print("[WARNING] pdfkit not installed. PDF generation will be disabled.")


# ==================== FLASK APP CONFIGURATION ====================

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ares-easm-secret-key-change-in-production')

# Store active scan threads
active_scans = {}


# ==================== UTILITY FUNCTIONS ====================

def format_datetime(dt):
    """Format datetime object for display."""
    if dt is None:
        return "N/A"
    if isinstance(dt, str):
        return dt
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def get_severity_color(severity):
    """Get Bootstrap color class for severity level."""
    colors = {
        "critical": "danger",
        "high": "warning",
        "medium": "info",
        "low": "secondary",
        "info": "primary"
    }
    return colors.get(severity.lower(), "secondary")


def get_severity_order(severity):
    """Get numeric order for severity sorting (higher = more severe)."""
    order = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1
    }
    return order.get(severity.lower(), 0)


# Register template filters
app.jinja_env.filters['datetime'] = format_datetime
app.jinja_env.filters['severity_color'] = get_severity_color


# ==================== WEB ROUTES ====================

@app.route('/')
def index():
    """
    Landing Page - ARES Scan entry point.
    Displays the minimalist scan input form.
    """
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def initiate_scan():
    """
    Initiate a new scan for a target domain.
    Starts the scan in a background thread.
    """
    target_domain = request.form.get('target_domain', '').strip().lower()
    
    # Validate input
    if not target_domain:
        flash('Please enter a valid domain.', 'error')
        return redirect(url_for('index'))
    
    # Remove protocol if present
    target_domain = target_domain.replace('https://', '').replace('http://', '')
    target_domain = target_domain.rstrip('/')
    
    # Basic domain validation
    if not target_domain or ' ' in target_domain:
        flash('Invalid domain format.', 'error')
        return redirect(url_for('index'))
    
    # Create scan record
    scan_id = db.create_scan(target_domain)
    
    # Start scan in background thread
    scan_thread = threading.Thread(
        target=run_scan_in_thread,
        args=(scan_id, target_domain),
        daemon=True
    )
    scan_thread.start()
    
    # Track active scan
    active_scans[scan_id] = {
        "thread": scan_thread,
        "target": target_domain,
        "started_at": datetime.utcnow()
    }
    
    # Redirect to scanning page
    return redirect(url_for('scanning', scan_id=scan_id))


def run_scan_in_thread(scan_id, target_domain):
    """
    Execute scan in a separate thread.
    
    Args:
        scan_id (str): The scan ID
        target_domain (str): The target domain
    """
    try:
        scanner = Scanner(scan_id, target_domain)
        scanner.run_full_scan()
    except Exception as e:
        print(f"[ERROR] Scan thread error: {e}")
        db.update_scan_status(scan_id, "failed")
        db.add_error(scan_id, str(e))
    finally:
        # Remove from active scans
        if scan_id in active_scans:
            del active_scans[scan_id]


@app.route('/scanning/<scan_id>')
def scanning(scan_id):
    """
    Scanning progress page.
    Shows real-time scan status and redirects to dashboard when complete.
    """
    scan = db.get_scan(scan_id)
    
    if not scan:
        flash('Scan not found.', 'error')
        return redirect(url_for('index'))
    
    # If scan is complete, redirect to dashboard
    if scan.get('status') == 'completed':
        return redirect(url_for('dashboard', scan_id=scan_id))
    
    return render_template('scanning.html', scan=scan, scan_id=scan_id)


@app.route('/dashboard/<scan_id>')
def dashboard(scan_id):
    """
    Dashboard page - displays scan results.
    Shows assets, ports, vulnerabilities with remediation capabilities.
    """
    scan = db.get_scan(scan_id)
    
    if not scan:
        flash('Scan not found.', 'error')
        return redirect(url_for('index'))
    
    # Get vulnerabilities sorted by severity
    vulnerabilities = scan.get('vulnerabilities', [])
    vulnerabilities_sorted = sorted(
        vulnerabilities,
        key=lambda v: get_severity_order(v.get('info', {}).get('severity', v.get('severity', 'info'))),
        reverse=True
    )
    
    # Prepare vulnerability data with remediation info
    vuln_data = []
    for vuln in vulnerabilities_sorted:
        template_id = vuln.get('template_id', vuln.get('template-id', 'unknown'))
        
        # Get severity from nested info or direct field
        if isinstance(vuln.get('info'), dict):
            severity = vuln['info'].get('severity', 'info')
            name = vuln['info'].get('name', template_id)
        else:
            severity = vuln.get('severity', 'info')
            name = vuln.get('template_name', template_id)
        
        # Get remediation data
        remediation = get_remediation(template_id)
        
        vuln_data.append({
            'id': template_id,
            'name': name,
            'severity': severity,
            'severity_color': get_severity_color(severity),
            'host': vuln.get('host', vuln.get('matched_at', 'N/A')),
            'matched_at': vuln.get('matched_at', vuln.get('matched-at', 'N/A')),
            'description': remediation.get('description', ''),
            'mitre_id': remediation.get('mitre_id', 'N/A'),
            'mitre_name': remediation.get('mitre_name', 'N/A'),
            'fix_commands': remediation.get('fix_commands', ''),
            'raw': vuln
        })
    
    # Calculate statistics
    stats = scan.get('stats', {})
    
    return render_template(
        'dashboard.html',
        scan=scan,
        scan_id=scan_id,
        vulnerabilities=vuln_data,
        stats=stats,
        subdomains=scan.get('subdomains', []),
        ports=scan.get('ports', []),
        live_hosts=scan.get('live_hosts', [])
    )


@app.route('/about')
def about():
    """About page - information about ARES."""
    remediation_stats = get_remediation_stats()
    return render_template('about.html', stats=remediation_stats)


# ==================== API ENDPOINTS ====================

@app.route('/api/scan/status/<scan_id>')
def api_scan_status(scan_id):
    """
    API endpoint to get scan status.
    Used for polling during scan progress.
    """
    scan = db.get_scan(scan_id)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    return jsonify({
        "scan_id": scan_id,
        "status": scan.get("status"),
        "progress": scan.get("progress"),
        "stats": scan.get("stats"),
        "target_domain": scan.get("target_domain"),
        "created_at": format_datetime(scan.get("created_at")),
        "completed_at": format_datetime(scan.get("completed_at"))
    })


@app.route('/api/scan/results/<scan_id>')
def api_scan_results(scan_id):
    """
    API endpoint to get full scan results.
    """
    scan = db.get_scan(scan_id)
    
    if not scan:
        return jsonify({"error": "Scan not found"}), 404
    
    # Convert ObjectId to string for JSON serialization
    scan['_id'] = str(scan['_id'])
    
    # Convert datetime objects
    if scan.get('created_at'):
        scan['created_at'] = format_datetime(scan['created_at'])
    if scan.get('updated_at'):
        scan['updated_at'] = format_datetime(scan['updated_at'])
    if scan.get('completed_at'):
        scan['completed_at'] = format_datetime(scan['completed_at'])
    
    return jsonify(scan)


@app.route('/api/remediation/<template_id>')
def api_remediation(template_id):
    """
    API endpoint to get remediation info for a vulnerability.
    """
    remediation = get_remediation(template_id)
    return jsonify(remediation)


@app.route('/api/scans')
def api_list_scans():
    """
    API endpoint to list all scans.
    """
    scans = db.get_all_scans(limit=50)
    
    result = []
    for scan in scans:
        result.append({
            "scan_id": str(scan['_id']),
            "target_domain": scan.get("target_domain"),
            "status": scan.get("status"),
            "stats": scan.get("stats"),
            "created_at": format_datetime(scan.get("created_at"))
        })
    
    return jsonify(result)


# ==================== PDF GENERATION ====================

@app.route('/download/pdf/<scan_id>')
def download_pdf(scan_id):
    """
    Generate and download PDF report for a scan.
    Uses pdfkit with wkhtmltopdf.
    """
    if not PDFKIT_AVAILABLE:
        flash('PDF generation is not available. Please install pdfkit and wkhtmltopdf.', 'error')
        return redirect(url_for('dashboard', scan_id=scan_id))
    
    scan = db.get_scan(scan_id)
    
    if not scan:
        flash('Scan not found.', 'error')
        return redirect(url_for('index'))
    
    # Get vulnerabilities with remediation data
    vulnerabilities = scan.get('vulnerabilities', [])
    vuln_data = []
    
    for vuln in vulnerabilities:
        template_id = vuln.get('template_id', vuln.get('template-id', 'unknown'))
        
        if isinstance(vuln.get('info'), dict):
            severity = vuln['info'].get('severity', 'info')
            name = vuln['info'].get('name', template_id)
        else:
            severity = vuln.get('severity', 'info')
            name = vuln.get('template_name', template_id)
        
        remediation = get_remediation(template_id)
        
        vuln_data.append({
            'id': template_id,
            'name': name,
            'severity': severity,
            'host': vuln.get('host', 'N/A'),
            'description': remediation.get('description', ''),
            'fix_commands': remediation.get('fix_commands', '')
        })
    
    # Sort by severity
    vuln_data.sort(key=lambda v: get_severity_order(v['severity']), reverse=True)
    
    # Render PDF template
    html_content = render_template(
        'pdf_report.html',
        scan=scan,
        scan_id=scan_id,
        vulnerabilities=vuln_data,
        stats=scan.get('stats', {}),
        subdomains=scan.get('subdomains', []),
        ports=scan.get('ports', []),
        live_hosts=scan.get('live_hosts', []),
        generated_at=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    
    try:
        # PDF options for better formatting
        options = {
            'page-size': 'A4',
            'margin-top': '15mm',
            'margin-right': '15mm',
            'margin-bottom': '15mm',
            'margin-left': '15mm',
            'encoding': 'UTF-8',
            'no-outline': None,
            'enable-local-file-access': None
        }
        
        # Generate PDF from HTML
        pdf = pdfkit.from_string(html_content, False, options=options)
        
        # Create response with PDF
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=ARES_Report_{scan.get("target_domain")}_{scan_id[:8]}.pdf'
        
        return response
        
    except Exception as e:
        print(f"[ERROR] PDF generation failed: {e}")
        flash(f'PDF generation failed: {str(e)}. Make sure wkhtmltopdf is installed.', 'error')
        return redirect(url_for('dashboard', scan_id=scan_id))


# ==================== SCAN MANAGEMENT ====================

@app.route('/scan/delete/<scan_id>', methods=['POST'])
def delete_scan(scan_id):
    """Delete a scan record."""
    if db.delete_scan(scan_id):
        flash('Scan deleted successfully.', 'success')
    else:
        flash('Failed to delete scan.', 'error')
    
    return redirect(url_for('index'))


@app.route('/history')
def scan_history():
    """Display scan history."""
    scans = db.get_all_scans(limit=100)
    
    scan_list = []
    for scan in scans:
        scan_list.append({
            "scan_id": str(scan['_id']),
            "target_domain": scan.get("target_domain"),
            "status": scan.get("status"),
            "stats": scan.get("stats", {}),
            "created_at": scan.get("created_at"),
            "completed_at": scan.get("completed_at")
        })
    
    return render_template('history.html', scans=scan_list)


# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def page_not_found(e):
    """Handle 404 errors."""
    return render_template('error.html', error="Page not found", code=404), 404


@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors."""
    return render_template('error.html', error="Internal server error", code=500), 500


# ==================== CONTEXT PROCESSORS ====================

@app.context_processor
def inject_globals():
    """Inject global variables into all templates."""
    return {
        'app_name': 'ARES',
        'app_version': '1.0.0',
        'current_year': datetime.utcnow().year
    }


# ==================== MAIN ENTRY POINT ====================

if __name__ == '__main__':
    print("\n" + "="*60)
    print("   ARES - Automated Remediation & Enumeration System")
    print("   External Attack Surface Management Dashboard")
    print("="*60)
    print(f"\n[*] Starting Flask development server...")
    print(f"[*] PDF Generation: {'Enabled' if PDFKIT_AVAILABLE else 'Disabled'}")
    print(f"[*] Open http://127.0.0.1:5000 in your browser")
    print("\n" + "="*60 + "\n")
    
    # Run Flask development server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True,
        threaded=True
    )
