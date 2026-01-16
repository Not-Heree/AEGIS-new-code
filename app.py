from flask import Flask, render_template, request, redirect, url_for, jsonify, make_response
from scanner import step_1_subfinder, step_2_naabu, step_3_httpx, step_4_nuclei
from db import get_db
import threading
from datetime import datetime
import pdfkit
import os

app = Flask(__name__)

# --- ROUTES ---

@app.route('/')
def index():
    """Homepage: Input form"""
    return render_template('index.html')

@app.route('/history')
def history():
    """History Page: List of all scans"""
    history = get_db().get_all_scans()
    return render_template('history.html', history=history)

@app.route('/scan', methods=['POST'])
def start_scan():
    """Receives domain from form, starts scan in background"""
    domain = request.form.get('domain')
    
    # 1. Create Scan Record immediately
    db = get_db()
    scan_id = db.create_scan(domain)
    db.update_scan_status(scan_id, "initializing")
    
    # Run scan in a separate thread so UI doesn't freeze
    thread = threading.Thread(target=run_full_scan, args=(domain, scan_id))
    thread.start()
    
    return render_template('scanning.html', scan_id=scan_id, domain=domain)

@app.route('/report/<scan_id>')
def report(scan_id):
    """Shows the final dashboard for a scan"""
    # Use get_scan_summary for the full dashboard data
    scan_data = get_db().get_scan_summary(scan_id)
    if not scan_data:
        return "Scan not found", 404
    return render_template('dashboard.html', scan=scan_data['scan'], assets=scan_data['assets'], vulnerabilities=scan_data['vulnerabilities'], statistics=scan_data['statistics'])

@app.route('/pdf/<scan_id>')
def download_pdf(scan_id):
    """Generates and downloads a PDF report"""
    scan_data = get_db().get_scan_summary(scan_id)
    if not scan_data:
        return "Scan not found", 404
        
    html = render_template('pdf_report.html', 
                          scan=scan_data['scan'], 
                          assets=scan_data['assets'], 
                          statistics=scan_data['statistics'],
                          vulnerabilities=scan_data['vulnerabilities'],
                          generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"))
    
    options = {
        'page-size': 'A4',
        'margin-top': '0mm',
        'margin-right': '0mm',
        'margin-bottom': '0mm',
        'margin-left': '0mm',
        'encoding': "UTF-8",
        'no-outline': None
    }
    
    try:
        # Check if wkhtmltopdf is in path, otherwise you might need configuration
        # For now assuming it is in PATH as per verify_setup.py check
        pdf = pdfkit.from_string(html, False, options=options)
        
        response = make_response(pdf)
        response.headers['Content-Type'] = 'application/pdf'
        response.headers['Content-Disposition'] = f'attachment; filename=ARES_Report_{scan_data["scan"]["target_domain"]}.pdf'
        return response
    except Exception as e:
        print(f"PDF Error: {e}")
        return f"Error generating PDF. Ensure wkhtmltopdf is installed. Details: {e}", 500

@app.route('/api/scan/<scan_id>/status')
def get_scan_status_api(scan_id):
    """API Endpoint for polling scan status"""
    db = get_db()
    status_data = db.get_scan_status(scan_id)
    if not status_data:
        return jsonify({"success": False, "error": "Scan not found"}), 404
    
    return jsonify({
        "success": True,
        "status": status_data['status'],
        "current_phase": status_data['current_phase'],
        "progress": status_data['progress_percent'],
        "message": f"Phase: {status_data['current_phase']}..." # Simple message for now
    })

# --- HELPER FUNCTION ---
def run_full_scan(target, scan_id):
    """
    Orchestrates the scan and saves to DB incrementally.
    """
    print(f"[API] Starting scan for {target}")
    db = get_db()
    
    # Start
    db.update_scan_status(scan_id, "running", phase="starting", progress=0)
    
    try:
        # Step 1: Subfinder
        db.update_scan_status(scan_id, "running", phase="subfinder", progress=10)
        subs = step_1_subfinder(target)
        
        # Ensure the target itself is always included (even if subfinder fails)
        if target not in subs:
            subs.append(target)
            
        if subs:
            db.add_assets_bulk(scan_id, subs)
        db.mark_phase_completed(scan_id, "subfinder")
        
        # Step 2: Naabu
        db.update_scan_status(scan_id, "running", phase="naabu", progress=30)
        ports = []
        if subs:
            ports = step_2_naabu(subs)
            if ports:
                # scanner.py returns list of dicts {host, port}
                db.add_ports_bulk(scan_id, ports)
        db.mark_phase_completed(scan_id, "naabu")
        
        # Step 3: HTTPX
        db.update_scan_status(scan_id, "running", phase="httpx", progress=60)
        live_urls = []
        # Get all ports from DB just to be safe or pass them along? 
        # For simplicity, we use what we just found. 
        # Ideally, we should fetch from DB to be stateless, but this is fine.
        if ports:
            live_urls = step_3_httpx(ports)
            if live_urls:
                # scanner.py returns list of dicts (rich data)
                db.add_live_urls_bulk(scan_id, live_urls)
        db.mark_phase_completed(scan_id, "httpx")
        
        # Step 4: Nuclei
        db.update_scan_status(scan_id, "running", phase="nuclei", progress=80)
        vulns = []
        if live_urls:
            vulns = step_4_nuclei(live_urls)
            if vulns:
                # scanner.py returns list of dicts (with correct keys now)
                db.add_vulnerabilities_bulk(scan_id, vulns)
        db.mark_phase_completed(scan_id, "nuclei")
        
        # Completion
        db.update_scan_status(scan_id, "completed", phase="done", progress=100)
        print(f"[API] Scan {scan_id} Finished and Saved.")
        
    except Exception as e:
        print(f"[!] Scan failed: {e}")
        import traceback
        traceback.print_exc()
        db.add_scan_error(scan_id, str(e))
        db.update_scan_status(scan_id, "failed")

if __name__ == "__main__":
    app.run(debug=True, port=5000)
