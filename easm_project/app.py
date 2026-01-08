from flask import Flask, render_template, request, redirect, url_for, jsonify
from scanner import step_1_subfinder, step_2_naabu, step_3_httpx, step_4_nuclei
from db import save_scan_result, get_all_scans, get_scan_by_id
import threading

app = Flask(__name__)

# --- ROUTES ---

@app.route('/')
def index():
    """Homepage: Input form + History"""
    history = get_all_scans()
    return render_template('index.html', history=history)

@app.route('/scan', methods=['POST'])
def start_scan():
    """Receives domain from form, starts scan in background"""
    domain = request.form.get('domain')
    
    # Run scan in a separate thread so UI doesn't freeze
    thread = threading.Thread(target=run_full_scan, args=(domain,))
    thread.start()
    
    return render_template('scanning.html', domain=domain)

@app.route('/report/<scan_id>')
def report(scan_id):
    """Shows the final dashboard for a scan"""
    scan_data = get_scan_by_id(scan_id)
    if not scan_data:
        return "Scan not found", 404
    return render_template('dashboard.html', scan=scan_data)

# --- HELPER FUNCTION ---
def run_full_scan(target):
    """
    Orchestrates the scan and saves to DB.
    NOTE: In a real app, use Celery. For FYP, Threading is fine.
    """
    print(f"[API] Starting scan for {target}")
    subs = step_1_subfinder(target)
    ports = []
    live_urls = []
    vulns = []

    if subs:
        ports = step_2_naabu(subs)
    if ports:
        live_urls = step_3_httpx(ports)
    if live_urls:
        vulns = step_4_nuclei(live_urls)
    
    # Save to DB
    save_scan_result(target, subs, ports, live_urls, vulns)
    print("[API] Scan Finished and Saved.")

if __name__ == "__main__":
    app.run(debug=True, port=5000)