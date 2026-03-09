# app.py
from flask import Flask, jsonify, render_template
from config import Config
from database.connection import init_db, test_connection, get_db
import os

# ─── Blueprint Imports ────────────────────────────────────────────────────
from routes.targets import targets_bp
from routes.scans import scans_bp
from routes.dashboard import dashboard_bp
from routes.assets import assets_bp
from routes.changes import changes_bp
from routes.vulns import vulns_bp
from routes.reports import reports_bp
from routes.remediation import remediation_bp

# ─── Create Flask App ─────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY


def initialize_app():
    """Initialize the EASM application and verify database connection."""
    print("=" * 50)
    print("  EASM TOOL - External Attack Surface Management")
    print("=" * 50)

    if test_connection():
        init_db()
        print("✅ Application initialized successfully")
    else:
        print("❌ Failed to connect to MongoDB")
        print("   Make sure MongoDB is running on localhost:27017")

    os.makedirs("generated_reports", exist_ok=True)
    print("✅ Reports directory ready")


# ─── Register Blueprints ──────────────────────────────────────────────────
app.register_blueprint(targets_bp)
app.register_blueprint(scans_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(assets_bp)
app.register_blueprint(changes_bp)
app.register_blueprint(vulns_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(remediation_bp)

# ─── Core API Routes ──────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("dashboard.html", active_page="dashboard")


@app.route("/api/health")
def health_check():
    try:
        is_connected = test_connection()
        return jsonify({
            "status": "healthy" if is_connected else "unhealthy",
            "database": "connected" if is_connected else "disconnected",
            "app": "EASM Tool"
        })
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)})


@app.route("/api/stats")
def stats():
    try:
        db = get_db()
        return jsonify({
            "targets": db[Config.TARGETS_COLLECTION].count_documents({}),
            "subdomains": db[Config.SUBDOMAINS_COLLECTION].count_documents({}),
            "ports_services": db[Config.PORTS_COLLECTION].count_documents({}),
            "http_assets": db[Config.HTTP_ASSETS_COLLECTION].count_documents({}),
            "vulnerabilities": db[Config.VULNS_COLLECTION].count_documents({}),
            "changes": db[Config.CHANGES_COLLECTION].count_documents({}),
            "scan_history": db[Config.SCANS_COLLECTION].count_documents({})
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/routes")
def list_routes():
    routes = []
    for rule in app.url_map.iter_rules():
        routes.append({
            "endpoint": rule.endpoint,
            "methods": sorted(list(rule.methods - {"HEAD", "OPTIONS"})),
            "url": str(rule)
        })
    return jsonify({
        "total": len(routes),
        "routes": sorted(routes, key=lambda x: x["url"])
    })


# ─── Template Routes ──────────────────────────────────────────────────────

@app.route("/dashboard")
def dashboard_view():
    return render_template("dashboard.html", active_page="dashboard")


@app.route("/targets")
def targets_view():
    return render_template("targets.html", active_page="targets")


@app.route("/targets/<domain>")
def target_detail_view(domain):
    return render_template("target_detail.html", active_page="targets", domain=domain)


@app.route("/scans")
def scans_view():
    return render_template("scans.html", active_page="scans")


@app.route("/assets")
def assets_view():
    return render_template("assets.html", active_page="assets")


@app.route("/vulnerabilities")
def vulnerabilities_view():
    return render_template("vulnerabilities.html", active_page="vulnerabilities")


@app.route("/changes")
def changes_view():
    return render_template("changes.html", active_page="changes")


@app.route("/reports")
def reports_view():
    return render_template("reports.html", active_page="reports")


# ─── Entry Point ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    initialize_app()
    app.run(
        host="0.0.0.0",
        port=Config.PORT,
        debug=Config.DEBUG,
        threaded=True
    )