

from flask import (
    Flask, jsonify, render_template,
    request, session, redirect, url_for
)
from functools import wraps
from config import Config
from database.connection import init_db, test_connection, get_db
from utils.logger import logger                                    # ◄ NEW
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
from routes.emails import emails_bp
from routes.passive_recon import passive_bp

# ─── Create Flask App ─────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY


def initialize_app():
    """Initialize the EASM application and verify database connection."""
                                             
    
                                             

    if test_connection():
        init_db()
        logger.info("Application initialized")       
    else:
        logger.error("Failed to connect to MongoDB")              
        logger.error(                                              
            "Make sure MongoDB is running on %s",                 
            Config.MONGO_URI                                      
        )                                                         

    os.makedirs("generated_reports", exist_ok=True)
    logger.info("Reports directory ready")                        


# ─── Register Blueprints ──────────────────────────────────────────────────
app.register_blueprint(targets_bp)
app.register_blueprint(scans_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(assets_bp)
app.register_blueprint(changes_bp)
app.register_blueprint(vulns_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(remediation_bp)
app.register_blueprint(emails_bp)
app.register_blueprint(passive_bp)


# AUTHENTICATION


PUBLIC_ROUTES = {
    "login",
    "static",
    "health_check",
}


@app.before_request
def require_login():
    """Global authentication guard."""
    if request.endpoint in PUBLIC_ROUTES:
        return None

    if session.get("logged_in"):
        return None

    if request.path.startswith("/api/"):
        return jsonify({
            "success": False,
            "error": "Authentication required. Please log in."
        }), 401
    else:
        return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    """GET /login — Show login form. POST /login — Authenticate."""
    if session.get("logged_in"):
        return redirect("/dashboard")

    error = None

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if (
            username == Config.ADMIN_USER
            and password == Config.ADMIN_PASS
        ):
            session["logged_in"] = True
            session["username"] = username
            session.permanent = True
            logger.info("User '%s' logged in", username)          
            return redirect("/dashboard")
        else:
            error = "Invalid username or password"
            logger.warning(                                       
                "Failed login attempt for user '%s'", username    
            )                                                     

    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    """Clear session and redirect to login page."""
    username = session.get("username", "unknown")
    session.clear()
    logger.info("User '%s' logged out", username)                 
    return redirect(url_for("login"))


# CORE API ROUTES

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
            "scan_history": db[Config.SCANS_COLLECTION].count_documents({}),
            "emails": db[Config.EMAILS_COLLECTION].count_documents({}),
             "passive_recon": {
                "shodan_subdomains": db[Config.SUBDOMAINS_COLLECTION].count_documents(
                    {"sources": "shodan"}
                ),
                "censys_subdomains": db[Config.SUBDOMAINS_COLLECTION].count_documents(
                    {"sources": "censys"}
                ),
                "shodan_ports": db[Config.PORTS_COLLECTION].count_documents(
                    {"sources": "shodan"}                         
                ),
                "censys_ports": db[Config.PORTS_COLLECTION].count_documents(
                    {"sources": "censys"}                         
                ),
            }
        })
    except Exception as e:
        logger.error("Stats endpoint error: %s", e)
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


# Template Routes

@app.route("/dashboard")
def dashboard_view():
    return render_template("dashboard.html", active_page="dashboard")

@app.route("/targets")
def targets_view():
    return render_template("targets.html", active_page="targets")

@app.route("/targets/<domain>")
def target_detail_view(domain):
    return render_template("target_detail.html", active_page="targets", domain=domain)
@app.route("/recon")
def recon_view():
    return render_template("recon.html", active_page="recon")
@app.route("/scans")
def scans_view():
    return render_template("scans.html", active_page="scans")

@app.route("/assets")
def assets_view():
    return render_template(
        "asset_breakdown.html",
        active_page="assets",
        domain=None
    )
@app.route("/api/passive-recon/<domain>")
def passive_recon_data(domain):
    from database.passive_recon_db import get_passive_recon
    records = get_passive_recon(domain)
    return jsonify({
        "success": True,
        "domain": domain,
        "records": records
    })
@app.route("/targets/<domain>/assets")
def target_assets_breakdown(domain):
    return render_template(
        "asset_breakdown.html",
        active_page="assets",
        domain=domain
    )
@app.route("/vulnerabilities")
def vulnerabilities_view():
    return render_template("vulnerabilities.html", active_page="vulnerabilities")

@app.route("/changes")
def changes_view():
    return render_template("changes.html", active_page="changes")

@app.route("/reports")
def reports_view():
    return render_template("reports.html", active_page="reports")

@app.route("/emails")
def emails_view():
    return render_template("emails.html", active_page="emails")


# Entry Point

if __name__ == "__main__":
    initialize_app()
    logger.info(
        "Starting AEGIS on port %d (debug=%s)",
        Config.PORT, Config.DEBUG
    )                                                             
    app.run(
        host="0.0.0.0",
        port=Config.PORT,
        debug=Config.DEBUG,
        use_reloader=False,
        threaded=True
    )
