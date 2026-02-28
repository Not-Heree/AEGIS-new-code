from flask import Blueprint

# Create blueprints
targets_bp = Blueprint("targets", __name__, url_prefix="/targets")
scans_bp = Blueprint("scans", __name__, url_prefix="/scans")
dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/")

# Import route modules (registers routes on the blueprints)
from routes import targets, scans, dashboard

# Export blueprints for app.py registration
__all__ = [targets_bp, scans_bp, dashboard_bp]
