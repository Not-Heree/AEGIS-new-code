# routes/dashboard.py

from flask import Blueprint, jsonify
from bson import ObjectId
from database.connection import get_db
from config import Config

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")


# ─── Helper Functions (replaces missing database modules) ────────────────

def _serialize(doc):
    """Convert MongoDB document to JSON-safe dict — handles ALL ObjectId and datetime fields."""
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


def _serialize_list(docs):
    return [_serialize(doc) for doc in docs]

def _get_vuln_stats(target_id):
    """Get vulnerability count grouped by severity for a target."""
    db = get_db()
    pipeline = [
        {"$match": {"target_id": ObjectId(target_id)}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}}
    ]
    return list(db[Config.VULNS_COLLECTION].aggregate(pipeline))


def _get_latest_scan(target_id):
    """Get the most recent scan for a target."""
    db = get_db()
    scan = db[Config.SCANS_COLLECTION].find_one(
        {"target_id": ObjectId(target_id)},
        sort=[("started_at", -1)]
    )
    return _serialize(scan) if scan else None


def _get_unacknowledged_count(target_id):
    """Count unacknowledged changes for a target."""
    db = get_db()
    return db[Config.CHANGES_COLLECTION].count_documents({
        "target_id": ObjectId(target_id),
        "acknowledged": {"$ne": True}
    })


# ─── Dashboard Home — Overall Stats ─────────────────────────────────────

@dashboard_bp.route("/", methods=["GET"])
def dashboard_home():
    """Main dashboard — returns overall stats across all targets."""
    try:
        db = get_db()

        # Get all targets
        all_targets = _serialize_list(
            db[Config.TARGETS_COLLECTION].find()
        )
        total_targets = len(all_targets)

        # Calculate overall risk score
        if all_targets:
            total_risk = sum(t.get("risk_score", 0) for t in all_targets)
            overall_risk_score = round(total_risk / len(all_targets))
        else:
            overall_risk_score = 0

        # Count critical and high vulns across ALL targets
        critical_vulns = db[Config.VULNS_COLLECTION].count_documents(
            {"severity": "critical"}
        )
        high_vulns = db[Config.VULNS_COLLECTION].count_documents(
            {"severity": "high"}
        )
        medium_vulns = db[Config.VULNS_COLLECTION].count_documents(
            {"severity": "medium"}
        )
        low_vulns = db[Config.VULNS_COLLECTION].count_documents(
            {"severity": "low"}
        )

        # Global counts
        total_subdomains = db[Config.SUBDOMAINS_COLLECTION].count_documents({})
        total_ports = db[Config.PORTS_COLLECTION].count_documents({})
        total_http_assets = db[Config.HTTP_ASSETS_COLLECTION].count_documents({})
        total_vulns = db[Config.VULNS_COLLECTION].count_documents({})
        total_emails = db[Config.EMAILS_COLLECTION].count_documents({})

        # Passive recon counts (Shodan + Censys + WHOIS)
        shodan_subdomains = db[Config.SUBDOMAINS_COLLECTION].count_documents({"sources": "shodan"})
        censys_subdomains = db[Config.SUBDOMAINS_COLLECTION].count_documents({"sources": "censys"})
        shodan_ports = db[Config.PORTS_COLLECTION].count_documents({"sources": "shodan"})
        censys_ports = db[Config.PORTS_COLLECTION].count_documents({"sources": "censys"})

        # WHOIS Stats
        whois_docs = list(db["passive_recon"].find({"source": "whois"}))
        whois_domains = len(whois_docs)
        whois_total_risks = 0
        whois_critical_risks = 0
        for w in whois_docs:
            flags = w.get("risk_flags", [])
            whois_total_risks += len(flags)
            whois_critical_risks += sum(1 for f in flags if isinstance(f, dict) and f.get("severity") in ("critical", "high"))

        passive_recon = {
            "shodan_subdomains": shodan_subdomains,
            "censys_subdomains": censys_subdomains,
            "shodan_ports": shodan_ports,
            "censys_ports": censys_ports,
            "whois_available": whois_domains > 0,
            "whois_domains": whois_domains,
            "whois_total_risks": whois_total_risks,
            "whois_critical_risks": whois_critical_risks
        }

        return jsonify({
            "success": True,
            "total_targets": total_targets,
            "overall_risk_score": overall_risk_score,
            "total_subdomains": total_subdomains,
            "total_ports": total_ports,
            "total_http_assets": total_http_assets,
            "total_vulns": total_vulns,
            "emails": total_emails,
            "vuln_breakdown": {
                "critical": critical_vulns,
                "high": high_vulns,
                "medium": medium_vulns,
                "low": low_vulns
            },
            "passive_recon": passive_recon,
            "targets": all_targets
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Summary for a Specific Domain ──────────────────────────────────────

@dashboard_bp.route("/summary/<domain>", methods=["GET"])
def summary(domain):
    """GET /api/dashboard/summary/<domain> — full overview for one domain."""
    try:
        db = get_db()

        # Check target exists
        target = db[Config.TARGETS_COLLECTION].find_one(
            {"root_domain": domain}
        )

        # Get counts
        subdomain_count = db[Config.SUBDOMAINS_COLLECTION].count_documents(
            {"target_domain": domain}
        )
        port_count = db[Config.PORTS_COLLECTION].count_documents(
            {"target_domain": domain}
        )
        http_count = db[Config.HTTP_ASSETS_COLLECTION].count_documents(
            {"target_domain": domain}
        )
        vuln_count = db[Config.VULNS_COLLECTION].count_documents(
            {"target_domain": domain}
        )
        change_count = db[Config.CHANGES_COLLECTION].count_documents(
            {"target_domain": domain}
        )
        endpoint_count = db[Config.ENDPOINTS_COLLECTION].count_documents(
            {"target_domain": domain}
        )

        # Vuln breakdown by severity
        vuln_breakdown = {
            "critical": db[Config.VULNS_COLLECTION].count_documents(
                {"target_domain": domain, "severity": "critical"}
            ),
            "high": db[Config.VULNS_COLLECTION].count_documents(
                {"target_domain": domain, "severity": "high"}
            ),
            "medium": db[Config.VULNS_COLLECTION].count_documents(
                {"target_domain": domain, "severity": "medium"}
            ),
            "low": db[Config.VULNS_COLLECTION].count_documents(
                {"target_domain": domain, "severity": "low"}
            ),
            "info": db[Config.VULNS_COLLECTION].count_documents(
                {"target_domain": domain, "severity": "info"}
            )
        }

        # Risk score
        risk_score = target.get("risk_score", 0) if target else 0
        last_scan_at = target.get("last_scanned") if target else None
        if last_scan_at and hasattr(last_scan_at, "isoformat"):
            last_scan_at = last_scan_at.isoformat()

        return jsonify({
            "success": True,
            "domain": domain,
            "risk_score": risk_score,
            "last_scan_at": last_scan_at,
            "summary": {
                "subdomains": subdomain_count,
                "ports": port_count,
                "http_assets": http_count,
                "vulnerabilities": vuln_count,
                "changes": change_count,
                "endpoints": endpoint_count
            },
            "vuln_breakdown": vuln_breakdown
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Target Detail by ID ────────────────────────────────────────────────

@dashboard_bp.route("/target/<target_id>", methods=["GET"])
def dashboard_target_detail(target_id):
    """GET /api/dashboard/target/<target_id> — detailed info for one target."""
    try:
        db = get_db()

        # Find target by ID
        try:
            target = db[Config.TARGETS_COLLECTION].find_one(
                {"_id": ObjectId(target_id)}
            )
        except Exception:
            return jsonify({"success": False, "error": "Invalid target ID"}), 400

        if not target:
            return jsonify({"success": False, "error": "Target not found"}), 404

        target = _serialize(target)
        domain = target.get("root_domain", "")

        # Get latest scan
        latest_scan = _get_latest_scan(target_id)

        # Get unacknowledged changes
        unacknowledged = _get_unacknowledged_count(target_id)

        # Get vuln stats
        vuln_stats = _get_vuln_stats(target_id)

        # Get counts
        subdomain_count = db[Config.SUBDOMAINS_COLLECTION].count_documents(
            {"target_domain": domain}
        )
        port_count = db[Config.PORTS_COLLECTION].count_documents(
            {"target_domain": domain}
        )
        http_count = db[Config.HTTP_ASSETS_COLLECTION].count_documents(
            {"target_domain": domain}
        )
        vuln_count = db[Config.VULNS_COLLECTION].count_documents(
            {"target_domain": domain}
        )
        endpoint_count = db[Config.ENDPOINTS_COLLECTION].count_documents(
            {"target_domain": domain}
        )

        return jsonify({
            "success": True,
            "target_id": target_id,
            "root_domain": domain,
            "org_name": target.get("org_name", ""),
            "risk_score": target.get("risk_score", 0),
            "total_subdomains": subdomain_count,
            "total_ports": port_count,
            "total_http_assets": http_count,
            "total_vulns": vuln_count,
            "total_endpoints": endpoint_count,
            "last_scan": latest_scan,
            "unacknowledged_changes": unacknowledged,
            "vuln_stats": vuln_stats
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Subdomains for Domain ──────────────────────────────────────────────

@dashboard_bp.route("/subdomains/<domain>", methods=["GET"])
def get_subdomains(domain):
    """GET /api/dashboard/subdomains/<domain>"""
    try:
        db = get_db()
        subs = _serialize_list(
            db[Config.SUBDOMAINS_COLLECTION].find(
                {"target_domain": domain}
            )
        )
        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(subs),
            "subdomains": subs
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Ports for Domain ───────────────────────────────────────────────────

@dashboard_bp.route("/ports/<domain>", methods=["GET"])
def get_ports(domain):
    """GET /api/dashboard/ports/<domain>"""
    try:
        db = get_db()
        ports = _serialize_list(
            db[Config.PORTS_COLLECTION].find(
                {"target_domain": domain}
            )
        )
        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(ports),
            "ports": ports
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── HTTP Assets for Domain ─────────────────────────────────────────────

@dashboard_bp.route("/http/<domain>", methods=["GET"])
def get_http_assets(domain):
    """GET /api/dashboard/http/<domain>"""
    try:
        db = get_db()
        assets = _serialize_list(
            db[Config.HTTP_ASSETS_COLLECTION].find(
                {"target_domain": domain}
            )
        )
        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(assets),
            "http_assets": assets
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Vulnerabilities for Domain ─────────────────────────────────────────

@dashboard_bp.route("/vulns/<domain>", methods=["GET"])
def get_vulns(domain):
    """GET /api/dashboard/vulns/<domain>"""
    try:
        db = get_db()
        vulns = _serialize_list(
            db[Config.VULNS_COLLECTION].find(
                {"target_domain": domain}
            )
        )
        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(vulns),
            "vulnerabilities": vulns
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Changes for Domain ─────────────────────────────────────────────────

@dashboard_bp.route("/changes/<domain>", methods=["GET"])
def get_changes(domain):
    """GET /api/dashboard/changes/<domain>"""
    try:
        db = get_db()
        changes = _serialize_list(
            db[Config.CHANGES_COLLECTION].find(
                {"target_domain": domain}
            ).sort("detected_at", -1).limit(1000)
        )
        return jsonify({
            "success": True,
            "domain": domain,
            "count": len(changes),
            "changes": changes
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── Remediation Report for Domain ──────────────────────────────────────

@dashboard_bp.route("/remediation/<domain>", methods=["GET"])
def get_remediation(domain):
    """GET /api/dashboard/remediation/<domain> — all fixes grouped by priority."""
    try:
        db = get_db()

        # Get all vulns that have remediation
        vulns = _serialize_list(
            db[Config.VULNS_COLLECTION].find(
                {
                    "target_domain": domain,
                    "remediation": {"$exists": True}
                }
            )
        )

        # Group by priority
        immediate = []
        short_term = []
        medium_term = []
        long_term = []

        for vuln in vulns:
            remediation = vuln.get("remediation", {})
            priority = remediation.get("priority", "medium_term")

            entry = {
                "vulnerability": vuln.get("vulnerability", ""),
                "name": vuln.get("name", ""),
                "severity": vuln.get("severity", ""),
                "host": vuln.get("host", ""),
                "remediation": remediation
            }

            if priority == "immediate":
                immediate.append(entry)
            elif priority == "short_term":
                short_term.append(entry)
            elif priority == "medium_term":
                medium_term.append(entry)
            else:
                long_term.append(entry)

        return jsonify({
            "success": True,
            "domain": domain,
            "total_with_remediation": len(vulns),
            "by_priority": {
                "immediate": immediate,
                "short_term": short_term,
                "medium_term": medium_term,
                "long_term": long_term
            }
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500