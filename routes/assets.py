# routes/assets.py

from flask import Blueprint, jsonify, request
from bson import ObjectId
from database.connection import get_db
from config import Config

assets_bp = Blueprint("assets", __name__, url_prefix="/api/assets")


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

# ─── GET All HTTP Assets ─────────────────────────────────────────────────

@assets_bp.route("/", methods=["GET"])
def get_all_assets():
    """GET /api/assets/ - List all HTTP assets"""
    try:
        db = get_db()
        assets = _serialize_list(
            db[Config.HTTP_ASSETS_COLLECTION].find()
        )
        return jsonify({
            "success": True,
            "count": len(assets),
            "assets": assets
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── GET Assets by Domain ────────────────────────────────────────────────

@assets_bp.route("/<domain>", methods=["GET"])
def get_assets_by_domain(domain):
    """GET /api/assets/<domain> - Get HTTP assets for a domain"""
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
            "assets": assets
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── GET Asset Stats by Domain ───────────────────────────────────────────

@assets_bp.route("/stats/<domain>", methods=["GET"])
def get_asset_stats(domain):
    """GET /api/assets/stats/<domain> - Get HTTP asset statistics"""
    try:
        db = get_db()

        total = db[Config.HTTP_ASSETS_COLLECTION].count_documents(
            {"target_domain": domain}
        )

        # Count by status code
        pipeline = [
            {"$match": {"target_domain": domain}},
            {"$group": {
                "_id": "$status_code",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}}
        ]
        by_status = list(
            db[Config.HTTP_ASSETS_COLLECTION].aggregate(pipeline)
        )

        # Count by technology
        tech_pipeline = [
            {"$match": {"target_domain": domain}},
            {"$unwind": "$technologies"},
            {"$group": {
                "_id": "$technologies",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        by_tech = list(
            db[Config.HTTP_ASSETS_COLLECTION].aggregate(tech_pipeline)
        )

        return jsonify({
            "success": True,
            "domain": domain,
            "total": total,
            "by_status_code": by_status,
            "top_technologies": by_tech
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ─── GET Passive Recon for Target Detail Page ────────────────────────────

@assets_bp.route("/passive-recon/<domain>", methods=["GET"])
def get_passive_recon_data(domain):
    """GET /api/passive-recon/<domain> — returns Shodan, Censys, WHOIS data."""
    try:
        db = get_db()
        records = list(db["passive_recon"].find(
            {"target_domain": domain}
        ))
        return jsonify({
            "success": True,
            "domain": domain,
            "records": _serialize_list(records)
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
# ─── GET Asset Breakdown for Tower Graph ─────────────────────────────────

@assets_bp.route("/breakdown/<domain>", methods=["GET"])
def get_asset_breakdown(domain):
    """
    GET /api/assets/breakdown/<domain>

    Returns per-asset vulnerability, port, and technology
    breakdown for the tower graph and asset-wise filter view.

    Aggregates data across vulns, ports, and http_assets
    collections, grouped by host. Each asset is classified
    into a criticality tier (critical/high/standard/low).
    """
    try:
        db = get_db()

        # ── Collect all unique hosts ─────────────────
        all_hosts = set()

        # From subdomains collection
        subs = list(db[Config.SUBDOMAINS_COLLECTION].find(
            {"target_domain": domain},
            {"subdomain": 1, "_id": 0}
        ))
        for s in subs:
            all_hosts.add(s["subdomain"])

        # ── Aggregate vulns by host + severity ───────
        vuln_agg = list(db[Config.VULNS_COLLECTION].aggregate([
            {
                "$match": {
                    "target_domain": domain,
                    "status": "open"
                }
            },
            {
                "$group": {
                    "_id": {
                        "host": "$host",
                        "severity": "$severity"
                    },
                    "count": {"$sum": 1}
                }
            }
        ]))

        vuln_by_host = {}
        for entry in vuln_agg:
            host = entry["_id"]["host"]
            severity = entry["_id"]["severity"].lower()
            count = entry["count"]
            all_hosts.add(host)

            if host not in vuln_by_host:
                vuln_by_host[host] = {
                    "critical": 0, "high": 0,
                    "medium": 0, "low": 0, "info": 0
                }
            if severity in vuln_by_host[host]:
                vuln_by_host[host][severity] = count

        # ── Aggregate ports by host ──────────────────
        port_agg = list(db[Config.PORTS_COLLECTION].aggregate([
            {"$match": {"target_domain": domain}},
            {
                "$group": {
                    "_id": "$host",
                    "ports": {"$addToSet": "$port"},
                    "count": {"$sum": 1}
                }
            }
        ]))

        port_by_host = {}
        for entry in port_agg:
            host = entry["_id"]
            if not host:
                continue
            all_hosts.add(host)
            port_by_host[host] = {
                "ports": sorted(entry["ports"]),
                "count": entry["count"]
            }

        # ── Get HTTP assets by host ──────────────────
        http_assets = list(
            db[Config.HTTP_ASSETS_COLLECTION].find(
                {"target_domain": domain}
            )
        )

        http_by_host = {}
        for asset in http_assets:
            host = asset.get("host", "")
            if not host:
                continue
            all_hosts.add(host)

            if host not in http_by_host:
                http_by_host[host] = {
                    "tech": set(),
                    "title": "",
                    "web_server": "",
                    "status_code": 0
                }

            for t in asset.get("tech", []):
                if t:
                    http_by_host[host]["tech"].add(t)

            if (asset.get("title")
                    and not http_by_host[host]["title"]):
                http_by_host[host]["title"] = asset["title"]

            if (asset.get("web_server")
                    and not http_by_host[host]["web_server"]):
                http_by_host[host]["web_server"] = (
                    asset["web_server"]
                )

            if (asset.get("status_code")
                    and not http_by_host[host]["status_code"]):
                http_by_host[host]["status_code"] = (
                    asset["status_code"]
                )

        # ── Build combined result ────────────────────
        from utils.asset_classifier import classify_host

        default_vulns = {
            "critical": 0, "high": 0,
            "medium": 0, "low": 0, "info": 0
        }

        assets = []
        for host in sorted(all_hosts):
            vulns = vuln_by_host.get(host, dict(default_vulns))
            ports = port_by_host.get(host, {
                "ports": [], "count": 0
            })
            http = http_by_host.get(host, {
                "tech": set(), "title": "",
                "web_server": "", "status_code": 0
            })

            total_vulns = sum(vulns.values())
            tier = classify_host(host)

            # Determine risk level from worst severity
            if vulns["critical"] > 0:
                risk_level = "critical"
            elif vulns["high"] > 0:
                risk_level = "high"
            elif vulns["medium"] > 0:
                risk_level = "medium"
            elif vulns["low"] > 0:
                risk_level = "low"
            else:
                risk_level = "clean"

            # Convert tech set to sorted list
            tech_list = sorted(http["tech"]) if isinstance(
                http["tech"], set
            ) else list(http.get("tech", []))

            assets.append({
                "host": host,
                "tier": tier,
                "risk_level": risk_level,
                "vuln_counts": vulns,
                "total_vulns": total_vulns,
                "ports": ports["ports"],
                "port_count": ports["count"],
                "tech": tech_list,
                "title": http.get("title", ""),
                "web_server": http.get("web_server", ""),
                "status_code": http.get("status_code", 0)
            })

        # Sort by total vulns descending
        assets.sort(
            key=lambda a: a["total_vulns"],
            reverse=True
        )

        # Tier summary
        tier_summary = {
            "critical": 0, "high": 0,
            "standard": 0, "low": 0
        }
        for a in assets:
            tier_summary[a["tier"]] += 1

        return jsonify({
            "success": True,
            "domain": domain,
            "total_assets": len(assets),
            "assets": assets,
            "tier_summary": tier_summary
        })

    except Exception as e:
        return jsonify({
            "success": False, "error": str(e)
        }), 500
# ─── DELETE Asset ────────────────────────────────────────────────────────

@assets_bp.route("/<asset_id>", methods=["DELETE"])
def delete_asset(asset_id):
    """DELETE /api/assets/<asset_id> - Delete an HTTP asset"""
    try:
        db = get_db()
        result = db[Config.HTTP_ASSETS_COLLECTION].delete_one(
            {"_id": ObjectId(asset_id)}
        )
        if result.deleted_count == 0:
            return jsonify({
                "success": False,
                "error": "Asset not found"
            }), 404

        return jsonify({
            "success": True,
            "message": "Asset deleted successfully"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500