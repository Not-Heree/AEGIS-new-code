"""
Target Database Operations
===========================
CRUD functions for the targets collection.

CANONICAL FIELD NAMES (consolidated):
    root_domain   — primary domain identifier (unique index)
    created_at    — when target was added
    last_scan_at  — when last scan completed
    scan_count    — number of completed scans

REMOVED LEGACY FIELDS:
    domain        — was identical to root_domain (removed)
    added_at      — was identical to created_at (removed)
    last_scanned  — was identical to last_scan_at (removed)
    critical_count, high_count, medium_count, low_count, info_count
                  — were NOT reliably updated; dashboard calculates
                    these dynamically from the vulns collection (removed)
"""

from datetime import datetime
from bson import ObjectId
from database.connection import get_collection
from config import Config


# ─── Helper ──────────────────────────────────────────────────────────────

def serialize_doc(doc):
    """Convert a MongoDB document to a JSON-serializable dict."""
    if doc is None:
        return None

    doc["_id"] = str(doc["_id"])

    for key, value in doc.items():
        if isinstance(value, ObjectId):                    # ◄ NEW: handle nested ObjectIds
            doc[key] = str(value)
        elif isinstance(value, datetime):
            doc[key] = value.isoformat()

    return doc


# ─── CRUD Functions ──────────────────────────────────────────────────────

def add_target(root_domain, org_name=None):
    """Add a new target (root domain) to monitor."""
    try:
        collection = get_collection(Config.TARGETS_COLLECTION)

        root_domain = root_domain.strip().lower()

        existing = collection.find_one({"root_domain": root_domain})
        if existing:
            return {
                "success": False,
                "message": "Target already exists",
                "target_id": str(existing["_id"])
            }

        target = {
            # ── Identity ──────────────────────────────
            "root_domain": root_domain,
            # REMOVED: "domain" — was identical to root_domain

            "org_name": org_name or "",
            "description": "",
            "status": "active",
            "scan_config": {
                "enable_parameter_discovery": False,
                "parameter_discovery_rate_limit": (
                    Config.ARJUN_RATE_LIMIT
                ),
            },

            # ── Computed Stats (updated by scanner) ───
            "total_subdomains": 0,
            "total_ports": 0,
            "total_http_assets": 0,
            "total_vulns": 0,
            "total_emails": 0,                             # ◄ NEW (was missing)
            "total_breached_emails": 0,                    # ◄ NEW (was missing)
            "risk_score": 0,

            # REMOVED: critical_count, high_count, medium_count,
            #          low_count, info_count
            # These are calculated dynamically by the dashboard
            # from the vulnerabilities collection.

            # ── Timestamps ────────────────────────────
            "created_at": datetime.utcnow(),
            # REMOVED: "added_at" — was identical to created_at

            "last_scan_at": None,
            # REMOVED: "last_scanned" — was identical to last_scan_at

            "scan_count": 0
        }

        result = collection.insert_one(target)

        return {
            "success": True,
            "message": "Target added successfully",
            "target_id": str(result.inserted_id)
        }

    except Exception as e:
        return {"success": False, "message": str(e)}


def get_all_targets():
    """Return all targets, sorted by newest first."""
    try:
        collection = get_collection(Config.TARGETS_COLLECTION)
        targets = collection.find().sort("created_at", -1)
        return [serialize_doc(t) for t in targets]
    except Exception:
        return []


def get_target_by_id(target_id):
    """Find a target by its ObjectId string."""
    try:
        collection = get_collection(Config.TARGETS_COLLECTION)
        doc = collection.find_one({"_id": ObjectId(target_id)})
        return serialize_doc(doc)
    except Exception:
        return None


def get_target(target_id):
    """Backward-compatible alias used by the scanner."""
    return get_target_by_id(target_id)


def get_target_by_domain(root_domain):
    """Find a target by its root_domain field."""
    try:
        collection = get_collection(Config.TARGETS_COLLECTION)
        doc = collection.find_one(
            {"root_domain": root_domain.strip().lower()}
        )

        # Fallback: check legacy "domain" field for old documents     # ◄ NEW
        if not doc:                                                    # ◄ NEW
            doc = collection.find_one(                                 # ◄ NEW
                {"domain": root_domain.strip().lower()}                # ◄ NEW
            )                                                          # ◄ NEW

        return serialize_doc(doc)
    except Exception:
        return None


def update_target_stats(target_id, stats_dict):
    """Update specific stat fields on a target using $set."""
    try:
        collection = get_collection(Config.TARGETS_COLLECTION)
        collection.update_one(
            {"_id": ObjectId(target_id)},
            {"$set": stats_dict}
        )
        return True
    except Exception:
        return False


def update_last_scan(target_id):
    """Set last_scan_at to now and increment scan_count by 1."""
    try:
        collection = get_collection(Config.TARGETS_COLLECTION)
        collection.update_one(
            {"_id": ObjectId(target_id)},
            {
                "$set": {"last_scan_at": datetime.utcnow()},
                "$inc": {"scan_count": 1}
            }
        )
        return True
    except Exception:
        return False


def delete_target(target_id):
    """Delete a target by its ObjectId string."""
    try:
        collection = get_collection(Config.TARGETS_COLLECTION)
        collection.delete_one({"_id": ObjectId(target_id)})
        return {"success": True, "message": "Target deleted"}
    except Exception as e:
        return {"success": False, "message": str(e)}

