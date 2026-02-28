from datetime import datetime
from bson import ObjectId
from database.connection import get_collection
from config import Config


# ─── Helper ──────────────────────────────────────────────────────────────

def serialize_doc(doc):
    """Convert a MongoDB document to a JSON-serializable dict.
    - Converts _id from ObjectId to string
    - Converts datetime fields to ISO format strings
    """
    if doc is None:
        return None

    doc["_id"] = str(doc["_id"])

    for key, value in doc.items():
        if isinstance(value, datetime):
            doc[key] = value.isoformat()

    return doc


# ─── CRUD Functions ──────────────────────────────────────────────────────

def add_target(root_domain, org_name=None):
    """Add a new target (root domain) to monitor."""
    try:
        collection = get_collection(Config.TARGETS_COLLECTION)

        # Clean the domain
        root_domain = root_domain.strip().lower()

        # Check if target already exists
        existing = collection.find_one({"root_domain": root_domain})
        if existing:
            return {
                "success": False,
                "message": "Target already exists",
                "target_id": str(existing["_id"])
            }

        # Build the target document
        target = {
            "root_domain": root_domain,
            "org_name": org_name,
            "status": "active",
            "total_subdomains": 0,
            "total_ports": 0,
            "total_http_assets": 0,
            "total_vulns": 0,
            "risk_score": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "created_at": datetime.utcnow(),
            "last_scan_at": None,
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


def get_target_by_domain(root_domain):
    """Find a target by its root_domain field."""
    try:
        collection = get_collection(Config.TARGETS_COLLECTION)
        doc = collection.find_one({"root_domain": root_domain.strip().lower()})
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


def get_target_count():
    """Return the total number of targets."""
    try:
        collection = get_collection(Config.TARGETS_COLLECTION)
        return collection.count_documents({})
    except Exception:
        return 0
