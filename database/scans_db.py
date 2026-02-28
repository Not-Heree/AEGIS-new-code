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
        if isinstance(value, ObjectId):
            doc[key] = str(value)
        elif isinstance(value, datetime):
            doc[key] = value.isoformat()

    return doc


# ─── CRUD Functions ──────────────────────────────────────────────────────

def create_scan(target_id, scan_type="full"):
    """Create a new scan record when a scan starts."""
    try:
        collection = get_collection(Config.SCANS_COLLECTION)

        doc = {
            "target_id": ObjectId(target_id),
            "scan_type": scan_type,
            "status": "running",
            "started_at": datetime.utcnow(),
            "completed_at": None,
            "duration_seconds": 0,
            "results": {},
            "error_message": ""
        }
        result = collection.insert_one(doc)

        return {
            "success": True,
            "scan_id": str(result.inserted_id)
        }

    except Exception as e:
        return {"success": False, "message": str(e)}


def complete_scan(scan_id, results_dict):
    """Mark a scan as completed with its results."""
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        scan_oid = ObjectId(scan_id)

        # Fetch the scan to calculate duration
        scan = collection.find_one({"_id": scan_oid})
        if not scan:
            return False

        duration = int((datetime.utcnow() - scan["started_at"]).total_seconds())

        collection.update_one(
            {"_id": scan_oid},
            {"$set": {
                "status": "completed",
                "completed_at": datetime.utcnow(),
                "duration_seconds": duration,
                "results": results_dict
            }}
        )
        return True
    except Exception:
        return False


def fail_scan(scan_id, error_message):
    """Mark a scan as failed with an error message."""
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        scan_oid = ObjectId(scan_id)

        # Fetch the scan to calculate duration
        scan = collection.find_one({"_id": scan_oid})
        if not scan:
            return False

        duration = int((datetime.utcnow() - scan["started_at"]).total_seconds())

        collection.update_one(
            {"_id": scan_oid},
            {"$set": {
                "status": "failed",
                "completed_at": datetime.utcnow(),
                "duration_seconds": duration,
                "error_message": error_message
            }}
        )
        return True
    except Exception:
        return False


def get_scans_by_target(target_id, limit=50):
    """Return scan history for a target, newest first."""
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        docs = collection.find(
            {"target_id": ObjectId(target_id)}
        ).sort("started_at", -1).limit(limit)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_latest_scan(target_id):
    """Return the most recent scan for a target."""
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        doc = collection.find(
            {"target_id": ObjectId(target_id)}
        ).sort("started_at", -1).limit(1)

        docs = list(doc)
        if docs:
            return serialize_doc(docs[0])
        return None
    except Exception:
        return None


def delete_scans_by_target(target_id):
    """Delete ALL scan records for a target."""
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        result = collection.delete_many({"target_id": ObjectId(target_id)})
        return result.deleted_count
    except Exception:
        return 0
