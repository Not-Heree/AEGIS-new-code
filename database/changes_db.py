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

def add_change(target_id, change_type, severity, details, scan_id=None):
    """Record a change in the attack surface."""
    try:
        collection = get_collection(Config.CHANGES_COLLECTION)

        doc = {
            "target_id": ObjectId(target_id),
            "scan_id": ObjectId(scan_id) if scan_id else None,
            "change_type": change_type,
            "severity": severity,
            "details": details,
            "acknowledged": False,
            "timestamp": datetime.utcnow()
        }
        result = collection.insert_one(doc)

        return {
            "success": True,
            "change_id": str(result.inserted_id)
        }

    except Exception as e:
        return {"success": False, "message": str(e)}


def get_changes_by_target(target_id, acknowledged=None, limit=100):
    """Return changes for a target, optionally filtered by acknowledged status."""
    try:
        collection = get_collection(Config.CHANGES_COLLECTION)
        query = {"target_id": ObjectId(target_id)}

        if acknowledged is not None:
            query["acknowledged"] = acknowledged

        docs = collection.find(query).sort("timestamp", -1).limit(limit)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def acknowledge_change(change_id):
    """Mark a change as acknowledged."""
    try:
        collection = get_collection(Config.CHANGES_COLLECTION)
        collection.update_one(
            {"_id": ObjectId(change_id)},
            {"$set": {"acknowledged": True}}
        )
        return True
    except Exception:
        return False


def get_unacknowledged_count(target_id):
    """Return the number of unacknowledged changes for a target."""
    try:
        collection = get_collection(Config.CHANGES_COLLECTION)
        return collection.count_documents({
            "target_id": ObjectId(target_id),
            "acknowledged": False
        })
    except Exception:
        return 0


def delete_changes_by_target(target_id):
    """Delete ALL changes for a target."""
    try:
        collection = get_collection(Config.CHANGES_COLLECTION)
        result = collection.delete_many({"target_id": ObjectId(target_id)})
        return result.deleted_count
    except Exception:
        return 0
