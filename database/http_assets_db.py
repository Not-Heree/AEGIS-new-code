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

def add_http_asset(target_id, subdomain_id, url, host, port,
                   status_code=0, title="", web_server="",
                   tech=None, content_length=0):
    """Add a new HTTP asset or update an existing one."""
    try:
        collection = get_collection(Config.HTTP_ASSETS_COLLECTION)
        target_oid = ObjectId(target_id)
        tech = tech if tech is not None else []

        # Check if this URL already exists for this target
        existing = collection.find_one({
            "target_id": target_oid,
            "url": url
        })

        if existing:
            # Update existing asset
            collection.update_one(
                {"_id": existing["_id"]},
                {"$set": {
                    "last_seen": datetime.utcnow(),
                    "is_new": False,
                    "status_code": status_code,
                    "title": title,
                    "web_server": web_server,
                    "tech": tech,
                    "content_length": content_length
                }}
            )
            return {
                "success": True,
                "message": "HTTP asset updated",
                "asset_id": str(existing["_id"]),
                "is_new": False
            }

        # Insert new HTTP asset
        doc = {
            "target_id": target_oid,
            "subdomain_id": ObjectId(subdomain_id),
            "url": url,
            "host": host,
            "port": port,
            "status_code": status_code,
            "title": title,
            "web_server": web_server,
            "tech": tech,
            "content_length": content_length,
            "is_new": True,
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow()
        }
        result = collection.insert_one(doc)

        return {
            "success": True,
            "message": "New HTTP asset added",
            "asset_id": str(result.inserted_id),
            "is_new": True
        }

    except Exception as e:
        return {"success": False, "message": str(e)}


def get_http_assets_by_target(target_id):
    """Return all HTTP assets for a target, sorted by URL."""
    try:
        collection = get_collection(Config.HTTP_ASSETS_COLLECTION)
        docs = collection.find(
            {"target_id": ObjectId(target_id)}
        ).sort("url", 1)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_http_assets_by_subdomain(subdomain_id):
    """Return all HTTP assets for a specific subdomain."""
    try:
        collection = get_collection(Config.HTTP_ASSETS_COLLECTION)
        docs = collection.find({"subdomain_id": ObjectId(subdomain_id)})
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_new_http_assets(target_id):
    """Return only HTTP assets marked as is_new=True for a target."""
    try:
        collection = get_collection(Config.HTTP_ASSETS_COLLECTION)
        docs = collection.find({
            "target_id": ObjectId(target_id),
            "is_new": True
        }).sort("url", 1)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def mark_all_http_assets_old(target_id):
    """Set is_new=False for ALL HTTP assets of a target.
    Called before a new scan so only fresh discoveries are marked new.
    """
    try:
        collection = get_collection(Config.HTTP_ASSETS_COLLECTION)
        result = collection.update_many(
            {"target_id": ObjectId(target_id)},
            {"$set": {"is_new": False}}
        )
        return result.modified_count
    except Exception:
        return 0


def get_http_asset_count(target_id):
    """Return the total number of HTTP assets for a target."""
    try:
        collection = get_collection(Config.HTTP_ASSETS_COLLECTION)
        return collection.count_documents({"target_id": ObjectId(target_id)})
    except Exception:
        return 0


def get_tech_summary(target_id):
    """Return a summary of detected technologies and their frequency.
    Uses aggregation to unwind the tech array and count occurrences.
    Returns: [{"_id": "React", "count": 5}, {"_id": "nginx", "count": 3}, ...]
    """
    try:
        collection = get_collection(Config.HTTP_ASSETS_COLLECTION)
        pipeline = [
            {"$match": {"target_id": ObjectId(target_id)}},
            {"$unwind": "$tech"},
            {"$group": {"_id": "$tech", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        return list(collection.aggregate(pipeline))
    except Exception:
        return []


def delete_http_assets_by_target(target_id):
    """Delete ALL HTTP assets for a target."""
    try:
        collection = get_collection(Config.HTTP_ASSETS_COLLECTION)
        result = collection.delete_many({"target_id": ObjectId(target_id)})
        return result.deleted_count
    except Exception:
        return 0


def delete_http_assets_by_subdomain(subdomain_id):
    """Delete all HTTP assets for a specific subdomain."""
    try:
        collection = get_collection(Config.HTTP_ASSETS_COLLECTION)
        result = collection.delete_many({"subdomain_id": ObjectId(subdomain_id)})
        return result.deleted_count
    except Exception:
        return 0
