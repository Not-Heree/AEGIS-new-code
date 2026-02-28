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

def add_subdomain(target_id, subdomain, ip_addresses=None, source="subfinder"):
    """Add a new subdomain or update an existing one for a target."""
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        subdomain = subdomain.strip().lower()
        target_oid = ObjectId(target_id)

        # Check if subdomain already exists for this target
        existing = collection.find_one({
            "target_id": target_oid,
            "subdomain": subdomain
        })

        if existing:
            # Update existing subdomain
            update_fields = {
                "last_seen": datetime.utcnow(),
                "is_new": False,
                "is_alive": True
            }
            if ip_addresses is not None:
                update_fields["ip_addresses"] = ip_addresses

            collection.update_one(
                {"_id": existing["_id"]},
                {"$set": update_fields}
            )
            return {
                "success": True,
                "message": "Subdomain updated",
                "subdomain_id": str(existing["_id"]),
                "is_new": False
            }

        # Insert new subdomain
        doc = {
            "target_id": target_oid,
            "subdomain": subdomain,
            "ip_addresses": ip_addresses if ip_addresses else [],
            "is_alive": True,
            "is_new": True,
            "source": source,
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow()
        }
        result = collection.insert_one(doc)

        return {
            "success": True,
            "message": "New subdomain added",
            "subdomain_id": str(result.inserted_id),
            "is_new": True
        }

    except Exception as e:
        return {"success": False, "message": str(e)}


def add_subdomains_bulk(target_id, subdomains_list):
    """Add multiple subdomains at once, tracking new vs updated counts."""
    new_count = 0
    updated_count = 0
    failed_count = 0

    for subdomain in subdomains_list:
        result = add_subdomain(target_id, subdomain)
        if result.get("success"):
            if result.get("is_new"):
                new_count += 1
            else:
                updated_count += 1
        else:
            failed_count += 1

    return {
        "success": True,
        "total": len(subdomains_list),
        "new": new_count,
        "updated": updated_count,
        "failed": failed_count
    }


def get_subdomains_by_target(target_id):
    """Return all subdomains for a target, sorted alphabetically."""
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        docs = collection.find(
            {"target_id": ObjectId(target_id)}
        ).sort("subdomain", 1)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_subdomain_by_id(subdomain_id):
    """Find a single subdomain by its ObjectId string."""
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        doc = collection.find_one({"_id": ObjectId(subdomain_id)})
        return serialize_doc(doc)
    except Exception:
        return None


def get_new_subdomains(target_id):
    """Return only subdomains marked as is_new=True for a target."""
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        docs = collection.find({
            "target_id": ObjectId(target_id),
            "is_new": True
        }).sort("subdomain", 1)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_alive_subdomains(target_id):
    """Return only subdomains marked as is_alive=True for a target."""
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        docs = collection.find({
            "target_id": ObjectId(target_id),
            "is_alive": True
        }).sort("subdomain", 1)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def mark_subdomain_dead(subdomain_id):
    """Set is_alive=False for a single subdomain."""
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        collection.update_one(
            {"_id": ObjectId(subdomain_id)},
            {"$set": {"is_alive": False}}
        )
        return True
    except Exception:
        return False


def mark_all_subdomains_old(target_id):
    """Set is_new=False for ALL subdomains of a target.
    Called before a new scan so only fresh discoveries are marked new.
    """
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        result = collection.update_many(
            {"target_id": ObjectId(target_id)},
            {"$set": {"is_new": False}}
        )
        return result.modified_count
    except Exception:
        return 0


def mark_dead_subdomains(target_id, alive_subdomains_list):
    """Mark subdomains NOT in alive_subdomains_list as dead.
    Compares current alive list against all stored subdomains.
    """
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)

        # Normalize the alive list
        alive_set = [s.strip().lower() for s in alive_subdomains_list]

        # Set is_alive=False for any subdomain not in the alive list
        result = collection.update_many(
            {
                "target_id": ObjectId(target_id),
                "subdomain": {"$nin": alive_set}
            },
            {"$set": {"is_alive": False}}
        )
        return result.modified_count
    except Exception:
        return 0


def get_subdomain_count(target_id):
    """Return the total number of subdomains for a target."""
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        return collection.count_documents({"target_id": ObjectId(target_id)})
    except Exception:
        return 0


def delete_subdomains_by_target(target_id):
    """Delete ALL subdomains for a target. Used when removing a target entirely."""
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        result = collection.delete_many({"target_id": ObjectId(target_id)})
        return result.deleted_count
    except Exception:
        return 0
