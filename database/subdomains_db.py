"""
Subdomains Database Layer
=========================
CRUD operations for discovered subdomains.
Stores source information to distinguish between active and passive discovery.
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
        if isinstance(value, ObjectId):
            doc[key] = str(value)
        elif isinstance(value, datetime):
            doc[key] = value.isoformat()

    return doc


# ─── CRUD Functions ──────────────────────────────────────────────────────

def add_subdomain(target_id, target_domain, subdomain,
                  ip_addresses=None, source="subfinder"):
    """
    Add or update a subdomain. Now stores target_domain and source
    for route queries and passive/active tracking.

    Args:
        target_id: Target document ObjectId string
        target_domain: Root domain string (e.g., "example.com")
        subdomain: Full subdomain string (e.g., "api.example.com")
        ip_addresses: Optional list of resolved IPs
        source: Discovery source — "subfinder", "crtsh", "shodan",
                "censys", or other tool name

    Returns:
        Dict with success, subdomain_id, is_new
    """
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        subdomain = subdomain.strip().lower()
        target_oid = ObjectId(target_id)

        existing = collection.find_one({
            "target_id": target_oid,
            "subdomain": subdomain
        })

        if existing:
            update_fields = {
                "last_seen": datetime.utcnow(),
                "is_new": False,
                "is_alive": True,
                "target_domain": target_domain,
            }

            if ip_addresses is not None:
                update_fields["ip_addresses"] = ip_addresses

            # Merge sources — don't overwrite, append new ones
            old_sources = existing.get("sources", [])
            if isinstance(old_sources, str):
                old_sources = [old_sources]
            if source and source not in old_sources:
                old_sources.append(source)
            update_fields["sources"] = old_sources

            # Keep the original single source field for backward compat
            if not existing.get("source"):
                update_fields["source"] = source

            collection.update_one(
                {"_id": existing["_id"]},
                {"$set": update_fields}
            )
            return {
                "success": True,
                "subdomain_id": str(existing["_id"]),
                "is_new": False
            }

        doc = {
            "target_id": target_oid,
            "target_domain": target_domain,
            "subdomain": subdomain,
            "ip_addresses": ip_addresses or [],
            "is_alive": True,
            "is_new": True,
            "source": source,
            "sources": [source] if source else [],
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow()
        }
        result = collection.insert_one(doc)

        return {
            "success": True,
            "subdomain_id": str(result.inserted_id),
            "is_new": True
        }

    except Exception as e:
        return {"success": False, "message": str(e)}


def add_subdomains_bulk(target_id, target_domain, subdomains_list,
                        source="subfinder"):
    """
    Add multiple subdomains. Passes target_domain and source through.

    Args:
        target_id: Target document ObjectId string
        target_domain: Root domain string
        subdomains_list: List of subdomain strings
        source: Discovery source — "subfinder", "shodan", "censys", etc.

    Returns:
        Dict with success, total, new count, updated count
    """
    new_count = 0
    updated_count = 0

    for subdomain in subdomains_list:
        result = add_subdomain(
            target_id, target_domain, subdomain, source=source
        )
        if result.get("success"):
            if result.get("is_new"):
                new_count += 1
            else:
                updated_count += 1

    return {
        "success": True,
        "total": len(subdomains_list),
        "new": new_count,
        "updated": updated_count
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


def get_subdomains_by_source(target_id, source):
    """
    Return subdomains discovered by a specific source.

    Args:
        target_id: Target document ObjectId string
        source: Source name — "subfinder", "shodan", "censys", etc.

    Returns:
        List of serialized subdomain documents
    """
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        docs = collection.find({
            "target_id": ObjectId(target_id),
            "sources": source
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

        alive_set = [s.strip().lower() for s in alive_subdomains_list]

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
        return collection.count_documents(
            {"target_id": ObjectId(target_id)}
        )
    except Exception:
        return 0


def get_source_summary(target_id):
    """
    Return a summary of how many subdomains each source discovered.

    Uses aggregation to unwind the sources array and count occurrences.
    Returns: [{"_id": "subfinder", "count": 30},
              {"_id": "shodan", "count": 12}, ...]
    """
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        pipeline = [
            {"$match": {"target_id": ObjectId(target_id)}},
            {"$unwind": "$sources"},
            {"$group": {"_id": "$sources", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        return list(collection.aggregate(pipeline))
    except Exception:
        return []


def delete_subdomains_by_target(target_id):
    """Delete ALL subdomains for a target.
    Used when removing a target entirely.
    """
    try:
        collection = get_collection(Config.SUBDOMAINS_COLLECTION)
        result = collection.delete_many(
            {"target_id": ObjectId(target_id)}
        )
        return result.deleted_count
    except Exception:
        return 0