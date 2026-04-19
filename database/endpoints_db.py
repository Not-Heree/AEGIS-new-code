"""
Endpoints Database Module
==========================
Stores HTTP endpoint parameter discovery results from Arjun.

Each ENDPOINT document represents a unique URL + method combination
with its discovered parameters. Follows the same hub-and-spoke
pattern as other collections — target_id FK pointing back to TARGET.

Schema:
    {
        "_id": ObjectId,
        "target_id": str,
        "target_domain": str,
        "host": str,
        "url": str,
        "method": str (GET | POST | JSON | XML),
        "parameters": [str],
        "discovered_at": datetime,
        "status": str ("active" | "old"),
    }
"""

from datetime import datetime
from urllib.parse import urlparse

from config import Config
from database.connection import get_db
from utils.logger import logger


def _get_collection():
    """Get the endpoints collection."""
    db = get_db()
    return db[Config.ENDPOINTS_COLLECTION]


def add_endpoint(
    target_id: str,
    target_domain: str,
    url: str,
    method: str,
    parameters: list,
    source: str = "arjun"
) -> dict:
    """
    Add or update an endpoint document.

    Upserts on (target_id, url, method) to prevent duplicates
    across rescans.

    Args:
        target_id:     MongoDB target document ID
        target_domain: Root domain string
        url:           Full URL (e.g. "https://api.example.com/users")
        method:        HTTP method (GET, POST, JSON, XML)
        parameters:    List of discovered parameter names
        source:        Source of the discovery (e.g. "arjun", "arjun_smart")

    Returns:
        {"inserted": bool, "updated": bool}
    """
    collection = _get_collection()

    # Extract host from URL
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
    except Exception:
        host = ""

    doc = {
        "target_id": target_id,
        "target_domain": target_domain,
        "host": host,
        "url": url,
        "method": method.upper() if method else "GET",
        "parameters": sorted(set(parameters)) if parameters else [],
        "source": source,
        "discovered_at": datetime.utcnow(),
        "status": "active",
    }

    identity = {
        "target_id": target_id,
        "url": url,
        "method": doc["method"],
    }

    result = collection.update_one(
        identity, {"$set": doc}, upsert=True
    )

    if result.upserted_id:
        return {"inserted": True, "updated": False}
    elif result.modified_count > 0:
        return {"inserted": False, "updated": True}
    else:
        return {"inserted": False, "updated": False}


def add_endpoints_bulk(
    target_id: str,
    target_domain: str,
    endpoints: list
) -> dict:
    """
    Bulk upsert a list of endpoint documents.

    Args:
        target_id:     MongoDB target document ID
        target_domain: Root domain
        endpoints:     List of dicts with url, method, parameters, source

    Returns:
        {"inserted": int, "updated": int}
    """
    inserted = 0
    updated = 0

    for ep in endpoints:
        result = add_endpoint(
            target_id=target_id,
            target_domain=target_domain,
            url=ep.get("url", ""),
            method=ep.get("method", "GET"),
            parameters=ep.get("parameters", []),
            source=ep.get("source", "arjun")
        )

        if result.get("inserted"):
            inserted += 1
        elif result.get("updated"):
            updated += 1

    logger.info(
        "[ENDPOINTS] Bulk upsert: %d inserted, %d updated",
        inserted, updated
    )
    return {"inserted": inserted, "updated": updated}


def get_endpoints_by_target(target_id: str) -> list:
    """Get all endpoint documents for a target."""
    collection = _get_collection()
    cursor = collection.find(
        {"target_id": target_id, "status": "active"}
    )
    return list(cursor)


def get_endpoint_count(target_id: str) -> int:
    """Count active endpoints for a target."""
    collection = _get_collection()
    return collection.count_documents(
        {"target_id": target_id, "status": "active"}
    )


def mark_all_endpoints_old(target_id: str) -> int:
    """
    Mark all existing endpoints as 'old' before a rescan.
    Used by the change detection pipeline.
    """
    collection = _get_collection()
    result = collection.update_many(
        {"target_id": target_id, "status": "active"},
        {"$set": {"status": "old"}}
    )
    return result.modified_count
