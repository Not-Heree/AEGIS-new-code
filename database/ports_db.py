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

def add_port(target_id, target_domain, subdomain_id, host, ip, port,
             protocol="tcp", service="", version="", source="unknown"):
    """
    Add or update a port. Now tracks discovery source.
    
    Args:
        ... existing args ...
        source: Discovery tool — "shodan", "censys", "naabu", etc.
    """
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        target_oid = ObjectId(target_id)
        port = int(port)

        existing = collection.find_one({
            "target_id": target_oid,
            "host": host,
            "port": port
        })

        if existing:
            update_fields = {
                "last_seen": datetime.utcnow(),
                "is_new": False,
                "target_domain": target_domain,
            }
            if ip:
                update_fields["ip"] = ip
            if service:
                update_fields["service"] = service
            if version:
                update_fields["version"] = version

            # ── Source tracking (same pattern as subdomains) ──
            old_sources = existing.get("sources", [])
            if isinstance(old_sources, str):
                old_sources = [old_sources]
            # Backfill: if old doc has no sources, seed from source field
            if not old_sources and existing.get("source"):
                old_sources = [existing["source"]]
            if source and source != "unknown" and source not in old_sources:
                old_sources.append(source)
            update_fields["sources"] = old_sources

            collection.update_one(
                {"_id": existing["_id"]},
                {"$set": update_fields}
            )
            return {
                "success": True,
                "port_id": str(existing["_id"]),
                "is_new": False
            }

        doc = {
            "target_id": target_oid,
            "target_domain": target_domain,
            "subdomain_id": ObjectId(subdomain_id) if subdomain_id else None,
            "host": host,
            "ip": ip,
            "port": port,
            "protocol": protocol,
            "service": service,
            "version": version,
            "status": "open",
            "is_new": True,
            "source": source,                                  # First discoverer
            "sources": [source] if source else [],             # All discoverers
            "first_seen": datetime.utcnow(),
            "last_seen": datetime.utcnow()
        }
        result = collection.insert_one(doc)
        return {
            "success": True,
            "port_id": str(result.inserted_id),
            "is_new": True
        }

    except Exception as e:
        return {"success": False, "message": str(e)}

def add_ports_bulk(target_id, target_domain, subdomain_id, host, ports_list,
                   source="unknown"):
    """
    Add multiple ports. Now passes source through.
    
    Args:
        ... existing args ...
        source: Discovery tool — "shodan", "censys", "naabu", etc.
    """
    new_count = 0
    updated_count = 0

    for port in ports_list:
        result = add_port(
            target_id, target_domain, subdomain_id,
            host, "", int(port), source=source
        )
        if result.get("success"):
            if result.get("is_new"):
                new_count += 1
            else:
                updated_count += 1

    return {
        "success": True,
        "total": len(ports_list),
        "new": new_count,
        "updated": updated_count
    }



def get_ports_by_target(target_id):
    """Return all ports for a target, sorted by host then port number."""
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        docs = collection.find(
            {"target_id": ObjectId(target_id)}
        ).sort([("host", 1), ("port", 1)])
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_ports_by_subdomain(subdomain_id):
    """Return all ports for a specific subdomain, sorted by port number."""
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        docs = collection.find(
            {"subdomain_id": ObjectId(subdomain_id)}
        ).sort("port", 1)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_ports_by_host(target_id, host):
    """Return all ports for a specific host within a target."""
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        docs = collection.find({
            "target_id": ObjectId(target_id),
            "host": host
        }).sort("port", 1)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_new_ports(target_id):
    """Return only ports marked as is_new=True for a target."""
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        docs = collection.find({
            "target_id": ObjectId(target_id),
            "is_new": True
        }).sort([("host", 1), ("port", 1)])
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def mark_all_ports_old(target_id):
    """Set is_new=False for ALL ports of a target.
    Called before a new scan so only fresh discoveries are marked new.
    """
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        result = collection.update_many(
            {"target_id": ObjectId(target_id)},
            {"$set": {"is_new": False}}
        )
        return result.modified_count
    except Exception:
        return 0


def get_port_count(target_id):
    """Return the total number of port entries for a target."""
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        return collection.count_documents({"target_id": ObjectId(target_id)})
    except Exception:
        return 0


def get_unique_ports_summary(target_id):
    """Return a summary of unique ports and how many hosts have each open.
    Uses MongoDB aggregation to group by port and count occurrences.
    Returns: [{"port": 443, "count": 25}, {"port": 80, "count": 20}, ...]
    """
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        pipeline = [
            {"$match": {"target_id": ObjectId(target_id)}},
            {"$group": {"_id": "$port", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}},
            {"$project": {"_id": 0, "port": "$_id", "count": 1}}
        ]
        return list(collection.aggregate(pipeline))
    except Exception:
        return []


def delete_ports_by_target(target_id):
    """Delete ALL ports for a target. Used when removing a target entirely."""
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        result = collection.delete_many({"target_id": ObjectId(target_id)})
        return result.deleted_count
    except Exception:
        return 0


def delete_ports_by_subdomain(subdomain_id):
    """Delete all ports for a specific subdomain."""
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        result = collection.delete_many({"subdomain_id": ObjectId(subdomain_id)})
        return result.deleted_count
    except Exception:
        return 0
def get_ports_by_source(target_id, source):
    """
    Return ports discovered by a specific source.
    
    Args:
        target_id: Target document ObjectId string
        source: Source name — "shodan", "censys", "naabu", etc.
    
    Returns:
        List of serialized port documents
    """
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        docs = collection.find({
            "target_id": ObjectId(target_id),
            "sources": source
        }).sort([("host", 1), ("port", 1)])
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_source_port_summary(target_id):
    """
    Return summary of how many ports each source discovered.
    
    Returns: [{"_id": "shodan", "count": 15}, 
              {"_id": "naabu", "count": 42}, ...]
    """
    try:
        collection = get_collection(Config.PORTS_COLLECTION)
        pipeline = [
            {"$match": {"target_id": ObjectId(target_id)}},
            {"$unwind": "$sources"},
            {"$group": {"_id": "$sources", "count": {"$sum": 1}}},
            {"$sort": {"count": -1}}
        ]
        return list(collection.aggregate(pipeline))
    except Exception:
        return []