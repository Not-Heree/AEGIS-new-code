"""
Email Exposures Database Layer
==============================
CRUD operations for discovered email addresses and breach data.

Stores:
  - Discovered email addresses with source tracking
  - Breach data per email
  - Person metadata (name, position, LinkedIn) from Hunter.io
  - Breach statistics and aggregations

Deduplicates by: target_domain + email (compound unique index)
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


# ─── Index & Dedup ───────────────────────────────────────────────────────

def ensure_email_indexes():
    """
    Create indexes for the email_exposures collection.
    Call ONCE on app startup (idempotent — safe to call repeatedly).

    1. Cleans up any legacy duplicate documents first
    2. Creates a unique compound index on (target_domain, email)
       so MongoDB itself rejects future duplicates
    3. Adds performance indexes for common queries
    """
    collection = get_collection(Config.EMAILS_COLLECTION)

    # Step 1 — remove existing duplicates before creating the unique index
    removed = deduplicate_emails()
    if removed:
        print(f"[EMAILS_DB] Cleaned up {removed} duplicate email records")

    # Step 2 — unique compound index (prevents all future duplicates)
    collection.create_index(
        [("target_domain", 1), ("email", 1)],
        unique=True,
        name="unique_domain_email",
        background=True
    )

    # Step 3 — performance indexes
    collection.create_index("target_id", background=True)
    collection.create_index("breach_status", background=True)

    print("[EMAILS_DB] Email indexes ensured")


def deduplicate_emails():
    """
    Remove duplicate email records that already exist in the DB.

    For each set of duplicates (same target_domain + email):
      - Keeps the document with the richest data
        (breached > clean > unknown, then most-recent last_seen)
      - Merges all sources into the keeper
      - Deletes the rest

    Returns:
        Number of documents removed
    """
    collection = get_collection(Config.EMAILS_COLLECTION)

    # Find groups that have more than one document for the same
    # (target_domain, email) pair
    pipeline = [
        {"$group": {
            "_id": {
                "target_domain": "$target_domain",
                "email": "$email"
            },
            "count": {"$sum": 1},
            "doc_ids": {"$push": "$_id"}
        }},
        {"$match": {"count": {"$gt": 1}}}
    ]

    duplicates = list(collection.aggregate(pipeline))
    total_removed = 0

    for dup in duplicates:
        doc_ids = dup["doc_ids"]

        # Fetch all copies, prefer:
        #   1. breach_status = "breached" first (alphabetically < "clean" < "unknown")
        #   2. most-recent last_seen
        docs = list(
            collection.find({"_id": {"$in": doc_ids}})
            .sort([("breach_status", 1), ("last_seen", -1)])
        )

        keeper = docs[0]

        # Merge sources from every copy into the keeper
        all_sources = set()
        for doc in docs:
            for s in doc.get("sources", []):
                all_sources.add(s)

        collection.update_one(
            {"_id": keeper["_id"]},
            {"$set": {"sources": sorted(all_sources)}}
        )

        # Delete the rest
        to_delete = [d["_id"] for d in docs[1:]]
        if to_delete:
            result = collection.delete_many({"_id": {"$in": to_delete}})
            total_removed += result.deleted_count

    return total_removed


# ─── Add / Update ────────────────────────────────────────────────────────

def add_email(target_id, target_domain, email, sources=None,
              first_name="", last_name="", position="",
              linkedin="", confidence=0, breach_data=None):
    """
    Add or update an email exposure record.
    Deduplicates by target_domain + email  (NOT target_id).

    This guarantees that no matter how many times you harvest,
    or how many target documents exist for the same domain,
    each email address appears exactly once per domain.
    """
    try:
        collection = get_collection(Config.EMAILS_COLLECTION)
        target_oid = ObjectId(target_id)
        email = email.lower().strip()
        target_domain = target_domain.lower().strip()
        sources = sources or []
        breach_data = breach_data or {}

        # ── Filter: domain + email (matches the unique index) ──
        filter_key = {
            "target_domain": target_domain,
            "email": email
        }

        # ── Fields updated every time ──
        update_set = {
            "target_id": target_oid,
            "target_domain": target_domain,
            "email": email,
            "last_seen": datetime.utcnow()
        }

        if first_name:
            update_set["first_name"] = first_name
        if last_name:
            update_set["last_name"] = last_name
        if position:
            update_set["position"] = position
        if linkedin:
            update_set["linkedin"] = linkedin
        if confidence:
            update_set["confidence"] = confidence

        # ── Fields set only on first insert ──
        set_on_insert = {
            "first_seen": datetime.utcnow()
        }

        if breach_data:
            update_set["breach_status"] = (
                "breached" if breach_data.get("breached")
                else "clean"
            )
            update_set["breach_count"] = breach_data.get(
                "breach_count", 0
            )
            update_set["breaches"] = breach_data.get("breaches", [])
            update_set["data_types_leaked"] = breach_data.get(
                "data_types_leaked", []
            )
            update_set["password_leaked"] = breach_data.get(
                "password_leaked", False
            )
            update_set["last_breach_check"] = datetime.utcnow()
        else:
            # Only set "unknown" on a brand-new document
            set_on_insert["breach_status"] = "unknown"

        result = collection.update_one(
            filter_key,
            {
                "$setOnInsert": set_on_insert,
                "$set": update_set,
                "$addToSet": {
                    "sources": {"$each": sources}
                }
            },
            upsert=True
        )

        return {
            "success": True,
            "email_id": (
                str(result.upserted_id)
                if result.upserted_id else "updated"
            ),
            "is_new": bool(result.upserted_id)
        }

    except Exception as e:
        return {"success": False, "message": str(e)}


def add_emails_bulk(target_id, target_domain, combined_emails):
    """
    Add multiple emails with their breach data.

    Args:
        target_id: Target document ObjectId string
        target_domain: Domain string
        combined_emails: List of dicts from harvest_and_check()

    Returns:
        Dict with success, total, new count, updated count
    """
    new_count = 0
    updated_count = 0

    for email_data in combined_emails:
        breach_info = None
        if email_data.get("breached") is not None:
            breach_info = {
                "breached": email_data.get("breached", False),
                "breach_count": email_data.get("breach_count", 0),
                "breaches": email_data.get("breaches", []),
                "data_types_leaked": email_data.get(
                    "data_types_leaked", []
                ),
                "password_leaked": email_data.get(
                    "password_leaked", False
                )
            }

        result = add_email(
            target_id=target_id,
            target_domain=target_domain,
            email=email_data.get("email", ""),
            sources=email_data.get("sources", []),
            first_name=email_data.get("first_name", ""),
            last_name=email_data.get("last_name", ""),
            position=email_data.get("position", ""),
            linkedin=email_data.get("linkedin", ""),
            confidence=email_data.get("confidence", 0),
            breach_data=breach_info
        )

        if result.get("success"):
            if result.get("is_new"):
                new_count += 1
            else:
                updated_count += 1

    return {
        "success": True,
        "total": len(combined_emails),
        "new": new_count,
        "updated": updated_count
    }


# ─── Query Functions ─────────────────────────────────────────────────────

def get_emails_by_target(target_id):
    """Return all emails for a target, sorted alphabetically."""
    try:
        collection = get_collection(Config.EMAILS_COLLECTION)
        docs = collection.find(
            {"target_id": ObjectId(target_id)}
        ).sort("email", 1)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_breached_emails(target_id):
    """Return only breached emails for a target."""
    try:
        collection = get_collection(Config.EMAILS_COLLECTION)
        docs = collection.find({
            "target_id": ObjectId(target_id),
            "breach_status": "breached"
        }).sort("breach_count", -1)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_email_by_address(target_id, email):
    """Find a single email record by target and email address."""
    try:
        collection = get_collection(Config.EMAILS_COLLECTION)
        doc = collection.find_one({
            "target_id": ObjectId(target_id),
            "email": email.lower().strip()
        })
        return serialize_doc(doc)
    except Exception:
        return None


def get_email_count(target_id):
    try:
        collection = get_collection(Config.EMAILS_COLLECTION)
        return collection.count_documents(
            {"target_id": ObjectId(target_id)}
        )
    except Exception:
        return 0


def get_breached_email_count(target_id):
    try:
        collection = get_collection(Config.EMAILS_COLLECTION)
        return collection.count_documents({
            "target_id": ObjectId(target_id),
            "breach_status": "breached"
        })
    except Exception:
        return 0


def get_password_leak_count(target_id):
    try:
        collection = get_collection(Config.EMAILS_COLLECTION)
        return collection.count_documents({
            "target_id": ObjectId(target_id),
            "password_leaked": True
        })
    except Exception:
        return 0


def get_email_stats(target_id):
    """Return comprehensive email statistics for a target."""
    try:
        collection = get_collection(Config.EMAILS_COLLECTION)
        target_oid = ObjectId(target_id)

        total = collection.count_documents(
            {"target_id": target_oid}
        )
        breached = collection.count_documents({
            "target_id": target_oid,
            "breach_status": "breached"
        })
        clean = collection.count_documents({
            "target_id": target_oid,
            "breach_status": "clean"
        })
        unchecked = collection.count_documents({
            "target_id": target_oid,
            "breach_status": "unknown"
        })
        password_leaks = collection.count_documents({
            "target_id": target_oid,
            "password_leaked": True
        })

        if total > 0:
            breach_rate = round(breached / total * 100, 1)
        else:
            breach_rate = 0

        pipeline_breaches = [
            {"$match": {
                "target_id": target_oid,
                "breach_status": "breached"
            }},
            {"$unwind": "$breaches"},
            {"$group": {
                "_id": "$breaches.name",
                "count": {"$sum": 1},
                "date": {"$first": "$breaches.breach_date"}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 10}
        ]
        top_breaches = list(
            collection.aggregate(pipeline_breaches)
        )

        pipeline_types = [
            {"$match": {
                "target_id": target_oid,
                "breach_status": "breached"
            }},
            {"$unwind": "$data_types_leaked"},
            {"$group": {
                "_id": "$data_types_leaked",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}}
        ]
        data_types = list(
            collection.aggregate(pipeline_types)
        )

        pipeline_sources = [
            {"$match": {"target_id": target_oid}},
            {"$unwind": "$sources"},
            {"$group": {
                "_id": "$sources",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}}
        ]
        source_summary = list(
            collection.aggregate(pipeline_sources)
        )

        return {
            "total": total,
            "breached": breached,
            "clean": clean,
            "unchecked": unchecked,
            "password_leaks": password_leaks,
            "breach_rate": breach_rate,
            "top_breaches": top_breaches,
            "data_types_leaked": data_types,
            "source_summary": source_summary
        }

    except Exception as e:
        print(f"[EMAILS_DB] Stats error: {e}")
        return {
            "total": 0, "breached": 0, "clean": 0,
            "unchecked": 0, "password_leaks": 0,
            "breach_rate": 0, "top_breaches": [],
            "data_types_leaked": [], "source_summary": []
        }


# ─── Lifecycle ───────────────────────────────────────────────────────────

def mark_all_emails_old(target_id):
    try:
        collection = get_collection(Config.EMAILS_COLLECTION)
        result = collection.update_many(
            {"target_id": ObjectId(target_id)},
            {"$set": {"is_new": False}}
        )
        return result.modified_count
    except Exception:
        return 0


def delete_emails_by_target(target_id):
    try:
        collection = get_collection(Config.EMAILS_COLLECTION)
        result = collection.delete_many(
            {"target_id": ObjectId(target_id)}
        )
        return result.deleted_count
    except Exception:
        return 0


def delete_email_by_id(email_id):
    try:
        collection = get_collection(Config.EMAILS_COLLECTION)
        result = collection.delete_one(
            {"_id": ObjectId(email_id)}
        )
        return result.deleted_count
    except Exception:
        return 0