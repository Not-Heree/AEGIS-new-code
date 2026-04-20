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


def add_vulnerability(target_id, target_domain, subdomain_id, host, url,
                      template_id, name, severity, cve_id=None,
                      description="", matched_at="", reference=None,
                      tags=None, cvss_score=None, cwe_id=None,
                      remediation=None, curl_command="",
                      extracted_results=None):
    """
    Add or update a vulnerability. Deduplicates by (target_id, host, template_id).
    Now stores target_domain AND all Nuclei output fields.
    """
    try:
        collection = get_collection(Config.VULNS_COLLECTION)
        target_oid = ObjectId(target_id)
        reference = reference or []
        tags = tags or []
        cwe_id = cwe_id or []
        extracted_results = extracted_results or []
        remediation = remediation or {}

        # Dedup: same template on same host = same vuln
        existing = collection.find_one({
            "target_id": target_oid,
            "host": host,
            "template_id": template_id
        })

        if existing:
            update_fields = {
                "last_found": datetime.utcnow(),
                "target_domain": target_domain,
            }

            # Regression: was resolved but found again
            if existing.get("status") == "resolved":
                update_fields["status"] = "open"
                update_fields["resolved_at"] = None
                update_fields["is_new"] = True
                is_new = True
            else:
                update_fields["is_new"] = False
                is_new = False

            # Update description/remediation if they were empty before
            if description and not existing.get("description"):
                update_fields["description"] = description
            if remediation and not existing.get("remediation"):
                update_fields["remediation"] = remediation
            if cve_id and not existing.get("cve_id"):
                update_fields["cve_id"] = cve_id
            if cvss_score and not existing.get("cvss_score"):
                update_fields["cvss_score"] = cvss_score

            collection.update_one(
                {"_id": existing["_id"]},
                {"$set": update_fields}
            )
            return {
                "success": True,
                "vuln_id": str(existing["_id"]),
                "is_new": is_new
            }

        # New vulnerability
        doc = {
            "target_id": target_oid,
            "target_domain": target_domain,          # NEW
            "subdomain_id": ObjectId(subdomain_id) if subdomain_id else None,
            "host": host,
            "url": url,
            "template_id": template_id,
            "name": name,
            "severity": severity,
            "cve_id": cve_id,                        # NEW — was dropped
            "cvss_score": cvss_score,                 # NEW — was dropped
            "description": description,
            "matched_at": matched_at,
            "reference": reference,                   # NEW — was dropped
            "tags": tags,                             # NEW — was dropped
            "cwe_id": cwe_id,                         # NEW — was dropped
            "remediation": remediation,               # NEW — was dropped
            "curl_command": curl_command,              # NEW — was dropped
            "extracted_results": extracted_results,    # NEW — was dropped
            "status": "open",
            "is_new": True,
            "first_found": datetime.utcnow(),
            "last_found": datetime.utcnow(),
            "resolved_at": None
        }
        result = collection.insert_one(doc)

        return {
            "success": True,
            "vuln_id": str(result.inserted_id),
            "is_new": True
        }

    except Exception as e:
        return {"success": False, "message": str(e)}


def get_vulns_by_target(target_id, status=None):
    """Return vulnerabilities for a target, optionally filtered by status."""
    try:
        collection = get_collection(Config.VULNS_COLLECTION)
        query = {"target_id": ObjectId(target_id)}
        if status:
            query["status"] = status
        docs = collection.find(query).sort("last_found", -1)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def get_new_vulns(target_id):
    """Return only vulnerabilities marked as is_new=True for a target."""
    try:
        collection = get_collection(Config.VULNS_COLLECTION)
        docs = collection.find({
            "target_id": ObjectId(target_id),
            "is_new": True
        }).sort("last_found", -1)
        return [serialize_doc(d) for d in docs]
    except Exception:
        return []


def update_vuln_status(vuln_id, status):
    """Update the status of a vulnerability (open, resolved, false_positive)."""
    try:
        collection = get_collection(Config.VULNS_COLLECTION)
        update_fields = {"status": status}

        if status == "resolved":
            update_fields["resolved_at"] = datetime.utcnow()
        else:
            update_fields["resolved_at"] = None

        collection.update_one(
            {"_id": ObjectId(vuln_id)},
            {"$set": update_fields}
        )
        return True
    except Exception:
        return False


def mark_all_vulns_old(target_id):
    """Set is_new=False for ALL vulnerabilities of a target.
    Called before a new scan so only fresh discoveries are marked new.
    """
    try:
        collection = get_collection(Config.VULNS_COLLECTION)
        result = collection.update_many(
            {"target_id": ObjectId(target_id)},
            {"$set": {"is_new": False}}
        )
        return result.modified_count
    except Exception:
        return 0


def get_vuln_stats(target_id):
    """Return counts of open vulnerabilities grouped by severity.
    Uses aggregation to produce: [{"_id": "critical", "count": 3}, ...]
    """
    try:
        collection = get_collection(Config.VULNS_COLLECTION)
        pipeline = [
            {"$match": {
                "target_id": ObjectId(target_id),
                "status": "open"
            }},
            {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
        ]
        return list(collection.aggregate(pipeline))
    except Exception:
        return []


def delete_vulns_by_target(target_id):
    """Delete ALL vulnerabilities for a target."""
    try:
        collection = get_collection(Config.VULNS_COLLECTION)
        result = collection.delete_many({"target_id": ObjectId(target_id)})
        return result.deleted_count
    except Exception:
        return 0
