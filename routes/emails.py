"""
Email Exposure Routes
"""
import threading
from flask import Blueprint, jsonify, request
from bson import ObjectId
from datetime import datetime
from database.connection import get_db
from config import Config
from utils.sanitize import (                              # ◄ NEW
    sanitize_domain, sanitize_object_id                   # ◄ NEW
)                                                         # ◄ NEW

emails_bp = Blueprint("emails", __name__, url_prefix="/api/emails")

_harvest_locks = {}
_locks_lock = threading.Lock()



def _start_harvest(domain):
    """Mark domain as being harvested. Returns False if already running."""
    with _locks_lock:
        if domain in _harvest_locks:
            return False
        _harvest_locks[domain] = True
        return True


def _end_harvest(domain):
    """Mark harvest as complete."""
    with _locks_lock:
        _harvest_locks.pop(domain, None)

# =============================================================================
# SERIALIZATION
# =============================================================================

def _serialize(doc):
    if doc is None:
        return None
    result = {}
    for key, value in doc.items():
        if isinstance(value, ObjectId):
            result[key] = str(value)
        elif isinstance(value, datetime):
            result[key] = value.isoformat()
        elif isinstance(value, list):
            result[key] = [
                _serialize(v) if isinstance(v, dict)
                else str(v) if isinstance(v, ObjectId)
                else v.isoformat() if isinstance(v, datetime)
                else v
                for v in value
            ]
        elif isinstance(value, dict):
            result[key] = _serialize(value)
        else:
            result[key] = value
    return result


def _serialize_list(docs):
    return [_serialize(doc) for doc in docs]


def _find_target(domain):
    db = get_db()
    target = db[Config.TARGETS_COLLECTION].find_one(
        {"root_domain": domain}
    )
    if not target:
        target = db[Config.TARGETS_COLLECTION].find_one(
            {"domain": domain}
        )
    return target


# =============================================================================
# GET ALL EMAILS
# =============================================================================

@emails_bp.route("/", methods=["GET"])
def get_all_emails():
    try:
        db = get_db()
        emails = _serialize_list(
            db[Config.EMAILS_COLLECTION].find()
            .sort("email", 1)
        )
        return jsonify({
            "success": True,
            "count": len(emails),
            "emails": emails
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# GET EMAILS BY DOMAIN
# =============================================================================

@emails_bp.route("/<domain>", methods=["GET"])
def get_emails_by_domain(domain):
    try:
        try:
            domain = sanitize_domain(domain)
        except ValueError as e:
            return jsonify({
                "success": False, "error": str(e)
            }), 400

        db = get_db()
        raw_emails = _serialize_list(
            db[Config.EMAILS_COLLECTION].find(
                {"target_domain": domain}
            ).sort("email", 1)
        )

        # ── Dedup safety net ──────────────────────────────────
        # If legacy duplicates still exist in the DB, collapse
        # them here so the frontend never sees them.
        seen = {}
        emails = []
        for e in raw_emails:
            addr = e.get("email", "").lower()
            if not addr:
                continue
            if addr not in seen:
                seen[addr] = e
                emails.append(e)
            else:
                # Merge sources from the duplicate into the keeper
                keeper = seen[addr]
                for s in e.get("sources", []):
                    if s not in keeper.get("sources", []):
                        keeper.setdefault("sources", []).append(s)
                # Keep richer breach data
                if (e.get("breach_status") == "breached"
                        and keeper.get("breach_status") != "breached"):
                    for field in ("breach_status", "breach_count",
                                  "breaches", "data_types_leaked",
                                  "password_leaked"):
                        if field in e:
                            keeper[field] = e[field]
        # ── End dedup ─────────────────────────────────────────

        # Calculate summary stats
        total = len(emails)
        breached = sum(
            1 for e in emails
            if e.get("breach_status") == "breached"
        )
        clean = sum(
            1 for e in emails
            if e.get("breach_status") == "clean"
        )
        unchecked = sum(
            1 for e in emails
            if e.get("breach_status") == "unknown"
        )
        password_leaks = sum(
            1 for e in emails
            if e.get("password_leaked")
        )

        return jsonify({
            "success": True,
            "domain": domain,
            "count": total,
            "summary": {
                "total": total,
                "breached": breached,
                "clean": clean,
                "unchecked": unchecked,
                "password_leaks": password_leaks,
                "breach_rate": round(
                    (breached / total * 100) if total > 0 else 0, 1
                )
            },
            "emails": emails
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# ON-DEMAND BREACH CHECK
# =============================================================================

@emails_bp.route("/<domain>/check-breaches", methods=["POST"])
def check_email_breaches(domain):
    """Trigger a breach check for all unchecked emails of a domain."""
    try:
        try:
            domain = sanitize_domain(domain)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        db = get_db()

        # Only check emails that are 'unknown'
        unchecked_docs = list(db[Config.EMAILS_COLLECTION].find({
            "target_domain": domain,
            "breach_status": "unknown"
        }))

        if not unchecked_docs:
            return jsonify({
                "success": True,
                "message": "No unchecked emails found for this domain",
                "checked": 0
            })

        emails_to_check = [doc["email"] for doc in unchecked_docs]

        from core.email_harvester import check_breaches_batch
        from database.emails_db import add_email

        breach_result = check_breaches_batch(emails_to_check)
        results = breach_result.get("results", {})

        target = _find_target(domain)
        target_id = str(target["_id"]) if target else None

        # Update each email with results
        updated = 0
        for email_addr, res in results.items():
            add_email(
                target_id=target_id,
                target_domain=domain,
                email=email_addr,
                breach_data=res
            )
            updated += 1

        return jsonify({
            "success": True,
            "checked": updated,
            "summary": breach_result.get("summary", {})
        })

    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# GET EMAIL STATS
# =============================================================================

@emails_bp.route("/stats/<domain>", methods=["GET"])
def get_email_stats(domain):
    try:
        try:                                               # ◄ NEW
            domain = sanitize_domain(domain)               # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        target = _find_target(domain)
        if not target:
            return jsonify({
                "success": False,
                "error": f"Target '{domain}' not found"
            }), 404

        from database.emails_db import get_email_stats as db_stats
        stats = db_stats(str(target["_id"]))

        return jsonify({
            "success": True,
            "domain": domain,
            "stats": stats
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# GET BREACH DETAILS
# =============================================================================

@emails_bp.route("/breaches/<domain>", methods=["GET"])
def get_breach_details(domain):
    try:
        try:                                               # ◄ NEW
            domain = sanitize_domain(domain)               # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        db = get_db()
        breached = _serialize_list(
            db[Config.EMAILS_COLLECTION].find({
                "target_domain": domain,
                "breach_status": "breached"
            }).sort("breach_count", -1)
        )

        total_breaches = sum(
            e.get("breach_count", 0) for e in breached
        )
        password_leaks = sum(
            1 for e in breached
            if e.get("password_leaked")
        )

        all_breach_names = set()
        for e in breached:
            for b in e.get("breaches", []):
                name = b.get("name", "")
                if name:
                    all_breach_names.add(name)

        return jsonify({
            "success": True,
            "domain": domain,
            "breached_count": len(breached),
            "total_breaches": total_breaches,
            "password_leaks": password_leaks,
            "unique_breaches": len(all_breach_names),
            "breach_names": sorted(all_breach_names),
            "emails": breached
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# TRIGGER MANUAL HARVEST
# =============================================================================

@emails_bp.route("/harvest/<domain>", methods=["POST"])
def trigger_harvest(domain):
    try:
        try:
            domain = sanitize_domain(domain)
        except ValueError as e:
            return jsonify({"success": False, "error": str(e)}), 400

        # ── Prevent concurrent harvests ──
        if not _start_harvest(domain):
            return jsonify({
                "success": False,
                "error": (
                    f"Harvest already running for {domain}. "
                    f"Please wait for it to finish."
                )
            }), 409

        try:
            target = _find_target(domain)
            if not target:
                return jsonify({
                    "success": False,
                    "error": f"Target '{domain}' not found"
                }), 404

            target_id = str(target["_id"])

            from core.email_harvester import harvest_and_check
            from database.emails_db import add_emails_bulk

            result = harvest_and_check(domain)

            if result.get("success"):
                combined = result.get("combined", {})
                emails_data = combined.get("emails", [])

                if emails_data:
                    saved = add_emails_bulk(
                        target_id, domain, emails_data
                    )
                else:
                    saved = {"new": 0, "updated": 0}

                try:
                    db = get_db()
                    db[Config.TARGETS_COLLECTION].update_one(
                        {"_id": target["_id"]},
                        {"$set": {
                            "total_emails": combined.get(
                                "total_emails", 0
                            ),
                            "total_breached_emails": combined.get(
                                "total_breached", 0
                            )
                        }}
                    )
                except Exception as e:
                    print(
                        f"[EMAILS] Error updating target "
                        f"stats: {e}"
                    )

                return jsonify({
                    "success": True,
                    "domain": domain,
                    "emails_found": combined.get(
                        "total_emails", 0
                    ),
                    "emails_breached": combined.get(
                        "total_breached", 0
                    ),
                    "password_leaks": combined.get(
                        "password_leaks", 0
                    ),
                    "saved": saved,
                    "source_stats": result.get(
                        "harvest", {}
                    ).get("source_stats", {})
                })
            else:
                return jsonify({
                    "success": False,
                    "error": result.get(
                        "error", "Harvest failed"
                    )
                }), 500

        finally:
            _end_harvest(domain)

    except Exception as e:
        _end_harvest(domain)
        return jsonify({
            "success": False, "error": str(e)
        }), 500

# =============================================================================
# DELETE SINGLE EMAIL
# =============================================================================

@emails_bp.route("/<email_id>", methods=["DELETE"])
def delete_email(email_id):
    try:
        try:                                               # ◄ NEW
            email_id = sanitize_object_id(                 # ◄ NEW
                email_id, "email_id"                       # ◄ NEW
            )                                              # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        db = get_db()
        result = db[Config.EMAILS_COLLECTION].delete_one(
            {"_id": ObjectId(email_id)}
        )
        if result.deleted_count == 0:
            return jsonify({
                "success": False,
                "error": "Email not found"
            }), 404

        return jsonify({
            "success": True,
            "message": "Email record deleted"
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# DELETE ALL EMAILS FOR DOMAIN
# =============================================================================

@emails_bp.route("/domain/<domain>", methods=["DELETE"])
def delete_emails_for_domain(domain):
    try:
        try:                                               # ◄ NEW
            domain = sanitize_domain(domain)               # ◄ NEW
        except ValueError as e:                            # ◄ NEW
            return jsonify({                               # ◄ NEW
                "success": False, "error": str(e)          # ◄ NEW
            }), 400                                        # ◄ NEW

        db = get_db()

        result = db[Config.EMAILS_COLLECTION].delete_many(
            {"target_domain": domain}
        )

        target = _find_target(domain)
        if target:
            db[Config.TARGETS_COLLECTION].update_one(
                {"_id": target["_id"]},
                {"$set": {
                    "total_emails": 0,
                    "total_breached_emails": 0
                }}
            )

        return jsonify({
            "success": True,
            "message": (
                f"Deleted {result.deleted_count} "
                f"email records for {domain}"
            ),
            "deleted_count": result.deleted_count
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500