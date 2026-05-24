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



def create_scan_with_domain(target_id, target_domain, scan_type="full"):
    """Create scan record with target_domain for route queries."""
    try:
        collection = get_collection(Config.SCANS_COLLECTION)

        doc = {
            "target_id": ObjectId(target_id),
            "target_domain": target_domain,            # NEW
            "scan_type": scan_type,
            "status": "running",
            "started_at": datetime.utcnow(),
            "completed_at": None,
            "duration_seconds": 0,
            "results": {},
            "error_message": "",
            "progress_percent": 0,
            "current_phase": "starting",
            "phase_detail": "Initializing scan...",
        }
        result = collection.insert_one(doc)

        return {
            "success": True,
            "scan_id": str(result.inserted_id)
        }

    except Exception as e:
        return {"success": False, "message": str(e)}


def cleanup_stale_scans():
    """Mark all 'running' scans as 'failed' (interrupted by server restart)."""
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        result = collection.update_many(
            {"status": "running"},
            {"$set": {
                "status": "failed",
                "completed_at": datetime.utcnow(),
                "error_message": "Scan interrupted by system restart. Ready for resume."
            }}
        )
        if result.modified_count > 0:
            from utils.logger import logger
            logger.info("Cleaned up %d stale scans", result.modified_count)
        return True
    except Exception:
        return False


def update_scan_progress(scan_id, progress_data):
    """Update scan progress. Called by scanner.py at each phase."""
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        collection.update_one(
            {"_id": ObjectId(scan_id)},
            {"$set": {
                "current_phase": progress_data.get("current_phase", ""),
                "phase_detail": progress_data.get("phase_detail", ""),
                "progress_percent": progress_data.get("progress_percent", 0),
            }}
        )
    except Exception as e:
        print(f"[SCANS_DB] Progress update error: {e}")

def get_scan_progress(scan_id):
    """Get scan progress for status endpoint."""
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        scan = collection.find_one({"_id": ObjectId(scan_id)})
        if scan:
            return serialize_doc(scan)
        return None
    except Exception:
        return None

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


# ═══════════════════════════════════════════════════════════════════════════
# RESUMABILITY FUNCTIONS — Support for scan checkpoints and resumption
# ═══════════════════════════════════════════════════════════════════════════

def mark_phase_completed(scan_id, phase_name):
    """
    Mark a phase as successfully completed.
    Allows scan to resume from this point if interrupted.

    Args:
        scan_id: Scan ID (string)
        phase_name: Phase name (e.g., "passive_recon", "port_scanning")
    """
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        collection.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$addToSet": {"phases_completed": phase_name},
                "$set": {"last_checkpoint": datetime.utcnow()}
            }
        )
        return True
    except Exception as e:
        print(f"[SCANS_DB] Error marking phase {phase_name} complete: {e}")
        return False


def get_completed_phases(scan_id):
    """
    Get list of already-completed phases for a scan.
    Used during resume to skip completed work.

    Returns:
        List of phase names (e.g., ["passive_recon", "subdomain_discovery"])
    """
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        scan = collection.find_one(
            {"_id": ObjectId(scan_id)},
            {"phases_completed": 1}
        )
        if scan:
            return scan.get("phases_completed", [])
        return []
    except Exception:
        return []


def can_resume_scan(scan_id):
    """
    Check if a scan can be resumed from a previous failure.

    Returns:
        Dict with {resumes: bool, completed_phases: list, error: str}
    """
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        scan = collection.find_one({"_id": ObjectId(scan_id)})

        if not scan:
            return {"can_resume": False, "error": "Scan not found"}

        # Can resume if: status is failed/interrupted AND has completed phases
        completed = scan.get("phases_completed", [])
        status = scan.get("status", "")

        if status not in ["failed", "interrupted"]:
            return {
                "can_resume": False,
                "error": f"Scan status is '{status}', not resumable"
            }

        if not completed:
            return {
                "can_resume": False,
                "error": "No completed phases to resume from"
            }

        return {
            "can_resume": True,
            "completed_phases": completed,
            "interrupted_at": scan.get("completed_at"),
            "last_checkpoint": scan.get("last_checkpoint")
        }

    except Exception as e:
        return {"can_resume": False, "error": str(e)}


def reset_scan_for_resume(scan_id):
    """
    Reset a scan record to resume from its last checkpoint.
    Clears end time, error message, re-marks as running.

    Returns:
        bool - success
    """
    try:
        collection = get_collection(Config.SCANS_COLLECTION)
        collection.update_one(
            {"_id": ObjectId(scan_id)},
            {
                "$set": {
                    "status": "running",
                    "completed_at": None,
                    "error_message": "",
                    "phase_detail": "Resuming scan from last checkpoint..."
                }
            }
        )
        return True
    except Exception as e:
        print(f"[SCANS_DB] Error resetting scan for resume: {e}")
        return False


def get_failed_scan_with_completed_phases(target_domain):
    """
    Find the most recent failed scan for a domain that has completed phases.
    Used for auto-resume when user initiates a new scan.

    Args:
        target_domain: Domain string (e.g., "example.com")

    Returns:
        Dict with scan_id, completed_phases, or None if no resumable scan found
    """
    try:
        collection = get_collection(Config.SCANS_COLLECTION)

        # Find most recent failed scan with completed phases
        scan = collection.find_one(
            {
                "target_domain": target_domain,
                "status": "failed",
                "phases_completed": {"$exists": True, "$ne": []}
            },
            sort=[("completed_at", -1)]
        )

        if scan:
            return {
                "scan_id": str(scan["_id"]),
                "completed_phases": scan.get("phases_completed", []),
                "last_checkpoint": scan.get("last_checkpoint"),
                "error_message": scan.get("error_message", "")
            }
        return None
    except Exception as e:
        print(f"[SCANS_DB] Error finding failed scan: {e}")
        return None
