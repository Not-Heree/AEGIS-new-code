"""
Scheduled Scans Database Layer
==============================
CRUD operations for managing scheduled security scans.

Stores scan schedules with cron expressions, frequency options,
and execution history.
"""

from datetime import datetime, timedelta
from bson import ObjectId
from database.connection import get_collection
from config import Config


def create_schedule(target_id, target_domain, frequency, time_of_day, enabled=True, scan_type='full'):
    """
    Create a new scan schedule.

    Args:
        target_id: Target ObjectId
        target_domain: Domain name
        frequency: 'daily', 'weekly', 'monthly'
        time_of_day: Time in HH:MM format (24-hour)
        enabled: Whether schedule is active
        scan_type: 'full' or 'passive'

    Returns:
        dict with success and schedule_id
    """
    try:
        collection = get_collection(Config.SCAN_SCHEDULES_COLLECTION)

        schedule = {
            "target_id": ObjectId(target_id) if isinstance(target_id, str) else target_id,
            "target_domain": target_domain,
            "frequency": frequency.lower(),  # 'daily', 'weekly', 'monthly'
            "time_of_day": time_of_day,  # HH:MM format
            "scan_type": scan_type,  # 'full' or 'passive'
            "enabled": enabled,
            "created_at": datetime.utcnow(),
            "last_run": None,
            "next_run": calculate_next_run(frequency, time_of_day),
            "total_runs": 0,
            "failed_runs": 0,
            "last_status": None,
            "notes": ""
        }

        result = collection.insert_one(schedule)
        return {
            "success": True,
            "schedule_id": str(result.inserted_id)
        }

    except Exception as e:
        return {
            "success": False,
            "message": str(e)
        }


def get_schedule(schedule_id):
    """Get a schedule by ID"""
    try:
        collection = get_collection(Config.SCAN_SCHEDULES_COLLECTION)
        schedule = collection.find_one({"_id": ObjectId(schedule_id)})

        if schedule:
            schedule["_id"] = str(schedule["_id"])
            if "target_id" in schedule:
                schedule["target_id"] = str(schedule["target_id"])
            if "created_at" in schedule:
                schedule["created_at"] = schedule["created_at"].isoformat()
            if "next_run" in schedule and schedule["next_run"]:
                schedule["next_run"] = schedule["next_run"].isoformat()

        return schedule

    except Exception:
        return None


def get_schedules_for_target(target_id):
    """Get all schedules for a specific target"""
    try:
        collection = get_collection(Config.SCAN_SCHEDULES_COLLECTION)
        schedules = list(collection.find({
            "target_id": ObjectId(target_id) if isinstance(target_id, str) else target_id
        }))

        result = []
        for s in schedules:
            s["_id"] = str(s["_id"])
            s["target_id"] = str(s["target_id"])
            if "created_at" in s:
                s["created_at"] = s["created_at"].isoformat()
            if "next_run" in s and s["next_run"]:
                s["next_run"] = s["next_run"].isoformat()
            result.append(s)

        return result

    except Exception:
        return []


def get_schedules_due_for_execution():
    """Get all schedules that are due to run now"""
    try:
        collection = get_collection(Config.SCAN_SCHEDULES_COLLECTION)
        now = datetime.utcnow()

        schedules = list(collection.find({
            "enabled": True,
            "next_run": {"$lte": now}
        }))

        result = []
        for s in schedules:
            s["_id"] = str(s["_id"])
            s["target_id"] = str(s["target_id"])
            result.append(s)

        return result

    except Exception:
        return []


def update_schedule(schedule_id, **kwargs):
    """Update a schedule"""
    try:
        collection = get_collection(Config.SCAN_SCHEDULES_COLLECTION)

        # Only allow specific fields to be updated
        allowed_fields = {
            'frequency', 'time_of_day', 'scan_type', 'enabled', 'notes'
        }

        update_data = {k: v for k, v in kwargs.items() if k in allowed_fields}

        if not update_data:
            return {"success": False, "message": "No valid fields to update"}

        result = collection.update_one(
            {"_id": ObjectId(schedule_id)},
            {"$set": update_data}
        )

        return {
            "success": result.modified_count > 0,
            "matched": result.matched_count > 0
        }

    except Exception as e:
        return {"success": False, "message": str(e)}


def record_execution(schedule_id, status, scan_id=None, error_message=None):
    """
    Record a scan execution for this schedule.

    Args:
        schedule_id: Schedule ID
        status: 'success', 'failed', 'skipped'
        scan_id: ID of the created scan (if successful)
        error_message: Error details if failed
    """
    try:
        collection = get_collection(Config.SCAN_SCHEDULES_COLLECTION)

        schedule = collection.find_one({"_id": ObjectId(schedule_id)})
        if not schedule:
            return {"success": False, "message": "Schedule not found"}

        # Update schedule
        update_dict = {
            "last_run": datetime.utcnow(),
            "last_status": status
        }

        if status == 'success':
            update_dict["total_runs"] = (schedule.get("total_runs", 0) or 0) + 1
        else:
            update_dict["failed_runs"] = (schedule.get("failed_runs", 0) or 0) + 1

        # Calculate next run
        frequency = schedule.get("frequency", "daily")
        time_of_day = schedule.get("time_of_day", "00:00")
        update_dict["next_run"] = calculate_next_run(frequency, time_of_day)

        collection.update_one(
            {"_id": ObjectId(schedule_id)},
            {"$set": update_dict}
        )

        # Log execution
        log_collection = get_collection("scan_schedule_executions")
        log_collection.insert_one({
            "schedule_id": ObjectId(schedule_id),
            "target_domain": schedule.get("target_domain"),
            "status": status,
            "scan_id": ObjectId(scan_id) if scan_id else None,
            "error": error_message,
            "executed_at": datetime.utcnow()
        })

        return {"success": True}

    except Exception as e:
        return {"success": False, "message": str(e)}


def delete_schedule(schedule_id):
    """Delete a schedule"""
    try:
        collection = get_collection(Config.SCAN_SCHEDULES_COLLECTION)
        result = collection.delete_one({"_id": ObjectId(schedule_id)})
        return {"success": result.deleted_count > 0}

    except Exception as e:
        return {"success": False, "message": str(e)}


def calculate_next_run(frequency, time_of_day):
    """
    Calculate the next scheduled run time.

    Args:
        frequency: 'daily', 'weekly', 'monthly'
        time_of_day: Time in HH:MM format

    Returns:
        datetime of next scheduled run
    """
    try:
        hours, minutes = map(int, time_of_day.split(':'))
        now = datetime.utcnow()

        # Create today's scheduled time
        scheduled_time = now.replace(hour=hours, minute=minutes, second=0, microsecond=0)

        # If scheduled time is in the past today, move to next period
        if scheduled_time <= now:
            if frequency == 'daily':
                scheduled_time += timedelta(days=1)
            elif frequency == 'weekly':
                scheduled_time += timedelta(weeks=1)
            elif frequency == 'monthly':
                # Add one month
                if scheduled_time.month == 12:
                    scheduled_time = scheduled_time.replace(year=scheduled_time.year + 1, month=1)
                else:
                    scheduled_time = scheduled_time.replace(month=scheduled_time.month + 1)

        return scheduled_time

    except Exception:
        # Default to tomorrow same time if error
        return datetime.utcnow() + timedelta(days=1)
