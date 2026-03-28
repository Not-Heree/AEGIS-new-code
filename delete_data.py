"""
EASM AEGIS — Database Reset Script
====================================
Deletes ALL data from ALL collections in the EASM database.
Use this to start fresh before a new scan.

Run with: python delete_data.py

WARNING: This is IRREVERSIBLE. All scan data will be lost.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from pymongo import MongoClient
    from config import Config
except ImportError:
    print("ERROR: Could not import pymongo or Config.")
    sys.exit(1)


def _get_db_name():
    """Get DB name from Config — tries multiple possible attribute names."""
    for attr in ["MONGO_DB_NAME", "DB_NAME", "DATABASE_NAME", "MONGO_DB", "MONGO_DATABASE"]:
        if hasattr(Config, attr):
            return getattr(Config, attr)

    # Fallback: extract from MONGO_URI if it contains a path
    # e.g., mongodb://localhost:27017/easm_db → easm_db
    uri = getattr(Config, "MONGO_URI", "")
    if "/" in uri and len(uri.rsplit("/", 1)) > 1:
        db_from_uri = uri.rsplit("/", 1)[-1].split("?")[0]
        if db_from_uri and db_from_uri not in ("", "admin", "test"):
            # Ensure it doesn't return 'localhost:27017' if no DB path
            if ":" not in db_from_uri:
                return db_from_uri

    return "easm_db"  # Fallback to default


def reset_database():
    db_name = _get_db_name()
    mongo_uri = getattr(Config, "MONGO_URI", "mongodb://localhost:27017")

    print("=" * 60)
    print("  EASM AEGIS — DATABASE RESET")
    print("=" * 60)
    print(f"  Database: {db_name}")
    print(f"  URI:      {mongo_uri}")
    print("=" * 60)

    # ── Confirmation prompt ──────────────────────────────
    confirm = input(
        "\n  Type 'yes' to confirm ALL data deletion (including targets): "
    ).strip().lower()

    if confirm != "yes":
        print("\n  Aborted. No data was deleted.")
        return

    try:
        client = MongoClient(mongo_uri)
        db = client[db_name]

        # Get all collection names
        collections = db.list_collection_names()

        if not collections:
            print("\n  Database is already empty.")
            client.close()
            return

        print(f"\n  Found {len(collections)} collections:\n")

        total_deleted = 0

        for name in sorted(collections):
            count = db[name].count_documents({})
            result = db[name].delete_many({})
            deleted = result.deleted_count
            total_deleted += deleted
            
            # Map collection names to friendly icons/labels
            label = ""
            if name == "targets": label = "🎯 (Targets)"
            elif "email" in name.lower(): label = "📧 (Emails)"
            elif "vuln" in name.lower(): label = "🛡️ (Vulns)"
            elif "port" in name.lower() or "service" in name.lower(): label = "🔌 (Ports)"
            elif "subdomain" in name.lower(): label = "🌐 (Subdomains)"
            elif "http" in name.lower(): label = "📄 (HTTP)"
            
            print(f"    {name:30s} — {deleted:>6d} docs deleted {label}")

        print(f"\n  {'TOTAL':30s} — {total_deleted:>6d} documents deleted")
        print("\n  ✅ Database reset complete. ALL data (including targets) has been wiped.")

        client.close()

    except Exception as e:
        print(f"\n  ERROR: {e}")
        sys.exit(1)


if __name__ == "__main__":
    reset_database()