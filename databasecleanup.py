# databasecleanup.py  (in root directory, same level as config.py)
"""
Database cleanup — wipes all EASM data.
Run ONCE before deploying the unified fix.
"""

from pymongo import MongoClient
import os
import glob

# Direct import since file is in root directory alongside config.py
try:
    from config import Config
    print("✅ Config loaded")
except ImportError as e:
    print(f"❌ Cannot import config: {e}")
    print(f"   Current directory: {os.getcwd()}")
    print(f"   Make sure config.py is in the same folder")
    exit(1)


def cleanup():
    print()
    print("=" * 50)
    print("  EASM AEGIS — Database Cleanup")
    print("=" * 50)
    print(f"  Database: {Config.MONGO_DB_NAME}")
    print(f"  URI:      {Config.MONGO_URI}")
    print()

    # Connect
    try:
        client = MongoClient(Config.MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        db = client[Config.MONGO_DB_NAME]
        print("✅ MongoDB connected")
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        print("   Make sure MongoDB is running!")
        return

    collections = [
        Config.TARGETS_COLLECTION,
        Config.SUBDOMAINS_COLLECTION,
        Config.PORTS_COLLECTION,
        Config.HTTP_ASSETS_COLLECTION,
        Config.VULNS_COLLECTION,
        Config.CHANGES_COLLECTION,
        Config.SCANS_COLLECTION,
    ]

    # Show current counts
    print()
    print("Current data:")
    total = 0
    for name in collections:
        count = db[name].count_documents({})
        total += count
        print(f"  {name}: {count} documents")

    print(f"\n  TOTAL: {total} documents across {len(collections)} collections")

    if total == 0:
        print("\n  Database is already empty!")
        return

    # Confirm
    print()
    confirm = input("  DELETE ALL DATA? Type 'yes' to confirm: ")
    if confirm.strip().lower() != "yes":
        print("  Aborted.")
        return

    # Delete everything
    print()
    for name in collections:
        count = db[name].count_documents({})
        db[name].delete_many({})
        try:
            db[name].drop_indexes()
        except Exception:
            pass
        print(f"  ✅ {name}: deleted {count} documents, indexes dropped")

    # Clean generated reports
    reports_dir = getattr(Config, 'REPORTS_DIR', 'generated_reports')
    if os.path.exists(reports_dir):
        pdfs = glob.glob(os.path.join(reports_dir, "*.pdf"))
        for pdf in pdfs:
            os.remove(pdf)
        print(f"  ✅ Removed {len(pdfs)} PDF reports")

    print()
    print("=" * 50)
    print("  ✅ Database wiped clean!")
    print("  Now restart Flask app to reinitialize indexes.")
    print("=" * 50)


if __name__ == "__main__":
    cleanup()