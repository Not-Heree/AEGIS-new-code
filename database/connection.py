# database/connection.py

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from config import Config

# ─── Module-level connection variables ───────────────────────────────────
client = None
db = None


# ─── Connection ──────────────────────────────────────────────────────────

def connect_db():
    """Creates MongoClient and connects to MongoDB."""
    global client, db
    try:
        client = MongoClient(
            Config.MONGO_URI,
            serverSelectionTimeoutMS=5000
        )
        db = client[Config.MONGO_DB_NAME]
        print(f"✅ MongoDB Connected: {Config.MONGO_URI}")
        print(f"📦 Database: {Config.MONGO_DB_NAME}")
        return db
    except ServerSelectionTimeoutError:
        print(f"❌ MongoDB Timeout: {Config.MONGO_URI}")
        raise
    except ConnectionFailure:
        print(f"❌ MongoDB Connection Failed: {Config.MONGO_URI}")
        raise
    except Exception as e:
        print(f"❌ Unexpected Error: {e}")
        raise


def test_connection():
    """Test if MongoDB is reachable by sending a ping command."""
    global client
    try:
        if client is None:
            connect_db()
        client.admin.command("ping")
        print("✅ MongoDB connection is alive")
        return True
    except Exception as e:
        print(f"❌ MongoDB ping failed: {e}")
        return False


# ─── Safe Index Creation ─────────────────────────────────────────────────

def _safe_create_index(collection, keys, **kwargs):
    """
    Create index safely — drops conflicting index if needed.
    
    This prevents crashes when index definition changes
    between code updates.
    """
    try:
        collection.create_index(keys, **kwargs)
    except Exception:
        try:
            # Try dropping by name first
            index_name = kwargs.get("name", None)
            if index_name:
                try:
                    collection.drop_index(index_name)
                except Exception:
                    pass
            # Drop all non-_id indexes and retry
            collection.drop_indexes()
            collection.create_index(keys, **kwargs)
        except Exception as e:
            print(f"  ⚠️  Index warning on {collection.name}: {e}")


# ─── Database Initialization ─────────────────────────────────────────────

def init_db():
    """
    Initialize MongoDB connection and create indexes on all 7 collections.
    
    Indexes match how routes actually query data:
    - Routes query by: root_domain, target_domain, subdomain, host, port
    - Indexes are created on those exact fields
    """
    global db

    try:
        if db is None:
            connect_db()

        # ── 1. targets ──────────────────────────────
        # Routes query: find_one({"root_domain": domain})
        _safe_create_index(
            db[Config.TARGETS_COLLECTION],
            [("root_domain", ASCENDING)],
            unique=True,
            name="root_domain_unique"
        )
        _safe_create_index(
            db[Config.TARGETS_COLLECTION],
            [("domain", ASCENDING)],
            unique=True,
            sparse=True,
            name="domain_unique"
        )
        print("  ✅ targets indexes created")

        # ── 2. subdomains ───────────────────────────
        # Routes query: find({"target_domain": domain})
        # Scanner saves: update_one({"subdomain": sub})
        _safe_create_index(
            db[Config.SUBDOMAINS_COLLECTION],
            [("subdomain", ASCENDING)],
            unique=True,
            name="subdomain_unique"
        )
        _safe_create_index(
            db[Config.SUBDOMAINS_COLLECTION],
            [("target_domain", ASCENDING)],
            name="subdomain_target_domain"
        )
        print("  ✅ subdomains indexes created")

        # ── 3. ports_services ───────────────────────
        # Routes query: find({"target_domain": domain})
        # Scanner saves: by host + port
        _safe_create_index(
            db[Config.PORTS_COLLECTION],
            [("host", ASCENDING), ("port", ASCENDING)],
            unique=True,
            name="host_port_unique"
        )
        _safe_create_index(
            db[Config.PORTS_COLLECTION],
            [("target_domain", ASCENDING)],
            name="port_target_domain"
        )
        print("  ✅ ports_services indexes created")

        # ── 4. http_assets ──────────────────────────
        # Routes query: find({"target_domain": domain})
        # Scanner saves: by url
        _safe_create_index(
            db[Config.HTTP_ASSETS_COLLECTION],
            [("url", ASCENDING)],
            unique=True,
            name="url_unique"
        )
        _safe_create_index(
            db[Config.HTTP_ASSETS_COLLECTION],
            [("target_domain", ASCENDING)],
            name="http_target_domain"
        )
        print("  ✅ http_assets indexes created")

        # ── 5. vulnerabilities ──────────────────────
        # Routes query: find({"target_domain": domain})
        # Dashboard: count_documents({"severity": "critical"})
        _safe_create_index(
            db[Config.VULNS_COLLECTION],
            [("target_domain", ASCENDING)],
            name="vuln_target_domain"
        )
        _safe_create_index(
            db[Config.VULNS_COLLECTION],
            [("severity", ASCENDING)],
            name="vuln_severity"
        )
        _safe_create_index(
            db[Config.VULNS_COLLECTION],
            [("status", ASCENDING)],
            name="vuln_status"
        )
        print("  ✅ vulnerabilities indexes created")

        # ── 6. changes ──────────────────────────────
        # Routes query: find({"target_domain": domain}).sort("detected_at", -1)
        _safe_create_index(
            db[Config.CHANGES_COLLECTION],
            [("target_domain", ASCENDING)],
            name="change_target_domain"
        )
        _safe_create_index(
            db[Config.CHANGES_COLLECTION],
            [("detected_at", DESCENDING)],
            name="change_date"
        )
        print("  ✅ changes indexes created")

        # ── 7. scan_history ─────────────────────────
        # Routes query: find({"target_domain": domain}).sort("started_at", -1)
        _safe_create_index(
            db[Config.SCANS_COLLECTION],
            [("target_domain", ASCENDING)],
            name="scan_target_domain"
        )
        _safe_create_index(
            db[Config.SCANS_COLLECTION],
            [("started_at", DESCENDING)],
            name="scan_date"
        )
        print("  ✅ scan_history indexes created")

        print("✅ All 7 collections initialized!")
        return True

    except Exception as e:
        print(f"❌ Index creation failed: {e}")
        raise


# ─── Getters ─────────────────────────────────────────────────────────────

def get_db():
    """Return the database object. Initializes connection if needed."""
    global db
    if db is None:
        connect_db()
    return db


def get_collection(collection_name):
    """Helper to get a specific MongoDB collection by name."""
    return get_db()[collection_name]