"""
Database Connection & Initialization Module
============================================
Manages the MongoDB connection lifecycle and ensures all
9 collections have the correct indexes for the application's
query patterns.

Index strategy:
  - Each collection indexed on target_domain for efficient lookups
  - Unique indexes prevent duplicate entries across scans
  - Time-based indexes (detected_at, started_at) support sorting
  - The passive_recon collection has a compound unique index
    on (target_domain, source) so each source has one entry per target
"""

from pymongo import MongoClient, ASCENDING, DESCENDING
from pymongo.errors import ConnectionFailure, ServerSelectionTimeoutError
from config import Config
from utils.logger import logger

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
        logger.info("MongoDB connected: %s", Config.MONGO_URI)
        logger.info("Database: %s", Config.MONGO_DB_NAME)
        return db
    except ServerSelectionTimeoutError:
        logger.error("MongoDB timeout: %s", Config.MONGO_URI)
        raise
    except ConnectionFailure:
        logger.error("MongoDB connection failed: %s", Config.MONGO_URI)
        raise
    except Exception as e:
        logger.error("Unexpected DB error: %s", e)
        raise


def test_connection():
    """Test if MongoDB is reachable by sending a ping command."""
    global client
    try:
        if client is None:
            connect_db()
        client.admin.command("ping")
        logger.info("MongoDB connection is alive")
        return True
    except Exception as e:
        logger.error("MongoDB ping failed: %s", e)
        return False


# ─── Safe Index Creation ─────────────────────────────────────────────────

def _safe_create_index(collection, keys, **kwargs):
    """
    Create index safely — drops conflicting index if needed.

    This prevents crashes when index definition changes
    between code updates (e.g., adding a new field to a
    unique compound index).
    """
    try:
        collection.create_index(keys, **kwargs)
    except Exception:
        try:
            index_name = kwargs.get("name", None)
            if index_name:
                try:
                    collection.drop_index(index_name)
                except Exception:
                    pass
            collection.drop_indexes()
            collection.create_index(keys, **kwargs)
        except Exception as e:
            logger.warning(
                "Index warning on %s: %s",
                collection.name, e
            )


# ─── Database Initialization ─────────────────────────────────────────────

def init_db():
    """
    Initialize MongoDB connection and create indexes on all 9 collections.

    Indexes match how routes actually query data:
      - Routes query by: root_domain, target_domain, subdomain, host, port
      - Indexes are created on those exact fields

    Collections:
      1. targets          — root domain lookup
      2. subdomains       — per-target subdomain lists
      3. ports_services   — host+port unique pairs
      4. http_assets      — per-URL unique assets
      5. vulnerabilities  — per-target, severity, status
      6. changes          — per-target, time sorted
      7. scan_history     — per-target, time sorted
      8. email_exposures  — per-target, breach status
      9. passive_recon    — per-target, per-source unique records
    """
    global db

    try:
        if db is None:
            connect_db()

        # ── 1. targets ──────────────────────────────
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
        logger.debug("targets indexes created")

        # ── 2. subdomains ───────────────────────────
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
        logger.debug("subdomains indexes created")

        # ── 3. ports_services ───────────────────────
        # Compound unique: same host+port pair cannot be duplicated
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
        logger.debug("ports_services indexes created")

        # ── 4. http_assets ──────────────────────────
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
        logger.debug("http_assets indexes created")

        # ── 5. vulnerabilities ──────────────────────
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
        logger.debug("vulnerabilities indexes created")

        # ── 6. changes ──────────────────────────────
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
        logger.debug("changes indexes created")

        # ── 7. scan_history ─────────────────────────
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
        logger.debug("scan_history indexes created")

        # ── 8. email_exposures ──────────────────────
        _safe_create_index(
            db[Config.EMAILS_COLLECTION],
            [("target_id", ASCENDING), ("email", ASCENDING)],
            unique=True,
            name="email_target_unique"
        )
        _safe_create_index(
            db[Config.EMAILS_COLLECTION],
            [("target_domain", ASCENDING)],
            name="email_target_domain"
        )
        _safe_create_index(
            db[Config.EMAILS_COLLECTION],
            [("breach_status", ASCENDING)],
            name="email_breach_status"
        )
        logger.debug("email_exposures indexes created")

        # ── 9. passive_recon ────────────────────────
        # Compound unique: one document per (target_domain, source) pair.
        # This ensures Shodan and Censys each have their own record per target.
        _safe_create_index(
            db["passive_recon"],
            [("target_domain", ASCENDING), ("source", ASCENDING)],
            unique=True,
            name="passive_domain_source_unique"
        )
        _safe_create_index(
            db["passive_recon"],
            [("target_id", ASCENDING)],
            name="passive_target_id"
        )
        logger.debug("passive_recon indexes created")

        logger.info("All 9 collections initialized successfully")
        return True

    except Exception as e:
        logger.error("Index creation failed: %s", e)
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