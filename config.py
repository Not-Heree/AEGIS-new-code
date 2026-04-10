# config.py

import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class ConfigMeta(type):
    """
    Metaclass for Config to allow dynamic property lookups.
    Intercepts access to API keys and routes to APIKeyManager if possible.
    """

    def __getattribute__(cls, name):
        # Specific keys that should be checked in database first
        dynamic_keys = {
            "HUNTER_API_KEY", "INTELX_API_KEY", "LEAKCHECK_API_KEY",
            "SHODAN_API_KEY", "CENSYS_PAT"
        }

        if name in dynamic_keys:
            try:
                # Lazy import to avoid circular dependency
                from core.api_key_manager import APIKeyManager
                val = APIKeyManager.get_key(name)
                if val:
                    return val
            except Exception:
                pass

        return super().__getattribute__(name)


class Config(metaclass=ConfigMeta):
    """Configuration class for the EASM Tool.
    All settings are loaded from environment variables
    with sensible defaults.
    """

    # ─── MongoDB Settings ────────────────────────────────
    MONGO_URI = os.getenv(
        "MONGO_URI", "mongodb://localhost:27017"
    )
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "easm_db")

    # ─── Flask Settings ──────────────────────────────────
    SECRET_KEY = os.getenv(
        "FLASK_SECRET_KEY",
        "easm-default-secret-key-change-in-production"
    )
    DEBUG = os.getenv(
        "FLASK_DEBUG", "True"
    ).lower() == "true"
    PORT = int(os.getenv("FLASK_PORT", "5000"))

    # ─── Admin Credentials ───────────────────────────────
    ADMIN_USER = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASS = os.getenv("ADMIN_PASS", "admin")

    # ─── Tool Paths ──────────────────────────────────────
    SUBFINDER_PATH = os.getenv(
        "SUBFINDER_PATH", "tools/subfinder.exe"
    )
    NAABU_PATH = os.getenv(
        "NAABU_PATH", "tools/naabu.exe"
    )
    HTTPX_PATH = os.getenv(
        "HTTPX_PATH", "tools/httpx.exe"
    )
    NUCLEI_PATH = os.getenv(
        "NUCLEI_PATH", "tools/nuclei.exe"
    )

    # ─── Scan Settings ───────────────────────────────────
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "3600"))

    # Naabu (Port Scanner)
    NAABU_TOP_PORTS = os.getenv(
        "NAABU_TOP_PORTS", "1000"
    )
    NAABU_RATE = int(os.getenv("NAABU_RATE", "1000"))
    NAABU_BATCH_SIZE = int(os.getenv("NAABU_BATCH_SIZE", "100"))

    # Nuclei (Vulnerability Scanner)
    NUCLEI_SEVERITY = os.getenv(
        "NUCLEI_SEVERITY",
        "critical,high,medium,low"
    )
    NUCLEI_RATE_LIMIT = int(
        os.getenv("NUCLEI_RATE_LIMIT", "60")
    )
    NUCLEI_RETRIES = int(
        os.getenv("NUCLEI_RETRIES", "1")
    )
    NUCLEI_TEMPLATES_PATH = os.getenv(
        "NUCLEI_TEMPLATES_PATH", ""
    )

    # Nuclei Performance Tuning
    #
    # NUCLEI_CONCURRENCY: Controls how many templates and
    #   hosts Nuclei processes in parallel WITHIN a single
    #   invocation. Maps to Nuclei's -c (template threads)
    #   and -bulk-size (hosts per template batch).
    #
    #   Low (10):  Safe, minimal resource usage
    #   Default (25): Balanced speed and stability
    #   High (50+): Fast but uses more RAM/CPU
    #
    # NUCLEI_TIMEOUT: Maximum seconds a single Nuclei
    #   process is allowed to run before being killed.
    #   Partial results captured before kill are preserved.
    #
    #   Short (300):  5 min — small scans, tight deadlines
    #   Default (600): 10 min — balanced for most scans
    #   Long (1200):  20 min — large target lists
    #
    NUCLEI_CONCURRENCY = int(
        os.getenv("NUCLEI_CONCURRENCY", "25")
    )
    NUCLEI_BATCH_SIZE = int(
        os.getenv("NUCLEI_BATCH_SIZE", "50")
    )
    NUCLEI_TIMEOUT = int(
        os.getenv("NUCLEI_TIMEOUT", "1800")
    )

    # HTTPX (HTTP Prober)
    HTTPX_THREADS = int(
        os.getenv("HTTPX_THREADS", "50")
    )
    HTTPX_TIMEOUT = int(
        os.getenv("HTTPX_TIMEOUT", "10")
    )

    # ─── Email Harvester Settings ────────────────────────
    THEHARVESTER_PATH = os.getenv(
        "THEHARVESTER_PATH", "theHarvester"
    )
    HARVESTER_TIMEOUT = int(
        os.getenv("HARVESTER_TIMEOUT", "120")
    )
    API_THROTTLE_SECONDS = float(
        os.getenv("API_THROTTLE_SECONDS", "5.0")
    )
    HARVESTER_SOURCES = os.getenv(
        "HARVESTER_SOURCES",
        "google,bing,linkedin,yahoo,"
        "dnsdumpster,threatminer"
    )
    EMAIL_HARVEST_LIMIT = int(
        os.getenv("EMAIL_HARVEST_LIMIT", "500")
    )

    # ─── Hunter.io ───────────────────────────────────────
    HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")

    # ─── IntelX / Phonebook.cz ──────────────────────────
    INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")
    INTELX_ENDPOINT = os.getenv("INTELX_ENDPOINT", "free.intelx.io")

    # ─── Shodan & Censys ─────────────────────────────────
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

    # Censys PAT (Personal Access Token)
    # Get from: https://search.censys.io/account → "API" tab
    CENSYS_PAT = os.getenv("CENSYS_PAT", "")

    # Legacy Censys credentials (backwards compatibility)
    CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")

    # ─── MongoDB Collection Names ────────────────────────
    TARGETS_COLLECTION = "targets"
    SUBDOMAINS_COLLECTION = "subdomains"
    PORTS_COLLECTION = "ports_services"
    HTTP_ASSETS_COLLECTION = "http_assets"
    VULNS_COLLECTION = "vulnerabilities"
    CHANGES_COLLECTION = "changes"
    SCANS_COLLECTION = "scan_history"
    EMAILS_COLLECTION = "email_exposures"

    # ─── Report Settings ─────────────────────────────────
    REPORTS_DIR = os.getenv(
        "REPORTS_DIR", "generated_reports"
    )
    REPORT_COMPANY_NAME = os.getenv(
        "REPORT_COMPANY_NAME", "EASM Tool"
    )

    # ─── Risk Scoring Constants ──────────────────────────
    # Controls the logarithmic compression of the vulnerability
    # score component. Formula: VULN_SCORE_CAP * (1 - e^(-raw / SENSITIVITY))
    # Higher = slower saturation (more spread between low/high vuln counts)
    # Lower  = faster saturation (large vuln counts score nearly the same)
    RISK_SCORE_SENSITIVITY = float(
        os.getenv("RISK_SCORE_SENSITIVITY", "80.0")
    )
