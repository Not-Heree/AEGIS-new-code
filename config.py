import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Configuration class for the EASM Tool.
    All settings are loaded from environment variables with sensible defaults.
    """

    # ─── MongoDB Settings ───────────────────────────────────────────────
    MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "easm_db")

    # ─── Flask Settings ─────────────────────────────────────────────────
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "easm-default-secret-key")
    DEBUG = os.getenv("FLASK_DEBUG", "True") == "True"
    PORT = int(os.getenv("FLASK_PORT", "5000"))

    # ─── Tool Paths ─────────────────────────────────────────────────────
    SUBFINDER_PATH = os.getenv("SUBFINDER_PATH", "tools/subfinder.exe")
    NAABU_PATH = os.getenv("NAABU_PATH", "tools/naabu.exe")
    HTTPX_PATH = os.getenv("HTTPX_PATH", "tools/httpx.exe")
    NUCLEI_PATH = os.getenv("NUCLEI_PATH", "tools/nuclei.exe")

    # ─── Scan Settings ──────────────────────────────────────────────────
    SCAN_TIMEOUT = 3600                              # seconds
    NAABU_TOP_PORTS = "1000"                         # top N ports to scan
    NUCLEI_SEVERITY = "critical,high,medium,low"     # severity filter
    NUCLEI_RATE_LIMIT = 150                          # requests per second

    # ─── MongoDB Collection Names ────────────────────────────────────────
    TARGETS_COLLECTION = "targets"
    SUBDOMAINS_COLLECTION = "subdomains"
    PORTS_COLLECTION = "ports_services"
    HTTP_ASSETS_COLLECTION = "http_assets"
    VULNS_COLLECTION = "vulnerabilities"
    CHANGES_COLLECTION = "changes"
    SCANS_COLLECTION = "scan_history"
