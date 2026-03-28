# config.py

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
    SECRET_KEY = os.getenv("FLASK_SECRET_KEY", "easm-default-secret-key-change-in-production")
    DEBUG = os.getenv("FLASK_DEBUG", "True").lower() == "true"
    PORT = int(os.getenv("FLASK_PORT", "5000"))

    # ─── Admin Credentials ──────────────────────────────────────────
    ADMIN_USER = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASS = os.getenv("ADMIN_PASS", "admin")

    # ─── Tool Paths ─────────────────────────────────────────────────────
    SUBFINDER_PATH = os.getenv("SUBFINDER_PATH", "tools/subfinder.exe")
    NAABU_PATH = os.getenv("NAABU_PATH", "tools/naabu.exe")
    HTTPX_PATH = os.getenv("HTTPX_PATH", "tools/httpx.exe")
    NUCLEI_PATH = os.getenv("NUCLEI_PATH", "tools/nuclei.exe")

    # ─── Scan Settings ──────────────────────────────────────────────────
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "3600"))

    # Naabu (Port Scanner)
    NAABU_TOP_PORTS = os.getenv("NAABU_TOP_PORTS", "1000")
    NAABU_RATE = int(os.getenv("NAABU_RATE", "1000"))

    # Nuclei (Vulnerability Scanner)
    NUCLEI_SEVERITY = os.getenv("NUCLEI_SEVERITY", "critical,high,medium,low")
    NUCLEI_RATE_LIMIT = int(os.getenv("NUCLEI_RATE_LIMIT", "150"))
    NUCLEI_RETRIES = int(os.getenv("NUCLEI_RETRIES", "1"))
    NUCLEI_TEMPLATES_PATH = os.getenv("NUCLEI_TEMPLATES_PATH", "")

    # HTTPX (HTTP Prober)
    HTTPX_THREADS = int(os.getenv("HTTPX_THREADS", "50"))
    HTTPX_TIMEOUT = int(os.getenv("HTTPX_TIMEOUT", "10"))

    # ─── Email Harvester Settings ────────────────────────────────────────
    THEHARVESTER_PATH = os.getenv("THEHARVESTER_PATH", "theHarvester")
    HARVESTER_TIMEOUT = int(os.getenv("HARVESTER_TIMEOUT", "120"))
    HARVESTER_SOURCES = os.getenv(
        "HARVESTER_SOURCES",
        "google,bing,linkedin,yahoo,dnsdumpster,threatminer"
    )

    # ─── Hunter.io (fallback email source) ───────────────────────────────
    HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")
     # ─── Intelix Phonebook.cz (pastebin) ───────────────────────────────
    INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")
    # ─── Shodan & Censys ─────────────────────────────────────────────────
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")
    CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")

    # ─── MongoDB Collection Names ────────────────────────────────────────
    TARGETS_COLLECTION = "targets"
    SUBDOMAINS_COLLECTION = "subdomains"
    PORTS_COLLECTION = "ports_services"
    HTTP_ASSETS_COLLECTION = "http_assets"
    VULNS_COLLECTION = "vulnerabilities"
    CHANGES_COLLECTION = "changes"
    SCANS_COLLECTION = "scan_history"
    EMAILS_COLLECTION = "email_exposures"

    # ─── Report Settings ─────────────────────────────────────────────────
    REPORTS_DIR = os.getenv("REPORTS_DIR", "generated_reports")
    REPORT_COMPANY_NAME = os.getenv("REPORT_COMPANY_NAME", "EASM Tool")