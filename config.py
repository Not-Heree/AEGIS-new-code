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

    # ─── Tool Paths ─────────────────────────────────────────────────────
    SUBFINDER_PATH = os.getenv("SUBFINDER_PATH", "tools/subfinder.exe")
    NAABU_PATH = os.getenv("NAABU_PATH", "tools/naabu.exe")
    HTTPX_PATH = os.getenv("HTTPX_PATH", "tools/httpx.exe")
    NUCLEI_PATH = os.getenv("NUCLEI_PATH", "tools/nuclei.exe")

    # ─── Scan Settings ──────────────────────────────────────────────────
    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "3600"))  # seconds (1 hour default)
    
    # Naabu (Port Scanner)
    NAABU_TOP_PORTS = os.getenv("NAABU_TOP_PORTS", "1000")  # top N ports to scan
    NAABU_RATE = int(os.getenv("NAABU_RATE", "1000"))       # packets per second
    
    # Nuclei (Vulnerability Scanner)
    NUCLEI_SEVERITY = os.getenv("NUCLEI_SEVERITY", "critical,high,medium,low")
    NUCLEI_RATE_LIMIT = int(os.getenv("NUCLEI_RATE_LIMIT", "150"))  # requests per second
    NUCLEI_RETRIES = int(os.getenv("NUCLEI_RETRIES", "1"))
    NUCLEI_TEMPLATES_PATH = os.getenv("NUCLEI_TEMPLATES_PATH", "")  # custom templates (optional)
    
    # HTTPX (HTTP Prober)
    HTTPX_THREADS = int(os.getenv("HTTPX_THREADS", "50"))
    HTTPX_TIMEOUT = int(os.getenv("HTTPX_TIMEOUT", "10"))  # seconds

    # ─── MongoDB Collection Names ────────────────────────────────────────
    TARGETS_COLLECTION = "targets"
    SUBDOMAINS_COLLECTION = "subdomains"
    PORTS_COLLECTION = "ports_services"
    HTTP_ASSETS_COLLECTION = "http_assets"
    VULNS_COLLECTION = "vulnerabilities"
    CHANGES_COLLECTION = "changes"
    SCANS_COLLECTION = "scan_history"

    # ─── Report Settings ─────────────────────────────────────────────────
    REPORTS_DIR = os.getenv("REPORTS_DIR", "generated_reports")
    REPORT_COMPANY_NAME = os.getenv("REPORT_COMPANY_NAME", "EASM Tool")