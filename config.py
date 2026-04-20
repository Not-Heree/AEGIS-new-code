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
    """
    Configuration class for the EASM Tool.

    All settings are loaded from environment variables with sensible defaults.
    Settings are organized by category for clarity and maintainability.
    """

    # ═══════════════════════════════════════════════════════════════
    # DATABASE SETTINGS
    # ═══════════════════════════════════════════════════════════════

    MONGO_URI = os.getenv(
        "MONGO_URI", "mongodb://localhost:27017"
    )
    MONGO_DB_NAME = os.getenv("MONGO_DB_NAME", "easm_db")

    # ═══════════════════════════════════════════════════════════════
    # FLASK APPLICATION SETTINGS
    # ═══════════════════════════════════════════════════════════════

    SECRET_KEY = os.getenv(
        "FLASK_SECRET_KEY",
        "easm-default-secret-key-change-in-production"
    )
    DEBUG = os.getenv(
        "FLASK_DEBUG", "True"
    ).lower() == "true"
    PORT = int(os.getenv("FLASK_PORT", "5000"))

    # ═══════════════════════════════════════════════════════════════
    # ADMIN CREDENTIALS
    # ═══════════════════════════════════════════════════════════════

    ADMIN_USER = os.getenv("ADMIN_USER", "admin")
    ADMIN_PASS = os.getenv("ADMIN_PASS", "admin")

    # ═══════════════════════════════════════════════════════════════
    # TOOL BINARY PATHS
    # ═══════════════════════════════════════════════════════════════

    SUBFINDER_PATH = os.getenv(
        "SUBFINDER_PATH", "tools/subfinder.exe"
    )
    AMASS_PATH = os.getenv(
        "AMASS_PATH", "tools/amass.exe"
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
    ARJUN_PATH = os.getenv(
        "ARJUN_PATH", "venv/Scripts/arjun.exe"
    )

    # ═══════════════════════════════════════════════════════════════
    # TOOL ENABLE FLAGS
    # ═══════════════════════════════════════════════════════════════

    # RUN_ARJUN: Global enable/disable for parameter discovery
    #   False (default): Skip Arjun entirely (passive mode only)
    #   True:            Allow Arjun if target.scan_config.enable_parameter_discovery=True
    #
    # WARNING: Arjun is an ACTIVE scanning tool that generates
    # thousands of HTTP requests. Only enable for authorized targets.
    # May trigger WAFs, rate limits, and intrusion detection systems.
    RUN_ARJUN = os.getenv(
        "RUN_ARJUN", "False"
    ).lower() == "true"

    # ═══════════════════════════════════════════════════════════════
    # GENERAL SCAN SETTINGS
    # ═══════════════════════════════════════════════════════════════

    SCAN_TIMEOUT = int(os.getenv("SCAN_TIMEOUT", "3600"))
    AMASS_TIMEOUT = int(os.getenv("AMASS_TIMEOUT", "1800"))

    # ═══════════════════════════════════════════════════════════════
    # ARJUN PARAMETER DISCOVERY SETTINGS
    # ═══════════════════════════════════════════════════════════════

    # Rate limit (requests per second per URL)
    #   1-5:   Slow, stealthy, WAF-safe (recommended)
    #   10-20: Moderate speed, may trigger rate limits
    #   50+:   Fast but VERY noisy, high WAF trigger risk
    ARJUN_RATE_LIMIT = int(os.getenv("ARJUN_RATE_LIMIT", "5"))

    # Timeout (seconds)
    #   300:  5 min — small target lists
    #   600:  10 min — balanced (default)
    #   1200: 20 min — large target lists with slow rate limits
    ARJUN_TIMEOUT = int(os.getenv("ARJUN_TIMEOUT", "1800"))

    # Threads (parallel URL processing)
    #   1-2:  Safe, minimal resource usage (recommended)
    #   5-10: Faster but more aggressive
    ARJUN_THREADS = int(os.getenv("ARJUN_THREADS", "2"))

    # Wordlist mode: auto | small | medium | large | /path/to/custom.txt
    #   auto:     Dynamic wordlist based on target intelligence (recommended)
    #   small:    100 params (~2 min per URL)
    #   medium:   500 params (~10 min per URL)
    #   large:    2000+ params (~40 min per URL)
    #   <path>:   Custom wordlist file path
    ARJUN_WORDLIST_MODE = os.getenv(
        "ARJUN_WORDLIST_MODE", "auto"
    )

    # Static wordlist paths (used when mode != "auto")
    ARJUN_WORDLIST_SMALL = os.getenv(
        "ARJUN_WORDLIST_SMALL",
        "wordlists/arjun/small.txt"
    )
    ARJUN_WORDLIST_MEDIUM = os.getenv(
        "ARJUN_WORDLIST_MEDIUM",
        "wordlists/arjun/medium.txt"
    )
    ARJUN_WORDLIST_LARGE = os.getenv(
        "ARJUN_WORDLIST_LARGE",
        "wordlists/arjun/large.txt"
    )

    # Enable/disable JavaScript analysis for dynamic wordlist
    #   True:  Analyze .js files for parameter names (requires HTTPX_STORE_BODY=True)
    #   False: Skip JS analysis (faster, less comprehensive)
    ARJUN_ANALYZE_JS = os.getenv(
        "ARJUN_ANALYZE_JS", "True"
    ).lower() == "true"

    # Maximum parameters in dynamic wordlist (prevents excessive scan times)
    #   1000:  Fast, minimal coverage
    #   5000:  Balanced (default)
    #   10000: Comprehensive but slow
    ARJUN_MAX_PARAMS = int(
        os.getenv("ARJUN_MAX_PARAMS", "5000")
    )

    # ═══════════════════════════════════════════════════════════════
    # NAABU PORT SCANNER SETTINGS
    # ═══════════════════════════════════════════════════════════════

    NAABU_TOP_PORTS = os.getenv(
        "NAABU_TOP_PORTS", "1000"
    )
    NAABU_RATE = int(os.getenv("NAABU_RATE", "1000"))
    NAABU_BATCH_SIZE = int(os.getenv("NAABU_BATCH_SIZE", "100"))

    # ═══════════════════════════════════════════════════════════════
    # NUCLEI VULNERABILITY SCANNER SETTINGS
    # ═══════════════════════════════════════════════════════════════

    NUCLEI_SEVERITY = os.getenv(
        "NUCLEI_SEVERITY",
        "critical,high,medium,low"
    )
    NUCLEI_TIER2C_SEVERITY = os.getenv(
        "NUCLEI_TIER2C_SEVERITY", "critical,high"
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

    # ═══════════════════════════════════════════════════════════════
    # HTTPX HTTP PROBER SETTINGS
    # ═══════════════════════════════════════════════════════════════

    HTTPX_THREADS = int(
        os.getenv("HTTPX_THREADS", "50")
    )
    HTTPX_TIMEOUT = int(
        os.getenv("HTTPX_TIMEOUT", "10")
    )

    # Response body extraction for JavaScript analysis
    #
    # HTTPX_STORE_BODY: Enable response body storage
    #   True:  Store response bodies (enables JS analysis, uses more disk)
    #   False: Skip body storage (faster, less disk usage)
    #
    # WARNING: Storing bodies increases disk usage significantly.
    # Only bodies matching HTTPX_BODY_EXTENSIONS are stored.
    HTTPX_STORE_BODY = os.getenv(
        "HTTPX_STORE_BODY", "True"
    ).lower() == "true"

    # Maximum response body size to store (bytes)
    #   524288:   512 KB (smaller, faster)
    #   1048576:  1 MB (default - good for JS files)
    #   2097152:  2 MB (larger files, slower)
    HTTPX_BODY_MAX_SIZE = int(
        os.getenv("HTTPX_BODY_MAX_SIZE", "1048576")
    )

    # Only store bodies for specific file types (comma-separated)
    # Default: JavaScript and JSON files only
    HTTPX_BODY_EXTENSIONS = os.getenv(
        "HTTPX_BODY_EXTENSIONS",
        ".js,.jsx,.ts,.tsx,.json"
    ).split(",")

    # ═══════════════════════════════════════════════════════════════
    # EMAIL HARVESTER SETTINGS
    # ═══════════════════════════════════════════════════════════════

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

    # ═══════════════════════════════════════════════════════════════
    # EXTERNAL API KEYS
    # ═══════════════════════════════════════════════════════════════

    # Hunter.io Email Discovery
    HUNTER_API_KEY = os.getenv("HUNTER_API_KEY", "")

    # IntelX / Phonebook.cz OSINT
    INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")
    INTELX_ENDPOINT = os.getenv("INTELX_ENDPOINT", "free.intelx.io")

    # Shodan Internet-wide Asset Search
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY", "")

    # Censys Certificate/TLS Search
    # Get PAT from: https://search.censys.io/account → "API" tab
    CENSYS_PAT = os.getenv("CENSYS_PAT", "")

    # Legacy Censys credentials (backwards compatibility)
    CENSYS_API_ID = os.getenv("CENSYS_API_ID", "")
    CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET", "")

    # ═══════════════════════════════════════════════════════════════
    # MONGODB COLLECTION NAMES
    # ═══════════════════════════════════════════════════════════════

    TARGETS_COLLECTION = "targets"
    SUBDOMAINS_COLLECTION = "subdomains"
    PORTS_COLLECTION = "ports_services"
    HTTP_ASSETS_COLLECTION = "http_assets"
    VULNS_COLLECTION = "vulnerabilities"
    CHANGES_COLLECTION = "changes"
    SCANS_COLLECTION = "scan_history"
    EMAILS_COLLECTION = "email_exposures"
    ENDPOINTS_COLLECTION = "endpoints"
    SCAN_SCHEDULES_COLLECTION = "scan_schedules"

    # ═══════════════════════════════════════════════════════════════
    # REPORT SETTINGS
    # ═══════════════════════════════════════════════════════════════

    REPORTS_DIR = os.getenv(
        "REPORTS_DIR", "generated_reports"
    )
    REPORT_COMPANY_NAME = os.getenv(
        "REPORT_COMPANY_NAME", "EASM Tool"
    )

    # ═══════════════════════════════════════════════════════════════
    # RISK SCORING CONSTANTS
    # ═══════════════════════════════════════════════════════════════

    # Controls the logarithmic compression of the vulnerability
    # score component. Formula: VULN_SCORE_CAP * (1 - e^(-raw / SENSITIVITY))
    #
    # Higher value = slower saturation (more spread between low/high vuln counts)
    # Lower value  = faster saturation (large vuln counts score nearly the same)
    #
    # Recommended values:
    #   50:  Aggressive scaling (small differences matter more)
    #   80:  Balanced (default)
    #   120: Conservative (large vuln counts matter more)
    RISK_SCORE_SENSITIVITY = float(
        os.getenv("RISK_SCORE_SENSITIVITY", "80.0")
    )

    # ═══════════════════════════════════════════════════════════════
    # ADVANCED SETTINGS (OPTIONAL)
    # ═══════════════════════════════════════════════════════════════

    # Enable verbose debug logging for specific modules
    DEBUG_WORDLIST_BUILDER = os.getenv(
        "DEBUG_WORDLIST_BUILDER", "False"
    ).lower() == "true"

    DEBUG_ARJUN = os.getenv(
        "DEBUG_ARJUN", "False"
    ).lower() == "true"

    # Wordlist cache TTL in hours (default: 24 hours)
    # Set to 0 to disable caching
    ARJUN_CACHE_TTL_HOURS = int(
        os.getenv("ARJUN_CACHE_TTL_HOURS", "24")
    )

    # Minimum parameter length for JS analysis (default: 2)
    # Filters out single-letter variable names
    ARJUN_MIN_PARAM_LENGTH = int(
        os.getenv("ARJUN_MIN_PARAM_LENGTH", "2")
    )


# ═══════════════════════════════════════════════════════════════
# CONFIGURATION VALIDATION
# ═══════════════════════════════════════════════════════════════

def validate_config():
    """
    Validate critical configuration settings on startup.
    Logs warnings for common misconfigurations.
    """
    from utils.logger import logger

    # Check Arjun configuration consistency
    if Config.RUN_ARJUN:
        if not Config.HTTPX_STORE_BODY and Config.ARJUN_ANALYZE_JS:
            logger.warning(
                "[CONFIG] ARJUN_ANALYZE_JS=True but HTTPX_STORE_BODY=False. "
                "JS analysis will be skipped. Set HTTPX_STORE_BODY=True to enable."
            )

        if Config.ARJUN_WORDLIST_MODE == "auto" and not Config.HTTPX_STORE_BODY:
            logger.warning(
                "[CONFIG] ARJUN_WORDLIST_MODE=auto works best with HTTPX_STORE_BODY=True "
                "for JavaScript parameter extraction."
            )

        if Config.ARJUN_RATE_LIMIT > 20:
            logger.warning(
                "[CONFIG] ARJUN_RATE_LIMIT=%d is very aggressive and may trigger WAFs. "
                "Consider reducing to 5-10 for stealthy scans.",
                Config.ARJUN_RATE_LIMIT
            )

        if Config.ARJUN_THREADS > 5:
            logger.warning(
                "[CONFIG] ARJUN_THREADS=%d is aggressive. "
                "Consider reducing to 1-2 for stealthy scans.",
                Config.ARJUN_THREADS
            )

    # Check wordlist files exist (if using static mode)
    if Config.ARJUN_WORDLIST_MODE in ["small", "medium", "large"]:
        wordlist_map = {
            "small": Config.ARJUN_WORDLIST_SMALL,
            "medium": Config.ARJUN_WORDLIST_MEDIUM,
            "large": Config.ARJUN_WORDLIST_LARGE,
        }
        wordlist_path = wordlist_map.get(Config.ARJUN_WORDLIST_MODE)
        if wordlist_path and not os.path.exists(wordlist_path):
            logger.error(
                "[CONFIG] Wordlist file not found: %s. "
                "Falling back to 'auto' mode.",
                wordlist_path
            )

    # Check HTTPX body size limit
    if Config.HTTPX_STORE_BODY:
        max_mb = Config.HTTPX_BODY_MAX_SIZE / 1024 / 1024
        logger.info(
            "[CONFIG] HTTPX body storage enabled (max %.1f MB per file, types: %s)",
            max_mb,
            ", ".join(Config.HTTPX_BODY_EXTENSIONS)
        )

    # Check API keys
    api_keys = {
        "SHODAN_API_KEY": Config.SHODAN_API_KEY,
        "CENSYS_PAT": Config.CENSYS_PAT,
        "HUNTER_API_KEY": Config.HUNTER_API_KEY,
        "INTELX_API_KEY": Config.INTELX_API_KEY,
    }

    missing_keys = [name for name, value in api_keys.items() if not value]
    if missing_keys:
        logger.info(
            "[CONFIG] Optional API keys not configured: %s. "
            "Some passive recon features will be limited.",
            ", ".join(missing_keys)
        )

    logger.info("[CONFIG] Configuration validation complete")


# Run validation on import (optional - comment out if not wanted)
# validate_config()