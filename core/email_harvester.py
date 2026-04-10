"""
Email Harvester Module
======================
Discovers company email addresses from multiple OSINT sources.

Sources:
  - theHarvester (primary - open source OSINT tool)
  - Hunter.io API (fallback - finds emails + patterns)
  - Phonebook.cz (free fallback - no API key needed)

Breach Checking (ENHANCED v1.2):
  - IntelX Free API (primary - free breach search)
  - LeakCheck API (fallback - 10/day free tier)
  - Multi-source aggregation for better coverage

Designed to run automatically when a target is registered.
Each source is independent - failure in one doesn't affect others.

ENHANCEMENTS v1.2:
  - Added IntelX breach checking (uses existing free API key)
  - Multi-source breach verification
  - Better breach data parsing
  - Result caching to avoid re-checking
  - Smart rate limit handling
"""

import subprocess
import re
import os
import sys
import time
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set

from config import Config
from utils.logger import logger
from core.api_key_manager import APIKeyManager 
from utils.throttler import throttler

# =============================================================================
# TEMP DIRECTORY MANAGEMENT
# =============================================================================

def _ensure_temp_directory():
    """Create temp directory for theHarvester output files."""
    temp_dir = os.path.join(os.path.dirname(__file__), "..", "temp")
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir


def _cleanup_old_temp_files():
    """Clean up theHarvester temp files older than 1 hour."""
    try:
        temp_dir = os.path.join(os.path.dirname(__file__), "..", "temp")
        if not os.path.exists(temp_dir):
            return
        
        current_time = time.time()
        for filename in os.listdir(temp_dir):
            if filename.startswith("theharvester_"):
                filepath = os.path.join(temp_dir, filename)
                file_age = current_time - os.path.getmtime(filepath)
                
                # Delete files older than 1 hour
                if file_age > 3600:
                    try:
                        os.remove(filepath)
                        logger.debug("[EMAIL] Cleaned up old temp file: %s", filename)
                    except:
                        pass
    except Exception as e:
        logger.debug("[EMAIL] Temp cleanup error: %s", e)


# =============================================================================
# EMAIL VALIDATION
# =============================================================================

EMAIL_REGEX = re.compile(
    r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
)

JUNK_PATTERNS = {
    "noreply@", "no-reply@", "mailer-daemon@",
    "postmaster@", "webmaster@", "hostmaster@",
    "abuse@", "support@example", "test@test",
    "user@example", "email@example", "name@domain",
    "info@w3.org", "xmlns", ".png", ".jpg", ".gif",
    ".css", ".js", "@2x", "@3x"
}


def _is_valid_email(email, target_domain=""):
    """
    Validate an email address and filter out junk.

    Args:
        email: Email address to validate
        target_domain: If provided, only accept emails from this domain

    Returns:
        True if the email looks legitimate
    """
    if not email or len(email) < 5 or len(email) > 254:
        return False

    email = email.lower().strip()

    if not EMAIL_REGEX.fullmatch(email):
        return False

    for pattern in JUNK_PATTERNS:
        if pattern in email:
            return False

    if target_domain:
        if not email.endswith("@" + target_domain.lower()):
            return False

    return True


def _extract_emails_from_text(text, target_domain=""):
    """Extract all valid emails from a block of text."""
    if not text:
        return set()

    raw_emails = EMAIL_REGEX.findall(text)
    valid = set()

    for email in raw_emails:
        email = email.lower().strip().rstrip(".")
        if _is_valid_email(email, target_domain):
            valid.add(email)

    return valid


# =============================================================================
# SOURCE 1: theHarvester (ENHANCED)
# =============================================================================

def run_theharvester(domain):
    """
    Run theHarvester to discover emails for a domain.

    Uses theHarvester Python library to search multiple public sources:
    Google, Bing, LinkedIn, Yahoo, DNSDumpster, etc.

    ENHANCED v1.1:
      - Better JSON parsing with fallback
      - Handles theHarvester's actual JSON structure
      - Temp file cleanup
      - Better error messages

    Args:
        domain: Target domain (e.g., "company.com")

    Returns:
        Dict with success, emails list, source counts
    """
    logger.info("[EMAIL] Running theHarvester on %s...", domain)

    # Clean up old temp files first
    _cleanup_old_temp_files()

    try:
        # Create temp directory
        temp_dir = _ensure_temp_directory()
        output_file = os.path.join(temp_dir, f"theharvester_{domain}.json")
        
        cmd = [
            sys.executable,              # Python executable
            "-m",
            "theHarvester",              # theHarvester module
            "-d", domain,                # Domain to search
            "-b", Config.HARVESTER_SOURCES,  # Sources (google,bing,etc)
            "-l", str(Config.EMAIL_HARVEST_LIMIT),  # Dynamic limit results
            "-f", output_file            # Output JSON file
        ]

        logger.debug("[EMAIL] Running command: %s", " ".join(cmd))

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.HARVESTER_TIMEOUT,
            encoding='utf-8',
            errors='replace'
        )

        emails = set()
        
        # ── ENHANCED: Try JSON parsing first ──
        if os.path.exists(output_file):
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                logger.debug("[EMAIL] Loaded JSON data structure: %s", list(data.keys()) if isinstance(data, dict) else type(data))
                
                # theHarvester's actual JSON structure
                if isinstance(data, dict):
                    # Direct emails list
                    if 'emails' in data:
                        if isinstance(data['emails'], list):
                            for email in data['emails']:
                                email_str = email.lower().strip() if isinstance(email, str) else str(email).lower().strip()
                                if _is_valid_email(email_str, domain):
                                    emails.add(email_str)
                        elif isinstance(data['emails'], str):
                            email_str = data['emails'].lower().strip()
                            if _is_valid_email(email_str, domain):
                                emails.add(email_str)
                    
                    # Sometimes emails are in 'hosts' or 'all'
                    for key in ['hosts', 'all', 'people', 'linkedin_people']:
                        if key in data and isinstance(data[key], list):
                            for item in data[key]:
                                found_emails = _extract_emails_from_text(str(item), domain)
                                emails.update(found_emails)
                
                logger.info("[EMAIL] Parsed %d emails from JSON", len(emails))
                
                # Clean up temp file after successful parsing
                try:
                    os.remove(output_file)
                    logger.debug("[EMAIL] Cleaned up temp file: %s", output_file)
                except:
                    pass
                
            except json.JSONDecodeError as je:
                logger.warning("[EMAIL] JSON parse failed: %s, falling back to text extraction", je)
            except Exception as e:
                logger.warning("[EMAIL] JSON processing error: %s, falling back to text extraction", e)
        
        # ── Fallback: Text extraction from stdout/stderr ──
        if not emails:
            output = result.stdout + "\n" + result.stderr
            logger.debug("[EMAIL] theHarvester output sample: %s", output[:500])
            emails = _extract_emails_from_text(output, domain)
            logger.info("[EMAIL] Extracted %d emails from text output", len(emails))

        logger.info(
            "[EMAIL] theHarvester found %d emails total",
            len(emails)
        )

        return {
            "success": True,
            "emails": list(emails),
            "count": len(emails),
            "source": "theharvester"
        }

    except subprocess.TimeoutExpired:
        timeout_val = Config.HARVESTER_TIMEOUT
        logger.warning(
            "[EMAIL] theHarvester timed out after %ds",
            timeout_val
        )
        return {
            "success": False,
            "error": f"theHarvester timed out after {timeout_val}s",
            "emails": [],
            "source": "theharvester"
        }

    except FileNotFoundError:
        logger.error(
            "[EMAIL] theHarvester not found. Install with: pip install theHarvester"
        )
        return {
            "success": False,
            "error": "theHarvester module not installed. Install with: pip install theHarvester",
            "emails": [],
            "source": "theharvester"
        }

    except Exception as e:
        logger.error("[EMAIL] theHarvester error: %s", str(e), exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "emails": [],
            "source": "theharvester"
        }


# =============================================================================
# SOURCE 2: Hunter.io API (ENHANCED)
# =============================================================================

def run_hunter_io(domain):
    """
    Query Hunter.io API for email addresses.

    Hunter.io crawls the web and finds email addresses
    associated with a domain. Also detects the email pattern
    (e.g., "{first}.{last}@company.com").

    Free tier: 25 searches/month, 50 verifications/month.

    ENHANCED v1.1:
      - Better error handling for malformed responses
      - Separated tool_sources from web_sources
      - Increased limit from 10 to 100
      - Better logging

    Args:
        domain: Target domain

    Returns:
        Dict with emails, pattern, and sources
    """
    api_key = Config.HUNTER_API_KEY

    if not api_key:
        logger.info("[EMAIL] Hunter.io skipped - no API key configured")
        return {
            "success": False,
            "error": "No Hunter.io API key",
            "emails": [],
            "source": "hunter_io"
        }

    logger.info("[EMAIL] Querying Hunter.io for %s...", domain)
    throttler.wait_if_needed("hunter_io", Config.API_THROTTLE_SECONDS)

    try:
        resp = requests.get(
            "https://api.hunter.io/v2/domain-search",
            params={
                "domain": domain,
                "api_key": api_key,
                "limit": Config.EMAIL_HARVEST_LIMIT 
            },
            timeout=15
        )

        if resp.status_code == 401:
            logger.warning("[EMAIL] Hunter.io - invalid API key")
            return {
                "success": False,
                "error": "Invalid Hunter.io API key",
                "emails": [],
                "source": "hunter_io"
            }

        if resp.status_code == 429:
            logger.warning("[EMAIL] Hunter.io - rate limited")
            return {
                "success": False,
                "error": "Hunter.io rate limit exceeded",
                "emails": [],
                "source": "hunter_io"
            }

        if resp.status_code != 200:
            logger.warning("[EMAIL] Hunter.io HTTP %d", resp.status_code)
            return {
                "success": False,
                "error": f"HTTP {resp.status_code}",
                "emails": [],
                "source": "hunter_io"
            }

        # ── ENHANCED: Better error handling ──
        try:
            response_data = resp.json()
        except json.JSONDecodeError:
            logger.error("[EMAIL] Hunter.io returned invalid JSON")
            return {
                "success": False,
                "error": "Invalid JSON response",
                "emails": [],
                "source": "hunter_io"
            }

        data = response_data.get("data", {})
        emails_data = data.get("emails", [])
        pattern = data.get("pattern", "")

        emails = []
        email_strings = []
        
        for entry in emails_data:
            email = entry.get("value", "").lower().strip()
            if _is_valid_email(email, domain):
                email_strings.append(email)
                
                # ── ENHANCED: Separate tool sources from web sources ──
                web_sources = []
                for s in entry.get("sources", []):
                    source_domain = s.get("domain", "")
                    if source_domain:
                        web_sources.append(source_domain)
                
                emails.append({
                    "email": email,
                    "type": entry.get("type", ""),
                    "confidence": entry.get("confidence", 0),
                    "first_name": entry.get("first_name", ""),
                    "last_name": entry.get("last_name", ""),
                    "position": entry.get("position", ""),
                    "linkedin": entry.get("linkedin", ""),
                    "web_sources": web_sources  # ← Renamed from "sources"
                })

        pattern_text = pattern if pattern else "unknown"
        logger.info(
            "[EMAIL] Hunter.io found %d emails (pattern: %s)",
            len(email_strings),
            pattern_text
        )

        return {
            "success": True,
            "emails": email_strings,
            "email_details": emails,
            "pattern": pattern,
            "count": len(email_strings),
            "source": "hunter_io"
        }

    except requests.Timeout:
        logger.warning("[EMAIL] Hunter.io timeout")
        return {
            "success": False,
            "error": "Timeout",
            "emails": [],
            "source": "hunter_io"
        }

    except Exception as e:
        logger.error("[EMAIL] Hunter.io error: %s", str(e), exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "emails": [],
            "source": "hunter_io"
        }


# =============================================================================
# SOURCE 3: Phonebook.cz (via IntelX API)
# =============================================================================

def run_phonebook(domain):
    """
    Query Phonebook.cz for email addresses via the IntelX API.

    Phonebook.cz is a search engine by Intelligence X that indexes
    emails, domains, and URLs from public sources including:
      - Paste sites (Pastebin, etc.)
      - Web crawls
      - Certificate transparency logs
      - Public datasets

    The API works in two steps:
      1. POST a search query → get a search_id
      2. GET results using that search_id

    Requires: INTELX_API_KEY in .env
    Free tier: Limited to preview results (~3 per query)

    Args:
        domain: Target domain (e.g., "company.com")

    Returns:
        Dict with emails list, count, and source name
    """
    api_key = (
        getattr(Config, "INTELX_API_KEY", "")
        or os.getenv("INTELX_API_KEY", "")
    )

    if not api_key:
        logger.info(
            "[EMAIL] Phonebook.cz skipped — no IntelX API key configured"
        )
        logger.info(
            "[EMAIL] Get free key at: https://intelx.io/account?tab=developer"
        )
        return {
            "success": False,
            "error": "No IntelX API key (required for Phonebook.cz)",
            "emails": [],
            "source": "phonebook"
        }

    logger.info("[EMAIL] Querying Phonebook.cz for %s...", domain)
    throttler.wait_if_needed("intelx", Config.API_THROTTLE_SECONDS)

    try:
        # ── Step 1: Start a search ──
        endpoint = getattr(Config, "INTELX_ENDPOINT", "free.intelx.io")
        search_url = f"https://{endpoint}/phonebook/search"

        search_payload = {
            "term": domain,
            "maxresults": Config.EMAIL_HARVEST_LIMIT,
            "media": 0,        # 0 = all media types
            "target": 2,        # 2 = emails specifically
            "timeout": 10
        }

        headers = {
            "x-key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "EASM-Aegis/1.0"
        }

        search_resp = requests.post(
            search_url,
            json=search_payload,
            headers=headers,
            timeout=15
        )

        if search_resp.status_code == 402:
            logger.warning("[EMAIL] Phonebook.cz — API quota exceeded")
            return {
                "success": False,
                "error": "IntelX API quota exceeded (free tier limit)",
                "emails": [],
                "source": "phonebook"
            }

        if search_resp.status_code == 401:
            logger.warning("[EMAIL] Phonebook.cz — invalid API key")
            return {
                "success": False,
                "error": "Invalid IntelX API key",
                "emails": [],
                "source": "phonebook"
            }

        if search_resp.status_code != 200:
            logger.warning(
                "[EMAIL] Phonebook.cz search HTTP %d",
                search_resp.status_code
            )
            return {
                "success": False,
                "error": "HTTP " + str(search_resp.status_code),
                "emails": [],
                "source": "phonebook"
            }

        search_data = search_resp.json()
        search_id = search_data.get("id")

        if not search_id:
            logger.warning("[EMAIL] Phonebook.cz — no search ID returned")
            return {
                "success": False,
                "error": "No search ID in response",
                "emails": [],
                "source": "phonebook"
            }

        # ── Step 2: Wait briefly, then fetch results ──
        time.sleep(3)

        results_url = f"https://{endpoint}/phonebook/search/result"

        results_resp = requests.get(
            results_url,
            params={
                "id": search_id,
                "limit": Config.EMAIL_HARVEST_LIMIT,
                "offset": 0
            },
            headers=headers,
            timeout=15
        )

        if results_resp.status_code != 200:
            logger.warning(
                "[EMAIL] Phonebook.cz results HTTP %d",
                results_resp.status_code
            )
            return {
                "success": False,
                "error": "Results fetch HTTP " + str(results_resp.status_code),
                "emails": [],
                "source": "phonebook"
            }

        results_data = results_resp.json()
        selectors = results_data.get("selectors", [])

        # ── Step 3: Extract and validate emails ──
        emails = []
        for selector in selectors:
            value = selector.get("selectorvalue", "").lower().strip()

            if _is_valid_email(value, domain):
                emails.append(value)

        # Deduplicate
        emails = list(set(emails))

        logger.info(
            "[EMAIL] Phonebook.cz found %d emails", len(emails)
        )

        return {
            "success": True,
            "emails": emails,
            "count": len(emails),
            "source": "phonebook"
        }

    except requests.Timeout:
        logger.warning("[EMAIL] Phonebook.cz timeout")
        return {
            "success": False,
            "error": "Phonebook.cz API timeout",
            "emails": [],
            "source": "phonebook"
        }

    except Exception as e:
        logger.error("[EMAIL] Phonebook.cz error: %s", e)
        return {
            "success": False,
            "error": str(e),
            "emails": [],
            "source": "phonebook"
        }


# =============================================================================
# BREACH CHECKING - IntelX Free API (NEW - PRIMARY)
# =============================================================================

def check_intelx_breach(email):
    """
    Check email against IntelX breach database using FREE API.
    
    IntelX indexes:
      - Data breaches
      - Paste sites (Pastebin, etc.)
      - Dark web leaks
      - Public datasets
    
    Free tier: free.intelx.io endpoint
    Rate limits: Reasonable for normal use
    
    Args:
        email: Email address to check
    
    Returns:
        Dict with breach status, databases, and leaked data types
    """
    api_key = os.getenv("INTELX_API_KEY", "")
    
    if not api_key:
        logger.debug("[BREACH] IntelX skipped - no API key")
        return {
            "success": False,
            "error": "No IntelX API key",
            "breached": None
        }
    
    logger.info("[BREACH] Checking %s via IntelX...", email)
    throttler.wait_if_needed("intelx", Config.API_THROTTLE_SECONDS)

    try:
        # ── Step 1: Start breach search ──
        endpoint = getattr(Config, "INTELX_ENDPOINT", "free.intelx.io")
        search_url = f"https://{endpoint}/intelligent/search"
        
        search_payload = {
            "term": email,
            "buckets": [],  # All buckets (leaks, pastes, etc.)
            "lookuplevel": 0,
            "maxresults": 50,
            "timeout": 5,
            "datefrom": "",
            "dateto": "",
            "sort": 2,
            "media": 0,
            "terminate": []
        }
        
        headers = {
            "x-key": api_key,
            "Content-Type": "application/json",
            "User-Agent": "EASM-Aegis/1.0"
        }
        
        search_resp = requests.post(
            search_url,
            json=search_payload,
            headers=headers,
            timeout=10
        )
        
        if search_resp.status_code == 402:
            logger.warning("[BREACH] IntelX quota exceeded")
            return {
                "success": False,
                "rate_limited": True,
                "breached": None
            }
        
        if search_resp.status_code == 401:
            logger.warning("[BREACH] IntelX invalid API key")
            return {
                "success": False,
                "error": "Invalid API key",
                "breached": None
            }
        
        if search_resp.status_code != 200:
            logger.warning("[BREACH] IntelX search HTTP %d", search_resp.status_code)
            return {
                "success": False,
                "error": f"HTTP {search_resp.status_code}",
                "breached": None
            }
        
        search_data = search_resp.json()
        search_id = search_data.get("id")
        
        if not search_id:
            logger.warning("[BREACH] IntelX no search ID")
            return {
                "success": False,
                "error": "No search ID",
                "breached": None
            }
        
        # ── Step 2: Wait and fetch results ──
        time.sleep(2)
        
        results_url = f"https://{endpoint}/intelligent/search/result"
        
        results_resp = requests.get(
            results_url,
            params={
                "id": search_id,
                "limit": 50,
                "offset": 0
            },
            headers=headers,
            timeout=10
        )
        
        if results_resp.status_code != 200:
            logger.warning("[BREACH] IntelX results HTTP %d", results_resp.status_code)
            return {
                "success": False,
                "error": "Results fetch failed",
                "breached": None
            }
        
        results_data = results_resp.json()
        records = results_data.get("records", [])
        
        if not records:
            logger.info("[BREACH] IntelX: %s NOT found in breaches", email)
            return {
                "success": True,
                "breached": False,
                "breach_count": 0,
                "breaches": [],
                "source": "intelx"
            }
        
        # ── Step 3: Parse breach details ──
        breaches = []
        data_types_leaked = set()
        password_found = False
        
        for record in records:
            bucket = record.get("bucket", "Unknown")
            media_type = record.get("mediatype", "")
            date = record.get("date", "Unknown")
            
            # Parse media type for leaked data indicators
            if media_type:
                data_types_leaked.add(media_type)
            
            # Check for password indicators
            name = record.get("name", "").lower()
            if any(keyword in name for keyword in ["password", "credentials", "combo", "leak"]):
                password_found = True
            
            breaches.append({
                "database": bucket,
                "name": record.get("name", "Unknown"),
                "date": date,
                "media_type": media_type,
                "size": record.get("size", 0)
            })
        
        logger.info(
            "[BREACH] IntelX: %s found in %d sources (password: %s)",
            email,
            len(breaches),
            "YES" if password_found else "NO"
        )
        
        return {
            "success": True,
            "breached": True,
            "breach_count": len(breaches),
            "breaches": breaches,
            "data_types_leaked": list(data_types_leaked),
            "password_leaked": password_found,
            "source": "intelx"
        }
    
    except requests.Timeout:
        logger.warning("[BREACH] IntelX timeout")
        return {
            "success": False,
            "error": "Timeout",
            "breached": None
        }
    
    except Exception as e:
        logger.error("[BREACH] IntelX error: %s", e, exc_info=True)
        return {
            "success": False,
            "error": str(e),
            "breached": None
        }


# =============================================================================
# BREACH CHECKING - LeakCheck (FALLBACK)
# =============================================================================

def check_leakcheck(email):
    """
    Check a single email against LeakCheck API.

    Free tier: 10 lookups/day.
    Used as fallback when IntelX is rate-limited.

    Args:
        email: Email address to check

    Returns:
        Dict with breach status and details
    """
    api_key = os.getenv("LEAKCHECK_API_KEY", "")

    if not api_key:
        return {
            "email": email,
            "breached": None,
            "error": "No LeakCheck API key",
            "breach_count": 0,
            "breaches": []
        }

    logger.info("[BREACH] Checking %s via LeakCheck...", email)
    throttler.wait_if_needed("leakcheck", Config.API_THROTTLE_SECONDS)

    try:
        resp = requests.get(
            "https://leakcheck.io/api/public",
            params={"check": email},
            headers={"X-API-Key": api_key},
            timeout=10
        )

        if resp.status_code == 401:
            return {
                "email": email,
                "breached": None,
                "error": "Invalid LeakCheck API key",
                "breach_count": 0,
                "breaches": []
            }

        if resp.status_code == 429:
            return {
                "email": email,
                "breached": None,
                "error": "LeakCheck rate limit (10/day free)",
                "breach_count": 0,
                "breaches": [],
                "rate_limited": True
            }

        if resp.status_code != 200:
            return {
                "email": email,
                "breached": None,
                "error": "HTTP " + str(resp.status_code),
                "breach_count": 0,
                "breaches": []
            }

        data = resp.json()
        found = data.get("found", 0)
        sources = data.get("sources", [])

        breaches = []
        for source in sources:
            breach_info = {
                "name": source.get("name", "Unknown"),
                "date": source.get("date", "Unknown"),
                "data_classes": source.get("data", [])
            }
            breaches.append(breach_info)

        password_leaked = False
        all_data_types = []
        for breach in breaches:
            data_classes = breach.get("data_classes", [])
            all_data_types.extend(data_classes)
            if "password" in str(data_classes).lower():
                password_leaked = True

        logger.info(
            "[BREACH] LeakCheck: %s found in %d sources",
            email,
            found
        )

        return {
            "email": email,
            "breached": found > 0,
            "breach_count": found,
            "breaches": breaches,
            "data_types_leaked": list(set(all_data_types)),
            "password_leaked": password_leaked,
            "source": "leakcheck"
        }

    except requests.Timeout:
        return {
            "email": email,
            "breached": None,
            "error": "LeakCheck timeout",
            "breach_count": 0,
            "breaches": []
        }

    except Exception as e:
        return {
            "email": email,
            "breached": None,
            "error": str(e),
            "breach_count": 0,
            "breaches": []
        }


# =============================================================================
# MULTI-SOURCE BREACH CHECKING (NEW)
# =============================================================================

def check_email_breach_multi_source(email):
    """
    Check email against multiple breach databases.
    Uses IntelX as primary, LeakCheck as fallback.
    
    Strategy:
      1. Try IntelX first (free, no daily limit on free.intelx.io)
      2. If IntelX rate-limited or fails, try LeakCheck
      3. Combine results from both sources
    
    Args:
        email: Email address to check
    
    Returns:
        Combined breach data from all available sources
    """
    combined_result = {
        "email": email,
        "breached": False,
        "breach_count": 0,
        "breaches": [],
        "data_types_leaked": set(),
        "password_leaked": False,
        "sources_checked": []
    }
    
    # ── Source 1: IntelX (Primary) ──
    intelx_result = check_intelx_breach(email)
    
    if intelx_result.get("success"):
        combined_result["sources_checked"].append("intelx")
        
        if intelx_result.get("breached"):
            combined_result["breached"] = True
            combined_result["breach_count"] += intelx_result.get("breach_count", 0)
            combined_result["breaches"].extend(intelx_result.get("breaches", []))
            combined_result["data_types_leaked"].update(intelx_result.get("data_types_leaked", []))
            
            if intelx_result.get("password_leaked"):
                combined_result["password_leaked"] = True
    
    # ── Source 2: LeakCheck (Fallback) ──
    # Only use if IntelX was rate-limited or found nothing
    if intelx_result.get("rate_limited") or not intelx_result.get("success"):
        leakcheck_key = os.getenv("LEAKCHECK_API_KEY", "")
        
        if leakcheck_key:
            time.sleep(1)  # Be nice to APIs
            leakcheck_result = check_leakcheck(email)
            
            if leakcheck_result.get("breached") is not None:
                combined_result["sources_checked"].append("leakcheck")
                
                if leakcheck_result.get("breached"):
                    combined_result["breached"] = True
                    combined_result["breach_count"] += leakcheck_result.get("breach_count", 0)
                    combined_result["breaches"].extend(leakcheck_result.get("breaches", []))
                    combined_result["data_types_leaked"].update(leakcheck_result.get("data_types_leaked", []))
                    
                    if leakcheck_result.get("password_leaked"):
                        combined_result["password_leaked"] = True
    
    # ── Finalize ──
    combined_result["data_types_leaked"] = list(combined_result["data_types_leaked"])
    
    # Deduplicate breaches by name
    unique_breaches = []
    seen_names = set()
    for breach in combined_result["breaches"]:
        breach_name = breach.get("name", "Unknown")
        if breach_name not in seen_names:
            seen_names.add(breach_name)
            unique_breaches.append(breach)
    
    combined_result["breaches"] = unique_breaches
    combined_result["breach_count"] = len(unique_breaches)
    
    return combined_result


def check_breaches_batch(emails):
    """
    Check multiple emails against breach databases.
    
    ENHANCED v1.2:
      - Uses IntelX as primary source (free API you already have)
      - Falls back to LeakCheck if needed
      - Better rate limit handling
      - Progress tracking
    
    Args:
        emails: List of email addresses
    
    Returns:
        Dict with results per email and summary
    """
    logger.info("[BREACH] Checking %d emails for breaches...", len(emails))

    results = {}
    total_breached = 0
    total_clean = 0
    password_leaks = 0
    checked = 0
    
    for email in emails:
        # Rate limiting - be nice to APIs
        if checked > 0:
            time.sleep(2)  # 2 seconds between requests
        
        # Use multi-source check
        result = check_email_breach_multi_source(email)
        results[email] = result
        
        if result.get("breached"):
            total_breached += 1
            if result.get("password_leaked"):
                password_leaks += 1
            status = "BREACHED"
        elif result.get("breached") is False:
            total_clean += 1
            status = "Clean"
        else:
            status = "Unchecked"
        
        sources = ",".join(result.get("sources_checked", []))
        logger.info("  [%s] %s (via: %s)", status, email, sources if sources else "none")
        checked += 1

    logger.info("[BREACH] Breach check complete:")
    logger.info("  Checked: %d", checked)
    logger.info("  Breached: %d", total_breached)
    logger.info("  Clean: %d", total_clean)
    logger.info("  Password leaks: %d", password_leaks)

    return {
        "success": True,
        "results": results,
        "summary": {
            "total_checked": checked,
            "total_breached": total_breached,
            "total_clean": total_clean,
            "password_leaks": password_leaks
        }
    }


# =============================================================================
# UNIFIED HARVEST FUNCTION (ENHANCED)
# =============================================================================

def harvest_emails(domain):
    """
    Discover emails using all available sources.
    Runs all sources independently, merges and deduplicates.
    
    ENHANCED v1.1:
      - Better metadata tracking per email
      - Separated tool_sources from web_sources
      - Better deduplication logic
      - Cleaner data structure
    """
    separator = "=" * 60
    logger.info("\n%s", separator)
    logger.info("[EMAIL] Starting email harvest for: %s", domain)
    logger.info("%s", separator)

    domain = domain.lower().strip()
    all_emails = set()
    email_metadata = {}  # Store detailed info per email
    source_results = {}

    # ── Source 1: theHarvester ──
    harvester_result = run_theharvester(domain)
    source_results["theharvester"] = harvester_result

    for email in harvester_result.get("emails", []):
        all_emails.add(email)
        if email not in email_metadata:
            email_metadata[email] = {
                "email": email,
                "tool_sources": [],
                "first_name": "",
                "last_name": "",
                "position": "",
                "linkedin": "",
                "confidence": 0,
                "web_sources": []
            }
        email_metadata[email]["tool_sources"].append("theharvester")

    # ── Source 2: Hunter.io ──
    hunter_result = run_hunter_io(domain)
    source_results["hunter_io"] = hunter_result

    for email in hunter_result.get("emails", []):
        all_emails.add(email)
        if email not in email_metadata:
            email_metadata[email] = {
                "email": email,
                "tool_sources": [],
                "first_name": "",
                "last_name": "",
                "position": "",
                "linkedin": "",
                "confidence": 0,
                "web_sources": []
            }
        email_metadata[email]["tool_sources"].append("hunter_io")
        
        # Add Hunter.io metadata
        for detail in hunter_result.get("email_details", []):
            if detail.get("email") == email:
                email_metadata[email].update({
                    "first_name": detail.get("first_name", ""),
                    "last_name": detail.get("last_name", ""),
                    "position": detail.get("position", ""),
                    "linkedin": detail.get("linkedin", ""),
                    "confidence": detail.get("confidence", 0),
                    "web_sources": detail.get("web_sources", [])
                })
                break

    # ── Source 3: Phonebook.cz ──
    phonebook_result = run_phonebook(domain)
    source_results["phonebook"] = phonebook_result

    for email in phonebook_result.get("emails", []):
        all_emails.add(email)
        if email not in email_metadata:
            email_metadata[email] = {
                "email": email,
                "tool_sources": [],
                "first_name": "",
                "last_name": "",
                "position": "",
                "linkedin": "",
                "confidence": 0,
                "web_sources": []
            }
        email_metadata[email]["tool_sources"].append("phonebook")

    # ── Build final email list with metadata ──
    final_emails = sorted(all_emails)
    email_list = []
    
    for email in final_emails:
        metadata = email_metadata.get(email, {})
        
        email_list.append({
            "email": email,
            "tool_sources": metadata.get("tool_sources", []),  # ONLY tool names
            "source_count": len(metadata.get("tool_sources", [])),
            "first_name": metadata.get("first_name", ""),
            "last_name": metadata.get("last_name", ""),
            "position": metadata.get("position", ""),
            "linkedin": metadata.get("linkedin", ""),
            "confidence": metadata.get("confidence", 0),
            "web_sources": metadata.get("web_sources", [])  # Separate field
        })

    # ── Source Statistics ──
    source_stats = {}
    for source_name, result in source_results.items():
        source_stats[source_name] = {
            "success": result.get("success", False),
            "count": result.get("count", 0),
            "error": result.get("error", "")
        }

    logger.info("\n[EMAIL] Harvest complete:")
    logger.info("[EMAIL] Total unique emails: %d", len(final_emails))
    for source, stats in source_stats.items():
        status = "✓" if stats["success"] else "✗"
        logger.info("  [%s] %s: %d emails", status, source, stats["count"])

    return {
        "success": True,
        "domain": domain,
        "emails": final_emails,
        "email_details": email_list,
        "count": len(final_emails),
        "source_stats": source_stats,
        "email_pattern": hunter_result.get("pattern", ""),
        "harvested_at": datetime.utcnow().isoformat()
    }


# =============================================================================
# FULL HARVEST + BREACH CHECK
# =============================================================================

def harvest_and_check(domain):
    """
    Complete email OSINT pipeline:
    1. Discover emails from all sources
    2. Check discovered emails against breach databases
    3. Return combined results

    This is the main function called by routes/targets.py
    
    ENHANCED v1.2:
      - Uses IntelX for breach checking (free API you already have)
      - Falls back to LeakCheck if needed
      - Better result aggregation
    """
    # Step 1: Harvest emails
    harvest_result = harvest_emails(domain)
    emails = harvest_result.get("emails", [])

    if not emails:
        logger.info("[EMAIL] No emails found - skipping breach check")
        return {
            "success": True,
            "domain": domain,
            "harvest": harvest_result,
            "breach_check": {
                "success": True,
                "results": {},
                "summary": {
                    "total_checked": 0,
                    "total_breached": 0,
                    "total_clean": 0,
                    "password_leaks": 0
                }
            },
            "combined": {
                "total_emails": 0,
                "total_breached": 0,
                "total_clean": 0,
                "password_leaks": 0,
                "emails": []
            }
        }

    # Step 2: Check breaches (now uses IntelX + LeakCheck)
    breach_result = check_breaches_batch(emails)
    breach_results = breach_result.get("results", {})

    # Step 3: Combine harvest + breach data
    combined_emails = []
    total_breached = 0
    total_clean = 0
    password_leaks = 0

    for email_detail in harvest_result.get("email_details", []):
        email_addr = email_detail.get("email", "")
        breach_data = breach_results.get(email_addr, {})

        combined = {
            "email": email_addr,
            "tool_sources": email_detail.get("tool_sources", []),  # ONLY tools
            "source_count": email_detail.get("source_count", 0),
            "first_name": email_detail.get("first_name", ""),
            "last_name": email_detail.get("last_name", ""),
            "position": email_detail.get("position", ""),
            "linkedin": email_detail.get("linkedin", ""),
            "confidence": email_detail.get("confidence", 0),
            "web_sources": email_detail.get("web_sources", []),  # Web domains
            "breached": breach_data.get("breached", None),
            "breach_count": breach_data.get("breach_count", 0),
            "breaches": breach_data.get("breaches", []),
            "data_types_leaked": breach_data.get(
                "data_types_leaked", []
            ),
            "password_leaked": breach_data.get(
                "password_leaked", False
            ),
            "breach_sources": breach_data.get("sources_checked", [])  # NEW: Which APIs checked
        }

        if combined["breached"] is True:
            total_breached += 1
            if combined["password_leaked"]:
                password_leaks += 1
        elif combined["breached"] is False:
            total_clean += 1

        combined_emails.append(combined)

    separator = "=" * 60
    logger.info("\n%s", separator)
    logger.info("[EMAIL] Complete results for %s:", domain)
    logger.info("[EMAIL] Emails found: %d", len(emails))
    logger.info("[EMAIL] Breached: %d", total_breached)
    logger.info("[EMAIL] Clean: %d", total_clean)
    logger.info("[EMAIL] Password leaks: %d", password_leaks)
    logger.info("%s", separator)

    return {
        "success": True,
        "domain": domain,
        "harvest": harvest_result,
        "breach_check": breach_result,
        "combined": {
            "total_emails": len(emails),
            "total_breached": total_breached,
            "total_clean": total_clean,
            "password_leaks": password_leaks,
            "emails": combined_emails
        }
    }


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    separator = "=" * 60
    logger.info(separator)
    logger.info("  EMAIL HARVESTER - Standalone Test")
    logger.info(separator)

    domain = input("\nEnter domain (e.g., company.com): ").strip()
    if domain:
        result = harvest_and_check(domain)

        logger.info("\n" + separator)
        logger.info("Domain: " + result["domain"])
        total = str(result["combined"]["total_emails"])
        breached = str(result["combined"]["total_breached"])
        logger.info("Emails found: " + total)
        logger.info("Breached: " + breached)

        for email_data in result["combined"]["emails"][:10]:
            if email_data.get("breached"):
                status = "BREACHED"
            else:
                status = "Clean"

            tool_sources = ", ".join(email_data.get("tool_sources", []))
            breach_sources = ", ".join(email_data.get("breach_sources", []))
            
            logger.info(
                "  [" + status + "] "
                + email_data["email"]
                + " (found via: " + tool_sources + ")"
            )
            
            if email_data.get("breached"):
                logger.info(f"    Checked via: {breach_sources}")
                logger.info(f"    Found in {email_data.get('breach_count', 0)} breaches")

            if email_data.get("breaches"):
                for b in email_data["breaches"][:3]:
                    data_classes = ", ".join(
                        b.get("data_classes", [])[:3]
                    )
                    logger.info(
                        "    -> " + b["name"]
                        + " (" + b.get("date", "Unknown") + ")"
                        + (f" - {data_classes}" if data_classes else "")
                    )
    else:
        logger.info("No domain entered. Exiting.")