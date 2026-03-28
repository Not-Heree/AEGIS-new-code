"""
Email Harvester Module
======================
Discovers company email addresses and checks them against breach databases.

Sources:
  - theHarvester (primary - open source OSINT tool)
  - Hunter.io API (fallback - finds emails + patterns)
  - Phonebook.cz (free fallback - no API key needed)

Breach Checking:
  - LeakCheck API (free tier - replaces HIBP)

Designed to run automatically when a target is registered.
Each source is independent - failure in one doesn't affect others.
"""

import subprocess
import re
import os
import time
import json
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional, Set

from config import Config
from utils.logger import logger


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
# SOURCE 1: theHarvester
# =============================================================================

def run_theharvester(domain):
    """
    Run theHarvester to discover emails for a domain.

    theHarvester searches multiple public sources:
    Google, Bing, LinkedIn, Yahoo, DNSDumpster, etc.

    Args:
        domain: Target domain (e.g., "company.com")

    Returns:
        Dict with success, emails list, source counts
    """
    print("[EMAIL] Running theHarvester on " + domain + "...")

    try:
        cmd = [
            Config.THEHARVESTER_PATH,
            "-d", domain,
            "-b", Config.HARVESTER_SOURCES,
            "-l", "200"
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=Config.HARVESTER_TIMEOUT,
            encoding='utf-8',
            errors='replace'
        )

        output = result.stdout + "\n" + result.stderr
        emails = _extract_emails_from_text(output, domain)

        print("[EMAIL] theHarvester found " + str(len(emails)) + " emails")

        return {
            "success": True,
            "emails": list(emails),
            "count": len(emails),
            "source": "theharvester"
        }

    except subprocess.TimeoutExpired:
        timeout = str(Config.HARVESTER_TIMEOUT)
        print("[EMAIL] theHarvester timed out after " + timeout + "s")
        return {
            "success": False,
            "error": "theHarvester timed out",
            "emails": [],
            "source": "theharvester"
        }

    except FileNotFoundError:
        path = str(Config.THEHARVESTER_PATH)
        print("[EMAIL] theHarvester not found at " + path)
        print("[EMAIL] Install with: pip install theHarvester")
        return {
            "success": False,
            "error": "theHarvester not found at " + path,
            "emails": [],
            "source": "theharvester"
        }

    except Exception as e:
        print("[EMAIL] theHarvester error: " + str(e))
        return {
            "success": False,
            "error": str(e),
            "emails": [],
            "source": "theharvester"
        }


# =============================================================================
# SOURCE 2: Hunter.io API
# =============================================================================

def run_hunter_io(domain):
    """
    Query Hunter.io API for email addresses.

    Hunter.io crawls the web and finds email addresses
    associated with a domain. Also detects the email pattern
    (e.g., "{first}.{last}@company.com").

    Free tier: 25 searches/month, 50 verifications/month.

    Args:
        domain: Target domain

    Returns:
        Dict with emails, pattern, and sources
    """
    api_key = Config.HUNTER_API_KEY

    if not api_key:
        print("[EMAIL] Hunter.io skipped - no API key configured")
        return {
            "success": False,
            "error": "No Hunter.io API key",
            "emails": [],
            "source": "hunter_io"
        }

    print("[EMAIL] Querying Hunter.io for " + domain + "...")

    try:
        resp = requests.get(
            "https://api.hunter.io/v2/domain-search",
            params={
                "domain": domain,
                "api_key": api_key,
                "limit": 10
            },
            timeout=15
        )

        if resp.status_code == 401:
            print("[EMAIL] Hunter.io - invalid API key")
            return {
                "success": False,
                "error": "Invalid Hunter.io API key",
                "emails": [],
                "source": "hunter_io"
            }

        if resp.status_code == 429:
            print("[EMAIL] Hunter.io - rate limited")
            return {
                "success": False,
                "error": "Hunter.io rate limit exceeded",
                "emails": [],
                "source": "hunter_io"
            }

        if resp.status_code != 200:
            print("[EMAIL] Hunter.io HTTP " + str(resp.status_code))
            return {
                "success": False,
                "error": "HTTP " + str(resp.status_code),
                "emails": [],
                "source": "hunter_io"
            }

        data = resp.json().get("data", {})
        emails_data = data.get("emails", [])
        pattern = data.get("pattern", "")

        emails = []
        for entry in emails_data:
            email = entry.get("value", "").lower().strip()
            if _is_valid_email(email, domain):
                source_list = []
                for s in entry.get("sources", []):
                    source_list.append(s.get("domain", ""))

                emails.append({
                    "email": email,
                    "type": entry.get("type", ""),
                    "confidence": entry.get("confidence", 0),
                    "first_name": entry.get("first_name", ""),
                    "last_name": entry.get("last_name", ""),
                    "position": entry.get("position", ""),
                    "linkedin": entry.get("linkedin", ""),
                    "sources": source_list
                })

        email_strings = [e["email"] for e in emails]
        pattern_text = pattern if pattern else "unknown"
        print(
            "[EMAIL] Hunter.io found " + str(len(email_strings))
            + " emails (pattern: " + pattern_text + ")"
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
        print("[EMAIL] Hunter.io timeout")
        return {
            "success": False,
            "error": "Timeout",
            "emails": [],
            "source": "hunter_io"
        }

    except Exception as e:
        print("[EMAIL] Hunter.io error: " + str(e))
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

    try:
        # ── Step 1: Start a search ──
        # The IntelX API uses a two-phase search:
        #   POST to start → returns search_id
        #   GET to fetch results using search_id
        search_url = "https://2.intelx.io/phonebook/search"

        search_payload = {
            "term": domain,
            "maxresults": 100,
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
        # The search runs async on IntelX's servers.
        # We need to wait a moment before fetching results.
        time.sleep(3)

        results_url = "https://2.intelx.io/phonebook/search/result"

        results_resp = requests.get(
            results_url,
            params={
                "id": search_id,
                "limit": 100,
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
            # Each selector has a "selectorvalue" field
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
# BREACH CHECKING - LeakCheck (Free HIBP Alternative)
# =============================================================================

def check_leakcheck(email):
    """
    Check a single email against LeakCheck API.

    Free tier: 10 lookups/day.
    Replaces HIBP which requires paid subscription.

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
                "breaches": []
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

        return {
            "email": email,
            "breached": found > 0,
            "breach_count": found,
            "breaches": breaches,
            "data_types_leaked": list(set(all_data_types)),
            "password_leaked": password_leaked
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


def check_breaches_batch(emails):
    """
    Check multiple emails against breach databases.

    Uses LeakCheck API (free tier: 10/day).

    Args:
        emails: List of email addresses

    Returns:
        Dict with results per email and summary
    """
    api_key = os.getenv("LEAKCHECK_API_KEY", "")

    if not api_key:
        print("[EMAIL] Breach checking skipped - no LeakCheck API key")
        print("[EMAIL] Get free key at: https://leakcheck.io")
        return {
            "success": False,
            "error": "No LeakCheck API key configured",
            "results": {},
            "summary": {
                "total_checked": 0,
                "total_breached": 0,
                "total_clean": 0,
                "password_leaks": 0
            }
        }

    print("[EMAIL] Checking " + str(len(emails)) + " emails for breaches...")

    results = {}
    total_breached = 0
    total_clean = 0
    password_leaks = 0
    checked = 0

    for email in emails:
        # Rate limiting - be nice to the API
        if checked > 0:
            time.sleep(2)

        result = check_leakcheck(email)
        results[email] = result

        if result.get("breached") is True:
            total_breached += 1
            if result.get("password_leaked"):
                password_leaks += 1
            status = "BREACHED"
        elif result.get("breached") is False:
            total_clean += 1
            status = "Clean"
        else:
            status = "Error"

        print("  [" + status + "] " + email)
        checked += 1

        # Free tier limit
        if checked >= 10:
            remaining = len(emails) - checked
            if remaining > 0:
                print(
                    "[EMAIL] LeakCheck free tier limit reached. "
                    + str(remaining) + " emails unchecked."
                )
            break

    print("[EMAIL] Breach check complete:")
    print("  Checked: " + str(checked))
    print("  Breached: " + str(total_breached))
    print("  Clean: " + str(total_clean))
    print("  Password leaks: " + str(password_leaks))

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
# UNIFIED HARVEST FUNCTION
# =============================================================================

def harvest_emails(domain):
    """
    Discover emails using all available sources.
    Runs all sources independently, merges and deduplicates.
    """
    separator = "=" * 60
    print("\n" + separator)
    print("[EMAIL] Starting email harvest for: " + domain)
    print(separator)

    domain = domain.lower().strip()
    all_emails = set()
    email_sources = {}
    source_results = {}

    # -- Source 1: theHarvester --
    harvester_result = run_theharvester(domain)
    source_results["theharvester"] = harvester_result

    for email in harvester_result.get("emails", []):
        all_emails.add(email)
        if email not in email_sources:
            email_sources[email] = []
        if "theharvester" not in email_sources[email]:
            email_sources[email].append("theharvester")

    # -- Source 2: Hunter.io --
    hunter_result = run_hunter_io(domain)
    source_results["hunter_io"] = hunter_result

    for email in hunter_result.get("emails", []):
        all_emails.add(email)
        if email not in email_sources:
            email_sources[email] = []
        if "hunter_io" not in email_sources[email]:
            email_sources[email].append("hunter_io")

    # -- Source 3: Phonebook.cz --
    phonebook_result = run_phonebook(domain)
    source_results["phonebook"] = phonebook_result

    for email in phonebook_result.get("emails", []):
        all_emails.add(email)
        if email not in email_sources:
            email_sources[email] = []
        if "phonebook" not in email_sources[email]:
            email_sources[email].append("phonebook")

    # -- Final dedup and sort --
    final_emails = sorted(all_emails)

    email_list = []
    for email in final_emails:
        sources = email_sources.get(email, [])
        entry = {
            "email": email,
            "sources": sources,           # ONLY tool names
            "source_count": len(sources),
        }

        # Add Hunter.io person metadata if available
        hunter_details = hunter_result.get("email_details", [])
        for hd in hunter_details:
            if hd.get("email") == email:
                entry["first_name"] = hd.get("first_name", "")
                entry["last_name"] = hd.get("last_name", "")
                entry["position"] = hd.get("position", "")
                entry["linkedin"] = hd.get("linkedin", "")
                entry["confidence"] = hd.get("confidence", 0)

                # ── FIX: Do NOT append web domains to sources ──
                # Web domains (linkedin.com, etc.) are where Hunter
                # *found* the email — they are NOT discovery tools.
                # Mixing them in caused visually-different "variants"
                # of the same email record.
                break

        email_list.append(entry)

    # Source statistics
    source_stats = {}
    for source_name, result in source_results.items():
        source_stats[source_name] = {
            "success": result.get("success", False),
            "count": result.get("count", 0),
            "error": result.get("error", "")
        }

    print("\n[EMAIL] Harvest complete:")
    print("[EMAIL] Total unique emails: " + str(len(final_emails)))
    for source, stats in source_stats.items():
        if stats["success"]:
            status = "OK"
        else:
            status = "FAIL"
        count = str(stats["count"])
        print("  [" + status + "] " + source + ": " + count + " emails")

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
    """
    # Step 1: Harvest emails
    harvest_result = harvest_emails(domain)
    emails = harvest_result.get("emails", [])

    if not emails:
        print("[EMAIL] No emails found - skipping breach check")
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

    # Step 2: Check breaches
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
            "sources": email_detail.get("sources", []),
            "source_count": email_detail.get("source_count", 0),
            "first_name": email_detail.get("first_name", ""),
            "last_name": email_detail.get("last_name", ""),
            "position": email_detail.get("position", ""),
            "linkedin": email_detail.get("linkedin", ""),
            "confidence": email_detail.get("confidence", 0),
            "breached": breach_data.get("breached", None),
            "breach_count": breach_data.get("breach_count", 0),
            "breaches": breach_data.get("breaches", []),
            "data_types_leaked": breach_data.get(
                "data_types_leaked", []
            ),
            "password_leaked": breach_data.get(
                "password_leaked", False
            )
        }

        if combined["breached"] is True:
            total_breached += 1
            if combined["password_leaked"]:
                password_leaks += 1
        elif combined["breached"] is False:
            total_clean += 1

        combined_emails.append(combined)

    separator = "=" * 60
    print("\n" + separator)
    print("[EMAIL] Complete results for " + domain + ":")
    print("[EMAIL] Emails found: " + str(len(emails)))
    print("[EMAIL] Breached: " + str(total_breached))
    print("[EMAIL] Clean: " + str(total_clean))
    print("[EMAIL] Password leaks: " + str(password_leaks))
    print(separator)

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
    print(separator)
    print("  EMAIL HARVESTER - Standalone Test")
    print(separator)

    domain = input("\nEnter domain (e.g., company.com): ").strip()
    if domain:
        result = harvest_and_check(domain)

        print("\n" + separator)
        print("Domain: " + result["domain"])
        total = str(result["combined"]["total_emails"])
        breached = str(result["combined"]["total_breached"])
        print("Emails found: " + total)
        print("Breached: " + breached)

        for email_data in result["combined"]["emails"][:10]:
            if email_data.get("breached"):
                status = "BREACHED"
            else:
                status = "Clean"

            sources = ", ".join(email_data.get("sources", []))
            print(
                "  [" + status + "] "
                + email_data["email"]
                + " (sources: " + sources + ")"
            )

            if email_data.get("breaches"):
                for b in email_data["breaches"][:3]:
                    data_classes = ", ".join(
                        b.get("data_classes", [])[:3]
                    )
                    print(
                        "    -> " + b["name"]
                        + " (" + b.get("date", "Unknown") + ")"
                        + " - " + data_classes
                    )
    else:
        print("No domain entered. Exiting.")