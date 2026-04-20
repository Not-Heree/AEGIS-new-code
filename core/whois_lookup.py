"""
WHOIS Passive Reconnaissance Module
=====================================
Queries public WHOIS databases for domain registration intelligence.
Zero traffic sent to the target — completely passive.

Provides:
  - Registrar and registration dates
  - Domain expiration monitoring (hijack risk)
  - Nameserver identification (DNS provider mapping)
  - DNSSEC status (DNS spoofing risk)
  - Domain transfer lock status (unauthorized transfer risk)
  - Registrant exposure detection (OSINT leakage)

Security value:
  - Expiring domain → attacker buys it after lapse
  - No DNSSEC → vulnerable to DNS cache poisoning
  - No transfer lock → domain can be stolen
  - Exposed registrant → social engineering fuel
  - Nameserver change between scans → possible hijack

No API key required — queries public WHOIS servers directly.
Designed to run as Phase 0c alongside Shodan and Censys.

Install: pip install python-whois
"""

from datetime import datetime, timezone
from utils.logger import logger
from typing import Dict, Any, List

try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    logger.warning("[WHOIS] python-whois not installed. Run: pip install python-whois")


# =============================================================================
# INITIALIZATION
# =============================================================================

def is_available() -> bool:
    """Check if WHOIS library is installed and usable."""
    return WHOIS_AVAILABLE


# =============================================================================
# DATE HELPERS
# =============================================================================

def _normalize_date(date_val):
    """
    Handle python-whois returning single date or list of dates.

    python-whois is inconsistent — some TLDs return a single
    datetime, others return a list. This normalizes both to
    an ISO string.

    Args:
        date_val: datetime, list of datetimes, or None

    Returns:
        ISO format string or None
    """
    if date_val is None:
        return None
    if isinstance(date_val, list):
        date_val = date_val[0] if date_val else None
    if date_val is None:
        return None
    if isinstance(date_val, datetime):
        return date_val.isoformat()
    return str(date_val)


def _parse_iso_date(iso_str):
    """
    Parse an ISO date string back to a timezone-aware datetime.

    Returns None if parsing fails.
    """
    if not iso_str:
        return None
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


# =============================================================================
# CORE WHOIS LOOKUP
# =============================================================================

def lookup_domain(domain: str) -> Dict[str, Any]:
    """
    Perform WHOIS lookup on a domain and extract all fields.

    Queries the public WHOIS server for the domain's TLD.
    Normalizes the inconsistent python-whois output into
    a clean, predictable structure.

    Args:
        domain: Root domain (e.g., "example.com")

    Returns:
        Dict with all WHOIS fields and raw data
    """
    if not WHOIS_AVAILABLE:
        return {
            "success": False,
            "error": "python-whois library not installed",
            "source": "whois"
        }

    logger.info("[WHOIS] Looking up registration data for %s...", domain)

    result = {
        "success": False,
        "domain": domain,
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "updated_date": None,
        "nameservers": [],
        "status": [],
        "dnssec": False,
        "registrant_org": None,
        "registrant_country": None,
        "registrant_emails": [],
        "privacy_enabled": False,
        "days_until_expiry": None,
        "domain_age_days": None,
        "source": "whois"
    }

    try:
        w = whois.whois(domain)

        if not w or not w.domain_name:
            logger.warning("[WHOIS] No data returned for %s", domain)
            result["error"] = "No WHOIS data returned"
            return result

        # ── Registrar ─────────────────────────────────
        result["registrar"] = w.registrar

        # ── Dates ─────────────────────────────────────
        result["creation_date"] = _normalize_date(
            w.creation_date
        )
        result["expiration_date"] = _normalize_date(
            w.expiration_date
        )
        result["updated_date"] = _normalize_date(
            w.updated_date
        )

        # ── Nameservers (normalize to lowercase) ─────
        if w.name_servers:
            if isinstance(w.name_servers, list):
                result["nameservers"] = sorted(set(
                    ns.lower().rstrip(".")
                    for ns in w.name_servers
                    if ns
                ))
            else:
                result["nameservers"] = [
                    w.name_servers.lower().rstrip(".")
                ]

        # ── Domain status flags ──────────────────────
        if w.status:
            if isinstance(w.status, list):
                result["status"] = w.status
            else:
                result["status"] = [w.status]

        # ── DNSSEC ────────────────────────────────────
        if hasattr(w, "dnssec") and w.dnssec:
            dnssec_val = str(w.dnssec).lower()
            result["dnssec"] = dnssec_val in (
                "signeddelegation", "yes", "true"
            )

        # ── Registrant info ──────────────────────────
        result["registrant_org"] = getattr(w, "org", None)
        result["registrant_country"] = getattr(
            w, "country", None
        )

        # ── Privacy detection ────────────────────────
        whois_text = str(w).lower()
        privacy_keywords = [
            "privacy", "redacted", "proxy", "whoisguard",
            "withheld", "data protected", "not disclosed",
            "contact privacy", "domains by proxy",
            "redacted for privacy", "statutory masking"
        ]
        result["privacy_enabled"] = any(
            kw in whois_text for kw in privacy_keywords
        )

        # Extract contact emails (if not privacy-protected)
        if not result["privacy_enabled"]:
            raw_emails = getattr(w, "emails", None)
            if raw_emails:
                if isinstance(raw_emails, str):
                    raw_emails = [raw_emails]
                # Filter out generic abuse@ addresses
                result["registrant_emails"] = [
                    e for e in raw_emails
                    if "abuse@" not in e.lower()
                ]

        # ── Calculate age and expiry ─────────────────
        now = datetime.now(timezone.utc)

        exp_dt = _parse_iso_date(result["expiration_date"])
        if exp_dt:
            result["days_until_expiry"] = (exp_dt - now).days

        created_dt = _parse_iso_date(result["creation_date"])
        if created_dt:
            result["domain_age_days"] = (now - created_dt).days

        result["success"] = True

        print(
            f"[WHOIS] Registrar: "
            f"{result['registrar'] or 'Unknown'}"
        )
        print(
            f"[WHOIS] Nameservers: "
            f"{', '.join(result['nameservers'][:4]) or 'None'}"
        )
        print(
            f"[WHOIS] Expires: "
            f"{result['expiration_date'] or 'Unknown'}"
            f" ({result['days_until_expiry']} days)"
            if result["days_until_expiry"] is not None
            else ""
        )
        print(
            f"[WHOIS] DNSSEC: "
            f"{'Enabled' if result['dnssec'] else 'Not enabled'}"
        )

        return result

    except Exception as e:
        logger.error("[WHOIS] Lookup error for %s: %s", domain, e, exc_info=True)
        result["error"] = str(e)
        return result


# =============================================================================
# RISK FLAG ANALYSIS
# =============================================================================

def _analyze_risks(whois_data: Dict) -> List[Dict]:
    """
    Analyze WHOIS data for security-relevant risk indicators.

    Each flag has a severity level that maps to risk score
    weights in Phase 6. Flags are stored in the DB so they
    can be displayed on the dashboard and tracked over time.

    Args:
        whois_data: Dict from lookup_domain()

    Returns:
        List of risk flag dicts with flag, severity, detail
    """
    flags = []
    now = datetime.now(timezone.utc)

    # ── Risk 1: Domain Expiration ─────────────────────
    days_left = whois_data.get("days_until_expiry")
    if days_left is not None:
        if days_left < 0:
            flags.append({
                "flag": "domain_expired",
                "severity": "critical",
                "detail": (
                    f"Domain expired {abs(days_left)} days "
                    f"ago. High risk of domain hijacking."
                )
            })
        elif days_left <= 30:
            flags.append({
                "flag": "domain_expiring_soon",
                "severity": "high",
                "detail": (
                    f"Domain expires in {days_left} days. "
                    f"Risk of lapse and takeover."
                )
            })
        elif days_left <= 90:
            flags.append({
                "flag": "domain_expiring_soon",
                "severity": "medium",
                "detail": (
                    f"Domain expires in {days_left} days. "
                    f"Renewal recommended."
                )
            })

    # ── Risk 2: No DNSSEC ─────────────────────────────
    if not whois_data.get("dnssec", False):
        flags.append({
            "flag": "no_dnssec",
            "severity": "medium",
            "detail": (
                "DNSSEC is not enabled. Domain is vulnerable "
                "to DNS cache poisoning and spoofing attacks."
            )
        })

    # ── Risk 3: No Transfer Lock ──────────────────────
    status_list = whois_data.get("status", [])
    if status_list:
        status_str = " ".join(status_list).lower()
        has_lock = any(
            lock in status_str for lock in [
                "clienttransferprohibited",
                "servertransferprohibited"
            ]
        )
        if not has_lock:
            flags.append({
                "flag": "no_transfer_lock",
                "severity": "high",
                "detail": (
                    "Domain does not have transfer lock "
                    "enabled. Vulnerable to unauthorized "
                    "domain transfer."
                )
            })

    # ── Risk 4: Registrant Info Exposed ───────────────
    if (not whois_data.get("privacy_enabled", False)
            and whois_data.get("registrant_org")):
        flags.append({
            "flag": "registrant_exposed",
            "severity": "low",
            "detail": (
                f"WHOIS privacy not enabled. Organisation "
                f"'{whois_data['registrant_org']}' is publicly "
                f"visible. Useful for social engineering."
            )
        })

    # ── Risk 5: Newly Registered Domain ───────────────
    age_days = whois_data.get("domain_age_days")
    if age_days is not None and age_days < 30:
        flags.append({
            "flag": "newly_registered",
            "severity": "medium",
            "detail": (
                f"Domain registered only {age_days} days "
                f"ago. Could indicate shadow IT or phishing "
                f"setup."
            )
        })

    return flags


# =============================================================================
# UNIFIED WHOIS RECON (Main Entry Point)
# =============================================================================

def run_whois_recon(domain: str) -> Dict[str, Any]:
    """
    Run complete WHOIS reconnaissance on a domain.

    This is the main function called by scanner.py Phase 0.
    Performs lookup, analyzes risks, and returns structured data.

    Args:
        domain: Target domain (e.g., "example.com")

    Returns:
        Dict with all WHOIS intelligence and risk flags
    """
    print(f"\n{'='*60}")
    logger.info("[WHOIS] Starting recon for: %s", domain)
    print(f"{'='*60}")

    if not is_available():
        print("[WHOIS] Not available — python-whois not installed")
        logger.warning("[WHOIS] Run: pip install python-whois")
        return {
            "success": False,
            "error": "python-whois library not installed",
            "domain": domain,
            "registrar": None,
            "creation_date": None,
            "expiration_date": None,
            "updated_date": None,
            "nameservers": [],
            "status": [],
            "dnssec": False,
            "registrant_org": None,
            "registrant_country": None,
            "registrant_emails": [],
            "privacy_enabled": False,
            "days_until_expiry": None,
            "domain_age_days": None,
            "risk_flags": [],
            "stats": {
                "risk_flags_count": 0,
                "days_until_expiry": None,
                "domain_age_days": None
            },
            "source": "whois"
        }

    # ── Step 1: WHOIS Lookup ──────────────────────────
    whois_data = lookup_domain(domain)

    # ── Step 2: Risk Analysis ─────────────────────────
    risk_flags = []
    if whois_data.get("success"):
        risk_flags = _analyze_risks(whois_data)
        whois_data["risk_flags"] = risk_flags
    else:
        whois_data["risk_flags"] = [{
            "flag": "whois_lookup_failed",
            "severity": "info",
            "detail": (
                f"WHOIS query failed: "
                f"{whois_data.get('error', 'Unknown error')}"
            )
        }]

    # ── Build stats ───────────────────────────────────
    whois_data["stats"] = {
        "risk_flags_count": len(risk_flags),
        "days_until_expiry": whois_data.get(
            "days_until_expiry"
        ),
        "domain_age_days": whois_data.get(
            "domain_age_days"
        ),
        "nameserver_count": len(
            whois_data.get("nameservers", [])
        ),
        "dnssec_enabled": whois_data.get("dnssec", False),
        "privacy_enabled": whois_data.get(
            "privacy_enabled", False
        )
    }

    whois_data["recon_at"] = datetime.utcnow().isoformat()

    # ── Print summary ─────────────────────────────────
    logger.info("[WHOIS] Recon complete")
    print(
        f"[WHOIS]   Registrar: "
        f"{whois_data.get('registrar', 'Unknown')}"
    )
    print(
        f"[WHOIS]   Nameservers: "
        f"{len(whois_data.get('nameservers', []))}"
    )
    print(
        f"[WHOIS]   DNSSEC: "
        f"{'Yes' if whois_data.get('dnssec') else 'No'}"
    )
    print(
        f"[WHOIS]   Risk flags: "
        f"{len(risk_flags)}"
    )

    if risk_flags:
        for flag in risk_flags:
            print(
                f"[WHOIS]     ⚠ {flag['severity'].upper()}: "
                f"{flag['detail']}"
            )

    return whois_data


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  WHOIS RECON — Standalone Test")
    print("=" * 60)

    if not is_available():
        print("\n❌ python-whois not installed")
        print("Run: pip install python-whois")
    else:
        domain = input(
            "\nEnter domain (e.g., example.com): "
        ).strip()
        if domain:
            result = run_whois_recon(domain)

            print(f"\n{'='*60}")
            print(f"Domain: {result['domain']}")
            print(f"Success: {result['success']}")

            if result["success"]:
                print(f"\nRegistrar: {result['registrar']}")
                print(f"Created: {result['creation_date']}")
                print(f"Expires: {result['expiration_date']}")
                print(
                    f"Days until expiry: "
                    f"{result['days_until_expiry']}"
                )
                print(
                    f"Domain age: "
                    f"{result['domain_age_days']} days"
                )
                print(
                    f"Nameservers: "
                    f"{', '.join(result['nameservers'])}"
                )
                print(
                    f"DNSSEC: "
                    f"{'Enabled' if result['dnssec'] else 'No'}"
                )
                print(f"Status: {result['status']}")
                print(
                    f"Privacy: "
                    f"{'Enabled' if result['privacy_enabled'] else 'No'}"
                )

                print(
                    f"\nRisk Flags "
                    f"({len(result['risk_flags'])}):"
                )
                for flag in result["risk_flags"]:
                    print(
                        f"  [{flag['severity'].upper()}] "
                        f"{flag['detail']}"
                    )
            else:
                print(f"Error: {result.get('error')}")