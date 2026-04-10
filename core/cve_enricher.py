"""
CVE Enricher — Threat Intelligence for Vulnerabilities

Enriches CVE findings with real-world threat data:
  - NVD (NIST): Official description, patch links, CVSS details
  - EPSS (FIRST.org): Probability of exploitation (0-1)
  - KEV (CISA): Is this actively exploited right now?

Designed for SMEs: Simple, cached, fault-tolerant.
Every API call has a fallback — enrichment failure never breaks scanning.
"""

import os
import json
import time
import requests
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from functools import lru_cache

from config import Config


# =============================================================================
# CONFIGURATION
# =============================================================================

# API endpoints
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# KEV catalog — downloaded locally for speed
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_LOCAL_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "kev_catalog.json"
)

# CWE knowledge base path
CWE_KB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "data", "cwe_remediation.json"
)

# NVD CWE API endpoint
NVD_CWE_API_URL = "https://cwe.mitre.org/data/json/cweDetailedByID.json"

# Cache settings
NVD_RATE_LIMIT_DELAY = 0.7  # NVD allows ~10 requests/minute without API key
CACHE_MAX_SIZE = 500
KEV_REFRESH_HOURS = 24  # Re-download KEV catalog daily
CWE_CACHE_HOURS = 24  # Cache NVD CWE lookups for 24 hours


# =============================================================================
# KEV (CISA Known Exploited Vulnerabilities)
# =============================================================================

_kev_cache = {
    "data": set(),
    "loaded_at": None,
    "full_data": {}
}


def _load_kev_catalog() -> None:
    """
    Load KEV catalog from local file.
    Downloads from CISA if local file is missing or stale.
    """
    global _kev_cache

    needs_download = False

    # Check if local file exists
    if not os.path.exists(KEV_LOCAL_PATH):
        needs_download = True
    elif _kev_cache["loaded_at"]:
        # Check if cache is stale
        age = datetime.utcnow() - _kev_cache["loaded_at"]
        if age > timedelta(hours=KEV_REFRESH_HOURS):
            needs_download = True
    else:
        # File exists but not loaded into memory yet
        needs_download = False

    # Download if needed
    if needs_download:
        try:
            print("[KEV] Downloading CISA KEV catalog...")
            resp = requests.get(KEV_URL, timeout=30)

            if resp.status_code == 200:
                # Ensure data directory exists
                os.makedirs(os.path.dirname(KEV_LOCAL_PATH), exist_ok=True)

                with open(KEV_LOCAL_PATH, "w", encoding="utf-8") as f:
                    f.write(resp.text)
                print("[KEV] Catalog downloaded successfully")
            else:
                print(f"[KEV] Download failed: HTTP {resp.status_code}")

        except Exception as e:
            print(f"[KEV] Download failed: {e}")

    # Load from local file
    try:
        if os.path.exists(KEV_LOCAL_PATH):
            with open(KEV_LOCAL_PATH, "r", encoding="utf-8") as f:
                catalog = json.load(f)

            vulns = catalog.get("vulnerabilities", [])
            _kev_cache["data"] = set(
                v.get("cveID", "").upper() for v in vulns
            )
            _kev_cache["full_data"] = {
                v.get("cveID", "").upper(): v for v in vulns
            }
            _kev_cache["loaded_at"] = datetime.utcnow()

            print(f"[KEV] Loaded {len(_kev_cache['data'])} known exploited vulnerabilities")
        else:
            print("[KEV] No local catalog available")

    except Exception as e:
        print(f"[KEV] Error loading catalog: {e}")


def is_in_kev(cve_id: str) -> bool:
    """Check if a CVE is in the CISA Known Exploited Vulnerabilities catalog."""
    if not _kev_cache["loaded_at"]:
        _load_kev_catalog()

    return cve_id.upper() in _kev_cache["data"]


def get_kev_details(cve_id: str) -> Optional[Dict[str, Any]]:
    """Get full KEV details for a CVE (due date, required action, etc)."""
    if not _kev_cache["loaded_at"]:
        _load_kev_catalog()

    return _kev_cache["full_data"].get(cve_id.upper())


# =============================================================================
# CWE KNOWLEDGE BASE
# =============================================================================

_cwe_cache = {
    "data": {},
    "loaded": False,
    "nvd_fallback": {},  # Cached NVD results for unknown CWEs
    "nvd_cache_time": {}  # Timestamp for each NVD entry
}


def _load_cwe_kb() -> None:
    """Load CWE remediation knowledge base from local JSON."""
    global _cwe_cache

    try:
        if os.path.exists(CWE_KB_PATH):
            with open(CWE_KB_PATH, "r", encoding="utf-8") as f:
                _cwe_cache["data"] = json.load(f)
            _cwe_cache["loaded"] = True
            print(f"[CWE] Loaded {len(_cwe_cache['data'])} CWE remediation entries")
        else:
            print(f"[CWE] Knowledge base not found at {CWE_KB_PATH}")
            _cwe_cache["loaded"] = True  # Mark loaded to prevent retries

    except Exception as e:
        print(f"[CWE] Error loading knowledge base: {e}")
        _cwe_cache["loaded"] = True


@lru_cache(maxsize=CACHE_MAX_SIZE)
def _fetch_cwe_from_nvd(cwe_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch CWE details from NVD/MITRE CWE JSON for unknown CWEs.
    
    Fallback for CWEs not in static database.
    Returns generic remediation guidance structure.
    
    Args:
        cwe_id: CWE ID (e.g., "CWE-1234")
    
    Returns:
        Dict with name, category, impact, fix_steps (generic), references
        or None on failure
    """
    global _cwe_cache
    
    # Check if already cached from previous NVD lookup
    if cwe_id in _cwe_cache["nvd_fallback"]:
        cached_time = _cwe_cache["nvd_cache_time"].get(cwe_id)
        if cached_time:
            age = datetime.utcnow() - cached_time
            if age < timedelta(hours=CWE_CACHE_HOURS):
                return _cwe_cache["nvd_fallback"][cwe_id]
    
    try:
        import re
        cwe_num = re.search(r'\d+', cwe_id)
        if not cwe_num:
            return None
        
        cwe_num = cwe_num.group()
        
        # Attempt CWE lookup via MITRE API (lightweight JSON)
        # Note: MITRE CWE JSON is static/offline-first
        try:
            resp = requests.get(
                f"https://cwe.mitre.org/data/json/cwe_by_id_cwe-{cwe_num}.json",
                timeout=5
            )
            if resp.status_code == 200:
                cwe_data = resp.json()
                
                # Extract and normalize response
                name = cwe_data.get("Name", "Unknown CWE")
                description = cwe_data.get("Description", "")
                
                # Generate generic remediation structure
                remediation = {
                    "name": name,
                    "category": "generic",
                    "impact": description[:200] if description else "Vulnerability of type " + cwe_id,
                    "business_impact": "Potential security impact - refer to NVD for details",
                    "fix_steps": [
                        "Identify vulnerable code patterns related to " + cwe_id,
                        "Review NVD documentation at nvd.nist.gov",
                        "Implement recommended mitigations from security advisories",
                        "Test fixes thoroughly in staging environment",
                        "Deploy and monitor in production"
                    ],
                    "code_examples": {"reference": "See NVD and MITRE documentation"},
                    "references": [f"https://cwe.mitre.org/data/definitions/{cwe_num}.html",
                                  f"https://nvd.nist.gov/vuln/search/results?query={cwe_id}"],
                    "timeline": "14 days",
                    "source": "nvd_fallback"
                }
                
                # Cache result
                _cwe_cache["nvd_fallback"][cwe_id] = remediation
                _cwe_cache["nvd_cache_time"][cwe_id] = datetime.utcnow()
                
                print(f"[CWE] Fetched {cwe_id} from NVD API fallback")
                return remediation
        except:
            pass
        
        # If NVD API fails, return generic template
        generic = {
            "name": f"{cwe_id} - Unknown CWE",
            "category": "generic",
            "impact": "Security vulnerability",
            "business_impact": "Potential security risk",
            "fix_steps": [
                "Review CVE details for specific vulnerability context",
                "Check NVD database for remediation guidance",
                "Consult security advisory from vendor",
                "Implement vendor's recommended patches/mitigations",
                "Validate fix and test thoroughly"
            ],
            "code_examples": {"reference": "Vendor advisory"},
            "references": [f"https://nvd.nist.gov/vuln/search/results?query={cwe_id}"],
            "timeline": "7-14 days",
            "source": "generic_fallback"
        }
        
        _cwe_cache["nvd_fallback"][cwe_id] = generic
        _cwe_cache["nvd_cache_time"][cwe_id] = datetime.utcnow()
        return generic
        
    except Exception as e:
        print(f"[CWE] NVD fallback failed for {cwe_id}: {e}")
        return None


def get_cwe_remediation(cwe_id: str) -> Optional[Dict[str, Any]]:
    """
    Look up CWE remediation details using HYBRID approach.
    
    Strategy:
    1. Check static database (110+ top CWEs - FAST)
    2. If not found, fetch from NVD API as fallback (SLOWER, cached 24h)
    3. If NVD fails, return generic remediation template
    
    This ensures:
    - Fast response for common CWEs (static DB)
    - Coverage for 1000+ CWE types (NVD fallback)
    - Graceful degradation on API failure (generic template)

    Args:
        cwe_id: CWE identifier (e.g., "CWE-79" or "79" or ["CWE-79"])

    Returns:
        Dict with name, impact, fix_steps, code_examples, references
        or None if all methods fail
    """
    if not _cwe_cache["loaded"]:
        _load_cwe_kb()

    # Normalize input
    if isinstance(cwe_id, list):
        # Take first CWE from list
        if not cwe_id:
            return None
        cwe_id = cwe_id[0]

    cwe_id = str(cwe_id).strip()

    # Normalize format to "CWE-XX"
    if not cwe_id.upper().startswith("CWE-"):
        cwe_id = f"CWE-{cwe_id}"
    else:
        cwe_id = cwe_id.upper()

    # =========================================================================
    # STEP 1: Try static database (110+ top CWEs)
    # =========================================================================
    static_result = _cwe_cache["data"].get(cwe_id)
    if static_result:
        # Mark as from static database for transparency
        static_result_copy = dict(static_result)
        static_result_copy["source"] = "static_database"
        return static_result_copy
    
    # =========================================================================
    # STEP 2: Try NVD API fallback (for unknown CWEs)
    # =========================================================================
    print(f"[CWE] {cwe_id} not in static DB, attempting NVD fallback...")
    nvd_result = _fetch_cwe_from_nvd(cwe_id)
    
    return nvd_result


# =============================================================================
# NVD (National Vulnerability Database)
# =============================================================================

@lru_cache(maxsize=CACHE_MAX_SIZE)
def fetch_nvd_data(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch CVE details from NVD API v2.0.

    Returns:
        Dict with description, references, published date, CVSS details
        or None on failure
    """
    try:
        # Rate limiting — NVD throttles without API key
        time.sleep(NVD_RATE_LIMIT_DELAY)

        resp = requests.get(
            NVD_API_URL,
            params={"cveId": cve_id.upper()},
            timeout=15,
            headers={"Accept": "application/json"}
        )

        if resp.status_code == 403:
            print(f"[NVD] Rate limited for {cve_id}")
            return None

        if resp.status_code != 200:
            print(f"[NVD] HTTP {resp.status_code} for {cve_id}")
            return None

        data = resp.json()
        vulns = data.get("vulnerabilities", [])

        if not vulns:
            return None

        cve_data = vulns[0].get("cve", {})

        # Extract English description
        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        # Extract references (vendor advisories, patches)
        references = []
        for ref in cve_data.get("references", []):
            ref_entry = {
                "url": ref.get("url", ""),
                "source": ref.get("source", ""),
                "tags": ref.get("tags", [])
            }
            references.append(ref_entry)

        # Extract CVSS data
        cvss_data = _extract_nvd_cvss(cve_data)

        # Extract affected products (CPE)
        affected = _extract_affected_products(cve_data)

        return {
            "cve_id": cve_id.upper(),
            "description": description,
            "references": references,
            "published": cve_data.get("published", ""),
            "last_modified": cve_data.get("lastModified", ""),
            "cvss": cvss_data,
            "affected_products": affected,
            "patch_urls": [
                r["url"] for r in references
                if any(t in r.get("tags", [])
                       for t in ["Patch", "Vendor Advisory", "Mitigation"])
            ]
        }

    except requests.Timeout:
        print(f"[NVD] Timeout fetching {cve_id}")
        return None

    except Exception as e:
        print(f"[NVD] Error fetching {cve_id}: {e}")
        return None


def _extract_nvd_cvss(cve_data: Dict) -> Dict[str, Any]:
    """Extract CVSS v3.1 or v3.0 data from NVD response."""
    metrics = cve_data.get("metrics", {})

    # Try CVSS v3.1 first, then v3.0
    for version_key in ["cvssMetricV31", "cvssMetricV30"]:
        cvss_list = metrics.get(version_key, [])
        if cvss_list:
            cvss = cvss_list[0].get("cvssData", {})
            return {
                "version": cvss.get("version", "3.1"),
                "score": cvss.get("baseScore"),
                "severity": cvss.get("baseSeverity", "").upper(),
                "vector": cvss.get("vectorString", ""),
                "attack_vector": cvss.get("attackVector", ""),
                "attack_complexity": cvss.get("attackComplexity", ""),
                "privileges_required": cvss.get("privilegesRequired", ""),
                "user_interaction": cvss.get("userInteraction", ""),
                "impact_score": cvss_list[0].get("impactScore"),
                "exploitability_score": cvss_list[0].get("exploitabilityScore")
            }

    return {}


def _extract_affected_products(cve_data: Dict) -> List[str]:
    """Extract affected product names from CPE data."""
    products = []

    try:
        configurations = cve_data.get("configurations", [])
        for config in configurations:
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    criteria = match.get("criteria", "")
                    # CPE format: cpe:2.3:a:vendor:product:version:...
                    parts = criteria.split(":")
                    if len(parts) >= 5:
                        vendor = parts[3]
                        product = parts[4]
                        version = parts[5] if len(parts) > 5 else "*"
                        name = f"{vendor} {product}"
                        if version != "*":
                            name += f" {version}"
                        if name not in products:
                            products.append(name)
    except Exception:
        pass

    return products[:10]  # Limit to 10 products


# =============================================================================
# EPSS (Exploit Prediction Scoring System)
# =============================================================================

@lru_cache(maxsize=CACHE_MAX_SIZE)
def fetch_epss_score(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Fetch EPSS score from FIRST.org API.

    EPSS = probability that a vulnerability will be exploited
    in the wild within the next 30 days.

    0.0 = very unlikely to be exploited
    1.0 = almost certain to be exploited

    Returns:
        Dict with score, percentile, and human-readable explanation
        or None on failure
    """
    try:
        resp = requests.get(
            EPSS_API_URL,
            params={"cve": cve_id.upper()},
            timeout=10
        )

        if resp.status_code != 200:
            return None

        data = resp.json()
        entries = data.get("data", [])

        if not entries:
            return None

        entry = entries[0]
        score = float(entry.get("epss", 0))
        percentile = float(entry.get("percentile", 0))

        return {
            "score": score,
            "percentile": percentile,
            "percentage": round(score * 100, 1),
            "explanation": _epss_explanation(score),
            "urgency": _epss_urgency(score)
        }

    except Exception as e:
        print(f"[EPSS] Error fetching {cve_id}: {e}")
        return None


def _epss_explanation(score: float) -> str:
    """Human-readable EPSS explanation for SME users."""
    pct = round(score * 100, 1)

    if score >= 0.9:
        return f"{pct}% chance of exploitation — almost certain to be attacked"
    elif score >= 0.7:
        return f"{pct}% chance of exploitation — very likely to be attacked"
    elif score >= 0.5:
        return f"{pct}% chance of exploitation — likely to be attacked"
    elif score >= 0.3:
        return f"{pct}% chance of exploitation — moderate risk"
    elif score >= 0.1:
        return f"{pct}% chance of exploitation — low but real risk"
    else:
        return f"{pct}% chance of exploitation — unlikely but not impossible"


def _epss_urgency(score: float) -> str:
    """Map EPSS score to urgency level."""
    if score >= 0.7:
        return "critical"
    elif score >= 0.4:
        return "high"
    elif score >= 0.1:
        return "medium"
    else:
        return "low"


# =============================================================================
# UNIFIED ENRICHMENT FUNCTION
# =============================================================================

def enrich_cve(cve_id: str) -> Dict[str, Any]:
    """
    Enrich a CVE with all available threat intelligence.

    Combines: NVD + EPSS + KEV + CWE knowledge base.
    Each source is independent — failure in one doesn't affect others.

    Args:
        cve_id: CVE identifier (e.g., "CVE-2024-1234")

    Returns:
        Dict with all enrichment data
    """
    if not cve_id:
        return {"enriched": False, "reason": "No CVE ID provided"}

    cve_id = cve_id.upper().strip()
    print(f"[ENRICHER] Enriching {cve_id}...")

    result = {
        "cve_id": cve_id,
        "enriched": True,
        "enriched_at": datetime.utcnow().isoformat(),
        "nvd": None,
        "epss": None,
        "kev": {
            "is_known_exploited": False,
            "details": None
        },
        "threat_level": "unknown",
        "recommended_timeline": "30 days"
    }

    # ── KEV Check (fastest — local lookup) ────────────────────
    try:
        kev_match = is_in_kev(cve_id)
        result["kev"]["is_known_exploited"] = kev_match

        if kev_match:
            kev_details = get_kev_details(cve_id)
            if kev_details:
                result["kev"]["details"] = {
                    "vendor": kev_details.get("vendorProject", ""),
                    "product": kev_details.get("product", ""),
                    "date_added": kev_details.get("dateAdded", ""),
                    "due_date": kev_details.get("dueDate", ""),
                    "required_action": kev_details.get("requiredAction", ""),
                    "known_ransomware_use": kev_details.get(
                        "knownRansomwareCampaignUse", "Unknown"
                    )
                }
            print(f"[ENRICHER] ⚠️  {cve_id} IS in CISA KEV — actively exploited!")
    except Exception as e:
        print(f"[ENRICHER] KEV check failed: {e}")

    # ── EPSS Score (fast API call) ────────────────────────────
    try:
        epss_data = fetch_epss_score(cve_id)
        if epss_data:
            result["epss"] = epss_data
            print(f"[ENRICHER] EPSS: {epss_data['percentage']}% exploitation probability")
    except Exception as e:
        print(f"[ENRICHER] EPSS fetch failed: {e}")

    # ── NVD Details (slower API call) ─────────────────────────
    try:
        nvd_data = fetch_nvd_data(cve_id)
        if nvd_data:
            result["nvd"] = nvd_data
            print(f"[ENRICHER] NVD: {len(nvd_data.get('patch_urls', []))} patch URLs found")
    except Exception as e:
        print(f"[ENRICHER] NVD fetch failed: {e}")

    # ── Calculate Threat Level ────────────────────────────────
    result["threat_level"] = _calculate_threat_level(result)
    result["recommended_timeline"] = _calculate_timeline(result)

    print(f"[ENRICHER] {cve_id} → Threat: {result['threat_level']}, "
          f"Fix by: {result['recommended_timeline']}")

    return result


def enrich_vulnerability(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich a vulnerability document with all available intelligence.
    
    ENHANCED: Now includes detailed remediation.

    Works with or without CVE ID — falls back to CWE knowledge base.

    Args:
        vuln: Vulnerability dict from database

    Returns:
        Enrichment data dict
    """
    enrichment = {
        "cve_enrichment": None,
        "cwe_remediation": None,
        "priority_score": 0,
        "priority_label": "informational",
        "recommended_timeline": "90 days",
        "threat_indicators": [],
        "detailed_remediation": None  # NEW
    }

    # ── CVE Enrichment ────────────────────────────────────────
    cve_id = vuln.get("cve_id")
    if cve_id:
        cve_data = enrich_cve(cve_id)
        enrichment["cve_enrichment"] = cve_data

        if cve_data.get("kev", {}).get("is_known_exploited"):
            enrichment["threat_indicators"].append("CISA KEV — actively exploited")

        epss = cve_data.get("epss")
        if epss and epss.get("score", 0) >= 0.5:
            enrichment["threat_indicators"].append(
                f"EPSS {epss['percentage']}% — high exploitation probability"
            )

    # ── CWE Remediation ───────────────────────────────────────
    cwe_ids = vuln.get("cwe_id", [])
    if cwe_ids:
        cwe_data = get_cwe_remediation(cwe_ids)
        if cwe_data:
            enrichment["cwe_remediation"] = cwe_data

    # ── Priority Score ────────────────────────────────────────
    enrichment["priority_score"] = calculate_priority_score(
        vuln, enrichment["cve_enrichment"]
    )
    enrichment["priority_label"] = _score_to_label(
        enrichment["priority_score"]
    )
    enrichment["recommended_timeline"] = _score_to_timeline(
        enrichment["priority_score"]
    )

    # ── NEW: Detailed Remediation ─────────────────────────────
    enrichment["detailed_remediation"] = generate_detailed_remediation(
        vuln, enrichment
    )

    return enrichment


# =============================================================================
# PRIORITY SCORING
# =============================================================================

def calculate_priority_score(vuln: Dict[str, Any],
                              cve_enrichment: Optional[Dict] = None) -> int:
    """
    Calculate remediation priority score (0-100).

    Higher = fix sooner.

    Factors:
        - Base severity (0-35 points)
        - CVSS score (0-20 points)
        - EPSS score (0-25 points)
        - KEV status (0-15 points)
        - Exposure indicators (0-5 points)
    """
    score = 0

    # ── Base Severity (35 points max) ─────────────────────────
    severity_scores = {
        "critical": 35,
        "high": 25,
        "medium": 15,
        "low": 8,
        "info": 0
    }
    severity = vuln.get("severity", "info").lower()
    score += severity_scores.get(severity, 0)

    # ── CVSS Score (20 points max) ────────────────────────────
    cvss = vuln.get("cvss_score")
    if cvss:
        try:
            score += min(int(float(cvss) * 2), 20)
        except (ValueError, TypeError):
            pass

    # ── EPSS Score (25 points max) ────────────────────────────
    if cve_enrichment:
        epss = cve_enrichment.get("epss")
        if epss:
            epss_score = epss.get("score", 0)
            score += min(int(epss_score * 25), 25)

    # ── KEV Status (15 points) ────────────────────────────────
    if cve_enrichment:
        if cve_enrichment.get("kev", {}).get("is_known_exploited"):
            score += 15

    # ── Exposure Indicators (5 points max) ────────────────────
    tags = vuln.get("tags", [])
    if isinstance(tags, list):
        exposure_tags = {"internet-facing", "external", "exposed", "public"}
        if any(t.lower() in exposure_tags for t in tags if isinstance(t, str)):
            score += 5

    return min(score, 100)


def _calculate_threat_level(enrichment: Dict) -> str:
    """Determine overall threat level from enrichment data."""
    # KEV = automatic critical
    if enrichment.get("kev", {}).get("is_known_exploited"):
        return "critical"

    # High EPSS = high threat
    epss = enrichment.get("epss")
    if epss:
        if epss.get("score", 0) >= 0.7:
            return "critical"
        elif epss.get("score", 0) >= 0.4:
            return "high"

    # CVSS-based
    nvd = enrichment.get("nvd")
    if nvd and nvd.get("cvss"):
        cvss_score = nvd["cvss"].get("score", 0)
        if cvss_score >= 9.0:
            return "critical"
        elif cvss_score >= 7.0:
            return "high"
        elif cvss_score >= 4.0:
            return "medium"

    return "low"


def _calculate_timeline(enrichment: Dict) -> str:
    """Determine recommended fix timeline."""
    # KEV — CISA mandates remediation
    kev_details = enrichment.get("kev", {}).get("details")
    if kev_details and kev_details.get("due_date"):
        return f"By {kev_details['due_date']} (CISA mandate)"

    if enrichment.get("kev", {}).get("is_known_exploited"):
        return "48 hours"

    # EPSS-based
    epss = enrichment.get("epss")
    if epss:
        if epss.get("score", 0) >= 0.7:
            return "48 hours"
        elif epss.get("score", 0) >= 0.4:
            return "7 days"
        elif epss.get("score", 0) >= 0.1:
            return "14 days"

    return "30 days"


def _score_to_label(score: int) -> str:
    """Convert priority score to human-readable label."""
    if score >= 80:
        return "FIX IMMEDIATELY"
    elif score >= 60:
        return "FIX THIS WEEK"
    elif score >= 40:
        return "FIX THIS MONTH"
    elif score >= 20:
        return "FIX NEXT QUARTER"
    else:
        return "INFORMATIONAL"


def _score_to_timeline(score: int) -> str:
    """Convert priority score to recommended timeline."""
    if score >= 80:
        return "48 hours"
    elif score >= 60:
        return "7 days"
    elif score >= 40:
        return "30 days"
    elif score >= 20:
        return "90 days"
    else:
        return "As resources allow"


# =============================================================================
# BATCH ENRICHMENT
# =============================================================================

def enrich_vulnerabilities_batch(vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Enrich a list of vulnerabilities.
    Rate-limits NVD calls automatically.

    Args:
        vulns: List of vulnerability dicts

    Returns:
        List of dicts, each with vuln + enrichment data
    """
    results = []
    cve_count = sum(1 for v in vulns if v.get("cve_id"))

    print(f"[ENRICHER] Batch enriching {len(vulns)} vulns ({cve_count} with CVE IDs)")

    for i, vuln in enumerate(vulns):
        enrichment = enrich_vulnerability(vuln)

        results.append({
            "vulnerability": vuln,
            "enrichment": enrichment
        })

        # Progress feedback
        if (i + 1) % 10 == 0:
            print(f"[ENRICHER] Progress: {i + 1}/{len(vulns)}")

    # Sort by priority score (highest first)
    results.sort(
        key=lambda x: x["enrichment"]["priority_score"],
        reverse=True
    )

    print(f"[ENRICHER] Batch complete. "
          f"Top priority: {results[0]['enrichment']['priority_label']}"
          if results else "[ENRICHER] No results")

    return results


# =============================================================================
# INITIALIZATION
# =============================================================================

def initialize():
    """Pre-load KEV catalog and CWE knowledge base on startup."""
    print("[ENRICHER] Initializing...")
    _load_kev_catalog()
    _load_cwe_kb()
    print("[ENRICHER] Ready")


# =============================================================================
# DETAILED REMEDIATION GENERATION (NEW)
# =============================================================================

def _is_more_urgent(timeline1: str, timeline2: str) -> bool:
    """Compare two timeline strings to determine which is more urgent."""
    urgency_map = {
        "24 hours": 1,
        "48 hours": 2,
        "7 days": 7,
        "14 days": 14,
        "30 days": 30,
        "90 days": 90,
        "As resources allow": 365
    }
    
    days1 = urgency_map.get(timeline1, 30)
    days2 = urgency_map.get(timeline2, 30)
    
    return days1 < days2


def _get_template_specific_steps(template_id: str, vuln: Dict[str, Any]) -> List[Dict[str, str]]:
    """Generate specific remediation steps based on Nuclei template ID."""
    steps = []
    template_lower = template_id.lower()
    
    # SSL/TLS specific
    if "ssl" in template_lower or "tls" in template_lower:
        if "weak-cipher" in template_lower or "cipher" in template_lower:
            steps.append({
                "step": "Update SSL/TLS Configuration",
                "description": "Disable weak cipher suites. Use only TLS 1.2+ with strong ciphers (ECDHE-RSA-AES256-GCM-SHA384, ECDHE-RSA-AES128-GCM-SHA256)",
                "source": "template-analysis"
            })
            steps.append({
                "step": "Test Configuration",
                "description": "Use SSL Labs (ssllabs.com/ssltest) to verify cipher configuration",
                "source": "template-analysis"
            })
        
        if "certificate" in template_lower or "cert" in template_lower or "expired" in template_lower:
            steps.append({
                "step": "Renew SSL Certificate",
                "description": "Obtain and install a valid SSL certificate from a trusted Certificate Authority",
                "source": "template-analysis"
            })
    
    # Exposed panels/consoles
    if any(x in template_lower for x in ["exposed", "panel", "console", "admin", "dashboard"]):
        steps.append({
            "step": "Restrict Access",
            "description": "Move admin panel to internal network or VPN. If internet-facing is required, implement IP allowlist.",
            "source": "template-analysis"
        })
        steps.append({
            "step": "Enable Authentication",
            "description": "Ensure strong authentication is required. Implement multi-factor authentication (MFA).",
            "source": "template-analysis"
        })
    
    # Default credentials
    if "default" in template_lower and ("login" in template_lower or "cred" in template_lower or "password" in template_lower):
        steps.append({
            "step": "Change Default Credentials",
            "description": "Change all default usernames and passwords immediately. Use strong, unique passwords.",
            "source": "template-analysis"
        })
        steps.append({
            "step": "Audit All Accounts",
            "description": "Review all user accounts and remove unnecessary default accounts.",
            "source": "template-analysis"
        })
    
    # Information disclosure
    if "disclosure" in template_lower or "exposure" in template_lower or "leak" in template_lower:
        matched_at = vuln.get("matched_at", "")
        if matched_at:
            steps.append({
                "step": "Remove Exposed Endpoint",
                "description": f"Remove or restrict access to: {matched_at}",
                "source": "template-analysis"
            })
    
    # Misconfigurations
    if "misconfig" in template_lower:
        steps.append({
            "step": "Review Configuration",
            "description": "Review and harden configuration according to vendor security best practices and CIS benchmarks.",
            "source": "template-analysis"
        })
    
    # CVE-specific
    if "cve-" in template_lower:
        steps.append({
            "step": "Apply Security Patch",
            "description": "Install the vendor security patch for this CVE. Check patch URLs in the References section below.",
            "source": "template-analysis"
        })
        steps.append({
            "step": "Verify Patch",
            "description": "After patching, re-run the vulnerability scan to confirm remediation.",
            "source": "template-analysis"
        })
    
    # Directory listing
    if "directory" in template_lower and "listing" in template_lower:
        steps.append({
            "step": "Disable Directory Listing",
            "description": "Configure web server to disable directory indexes (Options -Indexes in Apache, autoindex off in Nginx).",
            "source": "template-analysis"
        })
    
    # Open redirect
    if "redirect" in template_lower and "open" in template_lower:
        steps.append({
            "step": "Validate Redirect URLs",
            "description": "Implement allowlist for permitted redirect destinations. Validate all URLs before redirecting.",
            "source": "template-analysis"
        })
    
    # CORS misconfiguration
    if "cors" in template_lower:
        steps.append({
            "step": "Fix CORS Policy",
            "description": "Set Access-Control-Allow-Origin to specific trusted domains. Never use '*' with credentials.",
            "source": "template-analysis"
        })
    
    return steps


def _build_verification_steps(vuln: Dict[str, Any], remediation: Dict[str, Any]) -> List[str]:
    """Build verification steps for the vulnerability."""
    steps = [
        "Re-run the Nuclei scan with the same template to verify the issue is resolved",
        "Verify the fix doesn't break application functionality",
        "Document the remediation in your change log"
    ]
    
    # Add specific verification based on vulnerability type
    template_id = vuln.get("template_id", "").lower()
    
    if "ssl" in template_id or "tls" in template_id:
        steps.insert(1, "Test SSL configuration with SSL Labs (https://www.ssllabs.com/ssltest/)")
    
    if "exposed" in template_id or "panel" in template_id:
        steps.insert(1, "Verify the endpoint is no longer accessible from unauthorized networks")
    
    if "default" in template_id and "cred" in template_id:
        steps.insert(1, "Test that default credentials no longer work")
    
    if "cve-" in template_id and remediation.get("cve_patches"):
        steps.insert(1, "Verify the software version number has been updated")
    
    if "directory" in template_id and "listing" in template_id:
        steps.insert(1, "Attempt to access the directory URL - should return 403 Forbidden")
    
    return steps


def _generate_remediation_summary(vuln: Dict[str, Any], remediation: Dict[str, Any]) -> str:
    """Generate a concise remediation summary."""
    severity = remediation["severity"].upper()
    priority = remediation["priority"]
    timeline = remediation["timeline"]
    vuln_name = vuln.get("name", "Unknown Vulnerability")
    
    summary_parts = [
        f"[{severity}] {vuln_name}"
    ]
    
    # Add KEV warning
    if remediation.get("kev_status", {}).get("actively_exploited"):
        summary_parts.append("⚠️ ACTIVELY EXPLOITED IN THE WILD (CISA KEV)")
    
    # Add EPSS warning
    epss = remediation.get("epss")
    if epss and epss.get("score", 0) >= 0.5:
        summary_parts.append(f"High exploitation probability ({epss['percentage']}%)")
    
    # Add CWE context
    if remediation.get("cwe_guidance"):
        cwe_name = remediation["cwe_guidance"]["name"]
        summary_parts.append(f"Vulnerability Type: {cwe_name}")
    
    # Add priority and timeline
    summary_parts.append(f"Priority: {priority} | Timeline: {timeline}")
    
    return " | ".join(summary_parts)


def generate_detailed_remediation(vuln: Dict[str, Any], enrichment: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Generate detailed, actionable remediation guidance.
    
    Combines:
      - CWE-specific remediation from knowledge base
      - CVE-specific patches from NVD
      - Template-based remediation from Nuclei
      - Priority and timeline from enrichment
    
    Args:
        vuln: Vulnerability dict from Nuclei scan
        enrichment: CVE enrichment data (optional)
    
    Returns:
        Detailed remediation dict with multiple sections
    """
    remediation = {
        "summary": "",
        "priority": "medium",
        "timeline": "30 days",
        "severity": vuln.get("severity", "info").lower(),
        "steps": [],
        "technical_details": {},
        "verification": [],
        "references": [],
        "cwe_guidance": None,
        "cve_patches": [],
        "business_impact": ""
    }
    
    # ── Extract base info ────────────────────────────────
    template_id = vuln.get("template_id", "")
    cve_id = vuln.get("cve_id")
    cwe_ids = vuln.get("cwe_id", [])
    
    # ── Priority from enrichment ─────────────────────────
    if enrichment:
        remediation["priority"] = enrichment.get("priority_label", "medium")
        remediation["timeline"] = enrichment.get("recommended_timeline", "30 days")
        
        # Threat indicators
        if enrichment.get("threat_indicators"):
            remediation["threat_indicators"] = enrichment["threat_indicators"]
    
    # ── CWE-Specific Guidance ────────────────────────────
    if cwe_ids:
        cwe_data = get_cwe_remediation(cwe_ids)
        if cwe_data:
            remediation["cwe_guidance"] = {
                "name": cwe_data["name"],
                "category": cwe_data["category"],
                "impact": cwe_data["impact"],
                "business_impact": cwe_data["business_impact"],
                "fix_steps": cwe_data["fix_steps"],
                "code_examples": cwe_data.get("code_examples", {}),
                "timeline": cwe_data.get("timeline", "30 days")
            }
            
            # Use CWE timeline if more urgent than enrichment timeline
            cwe_timeline = cwe_data.get("timeline", "30 days")
            if _is_more_urgent(cwe_timeline, remediation["timeline"]):
                remediation["timeline"] = cwe_timeline
            
            # Use CWE impact as business impact
            remediation["business_impact"] = cwe_data["business_impact"]
            
            # Add CWE references
            remediation["references"].extend(cwe_data.get("references", []))
    
    # ── CVE-Specific Patches ─────────────────────────────
    if enrichment and enrichment.get("cve_enrichment"):
        cve_enrich = enrichment["cve_enrichment"]
        
        nvd_data = cve_enrich.get("nvd")
        if nvd_data:
            # Extract patch URLs
            patch_urls = nvd_data.get("patch_urls", [])
            remediation["cve_patches"] = patch_urls
            
            # Add NVD description
            remediation["technical_details"]["nvd_description"] = nvd_data.get("description", "")
            
            # Add affected products
            affected = nvd_data.get("affected_products", [])
            if affected:
                remediation["technical_details"]["affected_products"] = affected
            
            # Add CVSS details
            cvss = nvd_data.get("cvss", {})
            if cvss:
                remediation["technical_details"]["cvss"] = {
                    "score": cvss.get("score"),
                    "severity": cvss.get("severity"),
                    "vector": cvss.get("vector"),
                    "attack_vector": cvss.get("attack_vector"),
                    "attack_complexity": cvss.get("attack_complexity")
                }
            
            # Add NVD references
            for ref in nvd_data.get("references", []):
                remediation["references"].append({
                    "url": ref.get("url", ""),
                    "source": ref.get("source", "NVD"),
                    "tags": ref.get("tags", [])
                })
        
        # KEV guidance
        kev = cve_enrich.get("kev", {})
        if kev.get("is_known_exploited"):
            kev_details = kev.get("details", {})
            remediation["kev_status"] = {
                "actively_exploited": True,
                "due_date": kev_details.get("due_date", ""),
                "required_action": kev_details.get("required_action", ""),
                "ransomware_use": kev_details.get("known_ransomware_use", "Unknown")
            }
            remediation["timeline"] = "48 hours"
            remediation["priority"] = "FIX IMMEDIATELY"
        
        # EPSS guidance
        epss = cve_enrich.get("epss")
        if epss:
            remediation["epss"] = {
                "score": epss.get("score"),
                "percentage": epss.get("percentage"),
                "explanation": epss.get("explanation"),
                "urgency": epss.get("urgency")
            }
    
    # ── Nuclei Template Remediation ──────────────────────
    nuclei_remediation = vuln.get("remediation", {})
    if nuclei_remediation and isinstance(nuclei_remediation, dict):
        template_remedy = nuclei_remediation.get("description", "")
        if template_remedy and template_remedy not in ["", "Plan remediation within 90 days as part of regular maintenance."]:
            remediation["steps"].insert(0, {
                "step": "Template-Specific Action",
                "description": template_remedy,
                "source": "nuclei-template"
            })
    
    # ── Build Fix Steps from CWE ─────────────────────────
    if remediation["cwe_guidance"]:
        for i, step in enumerate(remediation["cwe_guidance"]["fix_steps"], 1):
            remediation["steps"].append({
                "step": f"CWE Fix Step {i}",
                "description": step,
                "source": "cwe-knowledge-base"
            })
    
    # ── Add Template-Based Steps ─────────────────────────
    template_steps = _get_template_specific_steps(template_id, vuln)
    remediation["steps"].extend(template_steps)
    
    # ── Build Verification Steps ─────────────────────────
    remediation["verification"] = _build_verification_steps(vuln, remediation)
    
    # ── Generate Summary ─────────────────────────────────
    remediation["summary"] = _generate_remediation_summary(vuln, remediation)
    
    # ── Add template references ──────────────────────────
    template_refs = vuln.get("reference", [])
    if template_refs:
        for ref in template_refs:
            if isinstance(ref, str):
                remediation["references"].append({"url": ref, "source": "nuclei-template", "tags": []})
    
    return remediation


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("  CVE ENRICHER — Standalone Test")
    print("=" * 60)

    initialize()

    test_cve = input("\nEnter CVE ID (e.g., CVE-2021-44228): ").strip()
    if test_cve:
        result = enrich_cve(test_cve)

        print(f"\n{'='*60}")
        print(f"CVE: {result['cve_id']}")
        print(f"Threat Level: {result['threat_level']}")
        print(f"Fix Timeline: {result['recommended_timeline']}")

        if result.get("kev", {}).get("is_known_exploited"):
            print(f"⚠️  ACTIVELY EXPLOITED (CISA KEV)")
            kev = result["kev"]["details"]
            if kev:
                print(f"   Vendor: {kev.get('vendor', 'N/A')}")
                print(f"   Due Date: {kev.get('due_date', 'N/A')}")
                print(f"   Ransomware: {kev.get('known_ransomware_use', 'N/A')}")

        if result.get("epss"):
            epss = result["epss"]
            print(f"EPSS: {epss['explanation']}")

        if result.get("nvd"):
            nvd = result["nvd"]
            print(f"Description: {nvd['description'][:200]}...")
            print(f"Patch URLs: {len(nvd.get('patch_urls', []))}")
            for url in nvd.get("patch_urls", [])[:3]:
                print(f"   → {url}")

    # Test CWE lookup
    print(f"\n{'='*60}")
    test_cwe = input("Enter CWE ID (e.g., CWE-79): ").strip()
    if test_cwe:
        cwe_data = get_cwe_remediation(test_cwe)
        if cwe_data:
            print(f"CWE: {cwe_data['name']}")
            print(f"Impact: {cwe_data['impact']}")
            print(f"Fix Steps:")
            for step in cwe_data.get("fix_steps", []):
                print(f"   • {step}")
        else:
            print(f"No data found for {test_cwe}")