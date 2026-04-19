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
import re

from config import Config
from core.threat_researcher import ThreatResearcher # ◄ NEW
from utils.logger import logger


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
# SMART BRIEF & COMMUNITY INTELLIGENCE
# =============================================================================

class SmartBriefEngine:
    """
    Generates executive-level vulnerability intelligence
    """
    
    # Template ID → Plain English Business Risk Mapping
    SIMPLE_DESCRIPTIONS = {
        # AWS/Cloud Security
        "aws-object-listing": {
            "brief": "Your AWS S3 bucket is misconfigured to allow public enumeration of all stored files",
            "business_risk": "Attackers can map your internal data architecture and identify sensitive backups or credentials",
            "severity_context": "Direct precursor to large-scale exfiltration—matches profiles of major historical breaches",
            "action": "Enable 'Block Public Access' and audit bucket policies for Principal: '*'"
        },
        
        "exposed-s3-bucket": {
            "brief": "Cloud storage is publicly accessible, allowing unauthenticated data download",
            "business_risk": "Immediate exposure of confidential files, system backups, and customer PII",
            "severity_context": "Critical infrastructure failure—equivalent to leaving a server room unlocked",
            "action": "Disable public ACLs and enforce bucket-only IAM policies"
        },
        
        "exposed-env-file": {
            "brief": "Environment configuration file (.env) is publicly downloadable",
            "business_risk": "Exposes critical infrastructure secrets, including database passwords and API keys",
            "severity_context": "Immediate and total system compromise is probable",
            "action": "Move .env files outside of the web root and rotate all exposed credentials"
        },

        "exposed-git-config": {
            "brief": "Application source code repository (.git) is publicly accessible",
            "business_risk": "Reveals the full application 'blueprint', including hardcoded logic and secrets",
            "severity_context": "Provides attackers with a roadmap for identifying deep application vulnerabilities",
            "action": "Block access to /.git/ at the web server level and clean the production web root"
        },
        
        "http-directory-listing": {
            "brief": "Web server directory listing is enabled for sensitive paths",
            "business_risk": "Allows unauthenticated users to browse and download files directly from the server",
            "severity_context": "Discloses internal file structures and forgotten or backup files",
            "action": "Disable 'AutoIndex' or 'Directory Browsing' in web server settings"
        },
        
        "insecure-cors-policy": {
            "brief": "CORS policy is overly permissive (Wildcard * or arbitrary origins)",
            "business_risk": "Enables malicious websites to steal user session data or perform unauthorized API actions",
            "severity_context": "Bypasses browser-level security controls intended to protect user sessions",
            "action": "Replace wildcard origin with a strictly validated allowlist of trusted domains"
        },
        
        "aws-cloudtrail-disabled": {
            "brief": "AWS activity logging (CloudTrail) is disabled for this region or account",
            "business_risk": "Zero visibility into infrastructure changes or administrative compromises",
            "severity_context": "Severe compliance and forensic blindspot during incident response",
            "action": "Enable CloudTrail with multi-region logging and log file integrity validation"
        },
        
        # Web Application Vulnerabilities
        "xss-reflected": {
            "brief": "Your web application executes untrusted code in user browsers",
            "business_risk": "Attackers can steal user sessions, credentials, or redirect to phishing sites",
            "severity_context": "Primary vector for account takeover attacks",
            "action": "Sanitize all user input and implement Content Security Policy"
        },
        
        "sql-injection": {
            "brief": "Database queries accept malicious commands from user input",
            "business_risk": "Complete database compromise—read, modify, or delete all records",
            "severity_context": "Critical: Full data breach probable",
            "action": "Implement parameterized queries immediately"
        },
        
        "path-traversal": {
            "brief": "Application allows access to files outside intended directories",
            "business_risk": "Attackers can read sensitive configuration files, source code, or credentials",
            "severity_context": "Often leads to server takeover",
            "action": "Validate and sanitize file path inputs"
        },
        
        # Authentication & Access Control
        "default-login": {
            "brief": "System uses factory-default administrator credentials",
            "business_risk": "Instant unauthorized access with no hacking required",
            "severity_context": "Publicly documented—automated scanners will find this",
            "action": "Change to strong, unique passwords immediately"
        },
        
        "weak-jwt": {
            "brief": "API tokens use weak signing that can be forged",
            "business_risk": "Attackers can impersonate any user or service",
            "severity_context": "API security completely bypassed",
            "action": "Upgrade to RS256 with proper key rotation"
        },
        
        "missing-authentication": {
            "brief": "Critical API endpoints lack authentication requirements",
            "business_risk": "Unrestricted access to sensitive operations or data",
            "severity_context": "Immediate exploitation likely",
            "action": "Implement authentication middleware"
        },
        
        # Network & Infrastructure
        "exposed-docker": {
            "brief": "Container management interface is accessible from the internet",
            "business_risk": "Full server control—deploy malware, steal data, pivot to internal network",
            "severity_context": "Infrastructure-level compromise",
            "action": "Bind Docker socket to localhost only"
        },
        
        "ssh-weak-cipher": {
            "brief": "Remote access service uses outdated encryption",
            "business_risk": "Encrypted connections can be decrypted by motivated attackers",
            "severity_context": "Compliance failure and credential theft risk",
            "action": "Update SSH configuration to modern ciphers"
        },
        
        "ssl-tls-weak": {
            "brief": "Web server supports outdated encryption protocols",
            "business_risk": "Man-in-the-middle attacks can intercept sensitive data",
            "severity_context": "Affects all users connecting to this service",
            "action": "Disable TLS 1.0/1.1 and weak cipher suites"
        },
        
        # Information Disclosure
        "git-exposed": {
            "brief": "Source code repository is publicly accessible",
            "business_risk": "Attackers gain full application source code, credentials, and architecture knowledge",
            "severity_context": "Complete blueprint for targeted attacks",
            "action": "Remove .git directory from web root"
        },
        
        "env-file-exposed": {
            "brief": "Configuration file containing secrets is downloadable",
            "business_risk": "API keys, database passwords, and tokens exposed",
            "severity_context": "Immediate credential compromise",
            "action": "Move .env outside web root and rotate all exposed credentials"
        },
        
        "phpinfo-exposure": {
            "brief": "Server configuration diagnostics page is publicly accessible",
            "business_risk": "Reveals software versions, file paths, and security settings",
            "severity_context": "Attackers use this for targeted exploit selection",
            "action": "Remove or restrict access to phpinfo() pages"
        }
    }
    
    # Community Reference Library (High-Quality Sources)
    # Community Reference Library (Now fully dynamic search)
    COMMUNITY_REFERENCES = {}
    
    # Fallback descriptions by vulnerability type
    FALLBACK_PATTERNS = {
        "xss": {
            "brief": "Web application executes untrusted code in user browsers (Cross-Site Scripting)",
            "business_risk": "Session hijacking, credential theft, and brand impersonation",
            "action": "Implement strict input validation and context-aware output encoding"
        },
        "sqli": {
            "brief": "Database queries accept malicious commands from unauthenticated input",
            "business_risk": "Full database compromise—attacker can read, modify, or delete all records",
            "action": "Deploy parameterized queries (Prepared Statements) immediately"
        },
        "injection": {
            "brief": "System executes untrusted commands or logic via external input",
            "business_risk": "High potential for Remote Code Execution or full system takeover",
            "action": "Validate all external input against a strict allowlist"
        },
        "path-traversal": {
            "brief": "Application allows access to files outside of the intended web directory",
            "business_risk": "Exposure of sensitive system files, configuration data, and source code",
            "action": "Sanitize file path inputs and use restricted service accounts"
        },
        "exposure": {
            "brief": "Sensitive internal data or diagnostics is accessible from the internet",
            "business_risk": "Critical information leakage aiding targeted exploitation",
            "action": "Implement IP-based restrictions or strong authentication"
        },
        "misconfiguration": {
            "brief": "Security control or service is configured with non-standard, insecure defaults",
            "business_risk": "Significantly expanded attack surface for automated exploitation",
            "action": "Review against hardening guides (CIS / Vendor Best Practices)"
        }
    }
    
    @staticmethod
    def get_simple_description(vuln: Dict) -> Dict:
        """
        Generate executive-friendly vulnerability description
        
        Args:
            vuln: Vulnerability dictionary with template_id, name, description
            
        Returns:
            {
                'brief': 'Plain English summary',
                'business_risk': 'Impact in business terms',
                'severity_context': 'Why this severity matters',
                'action': 'What to do next',
                'confidence': 0.0-1.0
            }
        """
        template_id = vuln.get("template_id", "").lower()
        name = vuln.get("name", "").lower()
        
        # 1. Check for research-data provided descriptions (Zero-Noise injection)
        research = vuln.get("enrichment", {}).get("research_data", {})
        if research:
            technical = research.get("technical_details", {})
            return {
                "brief": research.get("brief", vuln.get("description", vuln.get("name", "Vulnerability"))),
                "business_risk": research.get("business_impact", "Analyzed vulnerability impact."),
                "severity_context": technical.get("remediation_priority", "Requires security review"),
                "action": research.get("remediation_steps", [{"title": "Remediate"}])[0].get("title", "Apply Fix") if isinstance(research.get("remediation_steps"), list) and research.get("remediation_steps") else "Review Technical Analysis",
                "confidence": 0.95,
                "source": "research"
            }

        # 2. Try exact template match 
        if template_id in SmartBriefEngine.SIMPLE_DESCRIPTIONS:
            result = SmartBriefEngine.SIMPLE_DESCRIPTIONS[template_id].copy()
            result["confidence"] = 1.0
            result["source"] = "curated"
            return result
        
        # 3. Try pattern matching
        for pattern, fallback in SmartBriefEngine.FALLBACK_PATTERNS.items():
            if pattern in template_id or pattern in name:
                result = fallback.copy()
                result["severity_context"] = "Requires security review"
                result["confidence"] = 0.7
                result["source"] = "pattern"
                return result
        
        # Ultimate fallback
        return {
            "brief": vuln.get("description", vuln.get("name", "Security vulnerability detected")),
            "business_risk": "Potential security weakness requiring investigation",
            "severity_context": f"{vuln.get('severity', 'Unknown').upper()} severity finding",
            "action": "Review technical details and apply vendor recommendations",
            "confidence": 0.3,
            "source": "raw"
        }
    
    @staticmethod
    def get_community_reference(vuln: Dict) -> Optional[Dict]:
        """
        Get curated community reference for vulnerability
        
        Returns:
            {
                'title': 'Article Title',
                'url': 'https://...',
                'source': 'Publisher',
                'type': 'Category',
                'trustworthiness': 'official|authoritative|high|medium'
            }
        """
        template_id = vuln.get("template_id", "").lower()
        
        # 1. Direct match in curated references
        if template_id in SmartBriefEngine.COMMUNITY_REFERENCES:
            return SmartBriefEngine.COMMUNITY_REFERENCES[template_id]
        
        # 2. Check for research-data provided references (Zero-Noise injection)
        research = vuln.get("enrichment", {}).get("research_data", {})
        research_refs = research.get("references", [])
        if research_refs:
            # Pick the first non-Google ref as the primary community reference
            for ref in research_refs:
                if "google.com" not in ref.get("url", ""):
                    return {
                        "title": f"Technical Analysis: {vuln.get('name', 'Vulnerability')}",
                        "url": ref["url"],
                        "source": ref.get("source", "Authoritative Source"),
                        "type": "Technical Deep-Dive",
                        "trustworthiness": "high"
                    }

        # 3. CVE-based fallback
        cve_id = vuln.get("cve_id")
        if cve_id:
            return {
                "title": f"Official CVE Details: {cve_id}",
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                "source": "NIST NVD",
                "type": "CVE Database",
                "trustworthiness": "official"
            }
        
        # 4. Optimized Google Dorking Fallback
        vuln_name = vuln.get("name", "Vulnerability")
        query = f'{vuln_name} (site:github.com OR site:exploit-db.com OR site:medium.com OR site:gitbook.io) (writeup OR POC OR technical analysis)'
        search_url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
        
        return {
            "title": f"Technical Research: {vuln_name}",
            "url": search_url,
            "source": "Search Engine",
            "type": "Dynamic Intelligence",
            "trustworthiness": "medium"
        }
    
    @staticmethod
    def get_remediation_reference(vuln: Dict) -> Optional[Dict]:
        """
        Get curated remediation and hardening guides.
        Prioritizes research-data links over Google Dorking.
        """
        vuln_name = vuln.get("name", "Vulnerability")
        
        # 1. Check for research-data provided remediation guides (Zero-Noise injection)
        research = vuln.get("enrichment", {}).get("research_data", {})
        research_refs = research.get("references", [])
        if research_refs:
            # Look specifically for docs/remediation keywords in research links
            for ref in research_refs:
                url = ref.get("url", "").lower()
                if any(x in url for x in ["docs.", "support.", "remediation", "hardening", "guide"]):
                    return {
                        "title": f"Official Fix Guide: {vuln_name}",
                        "url": ref["url"],
                        "source": ref.get("source", "Vendor Documentation"),
                        "type": "Remediation Guide",
                        "trustworthiness": "high"
                    }

        # 2. Optimized Google Dorking Fallback
        # Google Dork for official docs and hardening guides
        query = f'{vuln_name} (site:docs.microsoft.com OR site:aws.amazon.com OR site:cloud.google.com OR site:owasp.org OR site:cisecurity.org OR site:nist.gov OR site:kubernetes.io OR site:snyk.io OR site:cloudflare.com) remediation hardening guide fix'
        search_url = f"https://www.google.com/search?q={query.replace(' ', '+')}"
        
        return {
            "title": f"Remediation Guide: {vuln_name}",
            "url": search_url,
            "source": "Official Docs / Standards",
            "type": "Fix Intelligence",
            "trustworthiness": "high"
        }

    @staticmethod
    def _synthesize_intelligence_narrative(vuln: Dict) -> str:
        """
        Synthesize the 'Rule of Four' into a professional narrative.
        1. CISA KEV (Active Exploitation)
        2. EPSS (Exploitation Probability)
        3. CVSS (Severity)
        4. Affected System Type
        """
        enrichment = vuln.get("enrichment") or {}
        cve_id = vuln.get("cve_id")
        
        # 1. KEV Status
        kev_status = "No active exploitation reported in the wild"
        if enrichment.get("kev_status", {}).get("actively_exploited"):
            kev_status = "ACTIVELY EXPLOITED IN THE WILD per CISA KEV catalog"
            
        # 2. EPSS Probability
        epss_narrative = "Standard exploitation probability"
        epss = enrichment.get("epss")
        if epss:
            epss_narrative = f"High exploitation probability ({epss['percentage']}% score)"
            
        # 3. CVSS Severity
        cvss_score = vuln.get("cvss_score", 5.0)
        severity = vuln.get("severity", "medium").upper()
        cvss_narrative = f"Severity: {severity} ({cvss_score}/10.0)"
        
        # 4. Affected System Type
        system = "Target System Infrastructure"
        research = enrichment.get("research_data") or {}
        if research.get("technical_details", {}).get("attack_vector"):
            system = f"System Context: {research['technical_details']['attack_vector']}"
            
        return f"{cvss_narrative}. {kev_status}. {epss_narrative}. {system}."

    @staticmethod
    def generate_smart_brief(vuln: Dict) -> Dict:
        """
        Complete Smart Brief generation
        """
        from core.mitre_mapper import mitre_mapper
        
        brief = {
            "description": SmartBriefEngine.get_simple_description(vuln),
            "reference": SmartBriefEngine.get_community_reference(vuln),
            "remediation_reference": SmartBriefEngine.get_remediation_reference(vuln),
            "google_search_url": f"https://www.google.com/search?q={vuln.get('name', 'Vulnerability').replace(' ', '+')}+(site:github.com+OR+site:exploit-db.com+OR+site:medium.com+OR+site:gitbook.io)+technical+analysis+writeup+poc",
            "campaign_context": mitre_mapper.map_to_mitre(vuln),
            "executive_metrics": SmartBriefEngine.get_executive_metrics(vuln),
            "technical_narrative": SmartBriefEngine._synthesize_intelligence_narrative(vuln)
        }
        return brief

    @staticmethod
    def get_executive_metrics(vuln: Dict) -> Dict:
        """Calculate executive-level metrics (Priority, Deadline)"""
        # ── Unified Scoring Alignment ────────────────────────
        # Use the primary scoring engine to ensure consistency with the dashboard
        enrichment = vuln.get("enrichment")
        score = calculate_priority_score(vuln, enrichment)
        
        # Determine label and timeline
        if score >= 80:
            label = "FIX IMMEDIATELY" 
            deadline = "48 Hours"
            color = "danger"
        elif score >= 60:
            label = "FIX THIS WEEK"
            deadline = "7 Days"
            color = "warning"
        elif score >= 40:
            label = "FIX THIS MONTH"
            deadline = "30 Days"
            color = "info"
        else:
            label = "FIX NEXT QUARTER"
            deadline = "90 Days"
            color = "secondary"
            
        return {
            "score": score,
            "label": label,
            "deadline": deadline,
            "color": color
        }


# Singleton instance
smart_brief_engine = SmartBriefEngine()


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
            logger.info("[KEV] Downloading CISA KEV catalog...")
            resp = requests.get(KEV_URL, timeout=30)

            if resp.status_code == 200:
                # Ensure data directory exists
                os.makedirs(os.path.dirname(KEV_LOCAL_PATH), exist_ok=True)

                with open(KEV_LOCAL_PATH, "w", encoding="utf-8") as f:
                    f.write(resp.text)
                logger.info("[KEV] Catalog downloaded successfully")
            else:
                logger.warning("[KEV] Download failed: HTTP %s", resp.status_code)

        except Exception as e:
            logger.warning("[KEV] Download failed: %s", e)

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

            logger.info("[KEV] Loaded %d known exploited vulnerabilities", len(_kev_cache["data"]))
        else:
            logger.warning("[KEV] No local catalog available")

    except Exception as e:
        logger.error("[KEV] Error loading catalog: %s", e)


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
            logger.info("[CWE] Loaded %d CWE remediation entries", len(_cwe_cache["data"]))
        else:
            logger.warning("[CWE] Knowledge base not found at %s", CWE_KB_PATH)
            _cwe_cache["loaded"] = True  # Mark loaded to prevent retries

    except Exception as e:
        logger.error("[CWE] Error loading knowledge base: %s", e)
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
                
                logger.info("[CWE] Fetched %s from NVD API fallback", cwe_id)
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
        logger.warning("[CWE] NVD fallback failed for %s: %s", cwe_id, e)
        return None


# =============================================================================
# CWE → CATEGORY MAPPING (for inheritance fallback)
# =============================================================================
#
# Maps 500+ CWE IDs to the categories already used in the static DB.
# When a CWE isn't in the 110-entry static database, we look up its
# category here and return the remediation from the best-matching
# static entry in that same category.
#
# This gives real, actionable fix steps instead of "go read NVD".

CWE_CATEGORY_MAP = {
    # ── Injection (SQL, XSS, Command, Code, LDAP, XPath, etc.) ──
    "CWE-77": "injection", "CWE-78": "injection", "CWE-79": "injection",
    "CWE-80": "injection", "CWE-83": "injection", "CWE-87": "injection",
    "CWE-89": "injection", "CWE-90": "injection", "CWE-91": "injection",
    "CWE-93": "injection", "CWE-94": "injection", "CWE-95": "injection",
    "CWE-96": "injection", "CWE-97": "injection", "CWE-98": "injection",
    "CWE-99": "injection", "CWE-113": "injection", "CWE-116": "injection",
    "CWE-134": "injection", "CWE-138": "injection", "CWE-150": "injection",
    "CWE-158": "injection", "CWE-159": "injection", "CWE-166": "injection",
    "CWE-167": "injection", "CWE-168": "injection", "CWE-176": "injection",
    "CWE-184": "injection", "CWE-185": "injection", "CWE-470": "injection",
    "CWE-471": "injection", "CWE-564": "injection", "CWE-565": "injection",
    "CWE-624": "injection", "CWE-625": "injection", "CWE-641": "injection",
    "CWE-643": "injection", "CWE-644": "injection", "CWE-652": "injection",
    "CWE-917": "injection", "CWE-915": "injection", "CWE-1321": "injection",
    "CWE-74": "injection", "CWE-75": "injection", "CWE-76": "injection",

    # ── Authentication & Credentials ──
    "CWE-259": "authentication", "CWE-260": "authentication",
    "CWE-261": "authentication", "CWE-262": "authentication",
    "CWE-263": "authentication", "CWE-287": "authentication",
    "CWE-288": "authentication", "CWE-289": "authentication",
    "CWE-290": "authentication", "CWE-294": "authentication",
    "CWE-301": "authentication", "CWE-303": "authentication",
    "CWE-304": "authentication", "CWE-305": "authentication",
    "CWE-306": "authentication", "CWE-307": "authentication",
    "CWE-308": "authentication", "CWE-309": "authentication",
    "CWE-521": "authentication", "CWE-522": "authentication",
    "CWE-523": "authentication", "CWE-549": "authentication",
    "CWE-593": "authentication", "CWE-603": "authentication",
    "CWE-613": "authentication", "CWE-620": "authentication",
    "CWE-640": "authentication", "CWE-798": "authentication",
    "CWE-916": "authentication", "CWE-1391": "authentication",

    # ── Authorization & Access Control ──
    "CWE-22": "path", "CWE-23": "path", "CWE-24": "path",
    "CWE-25": "path", "CWE-26": "path", "CWE-27": "path",
    "CWE-28": "path", "CWE-29": "path", "CWE-30": "path",
    "CWE-31": "path", "CWE-32": "path", "CWE-33": "path",
    "CWE-34": "path", "CWE-35": "path", "CWE-36": "path",
    "CWE-37": "path", "CWE-38": "path", "CWE-39": "path",
    "CWE-40": "path", "CWE-41": "path",
    "CWE-250": "authorization", "CWE-266": "authorization",
    "CWE-267": "authorization", "CWE-269": "authorization",
    "CWE-270": "authorization", "CWE-271": "authorization",
    "CWE-272": "authorization", "CWE-273": "authorization",
    "CWE-274": "authorization", "CWE-276": "authorization",
    "CWE-277": "authorization", "CWE-278": "authorization",
    "CWE-279": "authorization", "CWE-280": "authorization",
    "CWE-281": "authorization", "CWE-282": "authorization",
    "CWE-283": "authorization", "CWE-284": "authorization",
    "CWE-285": "authorization", "CWE-286": "authorization",
    "CWE-639": "authorization", "CWE-732": "authorization",
    "CWE-862": "authorization", "CWE-863": "authorization",

    # ── Session Management ──
    "CWE-311": "session", "CWE-312": "session",
    "CWE-315": "session", "CWE-316": "session",
    "CWE-317": "session", "CWE-318": "session",
    "CWE-319": "session", "CWE-320": "session",
    "CWE-384": "session", "CWE-539": "session",
    "CWE-598": "session", "CWE-614": "session",
    "CWE-1004": "session",

    # ── Cryptography ──
    "CWE-310": "cryptography", "CWE-321": "cryptography",
    "CWE-322": "cryptography", "CWE-323": "cryptography",
    "CWE-324": "cryptography", "CWE-325": "cryptography",
    "CWE-326": "cryptography", "CWE-327": "cryptography",
    "CWE-328": "cryptography", "CWE-329": "cryptography",
    "CWE-330": "cryptography", "CWE-331": "cryptography",
    "CWE-332": "cryptography", "CWE-333": "cryptography",
    "CWE-334": "cryptography", "CWE-335": "cryptography",
    "CWE-336": "cryptography", "CWE-337": "cryptography",
    "CWE-338": "cryptography", "CWE-339": "cryptography",
    "CWE-340": "cryptography", "CWE-341": "cryptography",
    "CWE-347": "cryptography", "CWE-348": "cryptography",
    "CWE-349": "cryptography", "CWE-350": "cryptography",
    "CWE-757": "cryptography", "CWE-759": "cryptography",
    "CWE-760": "cryptography", "CWE-780": "cryptography",
    "CWE-916": "cryptography", "CWE-1240": "cryptography",

    # ── Information Disclosure ──
    "CWE-200": "information_disclosure", "CWE-201": "information_disclosure",
    "CWE-202": "information_disclosure", "CWE-203": "information_disclosure",
    "CWE-204": "information_disclosure", "CWE-205": "information_disclosure",
    "CWE-206": "information_disclosure", "CWE-207": "information_disclosure",
    "CWE-208": "information_disclosure", "CWE-209": "information_disclosure",
    "CWE-210": "information_disclosure", "CWE-211": "information_disclosure",
    "CWE-212": "information_disclosure", "CWE-213": "information_disclosure",
    "CWE-214": "information_disclosure", "CWE-215": "information_disclosure",
    "CWE-532": "information_disclosure", "CWE-538": "information_disclosure",
    "CWE-540": "information_disclosure", "CWE-541": "information_disclosure",
    "CWE-548": "information_disclosure", "CWE-550": "information_disclosure",
    "CWE-598": "information_disclosure", "CWE-615": "information_disclosure",

    # ── Input Validation ──
    "CWE-20": "validation", "CWE-100": "validation",
    "CWE-101": "validation", "CWE-102": "validation",
    "CWE-103": "validation", "CWE-104": "validation",
    "CWE-105": "validation", "CWE-106": "validation",
    "CWE-107": "validation", "CWE-108": "validation",
    "CWE-120": "validation", "CWE-129": "validation",
    "CWE-130": "validation", "CWE-131": "validation",
    "CWE-170": "validation", "CWE-179": "validation",
    "CWE-180": "validation", "CWE-181": "validation",
    "CWE-182": "validation", "CWE-183": "validation",
    "CWE-601": "validation", "CWE-602": "validation",

    # ── Configuration & Deployment ──
    "CWE-2": "configuration", "CWE-5": "configuration",
    "CWE-7": "configuration", "CWE-8": "configuration",
    "CWE-9": "configuration", "CWE-11": "configuration",
    "CWE-12": "configuration", "CWE-13": "configuration",
    "CWE-14": "configuration", "CWE-15": "configuration",
    "CWE-16": "configuration", "CWE-17": "configuration",
    "CWE-756": "configuration", "CWE-1188": "configuration",

    # ── Denial of Service ──
    "CWE-400": "denial_of_service", "CWE-404": "denial_of_service",
    "CWE-405": "denial_of_service", "CWE-406": "denial_of_service",
    "CWE-407": "denial_of_service", "CWE-408": "denial_of_service",
    "CWE-409": "denial_of_service", "CWE-410": "denial_of_service",
    "CWE-770": "denial_of_service", "CWE-771": "denial_of_service",
    "CWE-772": "denial_of_service", "CWE-773": "denial_of_service",
    "CWE-774": "denial_of_service", "CWE-775": "denial_of_service",
    "CWE-776": "denial_of_service", "CWE-779": "denial_of_service",
    "CWE-834": "denial_of_service", "CWE-835": "denial_of_service",

    # ── Secrets & API Keys ──
    "CWE-255": "secrets", "CWE-256": "secrets",
    "CWE-257": "secrets", "CWE-258": "secrets",
    "CWE-312": "secrets", "CWE-313": "secrets",
    "CWE-314": "secrets", "CWE-315": "secrets",
    "CWE-316": "secrets", "CWE-359": "secrets",
    "CWE-526": "secrets", "CWE-527": "secrets",
    "CWE-528": "secrets", "CWE-529": "secrets",
    "CWE-530": "secrets", "CWE-531": "secrets",
    "CWE-540": "secrets", "CWE-615": "secrets",

    # ── Memory Safety ──
    "CWE-119": "memory", "CWE-120": "memory",
    "CWE-121": "memory", "CWE-122": "memory",
    "CWE-123": "memory", "CWE-124": "memory",
    "CWE-125": "memory", "CWE-126": "memory",
    "CWE-127": "memory", "CWE-128": "memory",
    "CWE-129": "memory", "CWE-131": "memory",
    "CWE-415": "memory", "CWE-416": "memory",
    "CWE-476": "memory", "CWE-787": "memory",
    "CWE-788": "memory", "CWE-789": "memory",
    "CWE-805": "memory", "CWE-806": "memory",

    # ── Race Conditions ──
    "CWE-362": "race_condition", "CWE-363": "race_condition",
    "CWE-364": "race_condition", "CWE-366": "race_condition",
    "CWE-367": "race_condition", "CWE-368": "race_condition",
    "CWE-370": "race_condition", "CWE-421": "race_condition",
    "CWE-689": "race_condition",

    # ── File Upload ──
    "CWE-434": "upload", "CWE-436": "upload",
    "CWE-430": "upload", "CWE-431": "upload",
    "CWE-433": "upload", "CWE-435": "upload",

    # ── API Security ──
    "CWE-918": "api", "CWE-441": "api",
    "CWE-610": "api", "CWE-611": "api",
    "CWE-776": "api", "CWE-942": "api",

    # ── Supply Chain ──
    "CWE-426": "supply_chain", "CWE-427": "supply_chain",
    "CWE-494": "supply_chain", "CWE-502": "supply_chain",
    "CWE-506": "supply_chain", "CWE-507": "supply_chain",
    "CWE-508": "supply_chain", "CWE-509": "supply_chain",
    "CWE-510": "supply_chain", "CWE-511": "supply_chain",
    "CWE-512": "supply_chain", "CWE-514": "supply_chain",
    "CWE-515": "supply_chain", "CWE-829": "supply_chain",

    # ── Error Handling ──
    "CWE-209": "error_handling", "CWE-210": "error_handling",
    "CWE-211": "error_handling", "CWE-388": "error_handling",
    "CWE-390": "error_handling", "CWE-391": "error_handling",
    "CWE-392": "error_handling", "CWE-393": "error_handling",
    "CWE-394": "error_handling", "CWE-395": "error_handling",
    "CWE-396": "error_handling", "CWE-397": "error_handling",

    # ── Logic / Business Logic ──
    "CWE-696": "logic", "CWE-697": "logic",
    "CWE-698": "logic", "CWE-705": "logic",
    "CWE-706": "logic", "CWE-754": "logic",
    "CWE-755": "logic", "CWE-840": "logic",
    "CWE-841": "logic",
}


# =============================================================================
# CATEGORY INDEX (built once from static DB)
# =============================================================================

# =============================================================================
# CATEGORY-LEVEL REMEDIATION TEMPLATES
# =============================================================================
#
# Curated guidance for each vulnerability category. Unlike the old approach
# (which inherited XSS fix steps for prototype pollution because both are
# "injection"), these templates give advice that is CORRECT for every CWE
# in the category.
#
# Each template covers:
#   - Universal fix steps applicable to ALL CWEs in that category
#   - Category-level code examples that demonstrate the principle
#   - OWASP/NIST references for the category (not a specific CWE)
#   - Appropriate remediation timeline based on risk class

CATEGORY_REMEDIATION = {
    "injection": {
        "name": "Injection Vulnerability",
        "impact": (
            "Injection flaws allow attackers to send untrusted data to an "
            "interpreter as part of a command or query. This can lead to "
            "unauthorized data access, data corruption, or system compromise."
        ),
        "business_impact": (
            "Data breach, unauthorized system access, compliance violations "
            "(PCI-DSS, GDPR), and reputational damage."
        ),
        "fix_steps": [
            "Validate and sanitize ALL user-supplied input at the boundary",
            "Use parameterized queries / prepared statements for database operations",
            "Apply context-appropriate output encoding (HTML, URL, JS, SQL, LDAP)",
            "Implement allowlists for expected input patterns — never blocklists alone",
            "Use framework-provided escaping and templating features",
            "Deploy a Web Application Firewall (WAF) as a defense-in-depth layer",
            "Apply least-privilege principles to application database accounts"
        ],
        "code_examples": {
            "python_sql": "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
            "python_xss": "from markupsafe import escape\nuser_input = escape(request.args.get('q', ''))",
            "javascript": "element.textContent = userInput;  // never use innerHTML"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html",
            "https://owasp.org/Top10/A03_2021-Injection/"
        ],
        "timeline": "48 hours",
        "compliance": "PCI-DSS Req 6.5.1 | SOC2 CC6.6 | ISO 27001 A.14.2.1"
    },

    "authentication": {
        "name": "Authentication Weakness",
        "impact": (
            "Authentication flaws allow attackers to bypass identity verification, "
            "steal credentials, or impersonate legitimate users."
        ),
        "business_impact": (
            "Account takeover, unauthorized access to sensitive data, "
            "identity theft, and regulatory non-compliance."
        ),
        "fix_steps": [
            "Enforce strong password policies (minimum 12 characters, complexity rules)",
            "Implement multi-factor authentication (MFA) for all privileged operations",
            "Use secure password hashing (bcrypt, scrypt, or Argon2 — never MD5/SHA1)",
            "Implement account lockout after repeated failed login attempts",
            "Rotate credentials and API keys on a regular schedule",
            "Never store plaintext credentials — use secure credential vaults",
            "Log and monitor all authentication events for anomaly detection"
        ],
        "code_examples": {
            "python": "from bcrypt import hashpw, gensalt\nhashed = hashpw(password.encode(), gensalt(rounds=12))",
            "rate_limit": "# Use flask-limiter or similar\n@limiter.limit('5 per minute')\ndef login(): ..."
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html",
            "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        ],
        "timeline": "7 days",
        "compliance": "PCI-DSS Req 8.2 | SOC2 CC6.1 | ISO 27001 A.9.2.1"
    },

    "authorization": {
        "name": "Authorization / Access Control Flaw",
        "impact": (
            "Authorization flaws allow users to access data or perform actions "
            "beyond their intended permissions."
        ),
        "business_impact": (
            "Privilege escalation, unauthorized data access, data manipulation, "
            "and potential full system compromise."
        ),
        "fix_steps": [
            "Implement server-side access control checks on every request",
            "Apply the principle of least privilege — grant minimum required permissions",
            "Use role-based access control (RBAC) with clearly defined roles",
            "Validate object ownership before granting access (prevent IDOR)",
            "Deny access by default — require explicit grants",
            "Log and alert on authorization failures and privilege escalation attempts",
            "Perform access control testing as part of CI/CD pipeline"
        ],
        "code_examples": {
            "pattern": "# Always check ownership server-side\nif resource.owner_id != current_user.id:\n    abort(403)"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        ],
        "timeline": "7 days",
        "compliance": "PCI-DSS Req 7.1 | SOC2 CC6.3 | ISO 27001 A.9.1.2"
    },

    "path": {
        "name": "Path Traversal Vulnerability",
        "impact": (
            "Path traversal allows attackers to access files and directories "
            "outside the intended scope of the application."
        ),
        "business_impact": (
            "Unauthorized file access, source code disclosure, "
            "configuration file exposure, and potential remote code execution."
        ),
        "fix_steps": [
            "Validate all file paths against an allowlist of permitted directories",
            "Use path canonicalization (realpath) to resolve symlinks and '..' sequences",
            "Implement chroot or containerized file access boundaries",
            "Never directly concatenate user input into filesystem operations",
            "Strip directory traversal sequences (../, ..\\ , %2e%2e) from input",
            "Apply filesystem-level access controls as defense-in-depth"
        ],
        "code_examples": {
            "python": "import os\nbase = '/safe/uploads/'\npath = os.path.realpath(os.path.join(base, filename))\nif not path.startswith(base): raise ValueError('Path traversal blocked')"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html",
            "https://owasp.org/www-community/attacks/Path_Traversal"
        ],
        "timeline": "48 hours",
        "compliance": "PCI-DSS Req 6.5.1 | SOC2 CC6.6 | ISO 27001 A.14.2.5"
    },

    "session": {
        "name": "Session Management Weakness",
        "impact": (
            "Session flaws allow attackers to hijack user sessions, "
            "steal session tokens, or perform actions as another user."
        ),
        "business_impact": (
            "Session hijacking, account takeover, and unauthorized "
            "operations performed under a legitimate user's identity."
        ),
        "fix_steps": [
            "Set HTTPOnly and Secure flags on all session cookies",
            "Implement session expiration and idle timeout (max 30 min idle)",
            "Regenerate session IDs after authentication and privilege changes",
            "Use SameSite cookie attribute to prevent CSRF",
            "Transmit session tokens only over HTTPS (TLS)",
            "Invalidate sessions server-side on logout",
            "Implement session fixation protection"
        ],
        "code_examples": {
            "cookie_flags": "Set-Cookie: session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/",
            "python_flask": "app.config['SESSION_COOKIE_HTTPONLY'] = True\napp.config['SESSION_COOKIE_SECURE'] = True"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html"
        ],
        "timeline": "7 days",
        "compliance": "PCI-DSS Req 8.1.8 | SOC2 CC6.1 | ISO 27001 A.9.2.3"
    },

    "cryptography": {
        "name": "Cryptographic Weakness",
        "impact": (
            "Cryptographic flaws expose sensitive data through weak algorithms, "
            "improper key management, or insufficient encryption."
        ),
        "business_impact": (
            "Data exposure, inability to prove data integrity, "
            "compliance violations (PCI-DSS, HIPAA), and compromised confidentiality."
        ),
        "fix_steps": [
            "Use modern algorithms: AES-256-GCM for encryption, SHA-256+ for hashing",
            "Eliminate deprecated algorithms: MD5, SHA1, DES, RC4, 3DES",
            "Generate cryptographically secure random values (CSPRNG)",
            "Implement proper key management — rotate keys regularly",
            "Enforce TLS 1.2+ for all data in transit",
            "Store encryption keys separate from encrypted data",
            "Use authenticated encryption modes (GCM, CCM) to prevent tampering"
        ],
        "code_examples": {
            "python": "from cryptography.fernet import Fernet\nkey = Fernet.generate_key()\ncipher = Fernet(key)",
            "tls": "# nginx.conf\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers HIGH:!aNULL:!MD5;"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
            "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        ],
        "timeline": "14 days",
        "compliance": "PCI-DSS Req 4.1 | SOC2 CC6.1 | ISO 27001 A.10.1.1"
    },

    "information_disclosure": {
        "name": "Information Disclosure",
        "impact": (
            "Information disclosure reveals sensitive data to unauthorized actors — "
            "stack traces, internal paths, database details, or user data."
        ),
        "business_impact": (
            "Reconnaissance assistance for attackers, privacy violations, "
            "compliance failures, and potential data breach liability."
        ),
        "fix_steps": [
            "Disable verbose error messages and stack traces in production",
            "Remove server version headers (Server, X-Powered-By)",
            "Ensure debug mode is disabled in production deployments",
            "Implement custom error pages that reveal no internal details",
            "Remove or restrict access to development files (.env, .git, backups)",
            "Audit API responses to ensure no sensitive data leaks in payloads",
            "Apply data masking/redaction for logs and error reports"
        ],
        "code_examples": {
            "python_flask": "app.config['DEBUG'] = False",
            "nginx": "server_tokens off;\nproxy_hide_header X-Powered-By;"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        ],
        "timeline": "7 days",
        "compliance": "PCI-DSS Req 6.5.5 | SOC2 CC6.6 | ISO 27001 A.8.2.3"
    },

    "validation": {
        "name": "Input Validation Failure",
        "impact": (
            "Insufficient input validation allows malformed, oversized, or "
            "malicious data to reach application logic and backend systems."
        ),
        "business_impact": (
            "Application crashes, data corruption, injection attacks, "
            "and potential remote code execution."
        ),
        "fix_steps": [
            "Validate all input on the server side — never trust client-side validation alone",
            "Define strict schemas for expected input (type, length, range, format)",
            "Use allowlists over blocklists for acceptable patterns",
            "Reject input that doesn't match expected patterns — fail closed",
            "Validate content type, file extensions, and file headers for uploads",
            "Implement request size limits to prevent resource exhaustion"
        ],
        "code_examples": {
            "python": "import re\nif not re.match(r'^[a-zA-Z0-9_]{3,20}$', username):\n    raise ValueError('Invalid username format')"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html"
        ],
        "timeline": "7 days",
        "compliance": "PCI-DSS Req 6.5.1 | SOC2 CC6.6 | ISO 27001 A.14.2.1"
    },

    "configuration": {
        "name": "Security Misconfiguration",
        "impact": (
            "Misconfigured security controls, default credentials, "
            "or unnecessary features create exploitable attack surfaces."
        ),
        "business_impact": (
            "Unintended exposure of admin interfaces, default password exploits, "
            "and unnecessary service exposure increasing attack surface."
        ),
        "fix_steps": [
            "Change all default credentials immediately after deployment",
            "Disable unnecessary features, services, and endpoints",
            "Implement security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)",
            "Remove sample applications, documentation pages, and test accounts",
            "Automate security configuration checks in deployment pipeline",
            "Review and harden server configurations against CIS benchmarks"
        ],
        "code_examples": {
            "headers": "X-Content-Type-Options: nosniff\nX-Frame-Options: DENY\nStrict-Transport-Security: max-age=31536000; includeSubDomains"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        ],
        "timeline": "7 days",
        "compliance": "PCI-DSS Req 2.1 | SOC2 CC6.6 | ISO 27001 A.14.1.1"
    },

    "denial_of_service": {
        "name": "Denial of Service Vulnerability",
        "impact": (
            "DoS vulnerabilities allow attackers to exhaust system resources, "
            "causing service degradation or complete unavailability."
        ),
        "business_impact": (
            "Service outages, revenue loss, SLA violations, "
            "and customer trust erosion."
        ),
        "fix_steps": [
            "Implement rate limiting on all public endpoints",
            "Set request size limits and timeouts for all inputs",
            "Use connection pooling with configurable limits",
            "Implement circuit breakers for downstream service calls",
            "Deploy CDN/DDoS protection (Cloudflare, AWS Shield)",
            "Monitor resource usage and set up auto-scaling triggers",
            "Validate and limit XML/JSON parsing depth to prevent billion laughs attacks"
        ],
        "code_examples": {
            "rate_limit": "# nginx rate limiting\nlimit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;\nlimit_req zone=api burst=20;"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Denial_of_Service_Cheat_Sheet.html"
        ],
        "timeline": "14 days",
        "compliance": "PCI-DSS Req 6.5.X | SOC2 A1.2 | ISO 27001 A.12.1.3"
    },

    "secrets": {
        "name": "Secrets / Credential Exposure",
        "impact": (
            "Exposed secrets, API keys, or credentials give attackers "
            "direct access to protected systems and data."
        ),
        "business_impact": (
            "Unauthorized API access, cloud resource abuse, "
            "data exfiltration, and financial loss from compromised accounts."
        ),
        "fix_steps": [
            "Remove all hardcoded secrets from source code immediately",
            "Use environment variables or dedicated secret managers (Vault, AWS Secrets Manager)",
            "Add secret patterns to .gitignore and implement pre-commit hooks",
            "Rotate ALL compromised credentials — assume exposure was immediate",
            "Scan git history for accidentally committed secrets (git-secrets, truffleHog)",
            "Implement automated secret scanning in CI/CD pipeline"
        ],
        "code_examples": {
            "python": "import os\napi_key = os.getenv('API_KEY')  # never hardcode",
            "gitignore": "# .gitignore\n.env\n*.pem\n*_secret*"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"
        ],
        "timeline": "24 hours",
        "compliance": "PCI-DSS Req 8.2 | SOC2 CC6.1 | ISO 27001 A.9.3.1"
    },

    "memory": {
        "name": "Memory Safety Vulnerability",
        "impact": (
            "Memory safety flaws (buffer overflows, use-after-free, null dereferences) "
            "can cause crashes, code execution, or information leaks."
        ),
        "business_impact": (
            "Remote code execution, application crashes, data corruption, "
            "and potential full system compromise."
        ),
        "fix_steps": [
            "Use memory-safe languages or safe abstractions where possible",
            "Enable compiler protections: ASLR, DEP/NX, stack canaries, CFI",
            "Use AddressSanitizer (ASan) and Valgrind during testing",
            "Validate all buffer sizes and array indices before access",
            "Prefer smart pointers and RAII patterns over raw memory management",
            "Apply the latest security patches from upstream vendors"
        ],
        "code_examples": {
            "c_safe": "// Use bounded functions\nstrncpy(dest, src, sizeof(dest) - 1);\ndest[sizeof(dest) - 1] = '\\0';"
        },
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Buffer_Overflow"
        ],
        "timeline": "48 hours",
        "compliance": "PCI-DSS Req 6.5.2 | SOC2 CC6.6 | ISO 27001 A.14.2.1"
    },

    "race_condition": {
        "name": "Race Condition / Concurrency Flaw",
        "impact": (
            "Race conditions allow attackers to exploit timing windows between "
            "check and use operations, leading to unauthorized state changes."
        ),
        "business_impact": (
            "Financial fraud (double-spending), privilege escalation, "
            "data corruption, and inconsistent application state."
        ),
        "fix_steps": [
            "Use atomic operations or database transactions for state changes",
            "Implement proper locking (mutexes, file locks) for shared resources",
            "Apply TOCTOU (time-of-check-to-time-of-use) prevention patterns",
            "Use optimistic concurrency control with version checks",
            "Serialize critical operations that must not run in parallel",
            "Test with race condition detection tools (ThreadSanitizer)"
        ],
        "code_examples": {
            "python": "from threading import Lock\nlock = Lock()\nwith lock:\n    # critical section"
        },
        "references": [
            "https://owasp.org/www-community/vulnerabilities/Race_condition"
        ],
        "timeline": "7 days",
        "compliance": "PCI-DSS Req 6.5.10 | SOC2 CC6.6 | ISO 27001 A.14.2.1"
    },

    "upload": {
        "name": "Unrestricted File Upload",
        "impact": (
            "Unrestricted file upload allows attackers to upload malicious files "
            "(web shells, malware) that execute on the server."
        ),
        "business_impact": (
            "Remote code execution, server compromise, malware distribution, "
            "and data exfiltration."
        ),
        "fix_steps": [
            "Validate file extension AND content type (magic bytes/MIME sniffing)",
            "Store uploaded files outside the web root — never serve directly",
            "Randomize stored filenames — never use user-supplied names",
            "Set maximum file size limits",
            "Scan uploaded files with antivirus/anti-malware tools",
            "Serve user uploads from a separate domain/CDN (origin isolation)"
        ],
        "code_examples": {
            "python": "ALLOWED = {'.pdf', '.png', '.jpg'}\next = os.path.splitext(filename)[1].lower()\nif ext not in ALLOWED: raise ValueError('Invalid file type')"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html"
        ],
        "timeline": "48 hours",
        "compliance": "PCI-DSS Req 6.5.1 | SOC2 CC6.6 | ISO 27001 A.14.2.5"
    },

    "api": {
        "name": "API Security Vulnerability",
        "impact": (
            "API flaws allow attackers to abuse server-side request capabilities, "
            "access internal services, or exploit XML/JSON parsing weaknesses."
        ),
        "business_impact": (
            "Internal network scanning (SSRF), data exfiltration from internal services, "
            "and bypass of security perimeters."
        ),
        "fix_steps": [
            "Validate and sanitize all URLs before server-side requests",
            "Block requests to internal IP ranges (127.x, 10.x, 172.16.x, 192.168.x)",
            "Disable external entity processing in XML parsers (prevent XXE)",
            "Implement allowlists for permitted external request destinations",
            "Use CORS policies to restrict cross-origin access",
            "Apply rate limiting and input validation on all API endpoints"
        ],
        "code_examples": {
            "python_xxe": "from defusedxml import ElementTree\ntree = ElementTree.parse(xml_file)  # safe XML parsing",
            "ssrf_check": "import ipaddress\nip = ipaddress.ip_address(target)\nif ip.is_private: raise ValueError('SSRF blocked')"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
            "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"
        ],
        "timeline": "7 days",
        "compliance": "PCI-DSS Req 6.5.1 | SOC2 CC6.6 | ISO 27001 A.14.2.1"
    },

    "supply_chain": {
        "name": "Supply Chain / Dependency Vulnerability",
        "impact": (
            "Vulnerable or malicious dependencies introduce security risks "
            "that the application inherits without writing any vulnerable code."
        ),
        "business_impact": (
            "Inherited vulnerabilities in production, potential backdoors, "
            "and compliance risks from unvetted third-party code."
        ),
        "fix_steps": [
            "Maintain a Software Bill of Materials (SBOM) for all dependencies",
            "Run dependency scanners (Dependabot, Snyk, pip-audit) in CI/CD",
            "Pin dependency versions — never use floating ranges in production",
            "Verify package integrity via checksums and signature verification",
            "Monitor CVE feeds for vulnerabilities in your dependency tree",
            "Apply security patches within SLA (critical: 48h, high: 7d)"
        ],
        "code_examples": {
            "pip_audit": "pip-audit --requirement requirements.txt",
            "pin_versions": "# requirements.txt\nflask==3.0.0  # pinned, not flask>=3.0"
        },
        "references": [
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
        ],
        "timeline": "14 days",
        "compliance": "PCI-DSS Req 6.2 | SOC2 CC7.1 | ISO 27001 A.15.1.1"
    },

    "error_handling": {
        "name": "Improper Error Handling",
        "impact": (
            "Improper error handling exposes internal details (stack traces, "
            "database queries, file paths) or fails to handle errors safely."
        ),
        "business_impact": (
            "Information leakage aiding attackers, application instability, "
            "and potential for uncaught exceptions to bypass security controls."
        ),
        "fix_steps": [
            "Implement centralized error handling that catches ALL exceptions",
            "Return generic error messages to users — log details server-side only",
            "Disable debug/verbose error output in production",
            "Use structured logging for error details (ELK, Splunk)",
            "Implement graceful degradation — never crash silently",
            "Test error handling paths with fault injection"
        ],
        "code_examples": {
            "python_flask": "@app.errorhandler(Exception)\ndef handle_error(e):\n    logger.error(f'Unhandled: {e}', exc_info=True)\n    return jsonify({'error': 'Internal error'}), 500"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html"
        ],
        "timeline": "7 days",
        "compliance": "PCI-DSS Req 6.5.5 | SOC2 CC6.6 | ISO 27001 A.14.2.1"
    },

    "logic": {
        "name": "Business Logic Flaw",
        "impact": (
            "Logic flaws allow attackers to abuse legitimate application workflows "
            "in unintended ways — bypassing business rules or validation."
        ),
        "business_impact": (
            "Financial fraud, process bypass, data integrity violations, "
            "and exploitation of application-specific business rules."
        ),
        "fix_steps": [
            "Document and enforce all business rules in server-side code",
            "Validate the complete transaction flow — not just individual inputs",
            "Implement server-side state checks at every workflow step",
            "Add integrity checks for price, quantity, and financial calculations",
            "Test with abuse cases, not just happy-path scenarios",
            "Monitor for anomalous patterns (eg. unusual purchase sequences)"
        ],
        "code_examples": {
            "pattern": "# Always recalculate server-side\nserver_total = sum(item.price * item.qty for item in cart)\nif server_total != client_total: raise ValueError('Price mismatch')"
        },
        "references": [
            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/"
        ],
        "timeline": "14 days",
        "compliance": "PCI-DSS Req 6.5.1 | SOC2 CC6.6 | ISO 27001 A.14.2.1"
    },

    "protocol": {
        "name": "Protocol Security Weakness",
        "impact": (
            "Protocol-level weaknesses allow man-in-the-middle attacks, "
            "version downgrade attacks, or insecure data transmission."
        ),
        "business_impact": (
            "Data interception, credential theft in transit, "
            "and non-compliance with data protection regulations."
        ),
        "fix_steps": [
            "Enforce TLS 1.2+ — disable SSLv3, TLS 1.0, and TLS 1.1",
            "Use HSTS headers with long max-age and includeSubDomains",
            "Configure secure cipher suites — disable weak ciphers",
            "Enable certificate transparency and OCSP stapling",
            "Redirect all HTTP traffic to HTTPS",
            "Implement certificate pinning for mobile applications"
        ],
        "code_examples": {
            "nginx": "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\nadd_header Strict-Transport-Security 'max-age=31536000' always;"
        },
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html"
        ],
        "timeline": "7 days",
        "compliance": "PCI-DSS Req 4.1 | SOC2 CC6.1 | ISO 27001 A.10.1.1"
    },

    "privilege_escalation": {
        "name": "Privilege Escalation Vulnerability",
        "impact": (
            "Privilege escalation allows attackers to gain higher "
            "permissions than intended, potentially achieving admin access."
        ),
        "business_impact": (
            "Full system compromise, unauthorized administrative actions, "
            "and ability to modify security controls."
        ),
        "fix_steps": [
            "Apply least-privilege to all accounts, services, and processes",
            "Validate user roles/permissions on every privileged operation",
            "Separate admin and user interfaces on different endpoints",
            "Implement just-in-time privilege elevation with audit logging",
            "Review and remove unnecessary SUID/SGID binaries",
            "Monitor for unauthorized privilege changes in real-time"
        ],
        "code_examples": {
            "pattern": "# Decorator for admin-only routes\n@require_role('admin')\ndef admin_panel(): ..."
        },
        "references": [
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        ],
        "timeline": "48 hours",
        "compliance": "PCI-DSS Req 7.1 | SOC2 CC6.3 | ISO 27001 A.9.1.2"
    },
}


# =============================================================================
# CATEGORY INDEX (built once from static DB)
# =============================================================================

_category_index = {}  # category_name → [list of static DB entries]


def _build_category_index() -> None:
    """
    Build a reverse index: category → representative CWE entries.
    Called once after the static CWE KB is loaded.
    """
    global _category_index
    if _category_index:
        return  # Already built

    if not _cwe_cache["loaded"]:
        _load_cwe_kb()

    for cwe_id, entry in _cwe_cache["data"].items():
        cat = entry.get("category", "generic")
        if cat not in _category_index:
            _category_index[cat] = []
        _category_index[cat].append({
            "cwe_id": cwe_id,
            **entry
        })


def _get_category_fallback(
    cwe_id: str
) -> Optional[Dict[str, Any]]:
    """
    Find remediation via CWE category inheritance.

    Uses CURATED category-level templates (CATEGORY_REMEDIATION)
    instead of inheriting from a specific sibling CWE. This ensures
    the advice is correct for ALL CWEs in the category — not just
    the one we happened to pick.

    Example:
        CWE-1321 (Prototype Pollution) → category "injection"
        → Returns injection prevention guidance (sanitize input,
          use parameterized queries, apply output encoding)
        NOT XSS-specific advice (CSP headers, auto-escaping)
    """
    _build_category_index()

    # Step 1: Find category for this CWE
    category = CWE_CATEGORY_MAP.get(cwe_id)
    if not category:
        return None

    # Step 2: Use curated category template (preferred)
    cat_template = CATEGORY_REMEDIATION.get(category)
    if cat_template:
        result = dict(cat_template)
        result["name"] = f"{cwe_id} ({cat_template['name']})"
        result["category"] = category
        result["source"] = "category_inheritance"
        result["inherited_from"] = f"category:{category}"
        return result

    # Step 3: Fallback — pick best static DB entry if no template
    category_entries = _category_index.get(category, [])
    if not category_entries:
        return None

    best = max(
        category_entries,
        key=lambda e: (
            len(e.get("fix_steps", [])),
            len(e.get("code_examples", {})),
        )
    )

    result = {
        "name": f"{cwe_id} (Related: {best.get('name', category)})",
        "category": category,
        "impact": best.get("impact", f"Vulnerability in {category} category"),
        "business_impact": best.get("business_impact", ""),
        "fix_steps": best.get("fix_steps", []),
        "code_examples": best.get("code_examples", {}),
        "references": best.get("references", []),
        "timeline": best.get("timeline", "14 days"),
        "compliance": best.get("compliance", "SOC2 CC6 | ISO 27001 Annex A | PCI-DSS Req 6"),
        "source": "category_inheritance",
        "inherited_from": best.get("cwe_id", "unknown"),
    }

    return result


def get_cwe_remediation(cwe_id: str) -> Optional[Dict[str, Any]]:
    """
    Look up CWE remediation details using HYBRID approach.

    Strategy:
    1. Check static database (110+ top CWEs - FAST)
    2. Try category inheritance fallback (500+ mapped CWEs - FAST)
    3. If not found, fetch from NVD API as fallback (SLOWER, cached 24h)
    4. If NVD fails, return generic remediation template

    This ensures:
    - Fast response for common CWEs (static DB)
    - Actionable guidance for related CWEs (category inheritance)
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
    # STEP 2: Try category inheritance (500+ mapped CWEs)
    # =========================================================================
    category_result = _get_category_fallback(cwe_id)
    if category_result:
        logger.info(
            "[CWE] %s not in static DB - inherited remediation from %s (category: %s)",
            cwe_id,
            category_result.get("inherited_from"),
            category_result.get("category")
        )
        return category_result

    # =========================================================================
    # STEP 3: Try NVD API fallback (for unmapped CWEs)
    # =========================================================================
    logger.info("[CWE] %s not in static DB or category map, attempting NVD fallback...", cwe_id)
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
            logger.warning("[NVD] Rate limited for %s", cve_id)
            return None

        if resp.status_code != 200:
            logger.warning("[NVD] HTTP %s for %s", resp.status_code, cve_id)
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
        logger.warning("[NVD] Timeout fetching %s", cve_id)
        return None

    except Exception as e:
        logger.warning("[NVD] Error fetching %s: %s", cve_id, e)
        return None


def generate_research_hubs(vuln: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Generate automated technical research links for a vulnerability.
    Creates a 'Research Matrix' based on CVE ID or technical finding name.
    """
    hubs = []
    cve_id = vuln.get("cve_id")
    name = vuln.get("name", "Vulnerability")
    
    # ── CVE Specific Hubs ────────────────────────────────────
    if cve_id:
        hubs.extend([
            {
                "title": "CVE.org Record",
                "url": f"https://www.cve.org/CVERecord?id={cve_id}",
                "source": "CVE Program",
                "type": "official"
            },
            {
                "title": "GitHub Advisory Search",
                "url": f"https://github.com/advisories?query={cve_id}",
                "source": "GitHub Security",
                "type": "community"
            },
            {
                "title": "VulnCheck Intelligence",
                "url": f"https://vulncheck.com/cve/{cve_id}",
                "source": "VulnCheck",
                "type": "research"
            },
            {
                "title": "Packet Storm Exploit search",
                "url": f"https://packetstormsecurity.com/search/?q={cve_id}",
                "source": "Packet Storm",
                "type": "exploit"
            }
        ])
    
    # ── General Technical Hubs ───────────────────────────────
    # If it's a template finding without a CVE, or alongside a CVE
    query_name = name.replace(" ", "+")
    hubs.append({
        "title": "Verified Remediation Guide",
        "url": f"https://www.google.com/search?q=%22{query_name}%22+(site:docs.microsoft.com+OR+site:aws.amazon.com+OR+site:owasp.org+OR+site:kubernetes.io)+remediation+hardening+fix",
        "source": "Official Docs / Standards",
        "type": "Fix Intelligence"
    })
    
    return hubs


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
        logger.warning("[EPSS] Error fetching %s: %s", cve_id, e)
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
    logger.info("[ENRICHER] Enriching %s", cve_id)

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
            logger.warning("[ENRICHER] %s is in CISA KEV and actively exploited", cve_id)
    except Exception as e:
        logger.warning("[ENRICHER] KEV check failed for %s: %s", cve_id, e)

    # ── EPSS Score (fast API call) ────────────────────────────
    try:
        epss_data = fetch_epss_score(cve_id)
        if epss_data:
            result["epss"] = epss_data
            logger.info("[ENRICHER] EPSS for %s: %s%% exploitation probability", cve_id, epss_data["percentage"])
    except Exception as e:
        logger.warning("[ENRICHER] EPSS fetch failed for %s: %s", cve_id, e)

    # ── NVD Details (slower API call) ─────────────────────────
    try:
        nvd_data = fetch_nvd_data(cve_id)
        if nvd_data:
            result["nvd"] = nvd_data
            logger.info("[ENRICHER] NVD for %s: %d patch URLs found", cve_id, len(nvd_data.get("patch_urls", [])))
    except Exception as e:
        logger.warning("[ENRICHER] NVD fetch failed for %s: %s", cve_id, e)

    # ── Calculate Threat Level ────────────────────────────────
    result["threat_level"] = _calculate_threat_level(result)
    result["recommended_timeline"] = _calculate_timeline(result)

    logger.info(
        "[ENRICHER] %s -> Threat: %s, Fix by: %s",
        cve_id,
        result["threat_level"],
        result["recommended_timeline"]
    )

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
        "detailed_remediation": None,
        "research_data": None,
        "research_hubs": [] # ◄ NEW
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

    # ── Business Impact (Smart Description) ───────────────────
    lightweight = lightweight_enrich_vuln(vuln)
    enrichment["business_impact"] = lightweight.get("impact")

    # ── Deep Threat Research (Template KB) ─────────────────────
    try:
        research = ThreatResearcher.research(vuln)
        if research:
            enrichment["research_data"] = research
            # Override business_impact with richer version if available
            if research.get("business_impact"):
                enrichment["business_impact"] = research["business_impact"]
            # Populate top-level fields the template expects
            if research.get("references"):
                enrichment["references"] = research["references"]
            if research.get("remediation_steps"):
                enrichment["remediation_steps"] = research["remediation_steps"]
            if research.get("mitre_attack"):
                enrichment["mitre_attack"] = research["mitre_attack"]
            if research.get("cwe_guidance"):
                enrichment["cwe_guidance"] = research["cwe_guidance"]
            if research.get("technical_details"):
                enrichment["technical_details"] = research["technical_details"]
            if research.get("threat_indicators"):
                enrichment["threat_indicators"].extend(
                    research["threat_indicators"]
                )
    except Exception as e:
        logger.warning("[ENRICHER] ThreatResearcher failed: %s", e)

    # ── Propagate KEV/EPSS from CVE enrichment to top level ─────
    cve = enrichment.get("cve_enrichment") or {}
    if cve.get("kev", {}).get("is_known_exploited"):
        enrichment["kev_status"] = {"actively_exploited": True}
    else:
        enrichment["kev_status"] = {"actively_exploited": False}
        
    epss = cve.get("epss")
    if epss:
        enrichment["epss"] = epss

    remediation = generate_detailed_remediation(vuln, enrichment)
    if not remediation.get("business_impact") and enrichment.get("business_impact"):
        remediation["business_impact"] = enrichment["business_impact"]

    enrichment["detailed_remediation"] = remediation
    enrichment["business_impact"] = (
        remediation.get("business_impact")
        or enrichment.get("business_impact")
    )
    enrichment["references"] = remediation.get(
        "references",
        enrichment.get("references", [])
    )
    enrichment["technical_details"] = remediation.get(
        "technical_details",
        enrichment.get("technical_details", {})
    )
    enrichment["cwe_guidance"] = remediation.get(
        "cwe_guidance",
        enrichment.get("cwe_guidance")
    )
    enrichment["kev_status"] = remediation.get(
        "kev_status",
        enrichment.get("kev_status", {"actively_exploited": False})
    )
    if remediation.get("epss"):
        enrichment["epss"] = remediation["epss"]
    enrichment["remediation_steps"] = [
        step.get("description", "")
        for step in remediation.get("steps", [])
        if isinstance(step, dict) and step.get("description")
    ]

    return enrichment


def lightweight_enrich_vuln(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    High-performance enrichment for vulnerability lists (Brief View).
    """
    # ── 0. Check Cache First (Alignment Fix) ───────────────
    cache = vuln.get("enrichment_cache")
    if cache:
        return {
            "impact": cache.get("business_impact", "Analyzed vulnerability."),
            "timeline": cache.get("recommended_timeline", "7 days"),
            "priority_label": cache.get("priority_label", "HIGH"),
            "is_kev": cache.get("kev_status", {}).get("actively_exploited", False),
            "score": cache.get("priority_score", 0)
        }

    template_id = vuln.get("template_id", "").lower()
    severity = vuln.get("severity", "info").lower()
    cve_id = vuln.get("cve_id")
    
    # ── 1. Smart Timeline Calculation ─────────────────────
    # Standard logic: Priority-based
    score = calculate_priority_score(vuln) # Fast version (no NVD)
    timeline = _score_to_timeline(score)
    priority_label = _score_to_label(score)
    
    # ── 2. Synthesized Business Impact ────────────────────
    impact = "A vulnerability has been identified that may affect system confidentiality, integrity, or availability."
    
    # Rule-based overrides (very fast)
    if "aws-object-listing" in template_id:
        impact = "Publicly accessible cloud storage. Enables unauthorized third parties to list and discover all files in the bucket."
        score = 20 # LOW
        timeline = "90 days"
        priority_label = "FIX NEXT QUARTER"
    elif "sqli" in template_id or "sql-injection" in template_id:
        impact = "Database vulnerability detected. Allows unauthorized actors to query, modify, or delete sensitive backend data."
        score = 70 # HIGH
        timeline = "7 days"
        priority_label = "FIX THIS WEEK"
    elif "xss" in template_id or "cross-site-scripting" in template_id:
        impact = "Client-side execution risk. Enables attackers to hijack user sessions or steal sensitive cookies via malicious scripts."
        score = 40 # MEDIUM / STANDARD
        timeline = "30 days"
        priority_label = "FIX THIS MONTH"
    elif "ssrf" in template_id:
        impact = "Server-Side Request Forgery. Allows attackers to use your server as a proxy to scan internal networks or access metadata services."
        score = 70 # HIGH
        timeline = "7 days"
        priority_label = "FIX THIS WEEK"
    elif "takeover" in template_id:
        impact = "Subdomain takeover identified. Attackers can gain full control over this domain to host phishing sites or intercept traffic."
        score = 90 # CRITICAL
        timeline = "48 hours"
        priority_label = "FIX IMMEDIATELY"
    elif "lfi" in template_id or "local-file-inclusion" in template_id:
        impact = "Input validation failure. Allows unauthorized reading of sensitive system files (e.g., /etc/passwd) from the server."
        score = 70 # HIGH
        timeline = "7 days"
        priority_label = "FIX THIS WEEK"
    elif "exposed" in template_id or "panel" in template_id:
        impact = "Internal administrative interface exposed to the public internet. High risk of unauthorized access or brute-force."
        score = 40 # MEDIUM
        timeline = "30 days"
        priority_label = "FIX THIS MONTH"
    elif "default-login" in template_id or "default-cred" in template_id:
        impact = "System is accessible via default factory credentials. Critical risk of immediate compromise."
        score = 90 # CRITICAL
        timeline = "48 hours"
        priority_label = "FIX IMMEDIATELY"
    elif cve_id:
        impact = f"Known CVE-based vulnerability ({cve_id}). Review technical analysis for specific system impact."
    
    return {
        "impact": impact,
        "timeline": timeline,
        "priority_label": priority_label,
        "is_kev": False, # Would need KEV cache lookup for full accuracy
        "score": score
    }


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

    # ── Base Severity (35 points baseline) ─────────────────────────
    # Standardized to 0-100 magnitude across AEGIS
    severity_scores = {
        "critical": 90,
        "high": 70,
        "medium": 40,
        "low": 20,
        "info": 5
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
        return "LOW INTEREST"


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
# INITIALIZATION
# =============================================================================

def initialize():
    """Pre-load KEV catalog and CWE knowledge base on startup."""
    logger.info("[ENRICHER] Initializing...")
    _load_kev_catalog()
    _load_cwe_kb()
    logger.info("[ENRICHER] Ready")


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


def get_simple_description(vuln: Dict[str, Any]) -> str:
    """Generate a hard-hitting 1-sentence description in plain English."""
    # Logic moved to SmartBriefEngine
    return smart_brief_engine.get_simple_description(vuln).get("brief")


def get_community_reference(vuln: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Find a high-quality external research link for this finding."""
    # Logic moved to SmartBriefEngine
    return smart_brief_engine.get_community_reference(vuln)


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
        summary_parts.append("ACTIVELY EXPLOITED IN THE WILD (CISA KEV)")
    
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
        "business_impact": "",
        "smart_brief": smart_brief_engine.generate_smart_brief(vuln)
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
                "name": cwe_data.get("name", "Unknown CWE"),
                "category": cwe_data.get("category", "Unknown Category"),
                "impact": cwe_data.get("impact", "Potential security impact"),
                "business_impact": cwe_data.get("business_impact", "Review details for business risk"),
                "fix_steps": cwe_data.get("fix_steps", []),
                "code_examples": cwe_data.get("code_examples", {}),
                "timeline": cwe_data.get("timeline", "30 days"),
                "compliance": cwe_data.get("compliance", "N/A")
            }
            
            # Use CWE timeline if more urgent than enrichment timeline
            cwe_timeline = cwe_data.get("timeline", "30 days")
            if _is_more_urgent(cwe_timeline, remediation["timeline"]):
                remediation["timeline"] = cwe_timeline
            
            # Use CWE impact as business impact
            remediation["business_impact"] = cwe_data.get("business_impact", "")
            
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
            print(f"ACTIVELY EXPLOITED (CISA KEV)")
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


