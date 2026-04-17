"""
Remediation Engine — The Brain

Combines all intelligence sources into actionable remediation plans.
Designed for SME users who need clear "what to fix and how" guidance.

Data flow:
    Vulnerability (from DB)
        → CVE enrichment (NVD + EPSS + KEV)
        → CWE knowledge base (fix steps + code examples)
        → Nuclei template remediation (already stored)
        → Priority scoring
        → Combined remediation plan

This is what routes/remediation.py calls.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional

from database.vulns_db import get_vulns_by_target, update_vuln_status
from utils.logger import logger
from core.cve_enricher import (
    enrich_vulnerability,
    is_in_kev,
    initialize as init_enricher
)


# =============================================================================
# MAIN FUNCTION — Called by routes/remediation.py
# =============================================================================

def get_remediation_plan(target_id: str,
                         target_domain: str = "") -> Dict[str, Any]:
    """
    Generate a complete remediation plan for a target.

    This is the main entry point. It:
        1. Gets all open vulns from DB
        2. Enriches each with threat intelligence
        3. Combines all remediation sources
        4. Sorts by priority
        5. Returns a structured plan

    Args:
        target_id: MongoDB target document ID
        target_domain: Domain name (for display)

    Returns:
        Dict with summary, priority_breakdown, and remediation_items
    """
    logger.info(f"Generating remediation plan for {target_domain or target_id}")

    # Ensure enrichment data sources are loaded
    try:
        init_enricher()
    except Exception as e:
        logger.warning(f"Enricher init warning: {e}")

    # Get all open vulnerabilities
    vulns = get_vulns_by_target(target_id, status="open")

    if not vulns:
        logger.info("No open vulnerabilities found")
        return {
            "success": True,
            "target_id": target_id,
            "target_domain": target_domain,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_vulns": 0,
                "total_with_cve": 0,
                "kev_count": 0,
                "message": "No open vulnerabilities. Your attack surface looks clean!"
            },
            "priority_breakdown": {
                "fix_immediately": 0,
                "fix_this_week": 0,
                "fix_this_month": 0,
                "fix_next_quarter": 0,
                "informational": 0
            },
            "remediation_items": []
        }

    # Build remediation items
    remediation_items = []
    kev_count = 0
    cve_count = 0

    priority_counts = {
        "fix_immediately": 0,
        "fix_this_week": 0,
        "fix_this_month": 0,
        "fix_next_quarter": 0,
        "informational": 0
    }

    for vuln in vulns:
        item = _build_remediation_item(vuln)
        remediation_items.append(item)

        # Count stats
        if item.get("has_cve"):
            cve_count += 1
        if item.get("is_kev"):
            kev_count += 1

        # Count priority buckets
        label = item.get("priority_label", "informational")
        label_key = label.lower().replace(" ", "_")
        if label_key in priority_counts:
            priority_counts[label_key] += 1

    # Sort by priority score (highest = most urgent = first)
    remediation_items.sort(
        key=lambda x: x.get("priority_score", 0),
        reverse=True
    )

    # Add rank numbers
    for i, item in enumerate(remediation_items):
        item["rank"] = i + 1

    # Build summary
    summary = {
        "total_vulns": len(vulns),
        "total_with_cve": cve_count,
        "kev_count": kev_count,
        "highest_priority": (
            remediation_items[0]["priority_label"]
            if remediation_items else "none"
        ),
        "highest_priority_vuln": (
            remediation_items[0]["name"]
            if remediation_items else "none"
        ),
        "message": _generate_summary_message(
            len(vulns), kev_count, priority_counts
        )
    }

    logger.info(f"Plan generated: {len(remediation_items)} items (KEV: {kev_count}, CVE: {cve_count})")
    logger.info(f"Priority breakdown: {priority_counts}")

    return {
        "success": True,
        "target_id": target_id,
        "target_domain": target_domain,
        "generated_at": datetime.utcnow().isoformat(),
        "summary": summary,
        "priority_breakdown": priority_counts,
        "remediation_items": remediation_items
    }


def _calculate_fix_by_date(priority_score, is_kev=False, kev_info=None):
    """Calculate the recommended fix date based on priority score and KEV status."""
    from datetime import datetime, timedelta
    
    now = datetime.utcnow()
    
    # Priority based timelines
    if is_kev or priority_score >= 80:
        days = 2
        label = "48 Hours"
    elif priority_score >= 60:
        days = 7
        label = "7 Days"
    elif priority_score >= 40:
        days = 30
        label = "30 Days"
    else:
        days = 90
        label = "90 Days"
        
    target_date = now + timedelta(days=days)
    return target_date.strftime("%b %d, %Y")


# =============================================================================
# BUILD INDIVIDUAL REMEDIATION ITEM
# =============================================================================

def _build_remediation_item(vuln: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a complete remediation item for a single vulnerability.

    Combines:
        - Vulnerability data from DB
        - CVE enrichment (NVD + EPSS + KEV)
        - CWE knowledge base
        - Nuclei template remediation (already in vuln)
        - Auto-generated fallback
    """
    cve_id = vuln.get("cve_id")
    cwe_ids = vuln.get("cwe_id", [])
    severity = vuln.get("severity", "info").lower()

    # ── Enrich with threat intelligence ───────────────────────
    enrichment = enrich_vulnerability(vuln)

    cve_enrichment = enrichment.get("cve_enrichment")
    remediation = _canonicalize_remediation(
        enrichment.get("detailed_remediation") or {}
    )

    # ── KEV details ───────────────────────────────────────────
    is_kev = False
    kev_info = None
    if cve_enrichment:
        kev_data = cve_enrichment.get("kev", {})
        is_kev = kev_data.get("is_known_exploited", False)
        if is_kev:
            kev_info = kev_data.get("details")

    # ── EPSS details ──────────────────────────────────────────
    epss_info = None
    if cve_enrichment:
        epss_info = cve_enrichment.get("epss")

    # ── NVD details ───────────────────────────────────────────
    nvd_description = ""
    patch_urls = []
    affected_products = []
    if cve_enrichment and cve_enrichment.get("nvd"):
        nvd = cve_enrichment["nvd"]
        nvd_description = nvd.get("description", "")
        patch_urls = nvd.get("patch_urls", [])
        affected_products = nvd.get("affected_products", [])

    # ── Timeline calculation ──────────────────────────────────
    fix_by_date = _calculate_fix_by_date(
        enrichment["priority_score"], is_kev, kev_info
    )

    # ── Build final item ──────────────────────────────────────
    return {
        # Identity
        "vuln_id": vuln.get("_id", vuln.get("vuln_id", "")),
        "name": vuln.get("name", "Unknown Vulnerability"),
        "template_id": vuln.get("template_id", ""),
        "severity": severity,
        "host": vuln.get("host", ""),
        "url": vuln.get("url", ""),
        "matched_at": vuln.get("matched_at", ""),

        # CVE info
        "has_cve": bool(cve_id),
        "cve_id": cve_id,
        "cvss_score": vuln.get("cvss_score"),
        "nvd_description": nvd_description,
        "affected_products": affected_products,

        # Threat intelligence
        "is_kev": is_kev,
        "kev_info": kev_info,
        "epss": epss_info,

        # Priority
        "priority_score": enrichment["priority_score"],
        "priority_label": enrichment["priority_label"],
        "threat_indicators": enrichment.get("threat_indicators", []),

        # Remediation (the actual fix guidance)
        "remediation": remediation,

        # Timeline
        "recommended_timeline": remediation.get(
            "timeline", enrichment["recommended_timeline"]
        ),
        "fix_by_date": fix_by_date,

        # Intelligence Matrix
        "intelligence_links": _consolidate_links(patch_urls, enrichment.get("research_hubs", []), enrichment.get("references", [])),
        
        # Primary reference (Restored as requested)
        "primary_reference": (enrichment.get("references", [])[0] if enrichment.get("references") else ({"url": patch_urls[0], "source": "NVD"} if patch_urls else None)),

        # Dynamic Research Search (Restored as requested)
        "google_search_url": enrichment.get("smart_brief", {}).get("google_search_url") or f"https://www.google.com/search?q={vuln.get('name', 'Vulnerability').replace(' ', '+')}+(site:github.com+OR+site:exploit-db.com+OR+site:medium.com+OR+site:gitbook.io)+technical+analysis+writeup+poc",
        
        # Official Fix Guide (NEW)
        "remediation_reference": enrichment.get("smart_brief", {}).get("remediation_reference")
    }


def _consolidate_links(patches, hubs, refs) -> List[Dict[str, str]]:
    """Unify all intelligence links into a single categorized list."""
    combined = []
    
    # Add Official Patches
    for url in (patches or []):
        combined.append({
            "title": "Official Patch / Vendor Advisory",
            "url": url,
            "type": "patch",
            "source": "NVD"
        })
        
    # Add Automated Research Hubs
    for hub in (hubs or []):
        combined.append(hub)
        
    # Add Curated KB References
    for ref in (refs or []):
        combined.append({
            "title": f"Technical Deep-Dive ({ref.get('source', 'Expert')})",
            "url": ref.get("url"),
            "type": "research",
            "source": ref.get("source", "AEGIS KB")
        })
        
    return combined


def _canonicalize_remediation(remediation: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize enricher remediation into the legacy remediation-engine shape."""
    canonical = dict(remediation or {})
    steps = canonical.get("steps", []) or []

    detailed_steps = []
    for step in steps:
        if isinstance(step, dict):
            desc = step.get("description") or step.get("step")
            if desc:
                detailed_steps.append(desc)
        elif isinstance(step, str) and step.strip():
            detailed_steps.append(step.strip())

    refs = canonical.get("references", []) or []
    normalized_refs = []
    for ref in refs:
        if isinstance(ref, dict):
            url = ref.get("url")
            if url:
                normalized_refs.append(url)
        elif isinstance(ref, str) and ref:
            normalized_refs.append(ref)

    cwe_guidance = canonical.get("cwe_guidance") or {}
    canonical.setdefault("source", "cve_enricher")
    canonical["detailed_steps"] = detailed_steps
    canonical["references"] = normalized_refs
    canonical["code_examples"] = cwe_guidance.get("code_examples", {})
    canonical["compliance"] = cwe_guidance.get(
        "compliance",
        canonical.get("compliance", "N/A")
    )
    return canonical
def _generate_summary_message(total_vulns, kev_count, priorities):
    """Generate a high-impact summary string for the remediation dashboard."""
    parts = []

    if kev_count > 0:
        parts.append(f"🔥 Found {kev_count} known-exploited vulnerabilities (KEV).")

    immediate = priorities.get("fix_immediately", 0)
    if immediate > 0:
        parts.append(
            f"🔴 {immediate} findings require "
            f"immediate attention (within 48 hours)."
        )

    week = priorities.get("fix_this_week", 0)
    if week > 0:
        parts.append(
            f"🟠 {week} should be fixed this week."
        )

    month = priorities.get("fix_this_month", 0)
    if month > 0:
        parts.append(
            f"🟡 {month} should be fixed this month."
        )

    if not parts:
        if total_vulns > 0:
            parts.append(
                f"Found {total_vulns} open vulnerabilities. "
                f"None require immediate action."
            )
        else:
            parts.append("No open vulnerabilities found. Looking good! 🎉")

    return " ".join(parts)


# =============================================================================
# SINGLE VULNERABILITY REMEDIATION (for detail view)
# =============================================================================

def get_single_remediation(vuln_id: str,
                            target_id: str) -> Optional[Dict[str, Any]]:
    """
    Get detailed remediation for a single vulnerability.
    Used when user clicks on a specific vuln for details.

    Args:
        vuln_id: Vulnerability document ID
        target_id: Target document ID

    Returns:
        Complete remediation item or None
    """
    try:
        # Get all vulns and find the specific one
        vulns = get_vulns_by_target(target_id)

        target_vuln = None
        for v in vulns:
            vid = v.get("_id", v.get("vuln_id", ""))
            if str(vid) == str(vuln_id):
                target_vuln = v
                break

        if not target_vuln:
            return None

        return _build_remediation_item(target_vuln)

    except Exception as e:
        logger.error(f"Error getting single remediation: {e}", exc_info=True)
        return None


# =============================================================================
# STATUS MANAGEMENT
# =============================================================================

def update_remediation_status(vuln_id: str,
                               new_status: str) -> Dict[str, Any]:
    """
    Update vulnerability status from remediation page.

    Valid statuses: open, in_progress, resolved, false_positive

    Args:
        vuln_id: Vulnerability document ID
        new_status: New status string

    Returns:
        Dict with success and message
    """
    valid_statuses = {"open", "in_progress", "resolved", "false_positive"}

    if new_status not in valid_statuses:
        return {
            "success": False,
            "message": f"Invalid status. Must be one of: {valid_statuses}"
        }

    try:
        result = update_vuln_status(vuln_id, new_status)

        if result:
            status_messages = {
                "open": "Vulnerability marked as open",
                "in_progress": "Vulnerability marked as in progress — good luck fixing it!",
                "resolved": "Vulnerability marked as resolved — great job! 🎉",
                "false_positive": "Vulnerability marked as false positive — excluded from future reports"
            }
            return {
                "success": True,
                "message": status_messages.get(new_status, "Status updated")
            }
        else:
            return {
                "success": False,
                "message": "Failed to update status"
            }

    except Exception as e:
        return {
            "success": False,
            "message": f"Error: {str(e)}"
        }


# =============================================================================
# EXPORT HELPERS
# =============================================================================

def get_remediation_summary_stats(target_id: str) -> Dict[str, Any]:
    """
    Get summary statistics for dashboard display.

    Returns quick stats without full enrichment.
    """
    try:
        vulns = get_vulns_by_target(target_id, status="open")

        severity_counts = {
            "critical": 0, "high": 0,
            "medium": 0, "low": 0, "info": 0
        }
        cve_count = 0
        kev_count = 0

        for v in vulns:
            sev = v.get("severity", "info").lower()
            if sev in severity_counts:
                severity_counts[sev] += 1

            if v.get("cve_id"):
                cve_count += 1
                # Quick KEV check (local, no API)
                if is_in_kev(v["cve_id"]):
                    kev_count += 1

        return {
            "total_open": len(vulns),
            "severity_counts": severity_counts,
            "cve_count": cve_count,
            "kev_count": kev_count,
            "needs_immediate_action": (
                severity_counts["critical"] + kev_count > 0
            )
        }

    except Exception as e:
        logger.error(f"Stats error: {e}", exc_info=True)
        return {
            "total_open": 0,
            "severity_counts": {},
            "cve_count": 0,
            "kev_count": 0,
            "needs_immediate_action": False
        }


# =============================================================================
# STANDALONE TEST
# =============================================================================

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("  REMEDIATION ENGINE — Standalone Test")
    logger.info("=" * 60)

    # Test with a mock vulnerability
    mock_vuln = {
        "_id": "test123",
        "name": "Apache Path Traversal",
        "template_id": "CVE-2021-41773",
        "severity": "critical",
        "host": "https://example.com",
        "url": "https://example.com/icons/.%2e/%2e%2e/etc/passwd",
        "cve_id": "CVE-2021-41773",
        "cvss_score": 9.8,
        "cwe_id": ["CWE-22"],
        "description": "Path traversal in Apache HTTP Server 2.4.49",
        "remediation": {
            "description": "Update Apache to version 2.4.51 or later",
            "priority": "immediate",
            "source": "nuclei-template"
        },
        "status": "open",
        "reference": ["https://httpd.apache.org/security/vulnerabilities_24.html"],
        "tags": ["cve", "apache", "path-traversal"]
    }

    logger.info("Building remediation item for mock vulnerability...")
    item = _build_remediation_item(mock_vuln)

    logger.info(f"\n{'='*60}")
    logger.info(f"Name: {item['name']}")
    logger.info(f"CVE: {item['cve_id']}")
    logger.info(f"Priority: {item['priority_score']}/100 — {item['priority_label']}")
    logger.info(f"KEV: {'YES' if item['is_kev'] else 'No'}")
    logger.info(f"Fix by: {item['fix_by_date']}")
    logger.info(f"Timeline: {item['recommended_timeline']}")

    if item.get("epss"):
        logger.info(f"EPSS: {item['epss']['explanation']}")

    logger.info(f"Remediation ({item['remediation']['source']}):")
    logger.info(f"  Summary: {item['remediation']['summary']}")
    logger.info(f"  Steps:")
    for i, step in enumerate(item["remediation"]["detailed_steps"], 1):
        logger.info(f"    {i}. {step}")

    if item["remediation"].get("code_examples"):
        logger.info(f"  Code Examples:")
        for lang, code in item["remediation"]["code_examples"].items():
            logger.info(f"    [{lang}]")
            for line in code.split("\n"):
                logger.info(f"      {line}")

    logger.info(f"  Threat Indicators:")
    for indicator in item.get("threat_indicators", []):
        logger.info(f"    {indicator}")
