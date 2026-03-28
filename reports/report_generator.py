"""
Report Generator Module
=======================
Queries all MongoDB collections for a domain and assembles
a structured report dict. This data is used by:

  - PDF generator (reports/pdf_generator.py)
  - JSON report endpoint (routes/reports.py)
  - Executive summary endpoint
  - Remediation report endpoint

Handles:
  - Full data serialization (ObjectId, datetime)
  - Risk score calculation
  - Vulnerability breakdown by severity
  - Email breach statistics
  - Technology frequency analysis
  - Auto-generated recommendations based on findings
"""

from datetime import datetime
from bson import ObjectId
from database.connection import get_db
from config import Config


# ─── Serialization Helper ────────────────────────────────────────────────

def _serialize(doc):
    """
    Convert MongoDB document to JSON-safe dict.

    Recursively handles:
    - ObjectId → string
    - datetime → ISO format string
    - Nested dicts and lists
    - Standalone ObjectId/datetime values
    """
    if doc is None:
        return None

    if isinstance(doc, list):
        return [_serialize(d) for d in doc]

    if isinstance(doc, dict):
        result = {}
        for key, value in doc.items():
            if isinstance(value, ObjectId):
                result[key] = str(value)
            elif isinstance(value, datetime):
                result[key] = value.isoformat()
            elif isinstance(value, dict):
                result[key] = _serialize(value)
            elif isinstance(value, list):
                result[key] = _serialize(value)
            else:
                result[key] = value
        return result

    if isinstance(doc, ObjectId):
        return str(doc)

    if isinstance(doc, datetime):
        return doc.isoformat()

    return doc


# ─── Main Report Generator ───────────────────────────────────────────────

def generate_report(domain, db=None):
    """
    Generate a complete report for a domain.

    Queries all 8 collections, calculates statistics,
    and returns a fully JSON-serializable dict.

    Args:
        domain: Target domain string (e.g., "example.com")
        db: Optional database connection (uses default if None)

    Returns:
        Structured report dict with all scan data
    """
    if db is None:
        db = get_db()

    print(f"[REPORT] Generating report for: {domain}")

    # ─── Get Target Info ─────────────────────────────────
    target = db[Config.TARGETS_COLLECTION].find_one(
        {"root_domain": domain}
    )
    if not target:
        target = db[Config.TARGETS_COLLECTION].find_one(
            {"domain": domain}
        )
    target = _serialize(target)

    # ─── Get All Data ────────────────────────────────────
    subdomains = _serialize(list(
        db[Config.SUBDOMAINS_COLLECTION].find(
            {"target_domain": domain}
        )
    ))

    ports = _serialize(list(
        db[Config.PORTS_COLLECTION].find(
            {"target_domain": domain}
        )
    ))

    http_assets = _serialize(list(
        db[Config.HTTP_ASSETS_COLLECTION].find(
            {"target_domain": domain}
        )
    ))

    vulnerabilities = _serialize(list(
        db[Config.VULNS_COLLECTION].find(
            {"target_domain": domain}
        )
    ))

    changes = _serialize(list(
        db[Config.CHANGES_COLLECTION].find(
            {"target_domain": domain}
        ).sort("detected_at", -1).limit(50)
    ))

    # ─── Get Email Exposures ─────────────────────────────
    emails = _serialize(list(
        db[Config.EMAILS_COLLECTION].find(
            {"target_domain": domain}
        ).sort("email", 1)
    ))

    email_stats = {
        "total": len(emails),
        "breached": sum(
            1 for e in emails
            if e.get("breach_status") == "breached"
        ),
        "clean": sum(
            1 for e in emails
            if e.get("breach_status") == "clean"
        ),
        "unchecked": sum(
            1 for e in emails
            if e.get("breach_status") == "unknown"
        ),
        "password_leaks": sum(
            1 for e in emails
            if e.get("password_leaked")
        ),
    }
    if email_stats["total"] > 0:
        email_stats["breach_rate"] = round(
            email_stats["breached"] /
            email_stats["total"] * 100, 1
        )
    else:
        email_stats["breach_rate"] = 0

    # ─── Get Latest Scan ─────────────────────────────────
    latest_scan = _serialize(
        db[Config.SCANS_COLLECTION].find_one(
            {"target_domain": domain},
            sort=[("started_at", -1)]
        )
    )

    # ─── Vulnerability Breakdown ─────────────────────────
    vuln_breakdown = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0
    }
    for vuln in vulnerabilities:
        sev = vuln.get("severity", "info").lower()
        if sev in vuln_breakdown:
            vuln_breakdown[sev] += 1

    # ─── Calculate Risk Score ────────────────────────────
    risk_score = 0

    # Vulnerability scoring
    risk_score += vuln_breakdown["critical"] * 40
    risk_score += vuln_breakdown["high"] * 25
    risk_score += vuln_breakdown["medium"] * 10
    risk_score += vuln_breakdown["low"] * 3
    risk_score += vuln_breakdown["info"] * 1

    # Exposure scoring
    if len(subdomains) > 50:
        risk_score += 10
    if len(ports) > 100:
        risk_score += 10
    if len(http_assets) > 20:
        risk_score += 5

    # Email breach scoring
    if email_stats["breached"] > 10:
        risk_score += 15
    elif email_stats["breached"] > 5:
        risk_score += 10
    elif email_stats["breached"] > 0:
        risk_score += 5

    if email_stats["total"] > 0:
        breach_rate = (
            email_stats["breached"] /
            email_stats["total"]
        )
        if breach_rate > 0.5:
            risk_score += 5

    risk_score = min(risk_score, 100)

    # ─── Group Vulnerabilities by Severity ───────────────
    vulns_by_severity = {
        "critical": [],
        "high": [],
        "medium": [],
        "low": [],
        "info": []
    }
    for vuln in vulnerabilities:
        sev = vuln.get("severity", "info").lower()
        if sev in vulns_by_severity:
            vulns_by_severity[sev].append(vuln)

    # ─── Technologies Summary ────────────────────────────
    technologies = {}
    for asset in http_assets:
        # Handle both field names (tech and technologies)
        tech_list = asset.get(
            "tech", asset.get("technologies", [])
        )
        for tech in tech_list:
            if tech:
                technologies[tech] = (
                    technologies.get(tech, 0) + 1
                )

    tech_list = sorted(
        technologies.items(),
        key=lambda x: x[1],
        reverse=True
    )

    # ─── Build Report ────────────────────────────────────
    report = {
        "meta": {
            "domain": domain,
            "generated_at": datetime.utcnow().isoformat(),
            "tool": "EASM Tool v1.0.0",
            "report_type": "Full Security Assessment"
        },
        "target": {
            "domain": domain,
            "org_name": (
                target.get("org_name", "")
                if target else ""
            ),
            "status": (
                target.get("status", "active")
                if target else "active"
            ),
            "added_at": (
                target.get("added_at", "")
                if target else ""
            ),
            "last_scanned": (
                target.get("last_scanned", "")
                if target else ""
            )
        },
        "summary": {
            "total_subdomains": len(subdomains),
            "total_ports": len(ports),
            "total_http_assets": len(http_assets),
            "total_vulnerabilities": len(vulnerabilities),
            "total_changes": len(changes),
            "total_emails": len(emails),
            "total_breached_emails": email_stats["breached"],
            "risk_score": risk_score,
            "risk_level": _get_risk_level(risk_score)
        },
        "vuln_breakdown": vuln_breakdown,
        "subdomains": subdomains,
        "ports": ports,
        "http_assets": http_assets,
        "vulnerabilities": vulnerabilities,
        "vulns_by_severity": vulns_by_severity,
        "changes": changes,
        "emails": emails,
        "email_stats": email_stats,
        "technologies": tech_list[:20],
        "latest_scan": latest_scan,
        "recommendations": _generate_recommendations(
            vuln_breakdown, len(subdomains),
            len(ports), email_stats
        )
    }

    print(
        f"[REPORT] Report generated: "
        f"{len(subdomains)} subs, "
        f"{len(vulnerabilities)} vulns, "
        f"{len(emails)} emails, "
        f"risk={risk_score}"
    )

    return report


# ─── Executive Summary ───────────────────────────────────────────────────

def get_executive_summary(domain, db=None):
    """
    Generate a brief executive summary for quick overview.

    Smaller response than full report — good for dashboards
    and management presentations.

    Args:
        domain: Target domain string
        db: Optional database connection

    Returns:
        Condensed summary dict
    """
    if db is None:
        db = get_db()

    report = generate_report(domain, db)

    summary = {
        "domain": domain,
        "generated_at": report["meta"]["generated_at"],
        "risk_score": report["summary"]["risk_score"],
        "risk_level": report["summary"]["risk_level"],
        "total_assets": (
            report["summary"]["total_subdomains"] +
            report["summary"]["total_http_assets"]
        ),
        "total_vulnerabilities": (
            report["summary"]["total_vulnerabilities"]
        ),
        "critical_findings": (
            report["vuln_breakdown"]["critical"]
        ),
        "high_findings": report["vuln_breakdown"]["high"],
        "medium_findings": report["vuln_breakdown"]["medium"],
        "total_emails": report["summary"]["total_emails"],
        "breached_emails": (
            report["summary"]["total_breached_emails"]
        ),
        "recommendations": report["recommendations"]
    }

    return summary


# ─── Remediation Report ──────────────────────────────────────────────────

def get_remediation_report(domain, db=None):
    """
    Generate a remediation-focused report.

    Groups vulnerabilities by priority with fix steps.
    Uses severity as the grouping criteria:
      - Critical → Immediate (fix within 24 hours)
      - High → Short-term (fix within 7 days)
      - Medium → Medium-term (fix within 30 days)
      - Low/Info → Long-term (fix within 90 days)

    Args:
        domain: Target domain string
        db: Optional database connection

    Returns:
        Remediation report dict grouped by priority
    """
    if db is None:
        db = get_db()

    vulnerabilities = _serialize(list(
        db[Config.VULNS_COLLECTION].find(
            {"target_domain": domain}
        )
    ))

    immediate = []
    short_term = []
    medium_term = []
    long_term = []

    for vuln in vulnerabilities:
        sev = vuln.get("severity", "info").lower()
        entry = {
            "name": vuln.get(
                "name",
                vuln.get("template_id", "Unknown")
            ),
            "severity": sev,
            "host": vuln.get("host", ""),
            "url": vuln.get(
                "matched_at", vuln.get("url", "")
            ),
            "description": vuln.get("description", ""),
            "remediation": vuln.get("remediation", {})
        }

        if sev == "critical":
            immediate.append(entry)
        elif sev == "high":
            short_term.append(entry)
        elif sev == "medium":
            medium_term.append(entry)
        else:
            long_term.append(entry)

    return {
        "domain": domain,
        "generated_at": datetime.utcnow().isoformat(),
        "total_findings": len(vulnerabilities),
        "by_priority": {
            "immediate": {
                "count": len(immediate),
                "timeframe": "Fix within 24 hours",
                "items": immediate
            },
            "short_term": {
                "count": len(short_term),
                "timeframe": "Fix within 7 days",
                "items": short_term
            },
            "medium_term": {
                "count": len(medium_term),
                "timeframe": "Fix within 30 days",
                "items": medium_term
            },
            "long_term": {
                "count": len(long_term),
                "timeframe": "Fix within 90 days",
                "items": long_term
            }
        }
    }


# ─── Helper Functions ────────────────────────────────────────────────────

def _get_risk_level(score):
    """Convert numeric risk score to text level."""
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 40:
        return "MEDIUM"
    elif score >= 20:
        return "LOW"
    else:
        return "MINIMAL"


def _generate_recommendations(vuln_breakdown, subdomain_count,
                               port_count, email_stats=None):
    """
    Generate prioritized recommendations based on findings.

    Covers:
    - Vulnerability remediation by severity
    - Asset exposure reduction
    - Email breach response
    - Default recommendation if nothing found

    Args:
        vuln_breakdown: Dict with severity counts
        subdomain_count: Total subdomain count
        port_count: Total port count
        email_stats: Optional dict with email breach data

    Returns:
        List of recommendation dicts with priority,
        action, and timeframe
    """
    recommendations = []

    # ── Vulnerability recommendations ─────────────────
    if vuln_breakdown.get("critical", 0) > 0:
        recommendations.append({
            "priority": "IMMEDIATE",
            "action": (
                f"Address {vuln_breakdown['critical']} "
                f"critical vulnerabilities immediately"
            ),
            "timeframe": "24 hours"
        })

    if vuln_breakdown.get("high", 0) > 0:
        recommendations.append({
            "priority": "HIGH",
            "action": (
                f"Remediate {vuln_breakdown['high']} "
                f"high-severity issues"
            ),
            "timeframe": "7 days"
        })

    if vuln_breakdown.get("medium", 0) > 0:
        recommendations.append({
            "priority": "MEDIUM",
            "action": (
                f"Address {vuln_breakdown['medium']} "
                f"medium-severity findings"
            ),
            "timeframe": "30 days"
        })

    # ── Exposure recommendations ──────────────────────
    if subdomain_count > 50:
        recommendations.append({
            "priority": "MEDIUM",
            "action": (
                f"Review {subdomain_count} subdomains "
                f"for unnecessary exposure"
            ),
            "timeframe": "30 days"
        })

    if port_count > 100:
        recommendations.append({
            "priority": "MEDIUM",
            "action": (
                f"Audit {port_count} open ports and "
                f"close unnecessary services"
            ),
            "timeframe": "30 days"
        })

    # ── Email breach recommendations ──────────────────
    if email_stats:
        breached = email_stats.get("breached", 0)
        password_leaks = email_stats.get(
            "password_leaks", 0
        )

        if password_leaks > 0:
            recommendations.append({
                "priority": "HIGH",
                "action": (
                    f"{password_leaks} employee email(s) "
                    f"have leaked passwords. Force password "
                    f"resets and enable MFA immediately."
                ),
                "timeframe": "48 hours"
            })

        if breached > 0 and password_leaks == 0:
            recommendations.append({
                "priority": "MEDIUM",
                "action": (
                    f"{breached} employee email(s) found in "
                    f"data breaches. Review affected accounts "
                    f"and enable MFA."
                ),
                "timeframe": "7 days"
            })

        total_emails = email_stats.get("total", 0)
        if total_emails > 20:
            recommendations.append({
                "priority": "MEDIUM",
                "action": (
                    f"{total_emails} employee emails "
                    f"discoverable online. Review email "
                    f"exposure and consider anti-harvesting "
                    f"measures."
                ),
                "timeframe": "30 days"
            })

    # ── Default recommendation ────────────────────────
    if not recommendations:
        recommendations.append({
            "priority": "LOW",
            "action": (
                "Continue regular security monitoring"
            ),
            "timeframe": "Ongoing"
        })

    return recommendations