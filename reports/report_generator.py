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


def calculate_risk_score(crit, high, med, low, info, subdomains_count, ports_count, http_assets_count, breached_emails, total_emails):
    """Refactored risk score calculation used by both domain and overall reports."""
    risk_score = 0

    # Vulnerability scoring
    risk_score += crit * 40
    risk_score += high * 25
    risk_score += med * 10
    risk_score += low * 3
    risk_score += info * 1

    # Exposure scoring
    if subdomains_count > 50:
        risk_score += 10
    if ports_count > 100:
        risk_score += 10
    if http_assets_count > 20:
        risk_score += 5

    # Email breach scoring
    if breached_emails > 10:
        risk_score += 15
    elif breached_emails > 5:
        risk_score += 10
    elif breached_emails > 0:
        risk_score += 5

    if total_emails > 0:
        breach_rate = breached_emails / total_emails
        if breach_rate > 0.5:
            risk_score += 5

    return min(risk_score, 100)


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

    # ─── Get Passive Recon Data (WHOIS, Shodan, Censys) ───
    whois_data = _serialize(
        db.get_collection("passive_recon").find_one(
            {"target_domain": domain, "source": "whois"}
        )
    )
    shodan_data = _serialize(
        db.get_collection("passive_recon").find_one(
            {"target_domain": domain, "source": "shodan"}
        )
    )
    censys_data = _serialize(
        db.get_collection("passive_recon").find_one(
            {"target_domain": domain, "source": "censys"}
        )
    )

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
    risk_score = calculate_risk_score(
        vuln_breakdown["critical"],
        vuln_breakdown["high"],
        vuln_breakdown["medium"],
        vuln_breakdown["low"],
        vuln_breakdown["info"],
        len(subdomains),
        len(ports),
        len(http_assets),
        email_stats["breached"],
        email_stats["total"]
    )

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
        if isinstance(tech_list, str):
            tech_list = [t.strip() for t in tech_list.split(",") if t.strip()]
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
        "whois": whois_data,
        "shodan": shodan_data,
        "censys": censys_data,
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
            "timeframe": "24 hours",
            "compliance": "SOC2 CC6.1, PCI-DSS Req 6.5.1"
        })

    if vuln_breakdown.get("high", 0) > 0:
        recommendations.append({
            "priority": "HIGH",
            "action": (
                f"Remediate {vuln_breakdown['high']} "
                f"high-severity issues"
            ),
            "timeframe": "7 days",
            "compliance": "SOC2 CC6.6, ISO 27001 A.14.2.1"
        })

    if vuln_breakdown.get("medium", 0) > 0:
        recommendations.append({
            "priority": "MEDIUM",
            "action": (
                f"Address {vuln_breakdown['medium']} "
                f"medium-severity findings"
            ),
            "timeframe": "30 days",
            "compliance": "SOC2 CC6.6, ISO 27001 A.14.2"
        })

    # ── Exposure recommendations ──────────────────────
    if subdomain_count > 50:
        recommendations.append({
            "priority": "MEDIUM",
            "action": (
                f"Review {subdomain_count} subdomains "
                f"for unnecessary exposure"
            ),
            "timeframe": "30 days",
            "compliance": "SOC2 CC6.6, PCI-DSS Req 2.1"
        })

    if port_count > 100:
        recommendations.append({
            "priority": "MEDIUM",
            "action": (
                f"Audit {port_count} open ports and "
                f"close unnecessary services"
            ),
            "timeframe": "30 days",
            "compliance": "PCI-DSS Req 1.1.6, ISO 27001 A.13.1.1"
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
                "timeframe": "48 hours",
                "compliance": "SOC2 CC6.1, PCI-DSS Req 8.2.4"
            })

        if breached > 0 and password_leaks == 0:
            recommendations.append({
                "priority": "MEDIUM",
                "action": (
                    f"{breached} employee email(s) found in "
                    f"data breaches. Review affected accounts "
                    f"and enable MFA."
                ),
                "timeframe": "7 days",
                "compliance": "SOC2 CC6.1, ISO 27001 A.9.2.1"
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


# ─── Overall Report Generator ───────────────────────────────────────────

def generate_overall_report(db=None):
    """
    Generate a portfolio-wide organization report.
    Aggregates risk metrics across all monitored domains.
    """
    if db is None:
        db = get_db()

    print("[REPORT] Generating overall organization report...")

    targets = list(db[Config.TARGETS_COLLECTION].find({}))
    
    overall_critical = 0
    overall_high = 0
    overall_medium = 0
    overall_low = 0
    total_risk_score = 0
    domains_stats = []

    for t in targets:
        domain = t.get("root_domain") or t.get("domain")
        if not domain:
            continue
            
        # Vulnerabilities
        vulns = list(db[Config.VULNS_COLLECTION].find({"target_domain": domain}))
        
        crit = sum(1 for v in vulns if v.get("severity", "").lower() == "critical")
        high = sum(1 for v in vulns if v.get("severity", "").lower() == "high")
        med = sum(1 for v in vulns if v.get("severity", "").lower() == "medium")
        low = sum(1 for v in vulns if v.get("severity", "").lower() in ["low"])
        info = sum(1 for v in vulns if v.get("severity", "").lower() == "info")
        
        # Exposure estimates
        subs = db[Config.SUBDOMAINS_COLLECTION].count_documents({"target_domain": domain})
        ports = db[Config.PORTS_COLLECTION].count_documents({"target_domain": domain})
        assets = db[Config.HTTP_ASSETS_COLLECTION].count_documents({"target_domain": domain})

        # Emails 
        emails = list(db[Config.EMAILS_COLLECTION].find({"target_domain": domain}))
        breached = sum(1 for e in emails if e.get("breach_status") == "breached")

        risk_score = calculate_risk_score(crit, high, med, low, info, subs, ports, assets, breached, len(emails))

        overall_critical += crit
        overall_high += high
        overall_medium += med
        overall_low += low
        total_risk_score += risk_score
        
        domains_stats.append({
            "domain": domain,
            "risk_score": risk_score,
            "critical_vulns": crit,
            "high_vulns": high,
            "medium_vulns": med,
            "low_vulns": low,
            "total_vulns": len(vulns)
        })

    average_risk = int(total_risk_score / len(domains_stats)) if domains_stats else 0

    return {
        "meta": {
            "report_type": "overall",
            "generated_at": datetime.utcnow().isoformat(),
            "target": "Organization Portfolio"
        },
        "organization_stats": {
            "total_domains": len(domains_stats),
            "total_critical": overall_critical,
            "total_high": overall_high,
            "total_medium": overall_medium,
            "total_low": overall_low,
            "average_risk_score": average_risk
        },
        "domains_stats": domains_stats
    }