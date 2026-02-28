# reports/report_generator.py

from datetime import datetime
from bson import ObjectId
from database.connection import get_db
from config import Config


# ─── Serialization Helper ────────────────────────────────────────────────

def _serialize(doc):
    """
    Convert MongoDB document to JSON-safe dict.
    
    Handles:
    - ObjectId → string
    - datetime → ISO format string
    - Nested dicts and lists
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
    
    Returns a structured dict with all scan data, fully JSON-serializable.
    """
    if db is None:
        db = get_db()

    print(f"[REPORT] Generating report for: {domain}")

    # ─── Get Target Info ─────────────────────────────────────────────
    target = db[Config.TARGETS_COLLECTION].find_one({"root_domain": domain})
    if not target:
        target = db[Config.TARGETS_COLLECTION].find_one({"domain": domain})
    target = _serialize(target)

    # ─── Get All Data (with serialization) ───────────────────────────
    subdomains = _serialize(list(db[Config.SUBDOMAINS_COLLECTION].find(
        {"target_domain": domain}
    )))

    ports = _serialize(list(db[Config.PORTS_COLLECTION].find(
        {"target_domain": domain}
    )))

    http_assets = _serialize(list(db[Config.HTTP_ASSETS_COLLECTION].find(
        {"target_domain": domain}
    )))

    vulnerabilities = _serialize(list(db[Config.VULNS_COLLECTION].find(
        {"target_domain": domain}
    )))

    changes = _serialize(list(db[Config.CHANGES_COLLECTION].find(
        {"target_domain": domain}
    ).sort("detected_at", -1).limit(50)))

    # ─── Get Latest Scan ─────────────────────────────────────────────
    latest_scan = _serialize(db[Config.SCANS_COLLECTION].find_one(
        {"target_domain": domain},
        sort=[("started_at", -1)]
    ))

    # ─── Vulnerability Breakdown ─────────────────────────────────────
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

    # ─── Calculate Risk Score ────────────────────────────────────────
    risk_score = 0
    risk_score += vuln_breakdown["critical"] * 40
    risk_score += vuln_breakdown["high"] * 25
    risk_score += vuln_breakdown["medium"] * 10
    risk_score += vuln_breakdown["low"] * 3
    risk_score += vuln_breakdown["info"] * 1

    # Add exposure factors
    if len(subdomains) > 50:
        risk_score += 10
    if len(ports) > 100:
        risk_score += 10
    if len(http_assets) > 20:
        risk_score += 5

    risk_score = min(risk_score, 100)  # Cap at 100

    # ─── Group Vulnerabilities by Severity ───────────────────────────
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

    # ─── Technologies Summary ────────────────────────────────────────
    technologies = {}
    for asset in http_assets:
        for tech in asset.get("technologies", []):
            if tech:
                technologies[tech] = technologies.get(tech, 0) + 1

    # Sort by count
    tech_list = sorted(
        technologies.items(),
        key=lambda x: x[1],
        reverse=True
    )

    # ─── Build Report ────────────────────────────────────────────────
    report = {
        "meta": {
            "domain": domain,
            "generated_at": datetime.utcnow().isoformat(),
            "tool": "EASM Tool v1.0.0",
            "report_type": "Full Security Assessment"
        },
        "target": {
            "domain": domain,
            "org_name": target.get("org_name", "") if target else "",
            "status": target.get("status", "active") if target else "active",
            "added_at": target.get("added_at", "") if target else "",
            "last_scanned": target.get("last_scanned", "") if target else ""
        },
        "summary": {
            "total_subdomains": len(subdomains),
            "total_ports": len(ports),
            "total_http_assets": len(http_assets),
            "total_vulnerabilities": len(vulnerabilities),
            "total_changes": len(changes),
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
        "technologies": tech_list[:20],  # Top 20
        "latest_scan": latest_scan,
        "recommendations": _generate_recommendations_from_data(vuln_breakdown, len(subdomains), len(ports))
    }

    print(f"[REPORT] Report generated: {len(subdomains)} subs, {len(vulnerabilities)} vulns, risk={risk_score}")

    return report


# ─── Executive Summary ───────────────────────────────────────────────────

def get_executive_summary(domain, db=None):
    """
    Generate a brief executive summary for quick overview.
    
    Smaller response — good for dashboards.
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
        "total_vulnerabilities": report["summary"]["total_vulnerabilities"],
        "critical_findings": report["vuln_breakdown"]["critical"],
        "high_findings": report["vuln_breakdown"]["high"],
        "medium_findings": report["vuln_breakdown"]["medium"],
        "recommendations": report["recommendations"]
    }

    return summary


# ─── Remediation Report ──────────────────────────────────────────────────

def get_remediation_report(domain, db=None):
    """
    Generate a remediation-focused report.
    
    Groups vulnerabilities by priority with fix steps.
    """
    if db is None:
        db = get_db()

    vulnerabilities = _serialize(list(db[Config.VULNS_COLLECTION].find(
        {"target_domain": domain}
    )))

    # Group by priority
    immediate = []  # Critical
    short_term = []  # High
    medium_term = []  # Medium
    long_term = []  # Low + Info

    for vuln in vulnerabilities:
        sev = vuln.get("severity", "info").lower()
        entry = {
            "name": vuln.get("name", vuln.get("template_id", "Unknown")),
            "severity": sev,
            "host": vuln.get("host", ""),
            "url": vuln.get("matched_at", vuln.get("url", "")),
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


def _generate_recommendations_from_data(vuln_breakdown, subdomain_count, port_count):
    """Generate basic recommendations based on findings."""
    recommendations = []

    if vuln_breakdown.get("critical", 0) > 0:
        recommendations.append({
            "priority": "IMMEDIATE",
            "action": f"Address {vuln_breakdown['critical']} critical vulnerabilities immediately",
            "timeframe": "24 hours"
        })

    if vuln_breakdown.get("high", 0) > 0:
        recommendations.append({
            "priority": "HIGH",
            "action": f"Remediate {vuln_breakdown['high']} high-severity issues",
            "timeframe": "7 days"
        })

    if vuln_breakdown.get("medium", 0) > 0:
        recommendations.append({
            "priority": "MEDIUM",
            "action": f"Address {vuln_breakdown['medium']} medium-severity findings",
            "timeframe": "30 days"
        })

    if subdomain_count > 50:
        recommendations.append({
            "priority": "MEDIUM",
            "action": f"Review {subdomain_count} subdomains for unnecessary exposure",
            "timeframe": "30 days"
        })

    if port_count > 100:
        recommendations.append({
            "priority": "MEDIUM",
            "action": f"Audit {port_count} open ports and close unnecessary services",
            "timeframe": "30 days"
        })

    if not recommendations:
        recommendations.append({
            "priority": "LOW",
            "action": "Continue regular security monitoring",
            "timeframe": "Ongoing"
        })

    return recommendations