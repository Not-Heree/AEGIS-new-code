"""
Risk Scorer Module
==================
Calculates a 0-100 risk score for a target based on three factors:

1. VULNERABILITY SCORING (0-100 base):
   - Critical vulns × 40 points each
   - High vulns × 25 points each
   - Medium vulns × 10 points each
   - Low vulns × 3 points each
   - Info vulns × 1 point each

2. EXPOSURE SCORING (0-25 bonus):
   - More than 50 subdomains → +10
   - More than 100 open ports → +10
   - More than 20 HTTP assets → +5

3. EMAIL BREACH SCORING (0-20 bonus):
   - More than 10 breached emails → +15
   - More than 5 breached emails → +10
   - Any breached emails → +5
   - More than 50% emails breached → +5 additional

Final score is capped at 100.

Risk levels:
    0-19:  MINIMAL  (green)
   20-39:  LOW      (light green)
   40-59:  MEDIUM   (orange)
   60-79:  HIGH     (red)
   80-100: CRITICAL (dark red)
"""

from database.vulns_db import get_vuln_stats
from database.subdomains_db import get_subdomain_count
from database.ports_db import get_port_count
from database.http_assets_db import get_http_asset_count
from database.emails_db import (
    get_breached_email_count,
    get_email_count
)
from utils.logger import logger


# Severity weights for vulnerability scoring
SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 3,
    "info": 1
}


def calculate_risk_score(target_id):
    """
    Calculate a risk score (0-100) for a target.

    Combines vulnerability severity, asset exposure,
    and email breach data into a single score.

    Args:
        target_id: Target document ObjectId string

    Returns:
        Integer risk score from 0 to 100
    """
    try:
        base_score = 0

        # ─── Vulnerability Scoring ───────────────────────
        vuln_stats = get_vuln_stats(target_id)
        vuln_score = 0
        for entry in vuln_stats:
            severity = entry["_id"].lower()
            count = entry["count"]
            weight = SEVERITY_WEIGHTS.get(severity, 1)
            vuln_score += count * weight

        base_score += vuln_score

        # ─── Asset Exposure Scoring ──────────────────────
        subdomain_count = get_subdomain_count(target_id)
        port_count = get_port_count(target_id)
        http_asset_count = get_http_asset_count(target_id)

        exposure_score = 0
        if subdomain_count > 50:
            exposure_score += 10
        if port_count > 100:
            exposure_score += 10
        if http_asset_count > 20:
            exposure_score += 5

        base_score += exposure_score

        # ─── Email Breach Scoring ────────────────────────
        breached_count = get_breached_email_count(target_id)
        total_emails = get_email_count(target_id)

        email_score = 0
        if breached_count > 10:
            email_score += 15
        elif breached_count > 5:
            email_score += 10
        elif breached_count > 0:
            email_score += 5

        # Extra penalty if high percentage are breached
        if total_emails > 0:
            breach_rate = breached_count / total_emails
            if breach_rate > 0.5:
                email_score += 5

        base_score += email_score

        # ─── Cap at 100 ─────────────────────────────────
        if base_score > 100:
            base_score = 100

        logger.info(
            "Risk score: %d/100 "
            "(vulns: %d, exposure: %d, email: %d) "
            "[%d subs, %d ports, %d/%d breached emails]",
            base_score, vuln_score, exposure_score, email_score,
            subdomain_count, port_count,
            breached_count, total_emails
        )

        return base_score

    except Exception as e:
        logger.error(
            "Risk score calculation error: %s",
            e, exc_info=True
        )
        return 0