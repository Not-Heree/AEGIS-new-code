import math
from config import Config
from database.vulns_db import get_vuln_stats, get_vulns_by_target
from database.subdomains_db import get_subdomain_count
from database.ports_db import get_port_count
from database.http_assets_db import get_http_asset_count
from database.emails_db import (
    get_breached_email_count,
    get_email_count
)
from database.passive_recon_db import get_whois_risk_flags
from utils.logger import logger
from utils.asset_classifier import get_multiplier


# ─── CONFIGURATION ──────────────────────────────────────────────────────────

# Severity weights for vulnerability scoring
SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 3,
    "info": 1
}

# Scale factors control how fast each severity saturates
SEVERITY_SCALE = {
    "critical": 15.0,
    "high": 12.0,
    "medium": 8.0,
    "low": 5.0,
    "info": 3.0
}

# Maximum contribution from ALL vulnerabilities combined
VULN_SCORE_CAP = 60

# Confidence weights based on discovery method
CONFIDENCE_WEIGHTS = {
    "high": 1.0,       # Shodan CVE confirmed by Nuclei
    "medium": 0.85,    # Tech/port/header targeted scan
    "standard": 0.65,  # Broad catch-all scan
}

WHOIS_RISK_WEIGHTS = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0
}


# ─── HELPER FUNCTIONS ────────────────────────────────────────────────────────

def _log_vuln_score(severity, count):
    """
    Calculate diminishing-returns score for a severity tier.
    Uses natural log to compress high counts.
    """
    if count <= 0:
        return 0.0

    weight = SEVERITY_WEIGHTS.get(severity, 1)
    scale = SEVERITY_SCALE.get(severity, 5.0)

    return weight * math.log(1 + count) * (scale / 10.0)


# ─── MAIN SCORING ENGINE ─────────────────────────────────────────────────────

def calculate_risk_score(target_id):
    """
    Calculate a risk score (0-100) for a target.

    Uses logarithmic vulnerability scoring and asset criticality
    multipliers to prevent score inflation from duplicate findings.

    Components:
      V (0-60): Vulnerability severity (log-scaled + multipliers)
      E (0-25): Asset exposure (graduated points)
      B (0-20): Email breaches (threshold-based)
      W (0-20): WHOIS infrastructure risk (flag-based)

    Total is capped at 100.
    """
    from bson import ObjectId
    
    try:
        # Ensure target_id is ObjectId format for database queries
        if isinstance(target_id, str):
            try:
                target_id = ObjectId(target_id)
            except Exception as e:
                logger.error("Invalid target_id format: %s", e)
                return 0
        base_score = 0

        # Severity buckets for tiered saturation
        # Each bucket has a (weight, cap, sensitivity)
        TIER_CONFIG = {
            "critical": {"cap": 50.0, "sens": 60.0},
            "high":     {"cap": 30.0, "sens": 50.0},
            "medium":   {"cap": 15.0, "sens": 30.0},
            "low":      {"cap": 5.0,  "sens": 20.0},
            "info":     {"cap": 2.0,  "sens": 10.0}
        }

        vuln_score = 0.0
        severity_counts = {}
        tier_raw_scores = {k: 0.0 for k in TIER_CONFIG.keys()}

        # Fetch vulnerability data from database
        all_vulns = get_vulns_by_target(target_id)
        vuln_stats = get_vuln_stats(target_id)

        logger.debug(
            "[RISK] Fetched %d vulns, stats: %s for target %s",
            len(all_vulns) if all_vulns else 0, vuln_stats, target_id
        )

        if all_vulns:
            # 1. Accumulate raw weighted scores per severity tier
            for v in all_vulns:
                sev = v.get("severity", "info").lower()
                if sev not in TIER_CONFIG: sev = "info"
                
                host = v.get("host", "")
                confidence = v.get("confidence", "standard")

                weight = SEVERITY_WEIGHTS.get(sev, 1)
                multiplier = get_multiplier(host)
                conf_weight = CONFIDENCE_WEIGHTS.get(confidence, 0.65)

                tier_raw_scores[sev] += weight * multiplier * conf_weight
                severity_counts[sev] = severity_counts.get(sev, 0) + 1

            # 2. Apply independent saturation curves per tier
            for sev, config in TIER_CONFIG.items():
                raw = tier_raw_scores[sev]
                if raw > 0:
                    # Tier_Score = Cap * (1 - e^(-raw / sensitivity))
                    tier_contribution = config["cap"] * (1 - math.exp(-raw / config["sens"]))
                    vuln_score += tier_contribution
        else:
            # Fallback to stats-only with a simplified tiered model
            for entry in vuln_stats:
                sev = entry["_id"].lower()
                if sev not in TIER_CONFIG: continue
                
                count = entry["count"]
                severity_counts[sev] = count
                
                raw = count * SEVERITY_WEIGHTS.get(sev, 1)
                tier_contribution = TIER_CONFIG[sev]["cap"] * (1 - math.exp(-raw / TIER_CONFIG[sev]["sens"]))
                vuln_score += tier_contribution

        # Ensure the combined vulnerability component stays within the global cap
        if vuln_score > VULN_SCORE_CAP:
            vuln_score = float(VULN_SCORE_CAP)

        vuln_score = round(vuln_score)
        base_score += vuln_score

        # ─── Asset Exposure Scoring (Graduated) ─────────
        subdomain_count = get_subdomain_count(target_id)
        port_count = get_port_count(target_id)
        http_asset_count = get_http_asset_count(target_id)

        exposure_score = 0

        # Subdomains: 0-15 points (graduated)
        if subdomain_count > 100:
            exposure_score += 15
        elif subdomain_count > 50:
            exposure_score += 10
        elif subdomain_count > 20:
            exposure_score += 5
        elif subdomain_count > 5:
            exposure_score += 2

        # Ports: 0-10 points (graduated)
        if port_count > 200:
            exposure_score += 10
        elif port_count > 100:
            exposure_score += 7
        elif port_count > 50:
            exposure_score += 4
        elif port_count > 20:
            exposure_score += 2

        # HTTP Assets: 0-5 points
        if http_asset_count > 50:
            exposure_score += 5
        elif http_asset_count > 20:
            exposure_score += 3
        elif http_asset_count > 5:
            exposure_score += 1

        # Cap exposure contribution at 25
        if exposure_score > 25:
            exposure_score = 25

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

        if total_emails > 0:
            breach_rate = breached_count / total_emails
            if breach_rate > 0.5:
                email_score += 5

        base_score += email_score

        # ─── WHOIS Risk Scoring ──────────────────────────
        whois_risk_flags = get_whois_risk_flags(target_id)
        whois_score = 0
        for flag in whois_risk_flags:
            severity = flag.get("severity", "info").lower()
            whois_score += WHOIS_RISK_WEIGHTS.get(
                severity, 0
            )

        if whois_score > 20:
            whois_score = 20

        base_score += whois_score

        # ─── Cap final score at 100 ─────────────────────
        if base_score > 100:
            base_score = 100

        logger.info(
            "Risk score: %d/100 "
            "(vulns: %d [C:%d H:%d M:%d L:%d], "
            "exposure: %d, email: %d, whois: %d) "
            "[%d subs, %d ports, %d/%d breached emails, "
            "%d whois flags]",
            base_score, vuln_score,
            severity_counts.get("critical", 0),
            severity_counts.get("high", 0),
            severity_counts.get("medium", 0),
            severity_counts.get("low", 0),
            exposure_score, email_score, whois_score,
            subdomain_count, port_count,
            breached_count, total_emails,
            len(whois_risk_flags)
        )

        return base_score

    except Exception as e:
        logger.error(
            "Risk score calculation error for target %s: %s",
            target_id, e, exc_info=True
        )
        return 0