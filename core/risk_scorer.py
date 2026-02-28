from database.vulns_db import get_vuln_stats
from database.subdomains_db import get_subdomain_count
from database.ports_db import get_port_count
from database.http_assets_db import get_http_asset_count


# Severity weights for vulnerability scoring
SEVERITY_WEIGHTS = {
    "critical": 40,
    "high": 25,
    "medium": 10,
    "low": 3,
    "info": 1
}


def calculate_risk_score(target_id):
    """Calculate a risk score (0-100) for a target based on vulns and asset exposure."""
    try:
        base_score = 0

        # ─── Vulnerability Scoring ───────────────────────────────────

        vuln_stats = get_vuln_stats(target_id)
        for entry in vuln_stats:
            severity = entry["_id"].lower()
            count = entry["count"]
            weight = SEVERITY_WEIGHTS.get(severity, 1)
            base_score += count * weight

        # ─── Asset Exposure Scoring ──────────────────────────────────

        subdomain_count = get_subdomain_count(target_id)
        port_count = get_port_count(target_id)
        http_asset_count = get_http_asset_count(target_id)

        if subdomain_count > 50:
            base_score += 10
        if port_count > 100:
            base_score += 10
        if http_asset_count > 20:
            base_score += 5

        # ─── Cap at 100 ─────────────────────────────────────────────

        if base_score > 100:
            base_score = 100

        print(f"[RISK SCORER] Calculated risk score: {base_score}/100")
        return base_score

    except Exception as e:
        print(f"[RISK SCORER] Error calculating risk: {e}")
        return 0
