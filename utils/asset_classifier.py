"""
Asset Criticality Classifier
==============================
Classifies subdomains into criticality tiers based on naming
patterns. Critical infrastructure assets (VPN, mail, API)
deserve higher risk weighting than test/dev environments.

Tiers:
    CRITICAL: Production infrastructure — VPN, mail, API,
              authentication, databases, CI/CD
    HIGH:     Customer-facing services — www, app, portal,
              shop, payment, CDN
    STANDARD: Unknown or generic subdomains
    LOW:      Development/testing — dev, test, staging,
              sandbox, demo

Usage:
    from utils.asset_classifier import classify_host, get_multiplier

    tier = classify_host("vpn.example.com")
    # Returns: "critical"

    multiplier = get_multiplier("vpn.example.com")
    # Returns: 1.5
"""


# ─── KEYWORD SETS ─────────────────────────────────────────────────────────

CRITICAL_KEYWORDS = {
    "vpn", "mail", "smtp", "imap", "pop3", "exchange",
    "owa", "api", "gateway", "auth", "login", "sso",
    "oauth", "idp", "ldap", "ad", "admin", "mgmt",
    "management", "console", "db", "database", "sql",
    "mongo", "redis", "backup", "vault", "secrets",
    "dns", "ns1", "ns2", "firewall", "fw", "proxy",
    "jenkins", "gitlab", "ci", "cd", "kubernetes",
    "k8s", "docker", "registry", "prod", "production",
}

HIGH_KEYWORDS = {
    "www", "web", "app", "portal", "shop", "store",
    "pay", "payment", "checkout", "cdn", "static",
    "assets", "media", "support", "help", "helpdesk",
    "ticket", "blog", "cms", "wordpress", "forum",
    "community",
}

LOW_KEYWORDS = {
    "dev", "development", "test", "testing", "qa",
    "staging", "stage", "stg", "sandbox", "demo",
    "preview", "uat", "poc", "canary", "beta", "alpha",
    "internal", "intranet", "temp", "tmp", "old",
    "legacy", "deprecated",
}


# ─── MULTIPLIERS ──────────────────────────────────────────────────────────

TIER_MULTIPLIERS = {
    "critical": 1.5,
    "high": 1.25,
    "standard": 1.0,
    "low": 0.75
}


# ─── FUNCTIONS ────────────────────────────────────────────────────────────

def classify_host(hostname):
    """
    Classify a hostname into a criticality tier.

    Extracts subdomain prefix and matches against keyword
    sets. Checks hyphenated segments too
    (e.g., "vpn-gateway" matches "vpn" and "gateway").

    Args:
        hostname: Full hostname (e.g., "vpn.example.com")

    Returns:
        Tier string: "critical", "high", "standard", or "low"
    """
    if not hostname:
        return "standard"

    hostname = hostname.lower().strip()
    parts = hostname.split(".")

    # Bare domain (example.com) = standard
    if len(parts) <= 2:
        return "standard"

    # Check subdomain parts (everything except last 2)
    subdomain_parts = parts[:-2]

    # Check critical first (highest priority)
    for part in subdomain_parts:
        segments = part.replace("_", "-").split("-")
        for segment in segments:
            if segment in CRITICAL_KEYWORDS:
                return "critical"

    # Then high
    for part in subdomain_parts:
        segments = part.replace("_", "-").split("-")
        for segment in segments:
            if segment in HIGH_KEYWORDS:
                return "high"

    # Then low
    for part in subdomain_parts:
        segments = part.replace("_", "-").split("-")
        for segment in segments:
            if segment in LOW_KEYWORDS:
                return "low"

    return "standard"


def get_multiplier(hostname):
    """
    Get the risk multiplier for a hostname.

    Used by risk_scorer.py to weight vulnerabilities
    based on the criticality of the asset they were
    found on.

    Args:
        hostname: Full hostname (e.g., "vpn.example.com")

    Returns:
        Float multiplier (0.75 to 1.5)
    """
    tier = classify_host(hostname)
    return TIER_MULTIPLIERS.get(tier, 1.0)
