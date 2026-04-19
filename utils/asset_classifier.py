"""
Asset Criticality Classifier
==============================
Classifies subdomains into criticality tiers based on naming
patterns using segment-based exact matching to eliminate false
positives from short keywords.

Returns a tuple (tier, is_legacy) where is_legacy is an additive
flag indicating the asset may be forgotten or unpatched infrastructure.
It does not override the tier — it augments it.

Tiers (in priority order):
    TIER_CROWN_JEWELS:  Auth, payment, secrets, identity providers
    TIER_CORE_INFRA:    Databases, CI/CD, DevOps tooling, docs
    TIER_CUSTOMER:      Public-facing services, CDN, support
    TIER_EXPOSED_DEV:   Publicly reachable dev/staging environments
    TIER_STANDARD:      Root domain or unmatched subdomains
    TIER_LEGACY:        Only assigned when no other tier matches
                        and legacy keywords are present.
                        Otherwise surfaces as is_legacy=True flag.
"""

TIER_CROWN_JEWELS = "Critical Infrastructure"
TIER_CORE_INFRA   = "High Value"
TIER_CUSTOMER     = "Customer Surface"
TIER_EXPOSED_DEV  = "Exposed Development"
TIER_STANDARD     = "Standard"
TIER_LEGACY       = "Legacy / Deprecated"

TIER_PRIORITY = {
    TIER_CROWN_JEWELS: 6,
    TIER_CORE_INFRA:   5,
    TIER_CUSTOMER:     4,
    TIER_EXPOSED_DEV:  3,
    TIER_STANDARD:     2,
    # TIER_LEGACY is intentionally excluded from priority resolution.
    # It is assigned only when no other tier matches.
}

KEYWORDS = {
    TIER_CROWN_JEWELS: {
        "auth", "login", "sso", "oauth", "saml", "ldap", "admin", "superadmin",
        "mgmt", "console", "root", "vpn", "gateway", "firewall", "proxy", "dns",
        "payment", "checkout", "billing", "pay", "stripe", "vault", "secrets",
        "pki", "cert", "hsm", "iam", "okta", "duo", "mfa", "idp", "owa",
        "exchange", "ns1", "ns2"
    },
    TIER_CORE_INFRA: {
        "api", "backend", "database", "sql", "mysql", "postgres", "mongo",
        "redis", "elastic", "kibana", "grafana", "jenkins", "gitlab", "github",
        "pipeline", "kubernetes", "k8s", "docker", "registry", "nexus", "sonar",
        "jira", "confluence", "smtp", "mail", "backup", "storage", "blob",
        "sftp", "kerberos", "docs", "documentation", "api-docs", "prod",
        "production"
    },
    TIER_CUSTOMER: {
        "www", "app", "web", "portal", "shop", "store", "ecommerce", "cdn",
        "media", "assets", "upload", "files", "download", "support", "helpdesk",
        "ticket", "crm", "blog", "forum", "community", "status", "monitor",
        "health", "static", "cms", "wordpress", "help"
    },
    TIER_EXPOSED_DEV: {
        "dev", "develop", "test", "testing", "qa", "staging", "stage", "stg",
        "uat", "demo", "sandbox", "preview", "beta", "alpha", "canary", "preprod",
        "pre-prod", "nightly", "experiment", "internal-test", "poc", "internal",
        "intranet"
    },
}

# Legacy keywords handled as a flag — never compete in tier resolution
LEGACY_KEYWORDS = {
    "old", "legacy", "deprecated", "archive", "temp", "tmp", "wip",
    "unused", "retired", "eol", "classic", "original", "backup-old"
}

# Payment hard override — always Crown Jewels regardless of other matches
PAYMENT_KEYWORDS = {
    "payment", "checkout", "billing", "pay", "stripe"
}

TIER_MULTIPLIERS = {
    TIER_CROWN_JEWELS: 1.5,
    TIER_CORE_INFRA:   1.3,
    TIER_CUSTOMER:     1.25,
    TIER_EXPOSED_DEV:  1.2,  # NOT reduced — exposed dev is not lower risk
    TIER_STANDARD:     1.0,
    TIER_LEGACY:       1.0,  # is_legacy flag handled separately in UI
}

TIER_UI = {
    TIER_CROWN_JEWELS: {"label": "Critical",         "color": "#E24B4A"},
    TIER_CORE_INFRA:   {"label": "High Value",        "color": "#EF9F27"},
    TIER_CUSTOMER:     {"label": "Customer Surface",  "color": "#378ADD"},
    TIER_EXPOSED_DEV:  {"label": "Exposed Dev",       "color": "#FAC775"},
    TIER_STANDARD:     {"label": "Standard",          "color": "#888780"},
    TIER_LEGACY:       {"label": "Legacy",            "color": "#7F77DD"},
}


def _get_segments(hostname: str) -> set:
    """
    Extract all discrete tokens from a hostname for exact matching.
    Splits on dots and hyphens/underscores.
    Example: "admin-dev.api.example.com"
             -> {"admin", "dev", "admin-dev", "api", "example", "com"}
    """
    parts = hostname.lower().strip().split(".")
    segments = set()
    for part in parts:
        segments.add(part)
        segments.update(part.replace("_", "-").split("-"))
    return segments


def classify_asset_tier(hostname: str) -> tuple:
    """
    Classify a hostname into a criticality tier with legacy flag.

    Uses segment-based exact matching to eliminate false positives
    from short keywords (e.g. "ca" matching "careers").
    Evaluates all tiers before resolving — no early returns.

    Args:
        hostname: Full hostname e.g. "admin-staging.example.com"

    Returns:
        Tuple of (tier_string, is_legacy_bool)
        e.g. ("Critical Infrastructure", False)
             ("High Value", True)
             ("Legacy / Deprecated", True)
    """
    if not hostname:
        return TIER_STANDARD, False

    segments = _get_segments(hostname)

    # Determine legacy flag first — excluded from tier resolution
    is_legacy = bool(LEGACY_KEYWORDS & segments)

    # Remove legacy tokens so they cannot influence tier matching
    active_segments = segments - LEGACY_KEYWORDS

    # Resolve tier by evaluating all tiers and taking the highest match
    matched_tier = None
    matched_priority = -1

    for tier, keywords in KEYWORDS.items():
        if keywords & active_segments:
            if TIER_PRIORITY[tier] > matched_priority:
                matched_tier = tier
                matched_priority = TIER_PRIORITY[tier]

    # Payment hard override — always Crown Jewels
    if PAYMENT_KEYWORDS & active_segments:
        matched_tier = TIER_CROWN_JEWELS

    # Assign final tier
    if matched_tier is None:
        matched_tier = TIER_LEGACY if is_legacy else TIER_STANDARD

    return matched_tier, is_legacy


def classify_host(hostname: str) -> str:
    """
    Legacy compatibility wrapper.
    Returns only the tier string for consumers that have not yet
    been updated to handle the tuple return from classify_asset_tier.
    Remove this once all consumers are updated.
    """
    tier, _ = classify_asset_tier(hostname)
    return tier


def get_multiplier(hostname: str) -> float:
    """
    Get the risk multiplier for a hostname.
    Used by risk_scorer.py to weight vulnerability scores
    based on asset criticality.

    Args:
        hostname: Full hostname e.g. "vpn.example.com"

    Returns:
        Float multiplier (1.0 to 1.5)
    """
    tier, _ = classify_asset_tier(hostname)
    return TIER_MULTIPLIERS.get(tier, 1.0)