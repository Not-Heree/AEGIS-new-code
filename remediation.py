"""
AEGIS - Remediation Knowledge Base
==================================
This module provides a static lookup table that maps Nuclei template IDs
to human-readable remediation advice. When a vulnerability is found,
scanner.py queries this database to enrich the finding with:
    - A clear title
    - MITRE ATT&CK technique ID (for framework mapping)
    - Actionable fix instructions

This approach keeps remediation advice centralized and easy to update
without modifying the core scanning logic.
"""

from typing import Dict, Any


# =============================================================================
# REMEDIATION DATABASE
# =============================================================================
# This dictionary maps known Nuclei template IDs to structured fix advice.
# Each entry contains:
#   - title: Human-readable name for the vulnerability.
#   - severity: The expected severity level.
#   - mitre_id: The MITRE ATT&CK technique ID for threat mapping.
#   - fix: Step-by-step instructions to remediate the issue.
# =============================================================================

REMEDIATION_DB: Dict[str, Dict[str, str]] = {
    # -------------------------------------------------------------------------
    # CONFIGURATION ISSUES
    # These are misconfigurations that expose sensitive files or directories.
    # -------------------------------------------------------------------------
    "git-config": {
        "title": "Exposed .git Directory",
        "severity": "High",
        "mitre_id": "T1003.006",
        "fix": "Configure web server to deny access to .git folder. Remove .git from production server."
    },
    "env-file": {
        "title": "Exposed .env File",
        "severity": "Critical",
        "mitre_id": "T1552.001",
        "fix": "Remove .env file from public directory. Ensure it is added to .gitignore."
    },
    "ds-store": {
        "title": "Exposed .DS_Store",
        "severity": "Low",
        "mitre_id": "T1005",
        "fix": "Remove .DS_Store files from web root. Configure server to block access."
    },
    "htaccess-file": {
        "title": "Exposed .htaccess",
        "severity": "Medium",
        "mitre_id": "T1005",
        "fix": "Configure web server (Apache) to deny access to .htaccess files."
    },

    # -------------------------------------------------------------------------
    # DEFAULT CREDENTIALS
    # These findings indicate services running with known default passwords.
    # -------------------------------------------------------------------------
    "default-login": {
        "title": "Default Credentials",
        "severity": "Critical",
        "mitre_id": "T1078",
        "fix": "Change default passwords immediately for the detected service."
    },
    "jenkins-default-login": {
        "title": "Jenkins Default Credentials",
        "severity": "Critical",
        "mitre_id": "T1078",
        "fix": "Secure Jenkins instance. Update admin password."
    },

    # -------------------------------------------------------------------------
    # INFORMATION DISCLOSURE
    # These expose internal server information to attackers.
    # -------------------------------------------------------------------------
    "phpinfo-files": {
        "title": "PHP Info File Exposed",
        "severity": "Medium",
        "mitre_id": "T1592",
        "fix": "Remove phpinfo() files from production. They disclose server configuration."
    },
    "apache-status": {
        "title": "Apache Server Status Exposed",
        "severity": "Low",
        "mitre_id": "T1592",
        "fix": "Restrict access to /server-status in httpd.conf."
    },
    "springboot-actuator": {
        "title": "Spring Boot Actuator Exposed",
        "severity": "High",
        "mitre_id": "T1592",
        "fix": "Secure Actuator endpoints. Disable unnecessary endpoints in application.properties."
    },
    "swagger-api": {
        "title": "Swagger API Docs Exposed",
        "severity": "Info",
        "mitre_id": "T1592",
        "fix": "Ensure API documentation is not exposing sensitive endpoints without authentication."
    },

    # -------------------------------------------------------------------------
    # VULNERABILITIES
    # Classic web application security flaws.
    # -------------------------------------------------------------------------
    "xss-reflected": {
        "title": "Reflected Cross-Site Scripting (XSS)",
        "severity": "Medium",
        "mitre_id": "T1189",
        "fix": "Implement strict input validation and output encoding. Use Content-Security-Policy (CSP)."
    },
    "sql-injection": {
        "title": "SQL Injection",
        "severity": "Critical",
        "mitre_id": "T1190",
        "fix": "Use prepared statements (parameterized queries). Validate all user inputs."
    },
    "open-redirect": {
        "title": "Open Redirect",
        "severity": "Medium",
        "mitre_id": "T1608.002",
        "fix": "Validate redirect targets against an allowlist of trusted domains."
    },
    "cors-misconfig": {
        "title": "CORS Misconfiguration",
        "severity": "High",
        "mitre_id": "T1190",
        "fix": "Restrict Access-Control-Allow-Origin to trusted domains. Do not use '*' with credentials."
    },
    "missing-security-headers": {
        "title": "Missing Security Headers",
        "severity": "Low",
        "mitre_id": "T1592",
        "fix": "Add HSTS, X-Frame-Options, X-Content-Type-Options, and CSP headers."
    },

    # -------------------------------------------------------------------------
    # TECHNOLOGY DETECTION (Informational)
    # These are not vulnerabilities but provide useful reconnaissance info.
    # -------------------------------------------------------------------------
    "tech-detect": {
        "title": "Technology Detected",
        "severity": "Info",
        "mitre_id": "T1592",
        "fix": "Information only. Keep software versions up to date."
    },
    "subdomain-takeover-detection": {
        "title": "Subdomain Takeover Possible",
        "severity": "High",
        "mitre_id": "T1584.004",
        "fix": "Claim the dangling resource pointed to by the CNAME record or remove the DNS entry."
    },

    # -------------------------------------------------------------------------
    # CRYPTOGRAPHY
    # SSL/TLS certificate and encryption issues.
    # -------------------------------------------------------------------------
    "ssl-issuer": {
        "title": "SSL Certificate Info",
        "severity": "Info",
        "mitre_id": "T1592",
        "fix": "Ensure certificate is valid and issued by a trusted CA."
    },
    "expired-ssl": {
        "title": "Expired SSL Certificate",
        "severity": "Medium",
        "mitre_id": "T1592",
        "fix": "Renew the SSL certificate immediately."
    }
}


# =============================================================================
# LOOKUP FUNCTION
# =============================================================================

def get_remediation(template_id: str) -> Dict[str, str]:
    """
    Retrieves remediation advice for a given Nuclei template ID.

    This function performs a lookup in the REMEDIATION_DB dictionary.
    It first tries an exact match, then a partial match (for template
    families like 'jira-detect' matching 'jira'), and finally returns
    a generic fallback if no match is found.

    Args:
        template_id: The Nuclei template ID string (e.g., "git-config").

    Returns:
        A dictionary containing:
            - title: Human-readable name for the vulnerability.
            - severity: The severity level (Critical, High, Medium, Low, Info).
            - mitre_id: The MITRE ATT&CK technique ID.
            - fix: Actionable remediation instructions.

    Example:
        >>> get_remediation("git-config")
        {"title": "Exposed .git Directory", "severity": "High", ...}
    """
    # Strategy 1: Exact match lookup.
    if template_id in REMEDIATION_DB:
        return REMEDIATION_DB[template_id]

    # Strategy 2: Partial/substring match (heuristic).
    # This handles cases where the template ID contains a known key
    # (e.g., "cve-2021-xxxx-sql-injection" matches "sql-injection").
    for key, data in REMEDIATION_DB.items():
        if key in template_id:
            return data

    # Strategy 3: Fallback for unknown templates.
    # Provides a generic response that instructs the user to research further.
    return {
        "title": f"Finding: {template_id}",
        "severity": "Unknown",
        "mitre_id": "T1592",  # Default to "Gather Victim Network Information"
        "fix": "Refer to the tool output and vendor documentation for specific remediation."
    }