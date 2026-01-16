# remediation.py

REMEDIATION_DB = {
    # --- CONFIGURATION ISSUES ---
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
    
    # --- DEFAULT CREDENTIALS ---
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
    
    # --- INFORMATION DISCLOSURE ---
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
    
    # --- VULNERABILITIES ---
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

    # --- TECHNOLOGY DETECTION (Informational) ---
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
    
    # --- CRYPTOGRAPHY ---
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

def get_remediation(template_id):
    """
    Returns remediation details for a given Nuclei template ID.
    Falls back to a generic message if not found.
    """
    # 1. Exact Match
    if template_id in REMEDIATION_DB:
        return REMEDIATION_DB[template_id]
    
    # 2. Key containing match (simple heuristic)
    for key, data in REMEDIATION_DB.items():
        if key in template_id:
            return data

    # 3. Fallback
    return {
        "title": f"Finding: {template_id}",
        "severity": "Unknown",
        "mitre_id": "T1592", # gathered information
        "fix": "Refer to the tool output and vendor documentation for specific remediation."
    }