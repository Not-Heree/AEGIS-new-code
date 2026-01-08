# remediation.py

REMEDIATION_DB = {
    "git-config": {
        "title": "Exposed .git Directory",
        "severity": "High",
        "mitre_id": "T1003.006",
        "fix": "Configure web server to deny access to .git folder."
    },
    "default-login": {
        "title": "Default Credentials",
        "severity": "Critical",
        "mitre_id": "T1078",
        "fix": "Change default passwords immediately."
    }
}

# --- THIS FUNCTION MUST EXIST ---
def get_remediation(template_id):
    if template_id in REMEDIATION_DB:
        return REMEDIATION_DB[template_id]
    
    # Fallback
    return {
        "title": f"Detected: {template_id}",
        "severity": "Unknown",
        "mitre_id": "N/A",
        "fix": "Refer to vendor documentation."
    }