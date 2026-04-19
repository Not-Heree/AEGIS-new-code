
import sys
import os
from jinja2 import Environment, FileSystemLoader

# Mock Objects for Vulnerability
class ObjectView(object):
    def __init__(self, d):
        self.__dict__ = d

def render_vuln(vuln_data):
    # Setup Jinja2
    template_dir = 'templates'
    env = Environment(loader=FileSystemLoader(template_dir))
    
    # Mock 'tojson' filter
    import json
    env.filters['tojson'] = lambda d, indent=None: json.dumps(d, indent=indent)

    try:
        template = env.get_template('vulnerability_detail.html')
        # We need to wrap and mock internal structures like 'vuln.enrichment'
        # Jinja2 access vuln.enrichment or {}
        # So providing a dict-like object is fine for simple access, 
        # but the template uses both dot notation and brackets.
        # We'll use a recursive dict-to-object wrapper.
        
        def wrap(data):
            if isinstance(data, dict):
                return ObjectView({k: wrap(v) for k, v in data.items()})
            if isinstance(data, list):
                return [wrap(v) for v in data]
            return data

        vuln_obj = wrap(vuln_data)
        
        output = template.render(vuln=vuln_obj)
        return output
    except Exception as e:
        return f"ERROR: {str(e)}"

# TEST CASES
# 1. CVE-backed KEV finding
kev_vuln = {
    "name": "Log4Shell RCE",
    "severity": "critical",
    "host": "logs.target.com",
    "cve_id": "CVE-2021-44228",
    "enrichment": {
        "kev_status": {"actively_exploited": True},
        "epss": {"score": "0.97", "percentage": 97, "explanation": "High probability of attack."},
        "smart_brief": {
            "executive_metrics": {"fix_deadline": "24 Hours"},
            "business_impact": "Full takeover of log processing server.",
            "recommended_action": "Apply immediate patch to log4j 2.17.1",
            "technical_narrative": "Remote code execution via JNDI lookup."
        }
    }
}

# 2. Template-based cloud misconfiguration
cloud_vuln = {
    "name": "AWS S3 Public Access",
    "severity": "high",
    "host": "prod-data.s3.amazonaws.com",
    "template_id": "aws-s3-public",
    "enrichment": {
        "smart_brief": {
            "executive_metrics": {"fix_deadline": "48 Hours"},
            "business_impact": "Exposure of sensitive customer PII.",
            "recommended_action": "Enable block public access on bucket.",
            "technical_narrative": "S3 bucket policies allow 'AllUsers' to perform 's3:ListBucket'."
        }
    }
}

# 3. Minimal finding
minimal_vuln = {
    "name": "Generic Finding",
    "severity": "medium",
    "host": "dev.local",
    "enrichment": None # Testing safety defaults
}

print("--- TESTING CASE 1: KEV ---")
res1 = render_vuln(kev_vuln)
if "ACTIVELY EXPLOITED" in res1: print("SUCCESS: KEV Badge found.")
else: print("FAILURE: KEV Badge MISSING.")

print("\n--- TESTING CASE 2: CLOUD ---")
res2 = render_vuln(cloud_vuln)
if "Exposure of sensitive customer PII" in res2: print("SUCCESS: Technical Narrative found.")
else: print("FAILURE: Technical Narrative MISSING.")

print("\n--- TESTING CASE 3: MINIMAL ---")
res3 = render_vuln(minimal_vuln)
if "Generic Security Finding" in res3: print("SUCCESS: Fallback Name found.")
if "Consult internal security policy" in res3: print("SUCCESS: Fallback Deadline found.")
if "ERROR" in res3: print(f"FAILURE: Crashed - {res3}")
else: print("SUCCESS: Rendered without Jinja2 errors.")
