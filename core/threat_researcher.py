"""
Threat Researcher — Template-Specific Intelligence Engine
==========================================================

Provides deep, actionable intelligence for Nuclei template findings
by maintaining a local knowledge base of:
  - Business impact descriptions (exec-readable)
  - Step-by-step remediation guides
  - MITRE ATT&CK technique mapping
  - CWE classification
  - Curated references
  - Real-world threat context

This module is PURELY LOCAL — no API calls, no network.
Designed for <1ms per lookup.
"""

from typing import Dict, Any, Optional, List
from utils.logger import logger


# =============================================================================
# TEMPLATE INTELLIGENCE KNOWLEDGE BASE
# =============================================================================

# Each entry maps a Nuclei template_id (or keyword) to rich intelligence.
# Fields:
#   business_impact   — exec-level description of the risk
#   remediation_steps — ordered list of concrete fix actions
#   references        — curated URLs with source labels
#   mitre_attack      — MITRE ATT&CK technique(s)
#   cwe_guidance      — CWE classification
#   threat_indicators — contextual threat signals
#   technical_details — deep technical explanation

_TEMPLATE_KB: Dict[str, Dict[str, Any]] = {

    # ─── Cloud Misconfigurations ──────────────────────────────
    "aws-object-listing": {
        "business_impact": (
            "An Amazon S3 bucket is publicly accessible and allows anyone on the internet "
            "to enumerate its contents. Attackers can discover sensitive files (backups, configs, "
            "credentials, PII) without authentication. This is a common precursor to data breaches "
            "and has been the root cause of major incidents including Capital One (2019) and "
            "Twitch (2021)."
        ),
        "remediation_steps": [
            {
                "title": "Block Public Access",
                "detail": "Enable S3 Block Public Access at the account level: "
                          "AWS Console → S3 → Block Public Access settings → Enable all 4 options.",
                "priority": "immediate"
            },
            {
                "title": "Review Bucket Policy",
                "detail": "Remove any bucket policy statements that grant s3:ListBucket, "
                          "s3:GetObject, or s3:* to Principal: \"*\" or to the AllUsers/AuthenticatedUsers groups.",
                "priority": "immediate"
            },
            {
                "title": "Principle of Least Privilege",
                "detail": "Configure IAM policies and Bucket Policies to explicitly grant only the necessary access. "
                          "Avoid using wildcard permissions (e.g., s3:* or s3:ListBucket for Principal: *).",
                "priority": "high"
            },
            {
                "title": "Disable ACLs",
                "detail": "AWS now recommends disabling ACLs in favor of using S3 Bucket Policies and IAM "
                          "for access control, as policies provide more granular and auditable control.",
                "priority": "high"
            }
        ],
        "references": [
            {"url": "https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html", "source": "AWS Docs"},
            {"url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/11-Test_Cloud_Storage", "source": "OWASP"},
            {"url": "https://attack.mitre.org/techniques/T1530/", "source": "MITRE ATT&CK"},
        ],
        "mitre_attack": {
            "tactic": "Collection",
            "technique": "T1530",
            "name": "Data from Cloud Storage",
            "description": "Adversaries may access data from cloud storage buckets that are misconfigured to allow public access."
        },
        "cwe_guidance": {
            "id": "CWE-284",
            "name": "Improper Access Control",
            "category": "Cloud Misconfiguration"
        },
        "technical_details": {
            "description": (
                "An S3 bucket listing occurs when the permissions on a bucket are misconfigured to allow public "
                "or overly broad access to the s3:ListBucket API action. While listing the bucket does not "
                "automatically grant access to the content of the files, it reveals the directory structure, "
                "file naming conventions, and existence of specific files. This data is invaluable to an attacker "
                "for planning further attacks (e.g., identifying predictable file paths or sensitive backups)."
            ),
            "attack_vector": "Remote Unauthenticated Enumeration",
            "compliance_impact": "GDPR, HIPAA, PCI DSS (Information Disclosure)"
        },
        "threat_indicators": [
            "Cloud storage publicly enumerable",
            "Potential data exposure to unauthenticated users",
        ]
    },

    "http-directory-listing": {
        "business_impact": (
            "Web server directory listing is enabled, allowing anyone to view the file structure and "
            "download sensitive files directly from the web browser. This can expose source code, "
            "configuration backups, and internal documentation."
        ),
        "remediation_steps": [
            {
                "title": "Disable Indexing",
                "detail": "Disable the 'AutoIndex' (Apache) or 'Directory Browsing' (IIS) settings in the web server configuration.",
                "priority": "immediate"
            },
            {
                "title": "Use Index Files",
                "detail": "Ensure every directory contains a default index file (e.g., index.html) to prevent the server from generating a listing.",
                "priority": "high"
            }
        ],
        "references": [
            {"url": "https://owasp.org/www-community/attacks/Directory_indexing", "source": "OWASP"},
            {"url": "https://cwe.mitre.org/data/definitions/548.html", "source": "CWE"}
        ],
        "cwe_guidance": {
            "id": "CWE-548",
            "name": "Information Exposure Through Indexing",
            "category": "Information Disclosure"
        },
        "technical_details": {
            "description": (
                "The web server is configured to generate an HTML index of files in a directory when no "
                "default index file (e.g., index.php, index.html) is present. Attackers can crawl this "
                "index to find hidden files, backup scripts, and sensitive configuration data."
            ),
            "attack_vector": "Web Browser Enumeration",
            "compliance_impact": "Information Disclosure"
        }
    },

    "exposed-env-file": {
        "business_impact": (
            "An environment configuration file (.env) is publicly accessible. These files typically "
            "contain sensitive secrets such as database credentials, API keys (AWS, Stripe, SendGrid), "
            "and application secrets. Exposure leads to immediate and full system compromise."
        ),
        "remediation_steps": [
            {
                "title": "Restrict Access Immediately",
                "detail": "Configure the web server (Nginx/Apache) to deny all requests to files starting with a dot (.).",
                "priority": "immediate"
            },
            {
                "title": "Rotate All Credentials",
                "detail": "Assume all keys in the exposed file are compromised. Rotate every API key, database password, and secret found in the file.",
                "priority": "immediate"
            }
        ],
        "references": [
            {"url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information", "source": "OWASP"}
        ],
        "cwe_guidance": {
            "id": "CWE-530",
            "name": "Exposure of Backup File to an Unauthorized Control Sphere",
            "category": "Information Disclosure"
        },
        "technical_details": {
            "description": (
                "The web server is serving dot-files (files starting with a period) which are intended for "
                "local configuration only. Attackers use automated scanners to find /.env, /.git, and /config.php.dist "
                "to exfiltrate infrastructure credentials."
            ),
            "attack_vector": "Direct URL Access",
            "compliance_impact": "Loss of Confidentiality, Critical Infrastructure Risk"
        }
    },

    "exposed-git-config": {
        "business_impact": (
            "The .git directory is publicly accessible, allowing anyone to download the entire source code "
            "history of your application. This can reveal hardcoded credentials, internal documentation, "
            "and sensitive logic used for authentication and data processing."
        ),
        "remediation_steps": [
            {
                "title": "Block .git Access",
                "detail": "Update web server configuration to deny all access to the /.git/ directory and its contents.",
                "priority": "immediate"
            },
            {
                "title": "Clean Web Root",
                "detail": "Remove the .git directory from the production web root. Use a proper deployment process (e.g., git archive) that excludes control directories.",
                "priority": "high"
            }
        ],
        "references": [
            {"url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information", "source": "OWASP"}
        ],
        "cwe_guidance": {
            "id": "CWE-538",
            "name": "Insertion of Sensitive Information into Externally-Accessible File or Directory",
            "category": "Information Disclosure"
        },
        "technical_details": {
            "description": (
                "Exposure of the /.git/ directory allows an attacker to reconstruct the source code via "
                "tools like 'git-dumper'. This bypasses all obfuscation and provides a roadmap for finding "
                "vulnerabilities within the application logic."
            ),
            "attack_vector": "Remote Git Reconstruction",
            "compliance_impact": "Intellectual Property Theft, Information Disclosure"
        }
    },

    "insecure-cors-policy": {
        "business_impact": (
            "The Cross-Origin Resource Sharing (CORS) policy is configured with a wildcard (*) or allows "
            "arbitrary origins. This enables an attacker to perform Cross-Site Request Forgery (CSRF) "
            "and steal sensitive user data (like session cookies or dynamic content) from a malicious site."
        ),
        "remediation_steps": [
            {
                "title": "Define Trusted Origins",
                "detail": "Replace 'Access-Control-Allow-Origin: *' with an explicit list of authorized domains.",
                "priority": "immediate"
            },
            {
                "title": "Restrict Credentials",
                "detail": "Avoid using 'Access-Control-Allow-Credentials: true' unless the origin is strictly validated and trusted.",
                "priority": "high"
            }
        ],
        "references": [
            {"url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing", "source": "OWASP"}
        ],
        "cwe_guidance": {
            "id": "CWE-942",
            "name": "Permissive List of Allowed Origins",
            "category": "Broken Access Control"
        },
        "technical_details": {
            "description": (
                "CORS misconfigurations occur when the server trusts any origin. An attacker can host a "
                "malicious page that makes authenticated requests to your API, exfiltrating responses "
                "because the browser respects the overly permissive 'Access-Control-Allow-Origin' header."
            ),
            "attack_vector": "Cross-Origin Data Exfiltration",
            "compliance_impact": "Broken Access Control, Session Theft"
        }
    },

    # ─── Subdomain Takeover ───────────────────────────────────
    "takeover": {
        "business_impact": (
            "A subdomain is pointing to a deprovisioned cloud service (e.g., S3 bucket, "
            "Heroku app, Azure, GitHub Pages) that no longer exists. An attacker can claim "
            "the abandoned resource and serve arbitrary content under your domain, enabling "
            "phishing, cookie theft, and full brand impersonation."
        ),
        "remediation_steps": [
            {
                "title": "Remove Dangling DNS Record",
                "detail": "Delete the CNAME/A record pointing to the deprovisioned service. "
                          "This is the fastest and most effective fix.",
                "priority": "immediate"
            },
            {
                "title": "Re-provision the Service",
                "detail": "If the subdomain is still needed, re-create the cloud resource "
                          "that the DNS record points to.",
                "priority": "immediate"
            },
            {
                "title": "Audit All DNS Records",
                "detail": "Review all DNS records for the domain to identify other dangling "
                          "CNAMEs pointing to deprovisioned services.",
                "priority": "high"
            },
        ],
        "references": [
            {"url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover", "source": "OWASP"},
            {"url": "https://developer.mozilla.org/en-US/docs/Web/Security/Subdomain_takeovers", "source": "MDN"},
            {"url": "https://github.com/EdOverflow/can-i-take-over-xyz", "source": "Community"},
        ],
        "mitre_attack": {
            "tactic": "Resource Development",
            "technique": "T1584.001",
            "name": "Compromise Infrastructure: Domains",
            "description": "Adversaries may hijack domains and/or subdomains to stage attacks."
        },
        "cwe_guidance": {
            "id": "CWE-284",
            "name": "Improper Access Control",
            "category": "DNS Misconfiguration"
        },
        "threat_indicators": [
            "Dangling DNS record to deprovisioned service",
            "Full domain impersonation possible",
        ],
    },

    # ─── SQL Injection ────────────────────────────────────────
    "sqli": {
        "business_impact": (
            "A SQL injection vulnerability allows attackers to execute arbitrary database queries. "
            "This can lead to unauthorized data extraction (customer PII, credentials), data "
            "modification or deletion, authentication bypass, and in some cases remote code execution "
            "on the database server."
        ),
        "remediation_steps": [
            {
                "title": "Use Parameterized Queries",
                "detail": "Replace all string concatenation in SQL queries with parameterized "
                          "statements (prepared statements). This is the primary and most effective fix.",
                "priority": "immediate"
            },
            {
                "title": "Apply Input Validation",
                "detail": "Implement server-side input validation and sanitization. "
                          "Use allowlist validation where possible.",
                "priority": "high"
            },
            {
                "title": "Apply Least Privilege",
                "detail": "Database accounts used by the application should have minimal permissions. "
                          "Never use sa/root/admin database accounts from the application.",
                "priority": "high"
            },
            {
                "title": "Deploy WAF Rules",
                "detail": "As an interim measure, deploy Web Application Firewall rules to "
                          "block common SQLi patterns while the code fix is being implemented.",
                "priority": "standard"
            },
        ],
        "references": [
            {"url": "https://owasp.org/www-community/attacks/SQL_Injection", "source": "OWASP"},
            {"url": "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html", "source": "OWASP"},
            {"url": "https://attack.mitre.org/techniques/T1190/", "source": "MITRE ATT&CK"},
        ],
        "mitre_attack": {
            "tactic": "Initial Access",
            "technique": "T1190",
            "name": "Exploit Public-Facing Application",
        },
        "cwe_guidance": {
            "id": "CWE-89",
            "name": "SQL Injection",
            "category": "Injection"
        },
        "threat_indicators": [
            "Database query injection confirmed",
            "Potential for full data exfiltration",
        ],
    },

    # ─── XSS ─────────────────────────────────────────────────
    "xss": {
        "business_impact": (
            "A Cross-Site Scripting vulnerability allows attackers to inject and execute "
            "malicious JavaScript in users' browsers. This enables session hijacking, "
            "credential theft, keylogging, phishing within the trusted domain, and "
            "defacement."
        ),
        "remediation_steps": [
            {
                "title": "Encode Output",
                "detail": "Apply context-sensitive output encoding for all user-controlled data "
                          "rendered in HTML, JavaScript, CSS, or URL contexts.",
                "priority": "immediate"
            },
            {
                "title": "Implement CSP",
                "detail": "Deploy a Content-Security-Policy header that restricts inline scripts "
                          "and limits script sources to trusted domains.",
                "priority": "high"
            },
            {
                "title": "Validate Input",
                "detail": "Apply server-side input validation using allowlists. "
                          "Reject unexpected characters and HTML tags.",
                "priority": "high"
            },
        ],
        "references": [
            {"url": "https://owasp.org/www-community/attacks/xss/", "source": "OWASP"},
            {"url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html", "source": "OWASP"},
        ],
        "mitre_attack": {
            "tactic": "Initial Access",
            "technique": "T1189",
            "name": "Drive-by Compromise",
        },
        "cwe_guidance": {
            "id": "CWE-79",
            "name": "Cross-site Scripting (XSS)",
            "category": "Injection"
        },
        "threat_indicators": ["Client-side code execution in user browsers"],
    },

    # ─── SSRF ────────────────────────────────────────────────
    "ssrf": {
        "business_impact": (
            "Server-Side Request Forgery allows attackers to make the server send HTTP requests "
            "to internal systems, cloud metadata services (169.254.169.254), or other protected "
            "resources. This can expose AWS credentials, internal APIs, and enable lateral movement."
        ),
        "remediation_steps": [
            {
                "title": "Validate & Allowlist URLs",
                "detail": "Restrict outbound requests to a strict allowlist of permitted domains and IPs. "
                          "Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x).",
                "priority": "immediate"
            },
            {
                "title": "Block Metadata Endpoints",
                "detail": "If running in cloud (AWS/GCP/Azure), enforce IMDSv2 and block requests "
                          "to metadata IP 169.254.169.254.",
                "priority": "immediate"
            },
        ],
        "references": [
            {"url": "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery", "source": "OWASP"},
            {"url": "https://attack.mitre.org/techniques/T1090/", "source": "MITRE ATT&CK"},
        ],
        "mitre_attack": {
            "tactic": "Discovery",
            "technique": "T1046",
            "name": "Network Service Discovery (via SSRF)",
        },
        "cwe_guidance": {
            "id": "CWE-918",
            "name": "Server-Side Request Forgery",
            "category": "Injection"
        },
        "threat_indicators": [
            "Server can be used as proxy to internal network",
            "Cloud metadata exposure risk",
        ],
    },

    # ─── Exposed Panels / Admin Interfaces ────────────────────
    "exposed": {
        "business_impact": (
            "An internal administrative interface or sensitive panel is exposed to the public "
            "internet. This significantly increases the attack surface by providing attackers "
            "with direct access to management functionality, often protected only by default "
            "or weak credentials."
        ),
        "remediation_steps": [
            {
                "title": "Restrict Network Access",
                "detail": "Move the admin panel behind a VPN, IP allowlist, or zero-trust gateway. "
                          "It should not be accessible from the public internet.",
                "priority": "immediate"
            },
            {
                "title": "Enforce Strong Auth",
                "detail": "Enable MFA/2FA on the admin interface. Ensure default credentials "
                          "have been changed. Implement account lockout after failed attempts.",
                "priority": "high"
            },
        ],
        "references": [
            {"url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/", "source": "OWASP"},
        ],
        "cwe_guidance": {
            "id": "CWE-200",
            "name": "Exposure of Sensitive Information",
            "category": "Information Disclosure"
        },
        "threat_indicators": ["Administrative interface publicly accessible"],
    },

    # ─── Default Credentials ──────────────────────────────────
    "default-login": {
        "business_impact": (
            "The system is accessible using factory-default credentials. This allows immediate, "
            "unauthenticated access to administrative functions. Default credential attacks are "
            "fully automated and are among the first techniques used by both opportunistic "
            "scanners and targeted attackers."
        ),
        "remediation_steps": [
            {
                "title": "Change Default Credentials Immediately",
                "detail": "Replace default username/password with strong, unique credentials. "
                          "Use a password manager to generate and store complex passwords.",
                "priority": "immediate"
            },
            {
                "title": "Disable Default Accounts",
                "detail": "Where possible, completely disable default/built-in accounts "
                          "and create new named accounts with appropriate permissions.",
                "priority": "immediate"
            },
        ],
        "references": [
            {"url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/02-Testing_for_Default_Credentials", "source": "OWASP"},
        ],
        "cwe_guidance": {
            "id": "CWE-798",
            "name": "Use of Hard-coded Credentials",
            "category": "Authentication"
        },
        "threat_indicators": [
            "System accessible with factory-default credentials",
            "Fully automated exploitation possible",
        ],
    },

    # ─── LFI ──────────────────────────────────────────────────
    "lfi": {
        "business_impact": (
            "Local File Inclusion allows attackers to read arbitrary files from the server, "
            "including configuration files, credentials, application source code, and system "
            "files like /etc/passwd. In some cases, LFI can be escalated to Remote Code Execution."
        ),
        "remediation_steps": [
            {
                "title": "Validate File Paths",
                "detail": "Never use user input directly in file path operations. Use an allowlist "
                          "of permitted files, or map user input to predefined file identifiers.",
                "priority": "immediate"
            },
            {
                "title": "Chroot/Sandbox",
                "detail": "Restrict the application's file system access to a specific directory tree "
                          "using chroot, containers, or OS-level sandboxing.",
                "priority": "high"
            },
        ],
        "references": [
            {"url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion", "source": "OWASP"},
        ],
        "cwe_guidance": {
            "id": "CWE-98",
            "name": "Improper Control of Filename for Include",
            "category": "Path Traversal"
        },
        "threat_indicators": ["Arbitrary file read from server filesystem"],
    },

    # ─── .env / Config File Exposure ──────────────────────────
    "env": {
        "business_impact": (
            "A .env or configuration file containing sensitive credentials (API keys, "
            "database passwords, secret keys) is publicly accessible. Attackers can use "
            "these credentials to access cloud services, databases, or escalate access "
            "within the application."
        ),
        "remediation_steps": [
            {
                "title": "Remove Public Access",
                "detail": "Add rules to your web server config to deny access to .env, .git, "
                          "and other sensitive files. For nginx: location ~ /\\.env { deny all; }",
                "priority": "immediate"
            },
            {
                "title": "Rotate All Exposed Credentials",
                "detail": "Every credential in the exposed file must be rotated immediately — "
                          "API keys, database passwords, secret keys, tokens.",
                "priority": "immediate"
            },
            {
                "title": "Move Secrets to Vault",
                "detail": "Migrate secrets from .env files to a secrets management service "
                          "(AWS Secrets Manager, HashiCorp Vault, Azure Key Vault).",
                "priority": "standard"
            },
        ],
        "references": [
            {"url": "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces", "source": "OWASP"},
        ],
        "cwe_guidance": {
            "id": "CWE-200",
            "name": "Exposure of Sensitive Information",
            "category": "Information Disclosure"
        },
        "threat_indicators": [
            "Credentials exposed in publicly accessible file",
            "Immediate credential rotation required",
        ],
    },

    # ─── WordPress Vulnerabilities ────────────────────────────
    "wordpress": {
        "business_impact": (
            "A vulnerability has been identified in a WordPress installation, plugin, or theme. "
            "WordPress powers ~43%% of the web and is a high-priority target. Exploitation can "
            "lead to site defacement, malware injection, data theft, or full server compromise."
        ),
        "remediation_steps": [
            {
                "title": "Update WordPress Core",
                "detail": "Update to the latest WordPress version. Enable automatic minor updates.",
                "priority": "immediate"
            },
            {
                "title": "Update/Remove Vulnerable Plugin",
                "detail": "Update the identified plugin/theme to the latest version, "
                          "or remove it if no longer maintained.",
                "priority": "immediate"
            },
            {
                "title": "Harden WordPress",
                "detail": "Disable XML-RPC if not needed, restrict wp-admin access, "
                          "enforce strong passwords, and use a WAF plugin.",
                "priority": "standard"
            },
        ],
        "references": [
            {"url": "https://developer.wordpress.org/advanced-administration/security/hardening/", "source": "WordPress"},
            {"url": "https://owasp.org/www-project-web-security-testing-guide/", "source": "OWASP"},
        ],
        "cwe_guidance": {
            "id": "CWE-1104",
            "name": "Use of Unmaintained Third-Party Components",
            "category": "Software Composition"
        },
        "threat_indicators": ["CMS vulnerability in widely-targeted platform"],
    },
}


# =============================================================================
# THREAT RESEARCHER CLASS
# =============================================================================

class ThreatResearcher:
    """
    Local threat intelligence engine for Nuclei template findings.

    Provides rich, actionable intelligence without any network calls.
    Designed for on-demand enrichment of the vulnerability detail view.
    """

    @staticmethod
    def research(vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Look up deep intelligence for a vulnerability based on its template_id.

        Args:
            vuln: Vulnerability dict from database

        Returns:
            Intelligence dict with business_impact, remediation_steps,
            references, mitre_attack, cwe_guidance, etc.
            Returns None if no template-specific intel is available.
        """
        template_id = vuln.get("template_id", "").lower()

        if not template_id:
            return None

        # ── Direct match first ────────────────────────────────
    @staticmethod
    def _build_keyword_fallback(template_id: str, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dynamically synthesize a technical narrative based on vulnerability keywords.
        """
        tid = template_id.lower()
        severity = vuln.get("severity", "info").lower()

        # Classification mapping
        classes = {
            "sqli": "SQL Injection",
            "xss": "Cross-Site Scripting (XSS)",
            "lfi": "Local File Inclusion",
            "rce": "Remote Code Execution",
            "ssrf": "Server-Side Request Forgery",
            "takeover": "Subdomain Takeover",
            "exposure": "Information Exposure",
            "disclosure": "Information Disclosure",
            "misconfig": "Security Misconfiguration",
            "auth": "Broken Access Control",
            "redirect": "Open Redirect",
            "cve": "Software Vulnerability (CVE)"
        }

        vuln_type = "Security Vulnerability"
        for key, name in classes.items():
            if key in tid:
                vuln_type = name
                break

        intel = _build_severity_fallback(severity, vuln)
        intel["technical_details"] = {
            "description": f"This is a {vuln_type} within the target system infrastructure. "
                           f"The identifier '{template_id}' indicates a specific security check "
                           "was triggered during the automated scan.",
            "attack_vector": "Automated Exploit Discovery",
            "compliance_impact": "Potential loss of confidentiality and integrity."
        }
        return intel

    @staticmethod
    def research(vuln: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get rich intelligence for a vulnerability finding."""
        template_id = vuln.get("template_id", "").lower()
        if not template_id:
            return None

        # ── Direct match ──────────────────────────────────────
        if template_id in _TEMPLATE_KB:
            logger.debug("[THREAT-RESEARCH] Direct KB match: %s", template_id)
            return _TEMPLATE_KB[template_id].copy()

        # ── Keyword match (partial) ───────────────────────────
        for keyword, intel in _TEMPLATE_KB.items():
            if keyword in template_id:
                logger.debug(
                    "[THREAT-RESEARCH] Keyword match: '%s' in '%s'",
                    keyword, template_id
                )
                return intel.copy()

        # ── Universal Keyword Fallback ───────────────────────
        return ThreatResearcher._build_keyword_fallback(template_id, vuln)

    @staticmethod
    def get_remediation_steps(template_id: str) -> List[Dict[str, str]]:
        """Get just the remediation steps for a template."""
        template_id = template_id.lower()

        for keyword, intel in _TEMPLATE_KB.items():
            if keyword in template_id or template_id == keyword:
                return intel.get("remediation_steps", [])

        return []

    @staticmethod
    def get_references(template_id: str) -> List[Dict[str, str]]:
        """Get curated references for a template."""
        template_id = template_id.lower()

        for keyword, intel in _TEMPLATE_KB.items():
            if keyword in template_id or template_id == keyword:
                return intel.get("references", [])

        return []

    @staticmethod
    def _build_keyword_fallback(template_id: str, vuln: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dynamically synthesize intelligence for unknown templates
        using keyword pattern recognition.
        """
        severity = vuln.get("severity", "low").lower()

        # 1. Define Universal Intelligence Patterns
        patterns = {
            "sqli": {
                "business_impact": "Unauthorized database access. Attackers can query, extract, or delete sensitive backend data including credentials and PII.",
                "threat_indicators": ["Database-level interaction detected", "Input validation failure"]
            },
            "xss": {
                "business_impact": "Client-side execution risk. Enables session hijacking, credential theft, and unauthorized actions in the context of a user's browser.",
                "threat_indicators": ["Malicious script injection potential", "Session security risk"]
            },
            "ssrf": {
                "business_impact": "Server-side request forgery. Allows attackers to use the server as a proxy to scan internal networks or access sensitive metadata services.",
                "threat_indicators": ["Internal network pivoting risk", "Cloud metadata exposure"]
            },
            "lfi": {
                "business_impact": "Unauthorized file disclosure. Attackers can read sensitive system files (e.g., /etc/passwd, .env) directly from the server.",
                "threat_indicators": ["System file read capability", "Credential exposure risk"]
            },
            "exposed": {
                "business_impact": "Information disclosure of internal assets. Critical diagnostics or administrative interfaces are accessible to the public internet.",
                "threat_indicators": ["Administrative interface exposure", "Reconnaissance data leakage"]
            },
            "rce": {
                "business_impact": "Full system compromise. Attackers can execute arbitrary commands on the server, leading to total takeover and persistence.",
                "threat_indicators": ["Remote command execution", "Critical system control loss"]
            }
        }

        # 2. Try to match patterns in template_id or name
        vuln_name = vuln.get("name", "").lower()
        for key, intel in patterns.items():
            if key in template_id or key in vuln_name:
                # Merge with severity-based remediation
                base = _build_severity_fallback(severity, vuln)
                base.update(intel)
                return base

        # 3. Ultimate Fallback (Severity only)
        return _build_severity_fallback(severity, vuln)


def _build_severity_fallback(
    severity: str, vuln: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Build generic but useful intelligence based on severity
    when no template-specific KB entry exists.
    """
    template_id = vuln.get("template_id", "unknown")
    description = vuln.get("description", "")

    severity_map = {
        "critical": {
            "business_impact": (
                f"A critical-severity vulnerability ({template_id}) has been identified. "
                "Critical findings typically allow unauthenticated remote code execution, "
                "full system compromise, or mass data exfiltration. "
                "Immediate remediation is required."
            ),
            "remediation_steps": [
                {
                    "title": "Investigate Immediately",
                    "detail": f"Review the Nuclei finding details for '{template_id}' and "
                              "assess the scope of impact on production systems.",
                    "priority": "immediate"
                },
                {
                    "title": "Apply Patch or Workaround",
                    "detail": "Check the vendor advisory for available patches. If no patch "
                              "exists, implement the recommended workaround or disable the "
                              "affected service.",
                    "priority": "immediate"
                },
            ],
        },
        "high": {
            "business_impact": (
                f"A high-severity vulnerability ({template_id}) has been identified. "
                "High-severity findings can lead to significant data exposure, privilege "
                "escalation, or service disruption. Prioritize remediation within 7 days."
            ),
            "remediation_steps": [
                {
                    "title": "Assess & Remediate",
                    "detail": f"Review the technical details for '{template_id}' and apply "
                              "the vendor-recommended fix or configuration change.",
                    "priority": "high"
                },
            ],
        },
        "medium": {
            "business_impact": (
                f"A medium-severity vulnerability ({template_id}) has been identified. "
                "While not immediately exploitable, it may contribute to a larger attack "
                "chain or information disclosure. Schedule remediation within 30 days."
            ),
            "remediation_steps": [
                {
                    "title": "Schedule Fix",
                    "detail": f"Plan remediation for '{template_id}' in the next sprint cycle. "
                              "Review the Nuclei template documentation for fix guidance.",
                    "priority": "standard"
                },
            ],
        },
        "low": {
            "business_impact": (
                f"A low-severity finding ({template_id}) has been identified. "
                "This typically represents an informational issue or minor misconfiguration "
                "that has limited direct security impact but should be addressed as part "
                "of security hardening."
            ),
            "remediation_steps": [
                {
                    "title": "Address in Regular Maintenance",
                    "detail": f"Include '{template_id}' remediation in the next maintenance "
                              "window. Review the finding to confirm it does not contribute "
                              "to a larger attack chain.",
                    "priority": "standard"
                },
            ],
        },
    }

    return severity_map.get(severity, severity_map.get("low", {}))
