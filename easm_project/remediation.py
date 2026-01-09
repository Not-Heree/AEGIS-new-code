"""
ARES - Remediation Knowledge Base (remediation.py)
Static Knowledge Base for Vulnerability Remediation

This module contains a dictionary mapping Nuclei Template IDs to detailed
remediation information including:
- Title: Human-readable vulnerability name
- Severity: critical, high, medium, low, info
- MITRE ATT&CK ID: Mapped attack technique
- Description: Explanation of the vulnerability
- Fix Commands: Step-by-step remediation commands
"""


# ==================== REMEDIATION KNOWLEDGE BASE ====================

REMEDIATION_DB = {
    
    # ==================== CRITICAL SEVERITY ====================
    
    "CVE-2021-44228": {
        "title": "Apache Log4j Remote Code Execution (Log4Shell)",
        "severity": "critical",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Apache Log4j2 versions 2.0-beta9 through 2.14.1 are vulnerable to a remote code execution vulnerability where an attacker can execute arbitrary code by sending a specially crafted string that gets logged. This is one of the most severe vulnerabilities discovered in recent years.",
        "fix_commands": """# Step 1: Identify Log4j version in your application
find /path/to/app -name "log4j*.jar" -type f

# Step 2: Upgrade Log4j to version 2.17.1 or later (recommended)
# For Maven projects, update pom.xml:
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.17.1</version>
</dependency>

# Step 3: If immediate upgrade is not possible, apply mitigation
# For Log4j 2.10 and above, set this system property:
-Dlog4j2.formatMsgNoLookups=true

# Step 4: Or set environment variable
LOG4J_FORMAT_MSG_NO_LOOKUPS=true

# Step 5: Restart all affected services
systemctl restart your-java-application"""
    },
    
    "CVE-2021-26855": {
        "title": "Microsoft Exchange Server SSRF (ProxyLogon)",
        "severity": "critical",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "A Server-Side Request Forgery (SSRF) vulnerability in Microsoft Exchange Server allows an attacker to send arbitrary HTTP requests and authenticate as the Exchange server. This can lead to remote code execution when chained with CVE-2021-27065.",
        "fix_commands": """# Step 1: Check Exchange Server version
Get-ExchangeServer | Format-List Name,Edition,AdminDisplayVersion

# Step 2: Download and apply the security update from Microsoft
# Visit: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26855

# Step 3: Apply the Exchange Security Update
# Run Windows Update or download patch manually

# Step 4: Verify the patch is applied
Get-Command Exsetup.exe | ForEach {$_.FileVersionInfo}

# Step 5: Review IIS logs for exploitation attempts
# Look for POST requests to /owa/auth/Current/ or /ecp/"""
    },
    
    "CVE-2023-44487": {
        "title": "HTTP/2 Rapid Reset Attack (DDoS)",
        "severity": "critical",
        "mitre_id": "T1499",
        "mitre_name": "Endpoint Denial of Service",
        "description": "The HTTP/2 protocol allows a denial of service attack because request cancellation can reset many streams quickly. Attackers can open and cancel streams in rapid succession, overwhelming servers.",
        "fix_commands": """# Step 1: For NGINX - Update to latest version and add rate limiting
sudo apt update && sudo apt upgrade nginx

# Add to nginx.conf:
http {
    limit_req_zone $binary_remote_addr zone=http2_limit:10m rate=100r/s;
    
    server {
        limit_req zone=http2_limit burst=200 nodelay;
        http2_max_concurrent_streams 100;
    }
}

# Step 2: For Apache - Update and configure
sudo apt update && sudo apt upgrade apache2

# Step 3: For Node.js applications
npm update

# Step 4: Apply cloud provider mitigations if applicable
# AWS: Enable AWS Shield
# Cloudflare: Enable DDoS protection

# Step 5: Monitor for unusual traffic patterns
tail -f /var/log/nginx/access.log | grep "RST_STREAM" """
    },
    
    "CVE-2021-34473": {
        "title": "Microsoft Exchange Server RCE (ProxyShell)",
        "severity": "critical",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "A pre-authentication path confusion vulnerability in Microsoft Exchange Server allows remote code execution. Part of the ProxyShell attack chain that was actively exploited in the wild.",
        "fix_commands": """# Step 1: Check current Exchange version
Get-ExchangeServer | Format-List Name,Edition,AdminDisplayVersion

# Step 2: Apply Microsoft Security Updates
# Download from: https://support.microsoft.com/en-us/topic/description-of-the-security-update-for-microsoft-exchange-server-2019-2016-and-2013-april-13-2021-kb5001779-8e08f3b3-fc7b-466c-bbb7-5d5aa16ef064

# Step 3: Run Exchange Health Checker
.\\HealthChecker.ps1

# Step 4: Review for indicators of compromise
Get-ChildItem -Recurse -Path "C:\\inetpub\\wwwroot" -Include "*.aspx" | Select-String -Pattern "JScript" 

# Step 5: Enable Extended Protection
Get-WebConfigurationProperty -Filter "//security/authentication/windowsAuthentication" -Name extendedProtection.tokenChecking"""
    },
    
    "CVE-2022-22965": {
        "title": "Spring Framework RCE (Spring4Shell)",
        "severity": "critical",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "A vulnerability in Spring Framework allows remote code execution via data binding when running on JDK 9+. Attackers can modify the class loader and write malicious JSP files.",
        "fix_commands": """# Step 1: Upgrade Spring Framework immediately
# For Maven, update pom.xml:
<dependency>
    <groupId>org.springframework</groupId>
    <artifactId>spring-webmvc</artifactId>
    <version>5.3.18</version>
</dependency>

# Step 2: If using Spring Boot, upgrade to 2.6.6 or 2.5.12
<parent>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-parent</artifactId>
    <version>2.6.6</version>
</parent>

# Step 3: Temporary mitigation - Disallow field binding
@ControllerAdvice
class BinderControllerAdvice {
    @InitBinder
    public void setDisallowedFields(WebDataBinder dataBinder) {
        String[] denyList = new String[]{"class.*", "*.class.*"};
        dataBinder.setDisallowedFields(denyList);
    }
}

# Step 4: Rebuild and redeploy application
mvn clean install
docker-compose down && docker-compose up -d"""
    },
    
    "CVE-2019-19781": {
        "title": "Citrix ADC/Gateway Path Traversal RCE",
        "severity": "critical",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "A vulnerability in Citrix Application Delivery Controller (ADC) and Gateway allows unauthenticated attackers to perform arbitrary code execution through directory traversal.",
        "fix_commands": """# Step 1: Apply the permanent fix - upgrade firmware
# Download from Citrix Support Portal

# Step 2: Temporary mitigation via responder policy
enable ns feature responder
add responder action respondwith403 respondwith "HTTP/1.1 403 Forbidden"
add responder policy block_vpns_urls "HTTP.REQ.URL.DECODE_USING_TEXT_MODE.CONTAINS(\\"/vpns/\\")" respondwith403
bind responder global block_vpns_urls 1 END -type REQ_OVERRIDE
save ns config

# Step 3: Check for indicators of compromise
find /var/vpn/bookmark -name "*.xml" -exec grep -l "NSC_" {} \\;
find /netscaler/portal/scripts -name "*.xml"

# Step 4: Review access logs
cat /var/nslog/ns.log | grep -i "vpns"

# Step 5: If compromised, rebuild from clean image"""
    },
    
    "CVE-2020-1472": {
        "title": "Zerologon - Netlogon Elevation of Privilege",
        "severity": "critical",
        "mitre_id": "T1068",
        "mitre_name": "Exploitation for Privilege Escalation",
        "description": "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller. An attacker who successfully exploits this can run arbitrary code with SYSTEM privileges on domain controllers.",
        "fix_commands": """# Step 1: Apply Windows Security Update immediately
# Run Windows Update or download from Microsoft Update Catalog

# Step 2: Enable enforcement mode (after patching all DCs)
# Registry: HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters
reg add "HKLM\\SYSTEM\\CurrentControlSet\\Services\\Netlogon\\Parameters" /v FullSecureChannelProtection /t REG_DWORD /d 1 /f

# Step 3: Monitor Event Logs for vulnerable connections
# Event ID 5827, 5828 in System log indicate blocked connections

# Step 4: Identify non-compliant devices
Get-WinEvent -FilterHashtable @{LogName='System';Id=5827,5828,5829,5830,5831} | Format-Table TimeCreated,Message

# Step 5: Update all domain controllers
Get-ADDomainController -Filter * | Select-Object Name,OperatingSystem"""
    },
    
    "CVE-2023-23397": {
        "title": "Microsoft Outlook Elevation of Privilege",
        "severity": "critical",
        "mitre_id": "T1187",
        "mitre_name": "Forced Authentication",
        "description": "A vulnerability in Microsoft Outlook allows attackers to steal NTLM hashes by sending a specially crafted email. The attack is triggered when Outlook processes the email, even in the preview pane.",
        "fix_commands": """# Step 1: Apply Microsoft Security Update immediately
# Install KB5023405 for Outlook

# Step 2: Block outbound SMB (TCP 445) to external networks
New-NetFirewallRule -DisplayName "Block Outbound SMB" -Direction Outbound -LocalPort 445 -Protocol TCP -Action Block -Profile Any

# Step 3: Add users to Protected Users security group
Add-ADGroupMember -Identity "Protected Users" -Members "username"

# Step 4: Disable NTLM where possible
# Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options
# Set "Network security: Restrict NTLM" policies

# Step 5: Use Microsoft's CVE-2023-23397 script to find malicious messages
.\\CVE-2023-23397.ps1 -Environment OnPrem"""
    },

    "CVE-2024-3400": {
        "title": "Palo Alto Networks PAN-OS Command Injection",
        "severity": "critical",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software allows an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
        "fix_commands": """# Step 1: Check if GlobalProtect is enabled
show system info | match glob
show system info | match version

# Step 2: Apply hotfix or upgrade to fixed version
# PAN-OS 10.2.9-h1, 11.0.4-h1, 11.1.2-h3 or later

# Step 3: If hotfix not available, apply mitigation
# Disable device telemetry:
set deviceconfig setting telemetry threat-prevention no

# Step 4: Apply Threat Prevention signature
# Threat ID 95187 blocks attacks

# Step 5: Check for indicators of compromise
grep "failed to unmarshal session" /var/log/pan/sslvpn_ngx_error.log
find /var/appweb/sslvpndocs -name "*.css" -newer /etc/pan-os-release"""
    },
    
    # ==================== HIGH SEVERITY ====================
    
    "CVE-2021-22986": {
        "title": "F5 BIG-IP iControl REST Unauthenticated RCE",
        "severity": "high",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "The iControl REST interface of F5 BIG-IP has an unauthenticated remote command execution vulnerability. Attackers can execute arbitrary system commands with root privileges.",
        "fix_commands": """# Step 1: Upgrade BIG-IP to patched version
# Fixed versions: 16.0.1.1, 15.1.2.1, 14.1.4, 13.1.3.6, 12.1.5.3

# Step 2: Temporary mitigation - Block iControl REST access
# Modify httpd configuration
# Set iControl REST to only allow management network

# Step 3: Add self IP port lockdown
modify net self <self_ip_name> port-lockdown allow-custom 
add { https ssh }

# Step 4: Check for compromise indicators
cat /var/log/restjavad.0.log | grep -i "admin"
ls -la /tmp/

# Step 5: Review running processes
ps aux | grep -E "(python|perl|nc|bash)"
netstat -antp | grep ESTABLISHED"""
    },
    
    "CVE-2020-5902": {
        "title": "F5 BIG-IP TMUI Remote Code Execution",
        "severity": "high",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "The Traffic Management User Interface (TMUI) of F5 BIG-IP has a remote code execution vulnerability due to directory traversal, allowing attackers to execute arbitrary commands.",
        "fix_commands": """# Step 1: Upgrade BIG-IP immediately
# Fixed versions: 15.1.0.4, 14.1.2.6, 13.1.3.4, 12.1.5.2, 11.6.5.2

# Step 2: Temporary mitigation via iRule
when HTTP_REQUEST {
    if { [HTTP::uri] contains "..;" } {
        reject
    }
}

# Step 3: Restrict access to configuration utility
# Allow only from management network
tmsh modify sys httpd allow { 192.168.1.0/24 }
tmsh save sys config

# Step 4: Monitor for exploitation
tail -f /var/log/ltm | grep -i "tmui"

# Step 5: Check for webshells
find /usr/local/www -name "*.php" -o -name "*.jsp" -mtime -7"""
    },
    
    "CVE-2021-26084": {
        "title": "Atlassian Confluence OGNL Injection RCE",
        "severity": "high",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "An OGNL injection vulnerability in Atlassian Confluence Server allows an unauthenticated attacker to execute arbitrary code on a Confluence Server or Data Center instance.",
        "fix_commands": """# Step 1: Upgrade Confluence immediately
# Fixed versions: 7.13.0, 7.12.5, 7.11.6, 7.4.11, 6.13.23

# Step 2: If upgrade not immediately possible, disable affected widgets
# Navigate to: Settings > General Configuration > Widgets

# Step 3: Block vulnerable endpoints at WAF/proxy level
# Block requests to /pages/createpage-entervariables.action

# Step 4: Check for indicators of compromise
grep -r "cmd.exe\\|/bin/bash\\|wget\\|curl" /var/atlassian/application-data/confluence/logs/

# Step 5: Review process list
ps aux | grep -E "(bash|sh|curl|wget|python)"
netstat -antp | grep java"""
    },
    
    "CVE-2022-1388": {
        "title": "F5 BIG-IP Authentication Bypass to RCE",
        "severity": "high",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "F5 BIG-IP iControl REST has an authentication bypass vulnerability that allows unauthenticated attackers to execute arbitrary system commands through the /mgmt/tm/util/bash endpoint.",
        "fix_commands": """# Step 1: Upgrade BIG-IP to fixed version
# Fixed versions: 17.0.0, 16.1.2.2, 15.1.5.1, 14.1.4.6, 13.1.5

# Step 2: Temporary mitigation - Block access
# Add to httpd.conf:
<LocationMatch "^/mgmt/tm/.*bash.*">
    Require all denied
</LocationMatch>

# Step 3: Restrict self IP access
tmsh modify net self <self_ip> port-lockdown allow-custom 
add { ssh }

# Step 4: Block iControl REST access from external
iptables -A INPUT -p tcp --dport 443 -j DROP

# Step 5: Monitor for exploitation attempts
grep -i "mgmt/tm/util/bash" /var/log/restjavad*.log"""
    },
    
    "CVE-2021-3129": {
        "title": "Laravel Ignition RCE",
        "severity": "high",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Ignition before 2.5.2 allows unauthenticated remote attackers to execute arbitrary code through the debug mode file creation functionality when used with Laravel before 8.4.3.",
        "fix_commands": """# Step 1: Update Ignition package
composer require facade/ignition:"^2.5.2"

# Step 2: Ensure debug mode is disabled in production
# In .env file:
APP_DEBUG=false
APP_ENV=production

# Step 3: Update Laravel to latest version
composer update laravel/framework

# Step 4: Clear cached configuration
php artisan config:clear
php artisan cache:clear
php artisan view:clear

# Step 5: Set proper file permissions
chown -R www-data:www-data /var/www/html
chmod -R 755 /var/www/html
chmod -R 775 /var/www/html/storage"""
    },
    
    "CVE-2022-22963": {
        "title": "Spring Cloud Function SpEL Injection RCE",
        "severity": "high",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Spring Cloud Function versions 3.1.6, 3.2.2 and older contain a SpEL expression injection vulnerability that allows remote code execution via a crafted HTTP request header.",
        "fix_commands": """# Step 1: Upgrade Spring Cloud Function
# For Maven, update pom.xml:
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-function-context</artifactId>
    <version>3.2.3</version>
</dependency>

# Step 2: If upgrade not possible, block malicious headers at WAF
# Block requests with spring.cloud.function.routing-expression header

# Step 3: Validate application configuration
# Disable routing functions if not needed

# Step 4: Rebuild and redeploy
mvn clean package -DskipTests
docker-compose down && docker-compose up -d

# Step 5: Monitor logs for exploitation
grep -i "routing-expression" /var/log/app/*.log"""
    },
    
    "ssl-expired": {
        "title": "Expired SSL/TLS Certificate",
        "severity": "high",
        "mitre_id": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "description": "The SSL/TLS certificate has expired. This can cause browser warnings, loss of customer trust, and potential man-in-the-middle attacks as users may ignore security warnings.",
        "fix_commands": """# Step 1: Check current certificate status
openssl s_client -connect example.com:443 -servername example.com 2>/dev/null | openssl x509 -noout -dates

# Step 2: Generate new certificate with Let's Encrypt
sudo certbot certonly --webroot -w /var/www/html -d example.com -d www.example.com

# Step 3: Or renew existing Let's Encrypt certificate
sudo certbot renew

# Step 4: Update web server configuration
# For Nginx:
ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/example.com/privkey.pem;

# Step 5: Reload web server
sudo systemctl reload nginx
# or
sudo systemctl reload apache2

# Step 6: Set up auto-renewal
echo "0 0 1 * * root /usr/bin/certbot renew --quiet" | sudo tee -a /etc/crontab"""
    },
    
    "cve-2018-7600": {
        "title": "Drupal Remote Code Execution (Drupalgeddon2)",
        "severity": "high",
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "description": "Drupal before 7.58, 8.x before 8.3.9, 8.4.x before 8.4.6, and 8.5.x before 8.5.1 allows remote attackers to execute arbitrary code due to improper input validation in Form API AJAX requests.",
        "fix_commands": """# Step 1: Upgrade Drupal immediately
# For Drupal 7:
drush up drupal-7.58

# For Drupal 8:
composer update drupal/core --with-dependencies

# Step 2: Apply security patch if upgrade not possible
wget https://www.drupal.org/files/issues/2018-03-28/SA-CORE-2018-002-7.x.patch
patch -p1 < SA-CORE-2018-002-7.x.patch

# Step 3: Check for indicators of compromise
grep -r "passthru\\|system\\|exec\\|shell_exec" /var/www/html/sites/

# Step 4: Clear Drupal caches
drush cr

# Step 5: Review file permissions
find /var/www/html -type f -perm -o+w"""
    },
    
    "exposed-docker-api": {
        "title": "Docker API Exposed",
        "severity": "high",
        "mitre_id": "T1610",
        "mitre_name": "Deploy Container",
        "description": "The Docker API is exposed without authentication. Attackers can create containers, access data, or execute commands on the host system.",
        "fix_commands": """# Step 1: Immediately stop exposing Docker API to network
# Edit /etc/docker/daemon.json
{
    "hosts": ["unix:///var/run/docker.sock"]
}

# Step 2: If remote access is needed, enable TLS
dockerd --tlsverify --tlscacert=ca.pem --tlscert=server-cert.pem --tlskey=server-key.pem -H=0.0.0.0:2376

# Step 3: Generate TLS certificates
# Create CA
openssl genrsa -aes256 -out ca-key.pem 4096
openssl req -new -x509 -days 365 -key ca-key.pem -sha256 -out ca.pem

# Step 4: Restrict firewall access
iptables -A INPUT -p tcp --dport 2375 -j DROP
iptables -A INPUT -p tcp --dport 2376 -s 10.0.0.0/8 -j ACCEPT

# Step 5: Check for suspicious containers
docker ps -a
docker images
docker logs $(docker ps -lq)"""
    },
    
    "default-credential": {
        "title": "Default Credentials Detected",
        "severity": "high",
        "mitre_id": "T1078.001",
        "mitre_name": "Valid Accounts: Default Accounts",
        "description": "The application is using default credentials which can be easily exploited by attackers to gain unauthorized access.",
        "fix_commands": """# Step 1: Immediately change default passwords
# Document all services using default credentials

# Step 2: Create strong passwords (minimum 16 characters)
# Use a password generator:
openssl rand -base64 24

# Step 3: For web applications, update config files
# Example for MySQL:
mysql -u root -p
ALTER USER 'root'@'localhost' IDENTIFIED BY 'new_strong_password';
FLUSH PRIVILEGES;

# Step 4: Implement password policies
# Minimum 12 characters
# Mix of uppercase, lowercase, numbers, special characters
# Password rotation every 90 days

# Step 5: Enable multi-factor authentication where possible
# Audit all service accounts"""
    },
    
    # ==================== MEDIUM SEVERITY ====================
    
    "missing-hsts": {
        "title": "HTTP Strict Transport Security Not Enabled",
        "severity": "medium",
        "mitre_id": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "description": "The HTTP Strict Transport Security (HSTS) header is not set. This leaves users vulnerable to SSL stripping attacks and protocol downgrade attacks.",
        "fix_commands": """# Step 1: For Nginx, add HSTS header
# In server block:
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;

# Step 2: For Apache, add to .htaccess or config
Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

# Step 3: For IIS, add to web.config
<system.webServer>
    <httpProtocol>
        <customHeaders>
            <add name="Strict-Transport-Security" value="max-age=31536000; includeSubDomains; preload"/>
        </customHeaders>
    </httpProtocol>
</system.webServer>

# Step 4: Submit to HSTS preload list (optional)
# Visit: https://hstspreload.org

# Step 5: Verify header is set
curl -I https://example.com | grep -i strict"""
    },
    
    "missing-csp": {
        "title": "Content Security Policy Not Implemented",
        "severity": "medium",
        "mitre_id": "T1059.007",
        "mitre_name": "Command and Scripting Interpreter: JavaScript",
        "description": "Content Security Policy (CSP) is not implemented. This header helps prevent XSS attacks, clickjacking, and other code injection attacks.",
        "fix_commands": """# Step 1: For Nginx, add CSP header
add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; frame-ancestors 'self';" always;

# Step 2: For Apache
Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';"

# Step 3: For Express.js (Node.js)
const helmet = require('helmet');
app.use(helmet.contentSecurityPolicy({
    directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
    }
}));

# Step 4: Start with report-only mode to test
Content-Security-Policy-Report-Only: default-src 'self'; report-uri /csp-report

# Step 5: Monitor CSP violations before enforcing
# Review reports and adjust policy accordingly"""
    },
    
    "missing-x-frame-options": {
        "title": "X-Frame-Options Header Missing",
        "severity": "medium",
        "mitre_id": "T1185",
        "mitre_name": "Browser Session Hijacking",
        "description": "The X-Frame-Options header is not set. This could allow the page to be embedded in an iframe, enabling clickjacking attacks.",
        "fix_commands": """# Step 1: For Nginx
add_header X-Frame-Options "SAMEORIGIN" always;

# Step 2: For Apache
Header always set X-Frame-Options "SAMEORIGIN"

# Step 3: For IIS (web.config)
<system.webServer>
    <httpProtocol>
        <customHeaders>
            <add name="X-Frame-Options" value="SAMEORIGIN"/>
        </customHeaders>
    </httpProtocol>
</system.webServer>

# Step 4: For Flask (Python)
from flask import Flask
app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    return response

# Step 5: Use CSP frame-ancestors as modern alternative
Content-Security-Policy: frame-ancestors 'self';"""
    },
    
    "missing-x-content-type-options": {
        "title": "X-Content-Type-Options Header Missing",
        "severity": "medium",
        "mitre_id": "T1059.007",
        "mitre_name": "Command and Scripting Interpreter: JavaScript",
        "description": "The X-Content-Type-Options header is missing. Without this header, browsers may try to MIME-sniff the content type, potentially executing malicious content.",
        "fix_commands": """# Step 1: For Nginx
add_header X-Content-Type-Options "nosniff" always;

# Step 2: For Apache
Header always set X-Content-Type-Options "nosniff"

# Step 3: For IIS (web.config)
<system.webServer>
    <httpProtocol>
        <customHeaders>
            <add name="X-Content-Type-Options" value="nosniff"/>
        </customHeaders>
    </httpProtocol>
</system.webServer>

# Step 4: For Express.js (Node.js)
const helmet = require('helmet');
app.use(helmet.noSniff());

# Step 5: Verify header
curl -I https://example.com | grep -i x-content-type"""
    },
    
    "missing-x-xss-protection": {
        "title": "X-XSS-Protection Header Missing",
        "severity": "medium",
        "mitre_id": "T1059.007",
        "mitre_name": "Command and Scripting Interpreter: JavaScript",
        "description": "The X-XSS-Protection header is not set. While deprecated in modern browsers, it still provides protection for older browsers against reflected XSS attacks.",
        "fix_commands": """# Step 1: For Nginx
add_header X-XSS-Protection "1; mode=block" always;

# Step 2: For Apache
Header always set X-XSS-Protection "1; mode=block"

# Step 3: For IIS
<system.webServer>
    <httpProtocol>
        <customHeaders>
            <add name="X-XSS-Protection" value="1; mode=block"/>
        </customHeaders>
    </httpProtocol>
</system.webServer>

# Step 4: Note: Modern approach is to use CSP instead
# X-XSS-Protection is deprecated in Chrome
# Use Content-Security-Policy with script-src directive

# Step 5: Recommended full security headers
add_header X-XSS-Protection "1; mode=block" always;
add_header Content-Security-Policy "default-src 'self';" always;"""
    },
    
    "cors-misconfiguration": {
        "title": "CORS Misconfiguration",
        "severity": "medium",
        "mitre_id": "T1189",
        "mitre_name": "Drive-by Compromise",
        "description": "The Access-Control-Allow-Origin header is set to a wildcard (*) or reflects the origin without validation, allowing any website to make cross-origin requests.",
        "fix_commands": """# Step 1: Define specific allowed origins (Nginx)
set $cors_origin "";
if ($http_origin ~* "^https://(www\\.)?yourdomain\\.com$") {
    set $cors_origin $http_origin;
}
add_header Access-Control-Allow-Origin $cors_origin always;

# Step 2: For Express.js
const cors = require('cors');
const corsOptions = {
    origin: ['https://yourdomain.com', 'https://app.yourdomain.com'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
};
app.use(cors(corsOptions));

# Step 3: For Flask (Python)
from flask_cors import CORS
CORS(app, origins=['https://yourdomain.com'], supports_credentials=True)

# Step 4: Never use Access-Control-Allow-Credentials with wildcard origin

# Step 5: Test CORS configuration
curl -H "Origin: https://evil.com" -I https://yoursite.com"""
    },
    
    "directory-listing": {
        "title": "Directory Listing Enabled",
        "severity": "medium",
        "mitre_id": "T1083",
        "mitre_name": "File and Directory Discovery",
        "description": "Directory listing is enabled on the web server, allowing attackers to enumerate files and directories, potentially exposing sensitive information.",
        "fix_commands": """# Step 1: For Apache, add to .htaccess or httpd.conf
Options -Indexes

# Step 2: For Nginx
location / {
    autoindex off;
}

# Step 3: For IIS, disable directory browsing
# In IIS Manager: Sites > Your Site > Directory Browsing > Disable

# Step 4: Add index files to prevent listing
# Create blank index.html in all directories
find /var/www/html -type d -exec touch {}/index.html \\;

# Step 5: Verify fix
curl -I https://example.com/uploads/"""
    },
    
    "wordpress-user-enumeration": {
        "title": "WordPress User Enumeration",
        "severity": "medium",
        "mitre_id": "T1589.002",
        "mitre_name": "Gather Victim Identity Information: Email Addresses",
        "description": "WordPress is vulnerable to user enumeration through author archives or REST API, allowing attackers to discover valid usernames for brute force attacks.",
        "fix_commands": """# Step 1: Disable author archives (add to functions.php)
add_action('template_redirect', function() {
    if (is_author()) {
        wp_redirect(home_url(), 301);
        exit;
    }
});

# Step 2: Disable REST API user endpoint
add_filter('rest_endpoints', function($endpoints) {
    if (isset($endpoints['/wp/v2/users'])) {
        unset($endpoints['/wp/v2/users']);
    }
    if (isset($endpoints['/wp/v2/users/(?P<id>[\\d]+)'])) {
        unset($endpoints['/wp/v2/users/(?P<id>[\\d]+)']);
    }
    return $endpoints;
});

# Step 3: Block ?author= queries in .htaccess
RewriteCond %{QUERY_STRING} ^author= [NC]
RewriteRule .* - [F,L]

# Step 4: Use security plugin like Wordfence or Sucuri

# Step 5: Implement login rate limiting
# Add to wp-config.php or use plugin"""
    },
    
    "phpinfo-exposure": {
        "title": "PHP Info Page Exposed",
        "severity": "medium",
        "mitre_id": "T1592.004",
        "mitre_name": "Gather Victim Host Information: Client Configurations",
        "description": "A phpinfo() page is publicly accessible, revealing sensitive server configuration, paths, installed modules, and environment variables.",
        "fix_commands": """# Step 1: Delete or restrict phpinfo files
find /var/www -name "phpinfo.php" -o -name "info.php" -o -name "test.php"
rm /var/www/html/phpinfo.php

# Step 2: Disable phpinfo function (php.ini)
disable_functions = phpinfo, exec, shell_exec, system, passthru

# Step 3: Block access via Nginx
location ~* (phpinfo|info|test)\\.php$ {
    deny all;
    return 404;
}

# Step 4: Block via Apache .htaccess
<FilesMatch "^(phpinfo|info|test)\\.php$">
    Require all denied
</FilesMatch>

# Step 5: Disable expose_php
# In php.ini:
expose_php = Off"""
    },
    
    "server-version-disclosure": {
        "title": "Server Version Disclosure",
        "severity": "medium",
        "mitre_id": "T1592",
        "mitre_name": "Gather Victim Host Information",
        "description": "The server is disclosing version information in HTTP headers or error pages. This helps attackers identify potential vulnerabilities for specific versions.",
        "fix_commands": """# Step 1: For Nginx, hide version
# In nginx.conf:
server_tokens off;

# Step 2: For Apache
# In httpd.conf:
ServerTokens Prod
ServerSignature Off

# Step 3: For PHP (php.ini)
expose_php = Off

# Step 4: For IIS, remove server header
<system.webServer>
    <security>
        <requestFiltering removeServerHeader="true"/>
    </security>
</system.webServer>

# Step 5: For Express.js
app.disable('x-powered-by');
# Or use helmet:
app.use(helmet.hidePoweredBy());"""
    },
    
    "open-redirect": {
        "title": "Open Redirect Vulnerability",
        "severity": "medium",
        "mitre_id": "T1566.002",
        "mitre_name": "Phishing: Spearphishing Link",
        "description": "The application redirects users to URLs specified in parameters without validation. Attackers can use this for phishing attacks by creating links that appear legitimate.",
        "fix_commands": """# Step 1: Validate redirect URLs against whitelist
# Python example:
ALLOWED_HOSTS = ['yourdomain.com', 'app.yourdomain.com']

def safe_redirect(url):
    from urllib.parse import urlparse
    parsed = urlparse(url)
    if parsed.netloc and parsed.netloc not in ALLOWED_HOSTS:
        return redirect('/')
    return redirect(url)

# Step 2: Use relative URLs only
# Instead of: redirect(request.args.get('next'))
# Use: redirect(url_for('dashboard'))

# Step 3: Add Content Security Policy
Content-Security-Policy: default-src 'self';

# Step 4: Implement URL validation in JavaScript
function isSafeRedirect(url) {
    const pattern = /^\\/((?!\\/).)*$/;
    return pattern.test(url);
}

# Step 5: Log suspicious redirect attempts
# Monitor for external domains in redirect parameters"""
    },
    
    # ==================== LOW SEVERITY ====================
    
    "missing-referrer-policy": {
        "title": "Referrer-Policy Header Missing",
        "severity": "low",
        "mitre_id": "T1592",
        "mitre_name": "Gather Victim Host Information",
        "description": "The Referrer-Policy header is not set. This may leak sensitive information in the Referer header when users navigate to external sites.",
        "fix_commands": """# Step 1: For Nginx
add_header Referrer-Policy "strict-origin-when-cross-origin" always;

# Step 2: For Apache
Header always set Referrer-Policy "strict-origin-when-cross-origin"

# Step 3: For HTML meta tag
<meta name="referrer" content="strict-origin-when-cross-origin">

# Step 4: Common policy options:
# - no-referrer: Never send referrer
# - same-origin: Only to same origin
# - strict-origin-when-cross-origin: Recommended

# Step 5: Verify header
curl -I https://example.com | grep -i referrer"""
    },
    
    "missing-permissions-policy": {
        "title": "Permissions-Policy Header Missing",
        "severity": "low",
        "mitre_id": "T1592",
        "mitre_name": "Gather Victim Host Information",
        "description": "The Permissions-Policy (formerly Feature-Policy) header is not set. This header controls which browser features can be used on the page.",
        "fix_commands": """# Step 1: For Nginx
add_header Permissions-Policy "geolocation=(), microphone=(), camera=(), payment=(), usb=()" always;

# Step 2: For Apache
Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"

# Step 3: For Express.js
const helmet = require('helmet');
app.use(helmet.permittedCrossDomainPolicies());

# Step 4: Common features to restrict:
# - geolocation, camera, microphone
# - payment, usb, fullscreen
# - accelerometer, gyroscope

# Step 5: Customize based on your needs
# Allow self: geolocation=(self)
# Allow specific origin: camera=(https://trusted.com)"""
    },
    
    "robots-txt-exposure": {
        "title": "Sensitive Paths in robots.txt",
        "severity": "low",
        "mitre_id": "T1592",
        "mitre_name": "Gather Victim Host Information",
        "description": "The robots.txt file reveals potentially sensitive paths or directories. While intended to guide search engines, attackers use this for reconnaissance.",
        "fix_commands": """# Step 1: Review robots.txt content
cat /var/www/html/robots.txt

# Step 2: Remove sensitive path disclosure
# BAD - reveals admin path:
Disallow: /admin/
Disallow: /backup/
Disallow: /config/

# Step 3: Use generic rules instead
User-agent: *
Disallow: /private/

# Step 4: Protect sensitive directories with authentication
# Don't rely on robots.txt for security

# Step 5: Consider using noindex meta tags instead
<meta name="robots" content="noindex, nofollow">"""
    },
    
    "cookie-without-secure-flag": {
        "title": "Cookie Without Secure Flag",
        "severity": "low",
        "mitre_id": "T1539",
        "mitre_name": "Steal Web Session Cookie",
        "description": "Cookies are being set without the Secure flag. These cookies can be transmitted over unencrypted HTTP connections, making them vulnerable to interception.",
        "fix_commands": """# Step 1: For PHP
ini_set('session.cookie_secure', 1);
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_samesite', 'Strict');

# Step 2: For Flask (Python)
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

# Step 3: For Express.js
app.use(session({
    cookie: {
        secure: true,
        httpOnly: true,
        sameSite: 'strict'
    }
}));

# Step 4: Manually set secure cookies
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict

# Step 5: Force HTTPS to ensure Secure cookies work
# Redirect all HTTP to HTTPS"""
    },
    
    "cookie-without-httponly-flag": {
        "title": "Cookie Without HttpOnly Flag",
        "severity": "low",
        "mitre_id": "T1539",
        "mitre_name": "Steal Web Session Cookie",
        "description": "Cookies are being set without the HttpOnly flag. This allows JavaScript to access the cookie, making it vulnerable to XSS attacks that steal session tokens.",
        "fix_commands": """# Step 1: For PHP
ini_set('session.cookie_httponly', 1);
# Or in php.ini:
session.cookie_httponly = 1

# Step 2: For Flask (Python)
app.config['SESSION_COOKIE_HTTPONLY'] = True

# Step 3: For Express.js
res.cookie('session', value, {
    httpOnly: true,
    secure: true,
    sameSite: 'strict'
});

# Step 4: For Django
SESSION_COOKIE_HTTPONLY = True
CSRF_COOKIE_HTTPONLY = True

# Step 5: Verify cookie flags
# Check in browser DevTools > Application > Cookies"""
    },
    
    "tech-detect": {
        "title": "Technology Stack Detected",
        "severity": "low",
        "mitre_id": "T1592.004",
        "mitre_name": "Gather Victim Host Information: Client Configurations",
        "description": "The technology stack of the application has been detected. While not a direct vulnerability, this information helps attackers identify potential attack vectors.",
        "fix_commands": """# Step 1: Remove technology-specific headers
# For PHP, disable expose_php in php.ini:
expose_php = Off

# Step 2: Remove generator meta tags
# Remove: <meta name="generator" content="WordPress 6.0">

# Step 3: Hide server tokens (Nginx)
server_tokens off;

# Step 4: Remove X-Powered-By header
# For Express.js:
app.disable('x-powered-by');

# Step 5: Obfuscate common file extensions
# Change .php to generic routes where possible
# Use URL rewriting to hide technology"""
    },
    
    "http-trace-enabled": {
        "title": "HTTP TRACE Method Enabled",
        "severity": "low",
        "mitre_id": "T1557",
        "mitre_name": "Adversary-in-the-Middle",
        "description": "The HTTP TRACE method is enabled. While rarely exploitable in modern browsers, it could be used for Cross-Site Tracing (XST) attacks to steal credentials.",
        "fix_commands": """# Step 1: For Apache
# In httpd.conf:
TraceEnable Off

# Step 2: For Nginx (TRACE is disabled by default)
# Verify with:
if ($request_method = TRACE) {
    return 405;
}

# Step 3: For IIS
<system.webServer>
    <security>
        <requestFiltering>
            <verbs>
                <add verb="TRACE" allowed="false"/>
            </verbs>
        </requestFiltering>
    </security>
</system.webServer>

# Step 4: Test TRACE is disabled
curl -X TRACE https://example.com

# Step 5: Also consider disabling other unused methods
# OPTIONS, DELETE, PUT if not needed"""
    },
    
    # ==================== INFO SEVERITY ====================
    
    "waf-detect": {
        "title": "Web Application Firewall Detected",
        "severity": "info",
        "mitre_id": "T1592",
        "mitre_name": "Gather Victim Host Information",
        "description": "A Web Application Firewall (WAF) has been detected. This is informational - the presence of a WAF indicates security measures are in place, but may also reveal the specific WAF product.",
        "fix_commands": """# This is informational - no immediate action required

# However, consider:

# Step 1: Review WAF configuration
# Ensure rules are up-to-date

# Step 2: Enable stealth mode if available
# Hide WAF signatures where possible

# Step 3: Regular WAF rule updates
# Subscribe to vendor security advisories

# Step 4: Test WAF effectiveness
# Conduct regular penetration testing

# Step 5: Monitor WAF logs
# Set up alerting for blocked attacks"""
    },
    
    "cdn-detect": {
        "title": "Content Delivery Network Detected",
        "severity": "info",
        "mitre_id": "T1592",
        "mitre_name": "Gather Victim Host Information",
        "description": "A CDN provider has been detected. This is informational and may help attackers understand the infrastructure or attempt to find the origin server.",
        "fix_commands": """# This is informational - no immediate action required

# However, consider:

# Step 1: Protect origin server IP
# Never expose origin IP directly

# Step 2: Restrict origin to CDN IPs only
# Example for Cloudflare:
iptables -A INPUT -p tcp --dport 443 -s 103.21.244.0/22 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j DROP

# Step 3: Remove origin IP from DNS history
# Check: securitytrails.com, shodan.io

# Step 4: Use origin certificate authentication
# Configure mTLS between CDN and origin

# Step 5: Enable CDN security features
# DDoS protection, WAF rules, bot management"""
    },
    
    "email-disclosure": {
        "title": "Email Address Disclosed",
        "severity": "info",
        "mitre_id": "T1589.002",
        "mitre_name": "Gather Victim Identity Information: Email Addresses",
        "description": "Email addresses were found in public pages. This information can be used for targeted phishing attacks or to enumerate valid users.",
        "fix_commands": """# This is informational - review and minimize exposure

# Step 1: Use contact forms instead of email links
# Replace mailto: links with web forms

# Step 2: Obfuscate email addresses
# JavaScript: document.write(atob('base64encoded'));
# Or use: contact [at] domain [dot] com

# Step 3: Use role-based addresses
# info@, support@, contact@ instead of personal

# Step 4: Implement CAPTCHA on contact forms
# Prevent automated scraping

# Step 5: Monitor email addresses for breaches
# Use haveibeenpwned.com API"""
    },
    
    "ssl-certificate-info": {
        "title": "SSL Certificate Information",
        "severity": "info",
        "mitre_id": "T1592",
        "mitre_name": "Gather Victim Host Information",
        "description": "SSL certificate information was extracted. This includes issuer, validity dates, and subject details which may reveal organizational information.",
        "fix_commands": """# This is informational - no immediate action required

# Recommendations:

# Step 1: Monitor certificate expiration
# Set up alerts 30 days before expiry

# Step 2: Use Certificate Transparency monitoring
# https://crt.sh to monitor your domains

# Step 3: Consider using wildcard certificates
# Reduces exposure of subdomains

# Step 4: Verify certificate chain is complete
openssl s_client -connect example.com:443 -showcerts

# Step 5: Implement CAA DNS records
# Restrict which CAs can issue certificates
example.com. 3600 IN CAA 0 issue "letsencrypt.org" """
    },
    
    "dns-zone-info": {
        "title": "DNS Information Disclosure",
        "severity": "info",
        "mitre_id": "T1596.001",
        "mitre_name": "Search Open Technical Databases: DNS/Passive DNS",
        "description": "DNS records were enumerated, revealing subdomains, mail servers, and other infrastructure information.",
        "fix_commands": """# This is informational - minimize unnecessary exposure

# Step 1: Disable zone transfers to public
# In BIND named.conf:
zone "example.com" {
    allow-transfer { none; };
};

# Step 2: Review and remove unused DNS records
# Stale records may point to abandoned/vulnerable systems

# Step 3: Use split-horizon DNS
# Internal records separate from external

# Step 4: Monitor for subdomain takeover risks
# Check CNAME records pointing to unused services

# Step 5: Use DNSSEC
# Prevent DNS spoofing attacks"""
    },
    
    "http-methods-detected": {
        "title": "HTTP Methods Detected",
        "severity": "info",
        "mitre_id": "T1592",
        "mitre_name": "Gather Victim Host Information",
        "description": "The allowed HTTP methods were detected via OPTIONS request. This includes standard methods like GET, POST, and potentially dangerous methods like PUT or DELETE.",
        "fix_commands": """# Review and restrict unnecessary HTTP methods

# Step 1: For Nginx, restrict methods
if ($request_method !~ ^(GET|POST|HEAD)$) {
    return 405;
}

# Step 2: For Apache, restrict methods
<LimitExcept GET POST HEAD>
    Require all denied
</LimitExcept>

# Step 3: Disable OPTIONS if not needed for CORS
location / {
    if ($request_method = OPTIONS) {
        return 204;
    }
}

# Step 4: For APIs, only allow needed methods per endpoint
# Document required methods in OpenAPI spec

# Step 5: Test method restrictions
curl -X OPTIONS https://example.com
curl -X DELETE https://example.com"""
    }
}


# ==================== REMEDIATION HELPER FUNCTIONS ====================

def get_remediation(template_id):
    """
    Get remediation information for a Nuclei template ID.
    
    Args:
        template_id (str): The Nuclei template ID (e.g., 'CVE-2021-44228')
        
    Returns:
        dict: Remediation information or default response if not found
    """
    # Normalize template ID (lowercase, handle variations)
    normalized_id = template_id.lower().strip()
    
    # Try exact match first
    for key, value in REMEDIATION_DB.items():
        if key.lower() == normalized_id:
            return value
    
    # Try partial match (for CVE variations)
    for key, value in REMEDIATION_DB.items():
        if normalized_id in key.lower() or key.lower() in normalized_id:
            return value
    
    # Return default remediation if not found
    return get_default_remediation(template_id)


def get_default_remediation(template_id):
    """
    Generate a default remediation response for unknown vulnerabilities.
    
    Args:
        template_id (str): The Nuclei template ID
        
    Returns:
        dict: Default remediation information
    """
    return {
        "title": f"Vulnerability: {template_id}",
        "severity": "unknown",
        "mitre_id": "N/A",
        "mitre_name": "Unknown Technique",
        "description": f"This vulnerability ({template_id}) was detected by Nuclei scanner. Please refer to the original Nuclei template documentation for detailed information about this vulnerability.",
        "fix_commands": f"""# Remediation for {template_id}

# Step 1: Research the vulnerability
# Visit: https://github.com/projectdiscovery/nuclei-templates
# Search for template: {template_id}

# Step 2: Understand the impact
# Review the template severity and description

# Step 3: Apply vendor patches
# Check the affected software vendor for security updates

# Step 4: Implement workarounds if patch not available
# Review the Nuclei template for mitigation steps

# Step 5: Verify the fix
# Re-run the scan to confirm vulnerability is resolved

# For additional help:
# - NVD: https://nvd.nist.gov/
# - CVE Details: https://www.cvedetails.com/
# - Exploit-DB: https://www.exploit-db.com/"""
    }


def get_all_remediations():
    """
    Get all remediation entries from the knowledge base.
    
    Returns:
        dict: The complete remediation database
    """
    return REMEDIATION_DB


def get_remediations_by_severity(severity):
    """
    Filter remediations by severity level.
    
    Args:
        severity (str): Severity level (critical, high, medium, low, info)
        
    Returns:
        dict: Filtered remediation entries
    """
    return {
        key: value 
        for key, value in REMEDIATION_DB.items() 
        if value.get("severity", "").lower() == severity.lower()
    }


def search_remediations(query):
    """
    Search the remediation database by keyword.
    
    Args:
        query (str): Search query
        
    Returns:
        dict: Matching remediation entries
    """
    query = query.lower()
    results = {}
    
    for key, value in REMEDIATION_DB.items():
        if (query in key.lower() or
            query in value.get("title", "").lower() or
            query in value.get("description", "").lower() or
            query in value.get("mitre_name", "").lower()):
            results[key] = value
    
    return results


def get_mitre_mapping():
    """
    Get a mapping of MITRE ATT&CK IDs to vulnerabilities.
    
    Returns:
        dict: MITRE ID to list of vulnerability IDs
    """
    mapping = {}
    
    for vuln_id, data in REMEDIATION_DB.items():
        mitre_id = data.get("mitre_id", "N/A")
        if mitre_id not in mapping:
            mapping[mitre_id] = []
        mapping[mitre_id].append({
            "id": vuln_id,
            "title": data.get("title"),
            "severity": data.get("severity")
        })
    
    return mapping


# ==================== STATISTICS ====================

def get_stats():
    """
    Get statistics about the knowledge base.
    
    Returns:
        dict: Statistics about the remediation database
    """
    severities = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    
    for data in REMEDIATION_DB.values():
        severity = data.get("severity", "info").lower()
        if severity in severities:
            severities[severity] += 1
    
    return {
        "total_entries": len(REMEDIATION_DB),
        "by_severity": severities,
        "unique_mitre_techniques": len(set(
            data.get("mitre_id") for data in REMEDIATION_DB.values()
        ))
    }


# Print stats when module is loaded (for debugging)
if __name__ == "__main__":
    stats = get_stats()
    print(f"\n[ARES Remediation Knowledge Base]")
    print(f"Total Entries: {stats['total_entries']}")
    print(f"By Severity: {stats['by_severity']}")
    print(f"Unique MITRE Techniques: {stats['unique_mitre_techniques']}")
