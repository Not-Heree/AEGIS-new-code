# EASM AEGIS — External Attack Surface Management

A comprehensive, production-grade tool for discovering, monitoring, and assessing an organization's external attack surface from an attacker's perspective. EASM AEGIS automates the complete reconnaissance and vulnerability assessment workflow—from passive intelligence gathering through active scanning, change detection, risk scoring, and remediation planning.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Core Capabilities](#core-capabilities)
- [Technology Stack](#technology-stack)
- [External Tools & Integrations](#external-tools--integrations)
- [System Architecture](#system-architecture)
- [Feature Breakdown](#feature-breakdown)
- [Data Management](#data-management)
- [Setup & Installation](#setup--installation)
- [Running the Application](#running-the-application)
- [API Endpoints](#api-endpoints)
- [Current Limitations](#current-limitations)

---

## Overview

EASM AEGIS is a Flask-based web application that simulates an attacker's reconnaissance workflow. It combines open-source tools (Nuclei, Naabu, Subfinder, HTTPX) with paid APIs (Shodan, Censys, Hunter.io) and free intelligence sources (LeakCheck, CISA KEV) to build a complete picture of an organization's exposed assets and vulnerabilities.

**Key Philosophy**: Automated, resumable, actionable security intelligence—not just reports.

---

## Core Capabilities

### 1. **Passive Reconnaissance** ✅
- **Shodan Integration**: Retrieves banners, services, vulnerabilities, and tech stacks from Shodan's passive scan database
- **Censys Integration**: Queries SSL/TLS certificates and exposed services from Censys
- **WHOIS Lookup**: Retrieves domain registration data and associated infrastructure
- **Email Discovery**: Harvests company email addresses from multiple sources for breach checking

### 2. **Active Asset Discovery** ✅
- **Subdomain Enumeration** (`subfinder`): Discovers subdomains via multiple sources (certificate transparency, DNS, web scraping)
- **Port Scanning** (`naabu`): Identifies open ports on discovered hosts with automatic rate limiting, high-port optimization, and **intelligent batching** for stable performance on large Windows-based host lists.
- **HTTP Fingerprinting** (`httpx`): Probes HTTP/HTTPS services to extract:
  - Status codes and response headers
  - Page titles
  - Web server identification
  - Technology stack detection (via header analysis)

### 3. **Vulnerability Scanning** ✅
- **Nuclei-Powered Scanning** (`nuclei`): Automated vulnerability detection using 10,000+ community templates
  - Tier 1A (Critical/High severity from CISA KEV)
  - Tier 1B (High-severity generic templates)
  - Tier 2A (Medium-severity tech detections)
  - Tier 2B (Low-severity, info-gathering templates)
  - Custom single/batched template execution for targeted verification
- **CVE Intelligence Enrichment**:
  - **CISA KEV Mapping**: Identifies actively exploited CVEs
  - **EPSS Scoring**: Predicts real-world exploit probability
  - **NVD Data**: Pulls official CVE descriptions and patch links
  - **CWE Classification**: Maps vulnerabilities to Common Weakness Enumeration categories

### 4. **Email Intelligence** ✅
- **Multi-Source Email Harvesting**:
  - `theHarvester`: OSINT tool for email extraction
  - `Hunter.io`: API-based email discovery and pattern detection
  - `Phonebook.cz`: Free phone number and infrastructure lookup (IntelX)
- **Breach Checking**: Validates harvested emails against breach databases via LeakCheck API
- **Exposure Tracking**: Records which emails appear in known public breaches

### 5. **Change Detection & Monitoring** ✅
- **Pre/Post-Scan Analysis**:
  - New/removed subdomains
  - New/closed ports (with high-severity port flagging)
  - New/resolved vulnerabilities
  - New email discoveries and breach detections
- **Smart Change Classification**:
  - High-severity port additions (SSH, RDP, SMB, databases, etc.) flagged automatically
  - Audit trail with scan ID and timestamp
  - Full change history queryable per target

### 6. **Risk Scoring** ✅
- **Multi-Factor Risk Algorithm**:
  - **Vulnerability Burden**: Logarithmic scoring by severity (critical 40 pts, high 25 pts, medium 10 pts, low 3 pts, info 1 pt)
  - **Exposure Multipliers**: 
    - Infrastructure assets (DNS, mail servers, cloud storage) weighted higher
    - Public-facing web apps weighted higher
    - Internal tools/dev systems weighted lower
  - **Email Breach Integration**: Each breached email adds to organizational risk
  - **WHOIS Risk Indicators**: Unprotected domain registration, recently changed, etc.
- **Score Output**: 0-100 scale with risk tier (Low/Medium/High/Critical)

### 7. **Remediation Planning** ✅
- **CWE-Based Remediation**: Pulls remediation guidance from CWE database
- **CVE-Specific Mapping**: Links each vulnerability to:
  - Official patch links
  - Workarounds
  - Detection methods
- **Remediation Tracking**:
  - Manual status updates (open/in-progress/resolved/mitigated)
  - Notes per vulnerability
  - UI-based bulk operations
- **Remediation Summary Stats**: Dashboard showing completion percentage and priority breakdown

### 8. **Smart Scanning (Resumability)** ✅
- **Interrupted Scan Recovery**:
  - Each phase checkpoints its results to MongoDB
  - Failed scans can be resumed without re-running completed phases
  - Phase dependencies handled automatically
- **Phase Tracking**:
  - Phase 0: Passive Recon (Shodan + Censys)
  - Phase 1: Subdomain Discovery
  - Phase 2: Port Scanning
  - Phase 3: HTTP Fingerprinting
  - Phase 4: Vulnerability Scanning
  - Phase 5: Change Detection
  - Phase 6: Risk Scoring

### 9. **Reporting** ✅
- **PDF Report Generation**:
  - Executive summary with key metrics
  - Asset inventory (subdomains, ports, services)
  - Vulnerability detail with CVSS/EPSS scores
  - Change history and new discoveries
  - Remediation recommendations
- **JSON Report Export**: Programmatic access to all report data
- **Real-Time Dashboard**: Live visualization of:
  - Target statistics
  - Vulnerability breakdown by severity
  - Email exposure status
  - Recent changes
  - Scan history and performance

### 10. **Web Dashboard** ✅
- **Target Management**:
  - Add/delete/list domains
  - View per-target statistics
  - Access historical data
- **Scan Management**:
  - Initiate full scans
  - Monitor in-progress scans
  - Resume failed scans
  - View scan history and logs
- **Port Scanning (Naabu)**: Processes targets in configurable batches to resolve Windows command-line length limits and performance bottlenecks during large-scale scans.
- **API Throttling & Quota Protection**: Integrated global `APIThrottler` that enforces mandatory delays between third-party API calls, protecting your search quotas and preventing rate-limiting blocks.
- **Zero-Marker Code Quality**: Optimized routes and serialization logic to clear all IDE linting markers, ensuring high maintainability and performance.
- **Asset Breakdown** (new):
  - Filterable listing of all discovered subdomains, ports, services
  - HTTP asset details with tech stacks
  - Asset classification and exposure tier
- **Vulnerability Dashboard**:
  - Browse all vulnerabilities with severity filtering
  - Link to external sources (NVD, CWE)
  - Exploitation probability via EPSS
- **Email Exposure Tracking**:
  - List all discovered emails
  - Flag breached emails
  - Source attribution (which harvester found each)
- **Changes Timeline**:
  - Chronological view of all asset changes
  - Change severity and impact assessment
- **Remediation Tracker**:
  - Per-vulnerability remediation status
  - Bulk status updates
  - Completion percentage KPI
- **Reports**:
  - Generate/download PDF reports
  - Export JSON for third-party tools
  - View historical reports

---

## Technology Stack

### Backend
- **Framework**: Flask 3.0.0
- **Database**: MongoDB 4.6+ (pymongo 4.6.1)
- **Security**: Werkzeug 3.0.1, python-dotenv for environment config

### Frontend
- **UI Framework**: Vanilla JavaScript + Bootstrap
- **Real-Time Updates**: Client-side polling for scan status
- **Charting**: Browser-native rendering

### External APIs (Paid)
- **Shodan**: Service enumeration, CVE data, SSL certificate data
- **Censys**: SSL/TLS certificate search, service exposure data
- **Hunter.io**: Email discovery and corporate email patterns

### External APIs (Free/Custom)
- **LeakCheck**: Email breach validation
- **IntelX (Phonebook)**: Infrastructure and phone number lookups
- **CISA KEV**: Known Exploited Vulnerabilities catalog (downloaded daily, cached locally)
- **NVD (NIST)**: Official CVE descriptions and CVSS scores
- **EPSS (FIRST.org)**: Exploit Prediction Scoring System

### Scanning/OSINT Tools (via subprocess)
- **Nuclei** (v3.3.7): 10,000+ vulnerability detection templates
- **Naabu** (v2.3.3): Fast port scanning
- **Subfinder** (v2.6.7): Multi-source subdomain discovery
- **HTTPX** (v1.6.10): HTTP fingerprinting and technology detection
- **theHarvester**: Open-source email and domain OSINT

### Data Processing
- **beautifulsoup4**: HTML parsing for HTTPX output cleanup
- **lxml**: XML/HTML backend for parsing
- **tldextract**: Domain and TLD extraction
- **dnspython**: DNS resolution and queries
- **pydantic**: Data validation

### Reporting
- **fpdf2**: PDF generation with tables, images, and formatting
- **PyYAML**: Configuration and data serialization

### Utilities
- **colorama**: Colored terminal logging (Windows-safe)
- **requests & httpx**: HTTP client libraries for all API calls

---

## External Tools & Integrations

### Primary Scanning Tools (Windows EXE / Linux binaries)

| Tool | Version | Purpose | Used In Phase |
|:-----|:--------|:--------|:--------------|
| **Nuclei** | v3.3.7 | Vulnerability template scanning | Phase 4 |
| **Naabu** | v2.3.3 | Fast port scanner | Phase 2 |
| **Subfinder** | v2.6.7 | Subdomain enumeration | Phase 1 |
| **HTTPX** | v1.6.10 | HTTP service fingerprinting | Phase 3 |
| **theHarvester** | Latest | Email OSINT harvesting | Background harvesting |

### Intelligence & Enrichment APIs

| Source | Type | Data Returned | Used In |
|:-------|:-----|:--------------|:--------|
| **Shodan** | REST API | Service info, banners, CVEs, SSL certs | Phase 0 (Passive) |
| **Censys** | REST API | SSL certificate data, exposed services | Phase 0 (Passive) |
| **Hunter.io** | REST API | Corporate emails, email patterns | Email Harvesting |
| **LeakCheck** | REST API | Email breach status, exposure count | Email Harvesting |
| **IntelX (Phonebook)** | REST API | Phone numbers, domain infrastructure | Email Harvesting |
| **CISA KEV** | JSON Feed | Actively exploited vulnerabilities | CVE Enrichment |
| **NVD (NIST)** | REST API | CVE descriptions, CVSS, patch links | CVE Enrichment |
| **EPSS (FIRST.org)** | REST API | Exploit prediction probability (0-1) | Risk Scoring |

---

## System Architecture

### Modular 3-Layer Design

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         UI Layer (templates/)                           │
│  - dashboard.html: Main overview + target management                    │
│  - scans.html: Scan initiation, monitoring, resumability                │
│  - assets.html: Discovered subdomains, ports, services                  │
│  - vulnerabilities.html: Filtered vuln browser with enrichment          │
│  - emails.html: Harvested emails with breach status                     │
│  - changes.html: Timeline of detected changes                           │
│  - remediation.html: Vulnerability remediation tracker                  │
│  - reports.html: Report generation and history                          │
│  - login.html: Simple session-based authentication                      │
└─────────────────────────────────────────────────────────────────────────┘
                                 ↓ (Flask AJAX)
┌─────────────────────────────────────────────────────────────────────────┐
│               API Layer (routes/ - Flask Blueprints)                    │
│  - targets.py: CRUD for target management + background email harvest   │
│  - scans.py: Full scan orchestration and phase tracking                 │
│  - dashboard.py: High-level statistics and summarization                │
│  - assets.py: Asset enumeration with filtering                          │
│  - vulns.py: Vulnerability browsing with sorting/filtering              │
│  - emails.py: Email management, manual harvesting                       │
│  - changes.py: Change history and timeline                              │
│  - remediation.py: Remediation plan generation and tracking             │
│  - reports.py: Report generation (PDF/JSON)                             │
│  - scan_resumability.py: Resume interrupted scans                       │
└─────────────────────────────────────────────────────────────────────────┘
                                 ↓ (Python functions)
┌─────────────────────────────────────────────────────────────────────────┐
│             Logic Layer (core/ - Orchestration & Processing)            │
│  - scanner.py: Full scan pipeline orchestrator (Phase 0-6)              │
│  - shodan_recon.py: Shodan passive data retrieval                       │
│  - censys_recon.py: Censys passive data retrieval                       │
│  - email_harvester.py: Multi-source email discovery + breach check      │
│  - subfinder.py: Subdomain enumeration subprocess wrapper               │
│  - naabu.py: Port scanning subprocess wrapper                           │
│  - httpx_runner.py: HTTP fingerprinting subprocess wrapper              │
│  - nuclei.py: Vulnerability scanning with batching & resumability      │
│  - change_detector.py: Pre/post-scan diff analysis                      │
│  - risk_scorer.py: Multi-factor risk calculation                        │
│  - cve_enricher.py: CISA KEV + EPSS + NVD enrichment                    │
│  - remediation_engine.py: CWE mapping and remediation plan gen          │
│  - whois_lookup.py: Domain registration data extraction                 │
│  - smart_scanner.py: Intelligent template selection for Nuclei          │
└─────────────────────────────────────────────────────────────────────────┘
                                 ↓ (MongoDB ops)
┌─────────────────────────────────────────────────────────────────────────┐
│            Data Layer (database/ - MongoDB Interface)                   │
│  - connection.py: MongoDB connection & initialization                   │
│  - targets_db.py: Target CRUD and statistics                            │
│  - subdomains_db.py: Subdomain storage with deduplication               │
│  - ports_db.py: Port/service records with source tracking               │
│  - http_assets_db.py: HTTP assets (title, tech stack, headers)          │
│  - vulns_db.py: Vulnerability records with full enrichment              │
│  - emails_db.py: Email storage with breach status                       │
│  - scans_db.py: Scan history and phase checkpoints                      │
│  - changes_db.py: Change event records with audit trail                 │
│  - passive_recon_db.py: WHOIS and passive intelligence                  │
└─────────────────────────────────────────────────────────────────────────┘
```

### Data Flow (Full Scan Pipeline)

```
User adds target (domain)
    ↓
[Background] Email harvesting starts
    ↓
User initiates full scan
    ↓
Phase 0: Passive Recon
    ├─ Query Shodan API → save subdomains + ports
    └─ Query Censys API → merge results
    ↓
Phase 1: Subdomain Discovery
    ├─ Run Subfinder binary
    └─ Merge with Phase 0 data
    ↓
Phase 2: Port Scanning
    ├─ Identify hosts from Phase 0+1
    ├─ Run Naabu binary (skips passive hosts)
    └─ Tag results with source="naabu"
    ↓
Phase 3: HTTP Fingerprinting
    ├─ Build list of all discovered IPs:ports
    ├─ Run HTTPX binary
    └─ Extract tech stack + headers
    ↓
Phase 4: Vulnerability Scanning
    ├─ Batch Nuclei by severity tier
    ├─ Run Nuclei with custom templates per phase
    └─ Enrich with CISA KEV + EPSS + NVD
    ↓
Phase 5: Change Detection
    ├─ Load pre-scan snapshot from DB
    ├─ Compare against current results
    └─ Record all additions/deletions
    ↓
Phase 6: Risk Scoring
    ├─ Calculate composite risk score
    └─ Update target metrics in DB
    ↓
Email enrichment (if harvesting completed)
    ├─ Check emails against LeakCheck
    └─ Tag breached emails
    ↓
Scan complete! Results available in UI
```

---

## Feature Breakdown

### Target Management

| Feature | Status | Details |
|:--------|:-------|:--------|
| Add target domain | ✅ | Validates, deduplicates, triggers background email harvest |
| Delete target | ✅ | Removes target and all associated data |
| List targets | ✅ | Paginated view with summary stats |
| Target statistics | ✅ | Subdomain count, port count, vuln count, email count, risk score |
| Domain normalization | ✅ | Extracts root domain from subdomains |

### Scanning Capabilities

| Feature | Status | Details |
|:--------|:-------|:--------|
| Full scan orchestration | ✅ | All 6 phases in sequence with error handling |
| Resumable scans | ✅ | Resume from last checkpoint on network failure |
| Scan scheduling | ⚠️ | No automatic scheduling; manual initiation only |
| Background processing | ✅ | Flask background threading (suitable for dev; use Celery in production) |
| Scan history | ✅ | All scans timestamped and queryable |
| Phase tracking | ✅ | Monitor individual phase progress |

### Asset Discovery

| Asset Type | Discovery Method | Status |
|:-----------|:-----------------|:-------|
| **Subdomains** | Passive (Shodan/Censys) + Active (Subfinder) | ✅ Complete |
| **Ports/Services** | Passive (Shodan/Censys) + Active (Naabu) | ✅ Complete |
| **HTTP Assets** | HTTPX fingerprinting | ✅ Complete with tech stack |
| **Email Addresses** | theHarvester + Hunter.io + Phonebook | ✅ Complete |
| **Certificates** | Censys SSL/TLS database | ✅ Via passive recon |
| **DNS Records** | DNSPython + Subfinder | ✅ Via subdomain discovery |

### Vulnerability Management

| Capability | Status | Tech |
|:-----------|:-------|:-----|
| Template-based scanning | ✅ | Nuclei 10,000+ templates |
| Severity filtering | ✅ | Critical/High/Medium/Low/Info |
| Known exploits flagging | ✅ | CISA KEV mapping |
| Exploitation scoring | ✅ | EPSS API (0-1 probability) |
| CWE classification | ✅ | Map to Common Weakness Enum |
| CVSS scoring | ✅ | From NVD API |
| Remediation guidance | ✅ | CWE remediations + patch links |
| Vuln history | ✅ | Track new/resolved vulns per scan |

### Email & Breach Intelligence

| Capability | Status | Sources |
|:-----------|:-------|:--------|
| Email discovery | ✅ | theHarvester, Hunter.io, Phonebook |
| Breach checking | ✅ | LeakCheck API |
| Multiple breach sources | ✅ | LeakCheck aggregates 500+ databases |
| Breach date tracking | ✅ | Records when email was exposed |
| Breach count | ✅ | How many databases exposed each email |
| Email pattern inference | ⚠️ | Hunter.io provides patterns |

### Change Detection

| Change Type | Detected | Action |
|:------------|:---------|:-------|
| New subdomains | ✅ | Recorded with timestamp |
| Removed subdomains | ✅ | Recorded with timestamp |
| New ports | ✅ | High-severity ports (SSH, RDP, SMB, DB) flagged |
| Closed ports | ✅ | Recorded with timestamp |
| New vulnerabilities | ✅ | Severity-based ranking |
| Resolved vulnerabilities | ✅ | Recorded as resolved |
| New emails | ✅ | Added to exposure list |
| New breaches | ✅ | Flagged immediately |

### Risk Scoring

| Component | Weight | Details | Status |
|:----------|:-------|:--------|:-------|
| Vulnerability burden | 40% | Logarithmic severity counts | ✅ |
| Exposure classification | 30% | Infrastructure/web/internal multipliers | ✅ |
| Email breaches | 20% | Per breached email in org | ✅ |
| WHOIS risk flags | 10% | Domain registration indicators | ✅ |
| **Final Score** | **0-100** | Bucketed to Low/Med/High/Critical tiers | ✅ |

### Reporting

| Report Type | Format | Contents | Status |
|:------------|:-------|:---------|:-------|
| Executive report | PDF | Summary stats, key findings, action items | ✅ |
| Asset inventory | PDF | All subdomains, ports, services with counts | ✅ |
| Vulnerability detail | PDF | All vulns with CVSS, EPSS, remediation | ✅ |
| Change history | PDF | Timeline of detected changes | ✅ |
| JSON export | JSON | All raw data (programmatic) | ✅ |
| HTML dashboard | HTML | Real-time web UI | ✅ |

### Authentication & Access Control

| Feature | Status | Details |
|:--------|:-------|:--------|
| User login | ⚠️ | Multi-user support needed; single admin currently |
| Session management | ✅ | Flask session-based |
| Role-based access | ❌ | Not implemented (all authenticated users see all data) |
| API key auth | ❌ | Not implemented |

---

## Data Management

### MongoDB Collections

```
easm_db/
├── targets                  # Domain targets being monitored
│   ├── domain (string)
│   ├── root_domain (string)
│   ├── added_at (datetime)
│   ├── last_scanned (datetime)
│   ├── risk_score (float: 0-100)
│   ├── subdomain_count (int)
│   ├── port_count (int)
│   ├── vuln_count (int)
│   ├── breached_email_count (int)
│   └── _id (ObjectId)
│
├── subdomains              # Discovered subdomains
│   ├── subdomain (string)
│   ├── target_domain (string)
│   ├── sources (array: ["shodan", "censys", "subfinder", ...])
│   ├── first_seen (datetime)
│   ├── last_seen (datetime)
│   ├── is_old (boolean)
│   ├── target_id (ObjectId ref)
│   └── _id (ObjectId)
│
├── ports_services          # Open ports and services
│   ├── host (string: IP/hostname)
│   ├── port (int)
│   ├── service (string: http, ssh, etc)
│   ├── protocol (string: tcp, udp)
│   ├── sources (array: ["shodan", "naabu", ...])
│   ├── first_seen (datetime)
│   ├── last_seen (datetime)
│   ├── is_old (boolean)
│   ├── target_id (ObjectId ref)
│   └── _id (ObjectId)
│
├── http_assets             # HTTP services with tech stacks
│   ├── url (string: scheme + host + port)
│   ├── status_code (int: 200, 404, etc)
│   ├── title (string)
│   ├── server (string: nginx, Apache, etc)
│   ├── technologies (array: [name, version])
│   ├── headers (dict: raw headers)
│   ├── first_seen (datetime)
│   ├── last_seen (datetime)
│   ├── is_old (boolean)
│   ├── target_id (ObjectId ref)
│   └── _id (ObjectId)
│
├── vulnerabilities         # CVE findings and template detections
│   ├── cve_id (string, nullable: "CVE-2024-1234" or null)
│   ├── template_id (string: nuclei-internal ID)
│   ├── name (string: human-readable vuln name)
│   ├── severity (string: critical, high, medium, low, info)
│   ├── cvss (float: 0-10)
│   ├── epss (float: 0-1)
│   ├── cisa_kev (boolean: actively exploited?)
│   ├── description (string)
│   ├── remediation (string: CWE guidance)
│   ├── affected_host (string: IP or hostname)
│   ├── affected_url (string, nullable)
│   ├── first_seen (datetime)
│   ├── last_seen (datetime)
│   ├── is_old (boolean)
│   ├── scan_id (ObjectId ref)
│   ├── target_id (ObjectId ref)
│   └── _id (ObjectId)
│
├── email_exposures         # Harvested emails and breach status
│   ├── email (string)
│   ├── sources (array: ["theHarvester", "hunter.io", ...])
│   ├── is_breached (boolean)
│   ├── breach_count (int: how many databases)
│   ├── breach_sources (array: database names)
│   ├── first_seen (datetime)
│   ├── last_checked_at (datetime)
│   ├── target_id (ObjectId ref)
│   └── _id (ObjectId)
│
├── changes                 # Detected changes between scans
│   ├── target_id (ObjectId ref)
│   ├── scan_id (ObjectId ref)
│   ├── change_type (string: "new_subdomain", "new_port", ...)
│   ├── severity (string: critical, high, medium, low, info)
│   ├── description (string)
│   ├── details (dict: specific data)
│   ├── detected_at (datetime)
│   └── _id (ObjectId)
│
├── scans                   # Scan execution history & checkpoints
│   ├── target_id (ObjectId ref)
│   ├── domain (string)
│   ├── status (string: "running", "completed", "failed", "paused")
│   ├── started_at (datetime)
│   ├── completed_at (datetime, nullable)
│   ├── completed_phases (array: phase names)
│   ├── failed_phases (array: phase names)
│   ├── phase_data (dict: phase-specific results)
│   ├── error_message (string, nullable)
│   ├── progress_percentage (int: 0-100)
│   └── _id (ObjectId)
│
└── passive_recon           # WHOIS and passive intelligence
    ├── domain (string)
    ├── whois_data (dict: registration info)
    ├── registrar (string)
    ├── created_date (datetime, nullable)
    ├── updated_date (datetime, nullable)
    ├── expiry_date (datetime, nullable)
    ├── risk_flags (array: ["unprotected_whois", ...])
    ├── last_updated (datetime)
    ├── target_id (ObjectId ref)
    └── _id (ObjectId)
```

---

## Setup & Installation

### Prerequisites

- **Python**: 3.9+
- **MongoDB**: 4.6+ (running on localhost:27017 by default)
- **External Tools**: Must be installed separately:
  - `nuclei` (v3.3.7+)
  - `naabu` (v2.3.3+)
  - `subfinder` (v2.6.7+)
  - `httpx` (v1.6.10+)
- **API Keys** (optional but recommended):
  - Shodan API key
  - Censys API ID and secret
  - Hunter.io API key
  - LeakCheck API key (free)

### Installation Steps

1. **Clone the repository**:
   ```bash
   git clone <repo-url>
   cd easm_aegis
   ```

2. **Create a Python virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Python dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Install external tools**:
   - On Linux: Use the Dockerfile as reference; download binary releases
   - On Windows: Download `.exe` files from projectdiscovery GitHub
   - Place all binaries in a `tools/` directory at project root

5. **Configure environment**:
   Create a `.env` file in the project root:
   ```bash
   # MongoDB
   MONGO_URI=mongodb://localhost:27017
   MONGO_DB_NAME=easm_db

   # Flask
   FLASK_SECRET_KEY=your-secret-key-here
   FLASK_DEBUG=True
   FLASK_PORT=5000

   # Admin credentials
   ADMIN_USER=admin
   ADMIN_PASS=admin

   # Tool paths
   SUBFINDER_PATH=tools/subfinder.exe      # Adjust for your OS
   NAABU_PATH=tools/naabu.exe
   NAABU_BATCH_SIZE=100                 # Hosts per batch
   HTTPX_PATH=tools/httpx.exe
   NUCLEI_PATH=tools/nuclei.exe
   API_THROTTLE_SECONDS=5.0             # Quota protection delay

   # API Keys (optional)
   SHODAN_API_KEY=your-key-here
   CENSYS_API_ID=your-id-here
   CENSYS_API_SECRET=your-secret-here
   HUNTER_IO_API_KEY=your-key-here
   LEAKCHECK_API_KEY=your-key-here
   INTELX_API_KEY=your-key-here

   # Scanning parameters
   NAABU_TOP_PORTS=1000
   NAABU_RATE=1000
   NUCLEI_SEVERITY=critical,high,medium,low
   NUCLEI_RATE_LIMIT=150
   SCAN_TIMEOUT=3600
   ```

6. **Initialize the database**:
   MongoDB will auto-initialize on first run. Ensure it's running:
   ```bash
   # Example (adjust for your environment)
   mongod --dbpath ./data
   ```

---

## Running the Application

### Development Mode

```bash
# From the project root (with venv activated)
python app.py
```

Server will start at `http://localhost:5000`

### Docker (Optional)

```bash
# Build
docker build -t easm-aegis .

# Run
docker run -p 5000:5000 --network host easm-aegis
```

### Health Check

```bash
# API health endpoint
curl http://localhost:5000/api/health

# Response:
{
  "status": "healthy",
  "database": "connected",
  "app": "EASM Tool"
}
```

---

## API Endpoints

### Targets

| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| `GET` | `/api/targets` | List all targets with pagination |
| `POST` | `/api/targets` | Add new target (triggers email harvest) |
| `GET` | `/api/targets/{id}` | Get target details |
| `DELETE` | `/api/targets/{id}` | Delete target and all data |

### Scans

| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| `POST` | `/api/scans/full/{domain}` | Initiate full scan (6 phases) |
| `GET` | `/api/scans/status/{scan_id}` | Get scan progress |
| `GET` | `/api/scans/history/{domain}` | Get all scans for a domain |
| `POST` | `/api/scans/resume/{scan_id}/now` | Resume failed scan |
| `GET` | `/api/scans/resume/{scan_id}/check` | Check if scan resumable |

### Assets

| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| `GET` | `/api/assets/subdomains/{domain}` | List subdomains with filters |
| `GET` | `/api/assets/ports/{domain}` | List ports/services |
| `GET` | `/api/assets/http/{domain}` | List HTTP assets with tech stacks |

### Vulnerabilities

| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| `GET` | `/api/vulns/{domain}` | List vulns with filtering/sorting |
| `POST` | `/api/vulns/{vuln_id}/notes` | Add remediation notes |

### Emails

| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| `GET` | `/api/emails/{domain}` | List emails with breach status |
| `POST` | `/api/emails/harvest/{domain}` | Manual email harvest |

### Changes

| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| `GET` | `/api/changes/{domain}` | Get change timeline |

### Remediation

| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| `GET` | `/api/remediation/generate/{domain}` | Generate remediation plan |
| `POST` | `/api/remediation/update/{vuln_id}` | Update vuln status |

### Reports

| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| `GET` | `/api/reports/json/{domain}` | Export report as JSON |
| `GET` | `/api/reports/pdf/{domain}` | Generate & download PDF |

### Dashboard

| Method | Endpoint | Purpose |
|:-------|:---------|:--------|
| `GET` | `/api/dashboard/summary` | Overall platform stats |
| `GET` | `/api/dashboard/target/{domain}` | Target-specific metrics |
| `GET` | `/api/stats` | Real-time asset/vuln counts |

---

## Current Limitations

### Known Issues

| Limitation | Impact | Workaround |
|:-----------|:-------|:-----------|
| **Single admin user** | Multi-user scenarios require code modification | Implement RBAC layer (future) |
| **No scan scheduling** | Must manually trigger scans | Use external cron/task scheduler |
| **Threading-based background jobs** | Will lose jobs on app restart | Deploy Celery for production |
| **Email harvesting async only on target add** | Must manually trigger if needing re-harvest | Use `/api/emails/harvest/{domain}` endpoint |
| **Nuclei template updates manual** | Templates may become outdated | Run `nuclei -update-templates` externally |

### Not Implemented

- ❌ Continuous scheduled scanning
- ❌ Webhook notifications on findings
- ❌ Multi-tenant isolation
- ❌ SAML/OAuth integration
- ❌ Fine-grained access control (RBAC)
- ❌ API versioning
- ❌ Rate limiting per user
- ❌ Slack/email alert integration
- ❌ Machine learning-based prioritization
- ❌ Historical trend analysis

### Performance Notes

- **Large scans** (1000+ hosts): May take 30-60 minutes depending on tool concurrency
- **Database growth**: After 100+ targets, consider MongoDB indexing optimization
- **Nuclei concurrency**: Controlled via `NUCLEI_CONCURRENCY` config; balance accuracy vs speed
- **Email harvesting**: theHarvester can be slow; 5-15 minutes per domain typical

---

## Support & Documentation

- **Architecture Guide**: See `architecture_and_workflow.md`
- **Technical Breakdown**: See `TECHNICAL_BREAKDOWN.md`
- **Project Guide**: See `PROJECT_GUIDE.md`
- **Nuclei Optimization**: See `NUCLEI_OPTIMIZATION.md`
- **Resumability Guide**: See `RESUMABILITY.md`
- **Implementation Guide**: See `IMPLEMENTATION_GUIDE.md`
- **Code Review**: See `CODE_REVIEW.md`

---

**Last Updated**: April 2026  
**Status**: Production-Ready with Known Limitations
