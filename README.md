# EASM AEGIS — External Attack Surface Management Platform

**AEGIS** (Automated External-asset Guardian & Intelligence System) is a modular, intelligence-driven EASM platform that automates the discovery, fingerprinting, and vulnerability assessment of an organization's external attack surface — and generates actionable, prioritized remediation plans.

> Built with Flask (Python 3.9+), MongoDB, and a pipeline of specialized reconnaissance tools.
>
> **Project Status**: Core pipeline and intelligence engine are **Production-Ready**. Dashboard analytics for passive recon are currently undergoing maintenance.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Scanning Pipeline](#scanning-pipeline)
3. [Project Structure](#project-structure)
4. [Database Schema](#database-schema)
5. [Core Modules](#core-modules)
6. [Routes & API](#routes--api)
7. [Frontend Templates](#frontend-templates)
8. [Utilities](#utilities)
9. [Configuration](#configuration)
10. [External Tools](#external-tools)
11. [Remediation Engine](#remediation-engine)
12. [Resumability](#resumability)
13. [Risk Scoring](#risk-scoring)
14. [Change Detection](#change-detection)
15. [Security Features](#security-features)
16. [Deployment](#deployment)
17. [Hardware & Software Requirements](#hardware--software-requirements)

---

## Architecture Overview

AEGIS follows a **hub-and-spoke** architecture with MongoDB as the central data store. The scanning pipeline is orchestrated by `core/scanner.py`, which calls specialized tool modules in sequence. Each phase's output feeds into the next, with checkpoints enabling full resumability.

```
┌─────────────────────────────────────────────────────────────────┐
│                        EASM AEGIS Platform                      │
│                                                                 │
│  ┌──────────┐   ┌──────────────┐   ┌──────────────────────────┐│
│  │  Flask    │   │   Scanner    │   │     External Tools       ││
│  │  Web App  │──▶│  Orchestrator│──▶│  Subfinder, Amass, Naabu ││
│  │  (app.py) │   │ (scanner.py) │   │  HTTPX, Nuclei, Arjun   ││
│  └────┬─────┘   └──────┬───────┘   │  Shodan, Censys, WHOIS   ││
│       │                │           │  theHarvester, LeakCheck  ││
│       ▼                ▼           └──────────────────────────┘│
│  ┌──────────────────────────────┐                              │
│  │          MongoDB             │                              │
│  │  targets, subdomains, ports  │                              │
│  │  http_assets, vulns, emails  │                              │
│  │  scans, changes, endpoints   │                              │
│  │  passive_recon               │                              │
│  └──────────────────────────────┘                              │
└─────────────────────────────────────────────────────────────────┘
```

### Data Flow

```
Security Analyst
    │
    ▼
Dashboard (Flask) ─── Add Target ──▶ MongoDB (targets)
    │                                     │
    ▼                                     ▼
View Results ◀──── Scanner Pipeline ─── Phase 0 → 6
    │                                     │
    ▼                                     ▼
Remediation Plan ◀── Enrichment ◀── NVD + EPSS + KEV
```

---

## Scanning Pipeline

The scanner (`core/scanner.py`) executes an 8-phase pipeline. Each phase is independently fault-tolerant (wrapped in try/except) and checkpoint-resumable.

| Phase | Name | Tool(s) | Output Collection |
|-------|------|---------|-------------------|
| **0** | Passive Recon | Shodan API, Censys API, WHOIS | `passive_recon` |
| **1** | Subdomain Discovery | Subfinder + Amass + crt.sh | `subdomains` |
| **2** | Port Scanning | Naabu (skips passive-covered hosts) | `ports` |
| **3** | HTTP Fingerprinting | HTTPX | `http_assets` |
| **3.5** | Parameter Discovery | Arjun (opt-in, active) | `endpoints` |
| **4** | Vulnerability Scanning | Nuclei (6-tier intelligence-driven) | `vulnerabilities` |
| **5** | Change Detection | Diff engine (pre/post snapshot) | `changes` |
| **6** | Risk Scoring | Multi-factor algorithm (logarithmic) | `targets.risk_score` |

### Phase 4: Intelligence-Driven Vulnerability Scanning (6 Tiers)

Phase 4 uses `core/smart_scanner.py` to build a scan plan with 6 tiers of decreasing specificity:

| Tier | Strategy | What It Scans |
|------|----------|---------------|
| **1A** | CVE-targeted | Known CVEs from Shodan/Censys → exact Nuclei templates |
| **1B** | Tech-targeted | Detected technologies (nginx, Apache, WordPress) → matching tags |
| **2A** | Port-targeted | Service ports (3306→MySQL, 6379→Redis) → service-specific tags |
| **2B** | Header-targeted | HTTP headers (Server, X-Powered-By) → tech-specific tags |
| **2C** | Catch-all (web) | Remaining web hosts → critical+high severity only |
| **2C-NET** | Network scan | Non-web hosts → network protocol templates |

### Phase 3.5: Parameter Discovery (Arjun)

Arjun is an **active, intrusive** tool — gated by an opt-in flag:

```python
# In MongoDB target document:
{
    "scan_config": {
        "enable_parameter_discovery": true,      # default: false
        "parameter_discovery_rate_limit": 15     # requests/sec override
    }
}
```

---

## Project Structure

```
easm code/
├── app.py                    # Flask application entry point
├── config.py                 # All configuration & environment variables
├── requirements.txt          # Python dependencies
├── Dockerfile                # Container build
├── docker-compose.yml        # Docker orchestration (app + MongoDB)
├── .env                      # Environment variables (API keys, DB URI)
│
├── core/                     # Pipeline engine modules
│   ├── scanner.py            # Main orchestrator (Phase 0–6)
│   ├── smart_scanner.py      # Intelligence-driven scan plan builder
│   ├── subfinder.py          # Subdomain discovery (Phase 1)
│   ├── amass.py              # Amass passive enum (Phase 1, parallel)
│   ├── naabu.py              # Port scanning (Phase 2)
│   ├── httpx_runner.py       # HTTP fingerprinting (Phase 3)
│   ├── arjun_runner.py       # Parameter discovery (Phase 3.5, opt-in)
│   ├── nuclei.py             # Vulnerability scanning (Phase 4)
│   ├── shodan_recon.py       # Shodan passive recon (Phase 0)
│   ├── censys_recon.py       # Censys passive recon (Phase 0)
│   ├── whois_lookup.py       # WHOIS passive recon (Phase 0)
│   ├── email_harvester.py    # Email discovery (theHarvester + IntelX + Hunter.io)
│   ├── change_detector.py    # Change detection engine (Phase 5)
│   ├── risk_scorer.py        # Risk scoring algorithm (Phase 6)
│   ├── cve_enricher.py       # CVE/CWE enrichment (NVD + EPSS + KEV)
│   ├── remediation_engine.py # Remediation plan generator
│   ├── api_key_manager.py    # Encrypted API key storage
│   └── wordlist_builder.py   # Dynamic wordlist generator for mining
│
├── database/                 # MongoDB collection modules
│   ├── connection.py         # MongoDB connection management
│   ├── targets_db.py         # TARGET collection CRUD
│   ├── subdomains_db.py      # SUBDOMAINS collection CRUD
│   ├── ports_db.py           # PORTS collection CRUD
│   ├── http_assets_db.py     # HTTP_ASSETS collection CRUD
│   ├── vulns_db.py           # VULNERABILITIES collection CRUD
│   ├── emails_db.py          # EMAILS collection CRUD
│   ├── endpoints_db.py       # ENDPOINTS collection CRUD (Arjun)
│   ├── scans_db.py           # SCANS collection + phase checkpoints
│   ├── passive_recon_db.py   # Shodan/Censys/WHOIS results
│   └── changes_db.py         # Change detection results
│
├── routes/                   # Flask route blueprints
│   ├── __init__.py           # Blueprint registration
│   ├── dashboard.py          # Dashboard analytics API
│   ├── targets.py            # Target management CRUD
│   ├── scans.py              # Scan launch, status, history
│   ├── vulns.py              # Vulnerability listing + detail
│   ├── remediation.py        # Remediation plan generation
│   ├── assets.py             # Asset breakdown + classification
│   ├── passive_recon.py      # Passive recon data display
│   ├── emails.py             # Email harvesting results
│   ├── changes.py            # Change detection feed
│   ├── reports.py            # PDF/JSON report generation
│   ├── api_keys.py           # API key management UI
│   └── scan_resumability.py  # Scan resume/retry control
│
├── templates/                # Jinja2 HTML templates
│   ├── base.html             # Main layout (sidebar, nav, scripts)
│   ├── base_minimal.html     # Minimal layout (login page)
│   ├── dashboard.html        # Security overview dashboard
│   ├── targets.html          # Target management list
│   ├── target_detail.html    # Single target deep-dive
│   ├── scans.html            # Scan history + controls
│   ├── vulnerabilities.html  # Vulnerability listing
│   ├── vulnerability_detail.html  # Single vuln detail
│   ├── remediation.html      # Remediation plan view
│   ├── asset_breakdown.html  # Asset criticality analysis
│   ├── recon.html            # Passive recon data view
│   ├── emails.html           # Email discovery results
│   ├── changes.html          # Change detection timeline
│   ├── reports.html          # Report generation UI
│   ├── api_keys.html         # API key configuration
│   └── login.html            # Authentication page
│
├── static/js/                # Frontend JavaScript
│   ├── api.js                # Shared API client
│   ├── dashboard.js          # Dashboard charts + real-time updates
│   ├── asset_breakdown.js    # Asset breakdown visualization
│   └── target.js             # Target detail interactions
│
├── utils/                    # Shared utilities
│   ├── logger.py             # Structured logging with colors
│   ├── encryption.py         # AES encryption for API keys
│   ├── sanitize.py           # Input sanitization
│   ├── pagination.py         # MongoDB pagination helper
│   ├── throttler.py          # API rate limiting
│   └── asset_classifier.py   # Subdomain criticality classifier
│
├── data/                     # Static data files
│   ├── cwe_remediation.json  # 110 CWE remediation entries
│   └── kev_catalog.json      # CISA KEV catalog (auto-refreshed)
│
├── tools/                    # External binary tools
│   ├── subfinder.exe         # Subdomain discovery
│   ├── amass.exe             # OWASP Amass passive enum
│   ├── naabu.exe             # Port scanner
│   ├── httpx.exe             # HTTP fingerprinting
│   ├── nuclei.exe            # Vulnerability scanner
│   └── theHarvester/         # Email harvesting tool
│
├── logs/                     # Application log files
├── temp/                     # Temporary scan I/O files
├── reports/                  # Generated PDF/JSON reports
└── generated_reports/        # Exported remediation reports
```

---

## Database Schema

MongoDB database: `easm_aegis` (configurable via `MONGO_DB_NAME`)

### Collections & Relationships

```
TARGET (root entity)
  ├── 1:N → SUBDOMAINS (source: subfinder/amass/censys/shodan/merged)
  ├── 1:N → PORTS (discovered by Naabu)
  ├── 1:N → HTTP_ASSETS (discovered by HTTPX)
  ├── 1:N → VULNERABILITIES (discovered by Nuclei + Shodan CVEs)
  ├── 1:N → EMAILS (harvested by theHarvester/IntelX/Hunter.io)
  ├── 1:N → ENDPOINTS (discovered by Arjun)
  ├── 1:N → SCANS (scan history with phase checkpoints)
  ├── 1:N → CHANGES (cross-scan diff results)
  └── 1:1 → PASSIVE_RECON (Shodan + Censys + WHOIS snapshots)
```

### Key Fields

**TARGET**: `domain`, `status`, `risk_score` (0-100), `scan_phase_completed`, `scan_config`

**SUBDOMAINS**: `subdomain`, `source` (subfinder|amass|censys|shodan|merged), `status` (active|old)

**VULNERABILITIES**: `name`, `severity` (critical|high|medium|low|info), `cve_id`, `cwe_id`, `host`, `matched_at`, `template_id`

**ENDPOINTS**: `url`, `method` (GET|POST|JSON|XML), `parameters` [list], `discovered_at`

**SCANS**: `scan_id`, `status`, `phases_completed` [list], `progress` (0-100)

### Status-Based Change Detection

All collections use `status: "active"|"old"` for change detection:
- Before scan: `mark_all_*_old(target_id)` marks existing records as `"old"`
- During scan: New/rediscovered records are written with `status: "active"`
- Phase 5: Compares `active` vs `old` records to detect new/removed assets

---

## Core Modules

### `core/scanner.py` — Pipeline Orchestrator
- Entry point: `run_full_scan(target_id, domain)` or `resume_scan(scan_id)`
- Manages all 8 phases sequentially
- Each phase writes checkpoints to MongoDB for resumability
- Progress updates pushed to DB for frontend polling
- Helper functions: `_run_tag_tier_scan()`, `_run_simple_tier_scan()`, `_preferred_targets_for_hosts()`

### `core/smart_scanner.py` — Scan Plan Builder
- `build_scan_plan()`: Analyzes passive recon + HTTPX + port data to create a 6-tier targeting matrix
- `PORT_TO_NUCLEI_TAGS`: Maps service ports to vulnerability tags (3306→mysql, 6379→redis)
- `NETWORK_SCAN_TAGS`: Tags for non-web host scanning (ssh, ftp, dns, smtp, etc.)
- `WEB_PORTS`: Ports for web-vs-non-web classification
- CVE template index: Pre-built mapping of CVE IDs to Nuclei template paths

### `core/amass.py` — Subdomain Discovery (Parallel)
- Runs OWASP Amass in **passive mode only** (`enum -passive`)
- Parallel to Subfinder in Phase 1
- Results tagged with `source: "amass"` or `source: "merged"` if found by both tools
- Graceful: `is_available()` check — pipeline proceeds without it if not installed

### `core/arjun_runner.py` — Parameter Discovery
- Discovers hidden HTTP parameters via fuzzing
- Only targets HTTPX-confirmed live URLs
- Uses `--stable` mode to reduce false positives
- Rate-limited via config
- Output stored in `endpoints` collection

### `core/email_harvester.py` — OSINT Identity Intel
- Discovers emails via theHarvester (Google, Bing, LinkedIn, etc.)
- Enriches with breach data from **IntelX** and **LeakCheck**
- Detects email patterns via Hunter.io API
- Automated cleanup of temporary OSINT data

### `core/cve_enricher.py` — Threat Intelligence
- **NVD**: CVE descriptions, patch links, CVSS details
- **EPSS**: Exploitation probability scores (0-1)
- **KEV**: CISA Known Exploited Vulnerabilities catalog
- **CWE KB**: 4-tier remediation lookup (static → category → NVD API → generic)
- All API calls are cached and rate-limited

### `core/remediation_engine.py` — Remediation Plan Generator
- Combines 4 sources: KEV required action → CWE knowledge base → Nuclei template → auto-generated
- Priority scoring based on severity × EPSS × KEV status
- Groups vulns into: Fix Immediately / Fix This Week / Fix This Month / Fix Next Quarter / Informational
- Entry point: `get_remediation_plan(target_id)`

### `core/risk_scorer.py` — Risk Scoring Algorithm
- Multi-factor score (0-100) combining:
  - Vulnerability severity (logarithmic compression to prevent inflation)
  - Asset criticality multipliers (production infrastructure weighted higher)
  - Exposure metrics (open ports, public services)
  - Email breach data
  - WHOIS security flags (expiring domain, missing DNSSEC)

### `core/change_detector.py` — Cross-Scan Diffing
- Snapshots assets before scan, compares after
- Detects: new subdomains, removed subdomains, new ports, closed ports, new vulns, fixed vulns
- Results stored in `changes` collection for timeline view

---

## Routes & API

All routes are registered as Flask Blueprints in `routes/__init__.py`.

| Route | File | Purpose |
|-------|------|---------|
| `/` | `dashboard.py` | Security overview with charts |
| `/api/dashboard/stats` | `dashboard.py` | JSON stats for dashboard JS |
| `/targets` | `targets.py` | Target CRUD |
| `/api/targets/<id>` | `targets.py` | Target detail API |
| `/scans` | `scans.py` | Scan history, launch, resume |
| `/api/scans/start` | `scans.py` | Start new scan |
| `/api/scans/resume/<id>` | `scan_resumability.py` | Resume interrupted scan |
| `/vulnerabilities` | `vulns.py` | Vulnerability listing |
| `/vulnerability/<id>` | `vulns.py` | Single vulnerability detail |
| `/remediation/<target>` | `remediation.py` | Remediation plan |
| `/assets` | `assets.py` | Asset breakdown |
| `/api/assets/breakdown` | `assets.py` | Asset classification data |
| `/recon/<target>` | `passive_recon.py` | Passive recon results |
| `/emails/<target>` | `emails.py` | Email discovery results |
| `/changes` | `changes.py` | Change detection timeline |
| `/reports` | `reports.py` | Report generation |
| `/api-keys` | `api_keys.py` | API key management |

---

## Frontend Templates

All templates extend `base.html`, which provides:
- Responsive sidebar navigation
- Top navbar with search and user controls
- CSS variables for theming
- Chart.js integration for data visualization
- WebSocket-ready structure for real-time scan updates

### Key Template Features

- **dashboard.html**: Risk score gauge, severity distribution pie chart, recent scan timeline, asset count cards
- **target_detail.html**: Tabbed view (subdomains, ports, HTTP assets, vulns, emails, passive recon)
- **remediation.html**: Priority-grouped action items with code examples, OWASP references, timelines
- **asset_breakdown.html**: Criticality tiers (Critical/High/Standard/Low) with vulnerability tower graph

---

## Utilities

| Module | Purpose |
|--------|---------|
| `utils/logger.py` | Color-coded logging with file + console handlers |
| `utils/encryption.py` | AES-256 encryption for API keys (PBKDF2 key derivation) |
| `utils/sanitize.py` | Input validation and XSS prevention |
| `utils/pagination.py` | MongoDB cursor pagination helper |
| `utils/throttler.py` | API rate limiting decorator |
| `utils/asset_classifier.py` | Subdomain criticality scoring (Critical/High/Standard/Low) |

---

## Configuration

All config is centralized in `config.py` (class `Config`), loaded from environment variables with sensible defaults.

### Environment Variables (.env)

```bash
# Database
MONGO_URI=mongodb://localhost:27017
MONGO_DB_NAME=easm_aegis

# API Keys (encrypted in MongoDB, set here for first-time setup)
SHODAN_API_KEY=your_key_here
CENSYS_API_ID=your_id_here
CENSYS_API_SECRET=your_secret_here

# Flask
FLASK_SECRET_KEY=your_secret_key
FLASK_DEBUG=false

# Encryption
ENCRYPTION_KEY=your_encryption_key_for_api_key_storage
```

### Tool Paths

```python
SUBFINDER_PATH = "tools/subfinder.exe"
NAABU_PATH     = "tools/naabu.exe"
HTTPX_PATH     = "tools/httpx.exe"
NUCLEI_PATH    = "tools/nuclei.exe"
AMASS_PATH     = "tools/amass.exe"
ARJUN_PATH     = "venv/Scripts/arjun.exe"
```

### Key Settings

```python
NUCLEI_BATCH_SIZE      = 25     # Hosts per Nuclei invocation
NUCLEI_RATE_LIMIT      = 150    # Requests/second for Nuclei
NUCLEI_TIER2C_SEVERITY = "critical,high"  # Catch-all tier filter
AMASS_TIMEOUT          = 600    # Max seconds for Amass
ARJUN_TIMEOUT          = 300    # Max seconds for Arjun
ARJUN_RATE_LIMIT       = 10     # Requests/second for Arjun
```

---

## External Tools

| Tool | Version | Purpose | Installation |
|------|---------|---------|-------------|
| **Subfinder** | Latest | Passive subdomain discovery | `tools/subfinder.exe` |
| **Amass** | v4.2.0 | OWASP passive subdomain enum | `tools/amass.exe` |
| **Naabu** | Latest | Port scanning | `tools/naabu.exe` |
| **HTTPX** | Latest | HTTP fingerprinting | `tools/httpx.exe` |
| **Nuclei** | Latest | Template-based vuln scanning | `tools/nuclei.exe` |
| **Arjun** | v2.2.7 | HTTP parameter discovery | `pip install arjun` |
| **theHarvester** | Latest | Email address harvesting | `tools/theHarvester/` |
| **IntelX** | API | Breach checking & OSINT | `intelx.io` |

All Go-based tools (Subfinder, Naabu, HTTPX, Nuclei) can be downloaded from [ProjectDiscovery GitHub](https://github.com/projectdiscovery).

---

## Remediation Engine

### 4-Tier CWE Lookup

```
CWE-ID arrives
    │
    ├── Tier 1: Static Database (110 exact entries)
    │           Source: data/cwe_remediation.json
    │           Quality: ★★★★★ (curated fix steps + code examples)
    │
    ├── Tier 2: Category Inheritance (322 mapped CWEs → 20 category templates)
    │           Source: CATEGORY_REMEDIATION in cve_enricher.py
    │           Quality: ★★★★☆ (category-appropriate universal guidance)
    │
    ├── Tier 3: NVD/MITRE API Fallback (for unmapped CWEs)
    │           Source: Live API call (cached 24h)
    │           Quality: ★★★☆☆ (fetched description + generic steps)
    │
    └── Tier 4: Generic Template (last resort)
                Quality: ★★☆☆☆ (boilerplate)
```

### Categories Covered by Tier 2

injection, authentication, authorization, path traversal, session management, cryptography, information disclosure, input validation, configuration, denial of service, secrets exposure, memory safety, race conditions, file upload, API security, supply chain, error handling, business logic, protocol security, privilege escalation

### Remediation Sources (Priority Order)

1. **CISA KEV Required Action** — Most authoritative (mandated by federal directive)
2. **CWE Knowledge Base** — Most detailed (fix steps + code examples)
3. **Nuclei Template Remediation** — Template-specific guidance
4. **Auto-generated Fallback** — Severity-based generic advice

---

## Resumability

Scans checkpoint to MongoDB after each phase. If interrupted:

1. `resume_scan(scan_id)` reads `phases_completed` from the scan document
2. Completed phases are skipped entirely
3. Phase outputs are reloaded from DB collections (subdomains, ports, etc.)
4. `mark_all_*_old()` is **not called** on resume (preserves existing data)
5. Scanning continues from the next incomplete phase

### Phase Names (Checkpoint Strings)

```
"passive_recon" → "subdomain_discovery" → "port_scanning" →
"http_fingerprinting" → "parameter_discovery" → "vuln_scanning" →
"change_detection" → "risk_scoring"
```

---

## Risk Scoring

The risk score (0-100) combines multiple factors:

| Factor | Weight | Source |
|--------|--------|--------|
| Vulnerability severity | High | Nuclei findings, logarithmic compression |
| KEV status | High | CISA actively exploited list |
| Asset criticality | Medium | Subdomain classification (Tier-based) |
| Exposure metrics | Low | Open port count, public services |
| Email breaches | Low | IntelX / LeakCheck results |
| WHOIS flags | Low | Expiring domain, missing DNSSEC |

---

## Change Detection

Phase 5 detects what changed since the last scan:

| Change Type | Detection Method |
|-------------|-----------------|
| New subdomain | In current scan, not in previous |
| Removed subdomain | In previous scan, not in current |
| New open port | Port active now, was old/missing before |
| Closed port | Port was active, now old/missing |
| New vulnerability | Vuln found now, not in previous scan |
| Fixed vulnerability | Vuln was in previous scan, not found now |

Results stored in `changes` collection with `change_type`, `severity`, `timestamp`, and `details`.

---

## Security Features

| Feature | Implementation |
|---------|---------------|
| API key encryption | AES-256 via `cryptography` library (PBKDF2 key derivation) |
| Input sanitization | `utils/sanitize.py` strips XSS, validates URLs/domains |
| Rate limiting | `utils/throttler.py` + per-tool rate limits in config |
| Passive-first recon | Phases 0-1 use passive sources only (no target interaction) |
| Opt-in active scanning | Arjun parameter discovery requires explicit enable |
| Graceful tool absence | Every tool has `is_available()` — pipeline skips missing tools |
| Error isolation | Each phase in try/except — one failure doesn't break the pipeline |
| Credential isolation | API keys stored encrypted in MongoDB, not in config files |

---

## Deployment

### Local Development

```bash
# 1. Install Python dependencies
pip install -r requirements.txt

# 2. Ensure MongoDB is running
mongod --dbpath /data/db

# 3. Configure .env file with API keys

# 4. Run the application
python app.py
# → http://localhost:5000
```

### Docker

```bash
# Build and run with Docker Compose
docker-compose up --build

# Services:
#   - web: Flask app on port 5000
#   - mongo: MongoDB on port 27017
```

### Production Considerations

- Set `FLASK_DEBUG=false` in production
- Use a WSGI server (Gunicorn) instead of Flask's built-in server
- Configure MongoDB authentication and TLS
- Set up log rotation for `logs/` directory
- Run Nuclei template updates regularly (`nuclei -update-templates`)

---

## Hardware & Software Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | Windows 10+, Ubuntu 20.04+, or macOS 12+ |
| **Python** | 3.9+ |
| **MongoDB** | 5.0+ |
| **RAM** | 4 GB minimum (8 GB recommended) |
| **Disk** | 2 GB for tools + variable for scan data |
| **Network** | Outbound HTTPS access for APIs and scanning |

### Python Dependencies

```
Flask==3.0.0, pymongo==4.6.1, requests==2.31.0, shodan==1.31.0,
dnspython==2.8.0, fpdf2==2.8.7, tldextract==5.3.1, python-whois==0.8.0,
cryptography>=41.0.0, colorama==0.4.6, PyYAML==6.0.2, arjun==2.2.7
```

### External Tool Sizes

| Tool | Size |
|------|------|
| Nuclei | ~154 MB |
| HTTPX | ~38 MB |
| Amass | ~36 MB |
| Naabu | ~28 MB |
| Subfinder | ~28 MB |

---

## License

Internal project — EASM AEGIS Platform.
