# EASM AEGIS — COMPLETE TECHNICAL BREAKDOWN

This document provides a definitive technical audit of the EASM AEGIS project. It details the exact data flows, tool integrations, database operations, and security mechanisms implementing the core External Attack Surface Management (EASM) functionality.

═══════════════════════════════════════════════════════════════
SECTION 1: COMPLETE DATA FLOW (Step by Step)
═══════════════════════════════════════════════════════════════

### 1.1 Action: Adding a New Target
**Trigger:** User sends POST request to `/api/targets/` with `domain`.
**Flow:**
1.  `routes/targets.py` -> `add_target()` receives request.
2.  Calls `utils/sanitize.py` -> `sanitize_domain()` for input validation.
3.  Calls `database/connection.py` -> `get_db()` to access MongoDB.
4.  Queries `Config.TARGETS_COLLECTION` ("targets") to check for duplicates.
5.  Inserts new document using `database/targets_db.py` -> `add_target()`.
6.  Spawns background thread calling `_harvest_emails_background()`.
7.  `_harvest_emails_background` calls `core/email_harvester.py` -> `harvest_and_check()`.
8.  See section 1.3 for detailed email harvest flow.

### 1.2 Action: Running a Full Scan
**Trigger:** User sends POST request to `/api/scans/full/<domain>`.
**Flow:**
1.  `routes/scans.py` -> `full_scan()` receives request.
2.  Calls `database/scans_db.py` -> `create_scan_with_domain()` to initialize record in "scans" collection.
3.  Spawns background thread calling `_run_scan_background()`.
4.  `_run_scan_background` calls `core/scanner.py` -> `run_full_scan()`.
5.  **Phase 0 (Passive Recon):** `scanner.py` calls `core/shodan_recon.py` -> `run_passive_recon()` and `core/censys_recon.py` -> `run_passive_recon()`. Results saved to "subdomains" and "ports_services" collections.
6.  **Phase 1 (Subdomain Discovery):** Calls `core/subfinder.py` -> `scan_subdomains()`. Merges results with Phase 0 data. Calls `database/subdomains_db.py` -> `add_subdomains_bulk()`.
7.  **Phase 2 (Port Scanning):** Identifies hosts not found via passive recon. Calls `core/naabu.py` -> `run_naabu()`. Results are tagged with `source="naabu"` and saved via `database/ports_db.py` -> `add_ports_bulk()`. Finally, all discovered ports (Passive + Naabu) are merged and saved with a generic `source="scan"` tag to update `last_seen` while preserving specific discovery history in the `sources` array.
8.  **Phase 3 (HTTP Probing):** Calls `core/httpx_runner.py` -> `run_httpx()`. Results saved via `database/http_assets_db.py` -> `add_http_asset()`.
9.  **Phase 4 (Vulnerability Scan):** Calls `core/nuclei.py` -> `run_nuclei()`. Results saved via `database/vulns_db.py` -> `add_vulnerability()`.
10. **Phase 5 (Change Detection):** Calls `core/change_detector.py` -> `detect_changes()`. Compares pre-scan snapshot with current results. Saves changes to "changes" collection.
11. **Phase 6 (Risk Scoring):** Calls `core/risk_scorer.py` -> `calculate_risk_score()`. Updates target metrics in "targets" collection.
12. **Finalize:** Calls `database/scans_db.py` -> `complete_scan()` to mark "scans" record as completed.

### 1.3 Action: Harvesting Emails (Discovery + Breach Check)
**Trigger:** Add Target background thread OR manual POST to `/api/emails/harvest/<domain>`.
**Flow:**
1.  `routes/emails.py` -> `manual_harvest()` OR `routes/targets.py` -> `_harvest_emails_background()`.
2.  Calls `core/email_harvester.py` -> `harvest_and_check()`.
3.  Calls `harvest_emails()` which runs:
    - `run_theharvester()`: Executes `theHarvester` binary.
    - `run_hunter_io()`: Queries `api.hunter.io/v2/domain-search`.
    - `run_phonebook()`: Queries `2.intelx.io/phonebook/search` (IntelX).
4.  Deduplicates unique email addresses.
5.  Calls `check_breaches_batch()` which iterates through emails and calls `check_leakcheck()`.
6.  `check_leakcheck()` queries `leakcheck.io/api/public`.
7.  Aggregated data (email + sources + breach status) returned to caller.
8.  Caller saves data via `database/emails_db.py` -> `add_emails_bulk()` into "email_exposures" collection.

### 1.4 Action: Generating Remediation Plan
**Trigger:** User sends GET to `/api/remediation/generate/<domain>`.
**Flow:**
1.  `routes/remediation.py` -> `generate_plan()` queries vulnerabilities in DB.
2.  Enriches findings with:
    - **CISA KEV:** Checks if CVE is in Known Exploited Vulnerabilities.
    - **EPSS:** Fetches Exploit Prediction Scoring System score.
    - **CWE:** Maps findings to Common Weakness Enumeration descriptions.

### 1.5 Action: Generating PDF Report
**Trigger:** User sends GET to `/api/reports/pdf/<domain>`.
**Flow:**
1.  `routes/reports.py` -> `generate_pdf_report()` gathers all target data (subs, ports, vulns, emails).
2.  Initializes `utils/pdf_generator.py` -> `EASMPDFReport` class.
3.  Generates executive summary, asset inventory, and vulnerability detail sections.
4.  Saves PDF to `generated_reports/` and returns file stream.

═══════════════════════════════════════════════════════════════
SECTION 2: EVERY EXTERNAL TOOL & API INTEGRATION
═══════════════════════════════════════════════════════════════

### 2.1 Subprocess Binaries (Local Tools)

| Tool | Purpose | Wrapper File | Exact Hook (Binary Command Array) |
| :--- | :--- | :--- | :--- |
| **Subfinder** | Subdomain discovery | `core/subfinder.py` | `[Config.SUBFINDER_PATH, "-d", domain, "-silent", "-oJ"]` |
| **Naabu** | Port scanning | `core/naabu.py` | `[Config.NAABU_PATH, "-host", joined_hosts, "-top-ports", Config.NAABU_TOP_PORTS, "-json", "-silent"]` |
| **HTTPX** | HTTP probing | `core/httpx_runner.py` | `[Config.HTTPX_PATH, "-l", temp_file, "-json", "-silent", "-title", "-web-server", "-tech-detect", "-status-code"]` |
| **Nuclei** | Vulnerability detection | `core/nuclei.py` | `[Config.NUCLEI_PATH, "-list", temp_file, "-jsonl", "-silent", "-severity", Config.NUCLEI_SEVERITY, "-timeout", "10", "-retries", "1", "-no-color", "-stats"]` |
| **theHarvester** | Email discovery | `core/email_harvester.py` | `[Config.THEHARVESTER_PATH, "-d", domain, "-b", Config.HARVESTER_SOURCES, "-l", "200"]` |

### 2.2 Cloud API Integrations

| API | Purpose | Exact URL(s) and Parameters | Authentication |
| :--- | :--- | :--- | :--- |
| **Shodan** | Passive Recon | `api.dns.domain_info(domain)` (DNS lookup) <br> `api.search("hostname:<domain>")` (Host search) | `shodan.Shodan(Config.SHODAN_API_KEY)` |
| **Censys** | Passive Recon | `certs_api.search("names: <domain>")` (Cert search) <br> `hosts_api.search("services.tls.certificates.leaf.names: <domain>")` | `api_id`, `api_secret` (Host search) |
| **Hunter.io** | Email Discovery | `https://api.hunter.io/v2/domain-search?domain=<domain>&api_key=<key>&limit=10` | Query Param: `api_key` |
| **IntelX (Phonebook)** | Email Discovery | POST: `https://2.intelx.io/phonebook/search` (Payload: `{"term": domain, "target": 2}`) <br> GET: `https://2.intelx.io/phonebook/search/result?id=<search_id>` | Header: `x-key` |
| **LeakCheck** | Breach Detection | `https://leakcheck.io/api/public?check=<email>` | Header: `X-API-Key` |

═══════════════════════════════════════════════════════════════
SECTION 3: EVERY DATABASE OPERATION (MongoDB)
═══════════════════════════════════════════════════════════════

The system uses MongoDB (schema-less) via `pymongo`. Configuration is centralized in `config.py`.

### 3.1 Collections & Indexing Strategy
Index definitions are located in `database/connection.py` -> `init_db()`.

| Collection | Constant | Purpose | Unique Index (Conflict Prevention) |
| :--- | :--- | :--- | :--- |
| **Targets** | `Config.TARGETS_COLLECTION` | Root domains & stats | `root_domain` |
| **Subdomains** | `Config.SUBDOMAINS_COLLECTION` | Found hosts | `subdomain` |
| **Ports/Services** | `Config.PORTS_COLLECTION` | IP/Port data | `host` + `port` (Tracks discovery via `sources` array) |
| **HTTP Assets** | `Config.HTTP_ASSETS_COLLECTION` | URL & tech stacks | `url` |
| **Vulnerabilities**| `Config.VULNS_COLLECTION` | Security findings | N/A (Allows history) |
| **Changes** | `Config.CHANGES_COLLECTION` | Surface drift logs | N/A |
| **Scan History** | `Config.SCANS_COLLECTION` | Scan status/logs | N/A |
| **Emails** | `Config.EMAILS_COLLECTION` | Breached accounts | `target_id` + `email` |

### 3.2 Key DB Logic Modules
- `database/connection.py`: Manages the shared `db` object and index creation.
- `database/subdomains_db.py`: Implements `add_subdomains_bulk()` using `update_one(upsert=True)` to prevent duplicates.
- `database/targets_db.py`: Implements `update_target_stats()` using `$set` for atomic counters.

═══════════════════════════════════════════════════════════════
SECTION 4: EVERY API ROUTE (Flask Registry)
═══════════════════════════════════════════════════════════════

Routes are registered in `app.py` via Blueprints located in `routes/`.

### 4.1 Target Management (`/api/targets`)
- `GET /api/targets/`: List all targets.
- `POST /api/targets/`: Add new root domain + trigger email harvest.
- `DELETE /api/targets/<id>`: Cascading delete of all target assets.

### 4.2 Scan Engine (`/api/scans`)
- `POST /api/scans/full/<domain>`: Start 7-phase background scan.
- `POST /api/scans/subdomains/<domain>`: Start specific subdomain discovery.
- `GET /api/scans/status/<scan_id>`: Poll progress (0-100%).
- `GET /api/scans/history/<domain>`: Retrieve past scan records.

### 4.3 Results & Insights
- **Assets:** `GET /api/assets/subdomains/<domain>`, `GET /api/assets/ports/<domain>`.
- **Vulnerabilities:** `GET /api/vulns/<domain>`, `GET /api/vulns/stats`.
- **Emails:** `GET /api/emails/<domain>`, `POST /api/emails/harvest/<domain>`.
- **Changes:** `GET /api/changes/<domain>`.
- **Remediation:** `GET /api/remediation/generate/<domain>`.
- **Reports:** `GET /api/reports/pdf/<domain>`, `GET /api/reports/csv/<domain>`.

═══════════════════════════════════════════════════════════════
SECTION 5: EVERY FRONTEND PAGE (Templates & JS)
═══════════════════════════════════════════════════════════════

The frontend is a Multi-Page Application (MPA) built with **Bootstrap 5** and **Vanilla JavaScript**.

### 5.1 Main View Templates (`templates/`)
- `dashboard.html`: Main HUD. Uses Chart.js for visualization.
- `target_detail.html`: Tactical view for a specific domain. Triggers active scans.
- `scans.html`: Global scan history and progress monitor.
- `vulnerabilities.html`: Searchable/filterable table of all security findings.
- `emails.html`: Interface for email exposure and breach discovery.

### 5.2 Client-Side Logic (`static/js/`)
- `api.js`: Standardized `fetch()` wrapper for all `/api/` endpoints. Handles 401 redirects.
- `dashboard.js`: Periodically polls `/api/stats` to update the HUD.
- `target.js`: Logic for the "Add Target" form and "Run Scan" buttons.

═══════════════════════════════════════════════════════════════
SECTION 6: SECURITY MECHANISMS (Auth & Sanitization)
═══════════════════════════════════════════════════════════════

### 6.1 Authentication & Session Management
- **Implementation:** `app.py` -> `require_login()` (line 73) uses a `@before_request` hook.
- **Session:** Uses Flask server-side sessions (encrypted via `SECRET_KEY`).
- **Redirects:** Unauthenticated requests to `/dashboard` or `/api/*` are redirected to `/login` or return 401.

### 6.2 Data Sanitization (Anti-NoSQL Injection)
- **Constraint:** Prevents malicious JSON payloads from being executed as MongoDB operators (e.g., `{"$ne": ""}`).
- **Logic:** `utils/sanitize.py` -> `sanitize_string()` (line 22) rejects any input starting with `$`.
- **Domain Validation:** `sanitize_domain()` (line 64) enforces regex-based domain format and strips protocols.

═══════════════════════════════════════════════════════════════
SECTION 7: CONFIGURATION (config.py & .env)
═══════════════════════════════════════════════════════════════

All settings are centralized in `config.py` and loaded via `.env`.

| Parameter | Default Key | Usage |
| :--- | :--- | :--- |
| **Tool Paths** | `SUBFINDER_PATH` | Full path to `.exe` or binary for each tool. |
| **Scan Timeout** | `SCAN_TIMEOUT` | Max seconds before a subprocess is killed (Default: 3600). |
| **API Keys** | `SHODAN_API_KEY` | Credentials for all 6 integrated cloud APIs. |
| **Severity** | `NUCLEI_SEVERITY` | Comma-separated list of severities to report. |

═══════════════════════════════════════════════════════════════
SECTION 8: ERROR HANDLING & EDGE CASES
═══════════════════════════════════════════════════════════════

### 8.1 Tool Failure Management
- **Timeouts:** `subprocess.run(timeout=SCAN_TIMEOUT)` is used in all wrappers.
- **Graceful Degradation:** If `Naabu` fails, `scanner.py` logs the error and proceeds to `HTTPX` (skipping dead phases only).
- **Crash Detection:** `core/nuclei.py` checks for exit codes and marks scans as "partial" if the tool crashed but returned some data.

### 8.2 Network & DB Reliability
- **Concurrent Access:** Threading locks (`routes/emails.py`) prevent two harvests for the same domain simultaneously.
- **Index Conflicts:** `database/connection.py` -> `_safe_create_index()` automatically drops and recreates indexes if they conflict with existing data.
