# EASM AEGIS: Master Project Reference

This document serves as the canonical map for the EASM AEGIS architecture, feature status, and data flow.

---

## 🏗️ CORE ARCHITECTURE

The system follows a **Tiered Parallel Pipeline** architecture. Each scan phase enriches the target with increasing depth.

### 1. The Pipeline Flow
`Target (Domain)` → `Phase 0: Passive Recon` → `Phase 1: Subdomain Discovery` → `Phase 2: Port Scanning` → `Phase 3: HTTP Probing` → `Phase 4: Vulnerability Scanning` → `Phase 5: OSINT/Email Harvesting` → `Phase 6: Risk Scoring`.

### 2. Primary Entry Points
- **Web UI**: `app.py` (Flask)
- **Scanner Orchestrator**: `core/scanner.py` (`run_full_scan`)
- **Intel Engine**: `core/cve_enricher.py` (Canonical Remediation)

---

## 📋 COMPLETE FEATURE LIST

Feature Name | Files Involved | Status
--- | --- | ---
**Subdomain Enumeration** | `core/subfinder.py`, `core/amass.py`, `database/subdomains_db.py` | WORKING
**Passive Intel (Shodan)** | `core/shodan_recon.py`, `database/passive_recon_db.py` | WORKING
**Passive Intel (Censys)** | `core/censys_recon.py`, `database/passive_recon_db.py` | WORKING
**WHOIS Analysis** | `core/whois_lookup.py`, `database/passive_recon_db.py` | WORKING
**Port Discovery** | `core/naabu.py`, `database/ports_db.py` | WORKING
**HTTP Fingerprinting** | `core/httpx_runner.py`, `database/http_assets_db.py` |  WORKING
**Parameter Mining** | `core/arjun_runner.py`, `core/wordlist_builder.py` |  WORKING
**Vulnerability Scan** | `core/nuclei.py`, `database/vulns_db.py`, `routes/vulns.py` | WORKING
**Remediation Logic** | `core/cve_enricher.py`, `core/remediation_engine.py` | WORKING
**Email / Breach OSINT** | `core/email_harvester.py`, `database/emails_db.py` | WORKING
**Risk Calculation** | `core/risk_scorer.py`, `core/cve_enricher.py` | WORKING
**Change Detection** | `core/change_detector.py`, `database/changes_db.py` | WORKING
**PDF Reporting** | `reports/pdf_generator.py`, `routes/reports.py` | WORKING
**Dashboard Analytics** | `routes/dashboard.py`, `static/js/dashboard.js` | PARTIAL (Passive recon cards broken)
**API Management** | `core/api_key_manager.py`, `routes/api_keys.py` | WORKING
**Auth Guard** | `app.py` (`require_login`), `config.py` | WORKING

---

## 🔗 DATA INTEGRITY MAP

| Collection | Purpose | Source Module |
| :--- | :--- | :--- |
| `targets` | Main domain inventory | `database/targets_db.py` |
| `subdomains` | Discovered hosts | `core/subfinder.py`, `core/amass.py` |
| `ports` | Service discovery | `core/naabu.py` |
| `http_assets` | Web fingerprinting | `core/httpx_runner.py` |
| `vulnerabilities`| Confirmed security issues | `core/nuclei.py`, `core/cve_enricher.py` |
| `passive_recon` | Shodan/Censys/WHOIS info | `database/passive_recon_db.py` |
| `emails` | OSINT identity intel | `core/email_harvester.py` |
| `changes` | Historic state changes | `core/change_detector.py` |

---

## 🛠️ EXTERNAL TOOL DEPENDENCIES

The project invokes several Go binaries. Paths must be configured in `.env` or `config.py`.

1.  **Subfinder**: Passive subdomain discovery.
2.  **Amass**: Advanced DNS/Passive enumeration.
3.  **Naabu**: Fast port scanning.
4.  **HTTPX**: HTTP probing and tech detection.
5.  **Nuclei**: Template-driven vulnerability scanning.
6.  **Arjun**: HTTP parameter discovery.

---

## 🩹 CRITICAL MAINTENANCE LOG (AUDIT FINDINGS)

### 1. Dead Code Candidates (Delete for Maturity)
- `core/remediation_engine.py` -> `_combine_remediation_sources()`
- `core/cve_enricher.py` -> `enrich_vulnerabilities_batch()`
- `core/scanner.py` -> `_cvss_to_severity()`

### 2. Architectural Debt
- **Duplication**: `serialize_doc()` repeats in 10 files. **Fix**: Move to `database/connection.py`.
- **API Mismatch**: Frontend calls `/api/passive/` but backend expects `/api/passive-recon/`. **Fix**: Standardize on `/api/passive/`.

### 3. Missing Infrastructure
- **Manual Cache Clear**: No UI button to force-clear the 24h Enrichment Cache.
- **Bulk Cleanup**: No "Delete All" for old scans or changes.
