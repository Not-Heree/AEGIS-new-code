# EASM AEGIS Core Pipeline: Technical Breakdown

This document provides a detailed analysis of every tool (internal "brains" and external wrappers) within the EASM AEGIS pipeline. It describes what each tool looks for, what it extracts, and the lifecycle of that data.

---

## 1. Pipeline Orchestrator (`scanner.py`)
**Mission**: The central nervous system of AEGIS. It coordinates the 10-phase scanning logic, manages scan state, and handles resumability.

*   **What it looks for**:
    *   **Input**: `target_id` (DB reference) and `domain` (root target).
    *   **State**: Checks the `scans` collection to see if a scan is already in progress or partially completed (for resumability).
*   **What it finds**:
    *   **Orchestration Plan**: A sequential execution of Phase 0 through Phase 6.
    *   **Checkpoints**: Completed phases are marked in the MongoDB.
*   **Data Lifecycle (What happens to that data)**:
    *   **Persistence**: Updates the `scans` collection with progress percentages and phase status.
    *   **Downstream**: Initiates and passes data between all other modules listed below.
    *   **Representation**: Provides the data for the "Scan Progress" progress bar and "Activity Feed" on the Dashboard.

---

## 2. Passive Recon: Shodan (`shodan_recon.py`)
**Mission**: Extracts "internet-wide" memory of the target without sending a single packet to the target's infrastructure.

*   **What it looks for (Search Criteria)**:
    *   **Input**: Root domain.
    *   **Source**: Shodan's historical DNS records, certificate transparency logs, and global port scans.
*   **What it finds (Intelligence Extracted)**:
    *   **Subdomains**: DNS "A" and "CNAME" records linked to the domain.
    *   **Exposed Ports**: IP addresses belonging to the domain with open ports detected by Shodan.
    *   **Vulnerabilities**: CVEs Shodan has already mapped to those IPs based on banner fingerprints.
    *   **Service Banners**: Raw text fingerprints from services (e.g., "nginx/1.18.0").
*   **Data Lifecycle (What happens to that data)**:
    *   **Persistence**: Stored in `passive_recon` collection; subdomains added to `subdomains`, ports to `ports`, and CVEs to `vulns`.
    *   **Downstream**: Subdomains are fed to Phase 1 (Discovery); Ports/CVEs are fed to `Smart Scanner` to build a targeted Nuclei plan.
    *   **Impact**: Directly populates the technical asset inventory before any active scan begins.

---

## 3. Passive Recon: Censys (`censys_recon.py`)
**Mission**: Secondary passive intelligence source, primarily used for Certificate Transparency (CT) and IP discovery.

*   **What it looks for (Search Criteria)**:
    *   **Input**: Root domain.
    *   **Source**: Censys Search API (Certificate logs + IPv4 search).
*   **What it finds (Intelligence Extracted)**:
    *   **SSL Certificates**: Full certificate chains, revealing subdomains in Subject Alternative Names (SANs).
    *   **Public IP Infrastructure**: IPs hosting services with the target domain in the SSL cert common name.
    *   **Technologies**: Service labels (e.g., "WordPress", "Fortinet").
*   **Data Lifecycle (What happens to that data)**:
    *   **Persistence**: Stored in `passive_recon` collection.
    *   **Downstream**: Hostnames/IPs merged into the active scan list. Technologies used by `Smart Scanner` for Tier 1B targeting.

---

## 4. Subdomain Discovery (`subfinder.py`)
**Mission**: The "Active Discovery" phase. It uses multiple external sources to find as many subdomains as possible.

*   **What it looks for**:
    *   **Input**: Root domain.
    *   **Source**: API connectors for VirusTotal, PassiveTotal, SecurityTrails, etc.
*   **What it finds**:
    *   A massive list of potential subdomains.
*   **Data Lifecycle**:
    *   **Persistence**: All unique subdomains are saved to the `subdomains` collection.
    *   **Downstream**: The full deduplicated list is passed to `Naabu` (Port Scanning) and `HTTPX` (Fingerprinting).

---

## 5. Port Scanning (`naabu.py`)
**Mission**: Verifies which of the discovered subdomains have live network services.

*   **What it looks for**:
    *   **Input**: List of hostnames.
    *   **Scan Strategy**: Only scans hosts NOT covered by Shodan/Censys passive data to save time.
*   **What it finds**:
    *   Open TCP ports on live hosts.
*   **Data Lifecycle**:
    *   **Persistence**: Updates the `ports` collection.
    *   **Downstream**: Open ports tell `Smart Scanner` whether to include a host in "Web Scans" or "Network Scans".

---

## 6. HTTP Fingerprinting (`httpx_runner.py`)
**Mission**: Analyzes the "Application Layer" of every live host.

*   **What it looks for**:
    *   **Input**: List of subdomains.
    *   **Probes**: HTTP/HTTPS requests to identify status, headers, and body content.
*   **What it finds**:
    *   **Web Intel**: Page titles, HTTP status codes (200, 403, 404).
    *   **Technologies**: Identifies JS frameworks, CMS (WordPress, drupal), and Web Servers (Apache, nginx).
    *   **Metadata**: Content length and Response headers (Server, X-Powered-By).
*   **Data Lifecycle**:
    *   **Persistence**: Stored in `http_assets` collection.
    *   **Downstream**: Technology tags are the primary input for **Smart Scanner Tier 1B** (Tech-targeted scans).

---

## 7. Smart Scanner: The Plan Builder (`smart_scanner.py`)
**Mission**: The "Brain" of the scanning phase. Instead of a blind "scan everything", it builds a surgical plan based on all gathered intel.

*   **What it looks for**:
    *   **Input**: ALL outputs from Shodan, Censys, Naabu, and HTTPX.
    *   **Logic**: Cross-references "What we found" with "What we can scan with Nuclei".
*   **What it finds**:
    *   **Tier 1A (CVE)**: Found a CVE on Shodan? Check ONLY that specific CVE on that host.
    *   **Tier 1B (Tech)**: Found WordPress? Run only WordPress-related vulnerability templates.
    *   **Tier 2 (Port/Header)**: Found an unusual port? Use service-specific templates.
*   **Data Lifecycle**:
    *   **Persistence**: Memory-only plan during the scan (JSON dict).
    *   **Downstream**: Fed directly to `run_nuclei()` as the final "Target + Template" list.

---

## 8. Vulnerability Verification (`nuclei.py`)
**Mission**: Executes the actual vulnerability checks against the target.

*   **What it looks for**:
    *   **Input**: The plan from `Smart Scanner`.
    *   **Source**: Thousands of YAML templates (CVEs, misconfigurations, default logins).
*   **What it finds**:
    *   **Confirmed Findings**: Vulnerability name, severity, evidence (curl commands, matched patterns).
*   **Data Lifecycle**:
    *   **Persistence**: Stored in the `vulns` collection.
    *   **Downstream**: Feeds the `Risk Scorer` and the `Remediation Engine`.
    *   **Representation**: Displayed on individual "Issue" pages and the "Vulnerabilities" table.

---

## 9. CVE Enricher (`cve_enricher.py`)
**Mission**: Adds "Threat Intelligence" to raw CVE findings to help prioritize what to fix first.

*   **What it looks for**:
    *   **Input**: CVE ID (e.g., CVE-2023-1234).
    *   **Sources**:
        *   **NVD (NIST)**: Descriptions and patch URLs.
        *   **EPSS (FIRST)**: Probability of exploitation (0.0 to 1.0).
        *   **KEV (CISA)**: Is it "Known Exploited" in the wild today?
*   **What it finds**:
    *   **Priority Scores**: A refined score based on severity + frequency of attacks.
    *   **Remediation Guidance**: CWE-based fix steps.
*   **Data Lifecycle**:
    *   **Persistence**: Memory cache (LRU) + enriched data injected into the remediation plan.
    *   **Downstream**: Primary driver for the **Remediation Engine priority**.

---

## 10. Remediation Engine (`remediation_engine.py`)
**Mission**: Translates "Computer Speak" (a vulnerability) into "Business Speak" (a fix plan).

*   **What it looks for**:
    *   **Input**: Vulnerability document + Enriched CVE data.
    *   **Logic**: Matches the finding against a local knowledge base of fix steps and code examples.
*   **What it finds**:
    *   **Actionable Steps**: "Update X to version Y", "Edit your config file to Z".
    *   **Priority Buckets**: "Fix Immediately" vs "Fix This Week".
*   **Data Lifecycle**:
    *   **Persistence**: Generated on-demand (no separate collection needed).
    *   **Representation**: The "Remediation Plans" tab on the Dashboard.

---

## 11. Change Detector (`change_detector.py`)
**Mission**: Identifies what has changed on the attack surface between two scans.

*   **What it looks for**:
    *   **Input**: Snapshot of current results vs. a snapshot of results before the scan started.
*   **What it finds**:
    *   **Added/Removed**: Subdomains, Ports, Vulnerabilities, and WHOIS changes.
*   **Data Lifecycle**:
    *   **Persistence**: Stored in the `changes` collection.
    *   **Representation**: Feeds the "Recent Changes" notification list on the Dashboard.

---

## 12. Risk Scorer (`risk_scorer.py`)
**Mission**: Aggregates all findings into a single numeric "Security Grade" (0-100).

*   **What it looks for**:
    *   **Input**: All assets and vulnerabilities associated with a `target_id`.
    *   **Weighting**: Critical vulns = high deduction; KEV vulns = extreme deduction; SSL exposure = minor deduction.
*   **What it finds**:
    *   A single integer (0 = Compromised, 100 = Perfect).
*   **Data Lifecycle**:
    *   **Persistence**: Updates the `target` document's `risk_score` field.
    *   **Representation**: The big Gauge chart on the main Dashboard.

---

## 13. Email Harvester & Breach Check (`email_harvester.py`)
**Mission**: Discovers employee emails and checks if they have been leaked in data breaches.

*   **What it looks for**:
    *   **Input**: Root domain.
    *   **Sources**: theHarvester (OSINT), Hunter.io (API), IntelX (Breach DB).
*   **What it finds**:
    *   **Email Addresses**: List of corporate emails.
    *   **Breach Status**: "Pwned" status, leak names (e.g., "LinkedIn Breach"), and leaked data types (Passwords, IPs).
*   **Data Lifecycle**:
    *   **Persistence**: Stored in the `emails` collection.
    *   **Impact**: Increases the `Risk Score` if many high-level employee emails are leaked with passwords.
    *   **Representation**: The "Email OSINT" tab.

---

## 14. Database Layer & Shared State (`database/`)
**Mission**: The "Data Glue" that holds the entire pipeline together.

*   **What it looks for**:
    *   API calls from all `core/` modules to save or retrieve state.
*   **What it find/manages**:
    *   **`targets_db`**: Target metadata & overall stats.
    *   **`scans_db`**: Progress, logs, and phase checkpoints.
    *   **`subdomains_db`**: Asset inventory for the domain.
    *   **`vulns_db`**: Finding inventory with evidence and status.
*   **Data Lifecycle**:
    *   Acts as the persistent memory enabling asynchronous scanning and UI updates.
