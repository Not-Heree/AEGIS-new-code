# EASM AEGIS: Master Project Context for AI Report Writing

This document serves as the "Master Brain" containing all the context, logic, and architectural details of the EASM AEGIS platform. Feed this to an AI to generate sections for your FYP report (Abstract, Design, Implementation, Security, etc.).

---

## 1. Project Overview
**Title:** EASM AEGIS (External Attack Surface Management)
**Objective:** To provide organizations with a continuous, automated view of their internet-facing assets, identifying vulnerabilities and tracking attack surface drift in real-time.
**Core Value Proposition:** Unlike "blind" scanners, AEGIS uses "Intelligence-Driven Scanning" to minimize noise and "Logarithmic Risk Scoring" to prioritize remediation based on business impact.

---

## 2. System Architecture
**Type:** Hub-and-Spoke Architecture
- **Central Spoke:** MongoDB (NoSQL) for high-velocity storage of unstructured scan data.
- **Backend:** Flask (Python 3.9+) orchestrates the pipeline and provides a REST API.
- **Frontend:** Responsive Web UI with real-time status updates via WebSockets (Socket.IO).
- **Tool Integration:** Wrappers for industry-standard Go-based security tools.

---

## 3. The 8-Phase Scanning Pipeline
The platform executes a sequential, fault-tolerant pipeline:
1.  **Phase 0: Passive Recon:** Non-intrusive OSINT querying (Shodan, Censys, WHOIS).
2.  **Phase 1: Subdomain Discovery:** Multi-tool discovery (Subfinder, Amass, crt.sh) with three-way deduplication.
3.  **Phase 2: Port Scanning:** Active discovery (Naabu) excluding hosts already mapped by passive recon (efficiency optimization).
4.  **Phase 3: HTTP Fingerprinting:** Probing live services (HTTPX) to detect tech stacks, status codes, and server headers.
5.  **Phase 3.5: Parameter Discovery:** (Opt-in) Finding hidden parameters (Arjun) for advanced attack surface mapping.
6.  **Phase 4: Vulnerability Scanning:** Intelligence-driven Nuclei execution using a 6-tier targeting strategy.
7.  **Phase 5: Change Detection:** Differential analysis comparing pre-scan vs. post-scan states to identify new/removed assets.
8.  **Phase 6: Risk Scoring:** Mathematical aggregation of all findings into a 0-100 organization risk score.

---

## 4. Key Algorithmic Innovations
### 4.1 6-Tier Smart Scanning
Replaces broad scans with cascading tiers:
- **Tier 1A (CVE):** Verified Shodan CVEs confirmed by Nuclei.
- **Tier 1B (Tech):** Technology-specific templates (e.g., WordPress templates only on WP sites).
- **Tier 2A (Port):** Service-specific templates based on open ports (e.g., Redis templates on port 6379).
- **Tier 2B (Header):** Mining 'Server' headers for clues (e.g., Gunicorn → Python/Flask templates).
- **Tier 2C (Broad):** Critical/High templates on remaining web hosts.
- **Tier 2C-NET (Network):** Non-web protocol scans (SSH, FTP, etc.).

### 4.2 Logarithmic Risk Scoring
$$R = \text{min}(100, V_{score} + E_{score} + B_{score} + W_{score})$$
- Uses an **asymptotic exponential approach** for vulnerabilities: $60 \times (1 - e^{-raw/500})$.
- **Rationale:** Ensures 500 vulnerabilities aren't "100x riskier" than 5; once critical thresholds are reached, the organization is at maximum risk regardless of additional findings.

---

## 5. Security & Robustness Measures
- **Secure by Default:** Flask debug mode disabled; no hardcoded credentials.
- **CSRF Protection:** Full-stack implementation using `Flask-WTF` and custom AJAX headers.
- **Security Headers:** Injected globally (CSP, HSTS, XSS protection).
- **NoSQL Injection Prevention:** Strict input sanitization in `utils/sanitize.py` rejecting MongoDB operators.
- **AES-256 Encryption:** PBKDF2 key derivation used to encrypt third-party API keys in the DB.
- **Command Injection Prevention:** List-based `subprocess` calls (no `shell=True`).

---

## 6. Data Integrity & Resumability
- **Checkpoints:** Each phase completion is marked in MongoDB. Scans can resume from the last failed phase without re-running long discovery steps.
- **Status Mechanism:** Assets are marked `status: "old"` before a scan and `active` if discovered, enabling precise drift detection.
- **Centralized Serialization:** Recursive `serialize_doc` helper ensures consistent JSON output across all 120+ API endpoints.

---

## 7. Technology Stack Summary
- **Language:** Python 3.9+
- **Framework:** Flask, Flask-SocketIO, Flask-WTF.
- **Database:** MongoDB 6.0+
- **Task Mgmt:** Native Python threading with state checkpoints (transitioning to Celery in roadmap).
- **OSINT APIs:** Shodan, Censys, IntelX (via custom throttler).
- **Discovery Tools:** Nuclei, Subfinder, Amass, Naabu, HTTPX, Arjun.

---

## 8. Testing Methodology
- **Unit Testing:** Pytest for core logic and sanitizers.
- **System Testing:** E2E pipeline verification and resumability testing.
- **VAPT:** Manual pentesting using Burp Suite and NoSQLMap targeting the management API.

---

**Academic Deliverables Available:**
- `ANALYSIS.md`: 15-point review.
- `ALGORITHMS.md`: Mathematical and logic breakdown.
- `TESTING_GUIDE.md`: Full VAPT and test methodology.
