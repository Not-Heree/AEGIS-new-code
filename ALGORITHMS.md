# EASM AEGIS - Algorithm & Logic Documentation

This document provides a detailed academic and technical breakdown of the algorithms, computational logic, and decision-making processes implemented in the External Attack Surface Management (EASM) AEGIS platform.

---

## 1. Scanning Orchestration Algorithms

### 1.1 Pipeline Orchestration Algorithm
**File:** `core/scanner.py` → `run_full_scan()`

**Purpose:** Executes the 8-phase scanning pipeline sequentially, ensuring data persistence and fault isolation between phases.

**Algorithm Steps:**
1. **Target Registration:** Check in with the `cancellation` manager to ensure the scan hasn't been aborted.
2. **Resumability Check:** Query MongoDB for `completed_phases`. If resuming, invoke `_reload_from_db()` to restore the pipeline state.
3. **Snapshotting:** Capture the "Before State" for differential analysis.
4. **Phase Loop:** Iterate through phases (Passive Recon → Discovery → Ports → HTTP → Params → Vulns → Changes → Scoring).
5. **Phase Execution:** Run each phase in a `try-except` block.
6. **Progress Tracking:** Update DB and emit WebSocket events for UI progress bars.
7. **Checkpointing:** Mark the phase as complete in the `scans` collection upon success.

**Pseudocode:**
```python
FUNCTION run_full_scan(target_id, domain):
    scan_id = create_scan(target_id)
    completed = get_completed_phases(scan_id)
    FOR phase IN PIPELINE:
        IF phase NOT IN completed:
            TRY:
                result = execute_phase(phase)
                checkpoint(scan_id, phase)
            EXCEPT:
                log_failure(phase)
    finalize_scan(scan_id)
END FUNCTION
```

**Complexity:** $O(P \cdot T)$ where $P$ = number of phases and $T$ = execution time of the slowest tool.

---

## 2. Intelligence-Driven Scanning Algorithms

### 2.1 6-Tier Scan Plan Builder Algorithm
**File:** `core/smart_scanner.py` → `build_scan_plan()`

**Purpose:** Optimizes scanning by matching specific intelligence data to targeted vulnerability templates.

**The 6-Tier Logic:**
- **Tier 1A (CVE):** Maps Shodan/Censys CVE IDs to specific Nuclei templates.
- **Tier 1B (Technology):** Uses HTTPX fingerprints to select technology tags (e.g., `wordpress`).
- **Tier 2A (Port):** Maps definitive ports (e.g., 3306) to service tags (e.g., `mysql`).
- **Tier 2B (Header):** Extracts tech clues from `Server` headers.
- **Tier 2C (Broad Web):** Scans remaining web hosts with `Critical` and `High` templates.
- **Tier 2C-NET (Network):** Scans non-web hosts with network protocol templates.

**Decision Tree:**
- **IF** host has Shodan CVE **THEN** Assign to Tier 1A.
- **ELSE IF** host has detected Tech **THEN** Assign to Tier 1B.
- **ELSE IF** host has specific service port **THEN** Assign to Tier 2A.
- ... (Waterfall continues to 2C-NET)

---

## 3. Risk Scoring Algorithms

### 3.1 Multi-Factor Risk Scoring Algorithm
**File:** `core/risk_scorer.py` → `calculate_risk_score()`

**Purpose:** Calculates a 0-100 score representing the organization's overall risk posture.

**Mathematical Formula:**
$$R = \text{min}(100, V + E + B + W)$$

**Components:**
1. **Vulnerability Score (V):** $60 \times (1 - e^{-\sum(weight \cdot mult)/500})$. Uses logarithmic compression to prevent score inflation.
2. **Exposure Score (E):** 0-25 points based on asset counts.
3. **Breach Score (B):** 0-20 points based on email leak density.
4. **WHOIS Score (W):** 0-20 points based on infrastructure flags.

---

## 4. Change Detection Algorithms

### 4.1 Cross-Scan Differential Algorithm
**File:** `core/change_detector.py` → `detect_changes_with_snapshot()`

**Purpose:** Identifies attack surface drift by comparing two snapshots in time.

**Mathematical Basis:**
Set Difference ($\Delta$):
- $A_{new} = S_{post} \setminus S_{pre}$
- $A_{removed} = S_{pre} \setminus S_{post}$

---

## 5. Remediation Engine Algorithms

### 5.1 4-Tier CWE Remediation Lookup
**File:** `core/cve_enricher.py` → `get_cwe_remediation()`

**Logic Flow:**
1. **Tier 1:** Search local `cwe_remediation.json` for exact CWE ID.
2. **Tier 2:** If not found, map CWE to a **Category** and use the category's master template.
3. **Tier 3:** If unmapped, query the NVD API for the raw CWE description.
4. **Tier 4:** Fallback to a generic "Severity-Based" remediation guide.

### 5.2 Priority Scoring Algorithm
**Formula:**
$$P = \text{Severity} \times \text{EPSS} \times \text{KEV\_Status}$$
- **Severity:** 1 (Low) to 4 (Critical).
- **EPSS:** Probability score [0.0 - 1.0].
- **KEV:** Multiplier of 1.5 if actively exploited.

---

## 6. Asset Classification Algorithms

### 6.1 Subdomain Criticality Classification
**File:** `utils/asset_classifier.py` → `classify_host()`

**Logic:** Keyword-based pattern matching with priority buckets.
- **Critical:** `vpn`, `mail`, `api`, `auth`, `prod`.
- **High:** `www`, `app`, `portal`.
- **Low:** `dev`, `test`, `staging`.

---

## 7. Search & Deduplication Algorithms

### 7.1 Subdomain Deduplication
**Logic:**
1. Normalization (lowercase, strip protocol, strip trailing dots).
2. Set Union across all sources (Subfinder, Amass, Shodan, Censys).
3. Sorting for deterministic output.

---

## 8. Data Flow: Subdomain Discovery → Vulnerability Scanning

1. **INPUT:** Domain name.
2. **PHASE 1:** Passive + Active discovery results merged into `subdomains` collection.
3. **PHASE 2:** Port scan identifies active attack surface.
4. **PHASE 3:** HTTP Probing identifies technologies and "Web" status.
5. **PHASE 4:** **Smart Scanner** builds a per-host scan plan.
6. **PHASE 4 EXECUTION:** Nuclei executes targeted templates.
7. **OUTPUT:** Enriched vulnerabilities stored in `vulns` collection.

---

## 9. Mathematical Formulas Summary

- **Progress Percent:** $P = \frac{\text{Current Phase Number}}{\text{Total Phases}} \times 100$
- **Risk Multiplier:** Critical (1.5x) > High (1.25x) > Standard (1.0x) > Low (0.75x).
- **EPSS Probability:** Percentage chance of exploitation in 30 days.

---

## 10. Optimization Techniques

1. **MongoDB Projection:** Only fetching required fields (e.g., `{"subdomain": 1}`) to save I/O.
2. **Batching:** `NUCLEI_BATCH_SIZE` prevents process OOM on large targets.
3. **Token Bucket Throttling:** Ensures third-party API keys are not rate-limited.
4. **Caching:** `wordlist_builder.py` caches dynamic wordlists to avoid re-generating the same permutations.

---

## 11. State Machine: Scan Lifecycle

- **PENDING:** Scan created in DB.
- **RUNNING:** Pipeline started.
- **PAUSED:** User manually paused (supported via `scans` collection status).
- **COMPLETED:** All phases finished.
- **FAILED:** Exception caught and logged.
- **CANCELLED:** `utils/cancellation` signal received.

---

## 12. Pattern Matching & Regex

| Pattern Name | Regex | Usage |
| :--- | :--- | :--- |
| **CVE ID** | `CVE-\d{4}-\d{4,7}` | Extracting CVEs from output |
| **Domain** | `^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,5}$` | Input validation |
| **Tech Detection** | `(?i)wordpress\|nginx\|apache` | Header parsing |

---

## 13. Algorithmic Complexity Table

| Algorithm | Best Case | Worst Case | Memory |
| :--- | :--- | :--- | :--- |
| **Deduplication** | $O(N)$ | $O(N \log N)$ | $O(N)$ |
| **Risk Scoring** | $O(V)$ | $O(V)$ | $O(1)$ |
| **Scan Plan Builder**| $O(H \cdot S)$| $O(H \cdot S)$| $O(H)$ |
| **Change Detection** | $O(1)$ | $O(N)$ | $O(N)$ |

*(N = number of assets, V = number of vulnerabilities, H = number of hosts, S = number of signatures)*
