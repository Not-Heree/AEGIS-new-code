# Testing & VAPT Guide for EASM AEGIS

This guide outlines the comprehensive testing strategy for the EASM AEGIS platform, categorized into Unit Testing, System Testing, and VAPT (Vulnerability Assessment and Penetration Testing).

---

## 1. Unit Testing Strategy
**Goal:** Verify the smallest testable parts of the application in isolation.

### 1.1 Core Logic Tests
| Module | Test Case | Expected Result |
| :--- | :--- | :--- |
| `utils/sanitize.py` | Input: `{"$ne": ""}` to `sanitize_string` | Raise `ValueError` (NoSQL Injection Blocked) |
| `utils/sanitize.py` | Input: `https://test.com/` to `sanitize_domain` | Returns: `test.com` (Protocol stripping) |
| `utils/encryption.py` | Encrypt "secret" → Decrypt result | Returns: "secret" (Integrity check) |
| `utils/asset_classifier.py` | Input: `vpn.prod.site.com` | Returns: `critical` tier |
| `core/risk_scorer.py` | Mock 1 Critical, 1 High vuln | Verify score is exactly as per formula (e.g., ~65) |
| `database/connection.py` | Input: BSON `ObjectId` to `serialize_doc` | Returns: String representation |

### 1.2 How to perform:
Use `pytest`. Create a `tests/` directory and implement test functions.
```python
def test_domain_sanitization():
    from utils.sanitize import sanitize_domain
    assert sanitize_domain("HTTPS://EXAMPLE.COM/") == "example.com"
```

---

## 2. System Testing (End-to-End)
**Goal:** Verify the integrated flow of the entire scanning pipeline.

### 2.1 Test Scenarios
| Scenario | Steps | Verification |
| :--- | :--- | :--- |
| **Full Pipeline Flow** | Add `example.com` → Start Scan → Wait for completion | Check DB for subdomains, ports, and vulnerabilities. |
| **Scan Resumability** | Start Scan → Kill process during Phase 2 → Click "Resume" | Verify Phase 0-2 are skipped and scan starts at Phase 3. |
| **Change Detection** | Scan `site.com` → Manually add a port in DB → Re-scan | Verify a "New Port" change is recorded in the `changes` collection. |
| **Cancellation** | Start Scan → Click "Stop Scan" | Use `ps aux | grep nuclei` to ensure subprocesses were killed. |
| **Data Integrity** | Run two scans on same target | Ensure first scan assets are marked `status: "old"` and new ones are `active`. |

### 2.2 How to perform:
- **Manual:** Use the Web UI and monitor logs in real-time.
- **Automated:** Use **Playwright** or **Selenium** to simulate user actions in the browser and verify UI states.

---

## 3. VAPT (Vulnerability Assessment & Penetration Testing)
**Goal:** Identify and exploit security weaknesses in the platform.

### 3.1 VAPT Checklist
| Category | Vulnerability | Test Methodology |
| :--- | :--- | :--- |
| **Injection** | **NoSQL Injection** | Intercept `POST /api/v1/targets` and change domain to `{"$ne": null}`. Ensure it returns 400 Error. |
| **Injection** | **Command Injection** | Add a target with name `; sleep 10;`. Ensure the scanner doesn't execute the sleep command. |
| **Broken Auth** | **Brute Force** | Attempt 100 logins to `/login`. Ensure `Flask-Limiter` (if implemented) or account lockout triggers. |
| **CSRF** | **Cross-Site Request Forgery** | Create a malicious HTML page that sends a POST to `/api/v1/targets/delete`. Verify it fails without a `csrf_token`. |
| **Sensitive Data** | **Info Disclosure** | Access a non-existent route `/api/debug`. Ensure no stack traces or `.env` variables are shown. |
| **SSRF** | **Server-Side Request Forgery** | Set scan target to `169.254.169.254` (Cloud Metadata). Ensure the scanner rejects internal IP ranges. |
| **XSS** | **Stored XSS** | Set a Target Organization name to `<script>alert(1)</script>`. Check if it executes in the Dashboard. |

### 3.2 Tools to Use:
- **Burp Suite:** For intercepting and modifying API requests.
- **OWASP ZAP:** Automated vulnerability scanning of the Flask web interface.
- **NoSQLMap:** Specifically for testing MongoDB injection points.
- **Postman:** For functional security testing of the REST API.

---

## 4. Performance & Stress Testing
**Goal:** Determine the platform's limits.

- **Load Test:** Add 10 targets and run them concurrently. Monitor CPU/RAM usage of the `mongod` and `python` processes.
- **Large Dataset Test:** Scan a domain known to have 5,000+ subdomains. Verify that `pagination.py` handles the UI load and the DB doesn't time out.

---

## 5. Summary Table for FYP Report

| Test Tier | Focus Area | Methodology |
| :--- | :--- | :--- |
| **Unit** | Individual Functions | Pytest / Mocking |
| **Integration** | DB + Core Modules | Integration test suite with test DB |
| **System** | Full Scan Pipeline | Manual E2E + Playwright |
| **VAPT** | Security / OWASP Top 10 | Burp Suite / Manual Pentesting |
| **Acceptance** | User Requirements | User Feedback / Demo |
