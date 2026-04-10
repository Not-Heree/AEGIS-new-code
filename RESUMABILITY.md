# Scan Resumability Feature

## Overview

Scan resumability adds checkpoint support to your EASM scanner. When a scan is interrupted or fails, it can now be **automatically resumed** from its last completed phase instead of starting from scratch.

**Key Feature**: When a user attempts to scan a domain that has a failed scan with completed phases, the system **automatically resumes** the previous scan without requiring manual intervention.

**Impact**: If a 40-minute scan fails at minute 35, the next scan attempt automatically resumes from phase 4 (saving ~35 minutes of work).

---

## Auto-Resume Behavior (NEW)

When a user initiates a new scan via `POST /api/scans/full/<domain>`:

1. **System checks**: Is there a failed scan for this domain with completed phases?
2. **If YES (auto-resume)**:
   - Previous scan is reset to "running" status
   - Scan continues from the phase after the last completed phase
   - User sees `"resumed": true` in response
   - Logs show: `AUTO-RESUME: Scan <id> for <domain> — Completed phases: [...]`
3. **If NO (fresh scan)**:
   - New scan is created
   - Scan starts from phase 0
   - User sees `"resumed": false` in response

### Example Flow

**Attempt 1** (fails at Phase 4):
```bash
POST /api/scans/full/example.com
→ New scan created (scan_id: AAA)
→ Phases 0-3 complete successfully
→ Phase 4 (Nuclei) crashes due to timeout
→ Scan marked as "failed"
→ Completed phases: ["passive_recon", "subdomain_discovery", "port_scanning", "http_fingerprinting"]
```

**Attempt 2** (auto-resumes):
```bash
POST /api/scans/full/example.com
→ System detects failed scan AAA with 4 completed phases
→ Automatically resets scan AAA to "running"
→ Resumes from Phase 5 (skips phases 0-4)
→ Response: {
   "scan_id": "AAA",
   "resumed": true,
   "completed_phases": ["passive_recon", "subdomain_discovery", "port_scanning", "http_fingerprinting"],
   "message": "Resuming failed scan for example.com"
}
```

### Manual Resume Still Available

If you prefer manual control, the `/api/scans/resume/<scan_id>/check` and `/api/scans/resume/<scan_id>/now` endpoints remain available for explicit resume requests.

---

## What Was Added

### 0. **Auto-Resume on Scan Initiation** (NEW)

#### Endpoint Changes (`routes/scans.py`):
- `POST /api/scans/full/<domain>` now checks for resumable failed scans **before creating new scan**
- If a failed scan with completed phases exists: **automatically resumes it**
- If no resumable scan: creates fresh scan
- Response includes `"resumed": true|false` flag + completed_phases list (if resumed)
- Logs clearly indicate auto-resume with phase list

#### Database Function Added (`database/scans_db.py`):
- `get_failed_scan_with_completed_phases(domain)` — Finds last failed scan with checkpoints
  - Searches for most recent failed scan with non-empty `phases_completed` array
  - Returns: scan_id, completed_phases, last_checkpoint, error_message
  - Returns None if no resumable scan exists

### 1. **Phase Checkpointing System** 

#### Database Changes (`database/scans_db.py`):
- Added `phases_completed` array to track which phases have finished
- Added `last_checkpoint` timestamp for resume tracking
- Functions:
  - `mark_phase_completed(scan_id, phase_name)` — Mark a phase as done
  - `get_completed_phases(scan_id)` — Get already-completed phases for a scan
  - `can_resume_scan(scan_id)` — Check if a scan is resumable
  - `reset_scan_for_resume(scan_id)` — Prepare a failed scan for resumption

#### Scanner Updates (`core/scanner.py`):
- Added resumability imports and helper functions
- At startup, checks for and loads previously completed phases
- After each phase succeeds, marks it as completed in MongoDB
- On resume, skips already-completed phases and continues from the next one

### 2. **Resume API Endpoints** (`routes/scan_resumability.py`)

**Endpoint: `/api/scans/resume/<scan_id>/check`** (GET)
```json
{
  "can_resume": true,
  "completed_phases": ["passive_recon", "subdomain_discovery", "port_scanning"],
  "interrupted_at": "2026-04-03T07:45:30",
  "last_checkpoint": "2026-04-03T07:45:20"
}
```

**Endpoint: `/api/scans/resume/<scan_id>/now`** (POST)
```json
{
  "success": true,
  "message": "Scan resuming from checkpoint",
  "scan_id": "...",
  "domain": "example.com",
  "completed_phases": ["passive_recon", "subdomain_discovery"],
  "status_url": "/api/scans/status/{scan_id}"
}
```
Resumes the scan from where it left off (background thread).

**Endpoint: `/api/scans/resume/<scan_id>/phases`** (GET)
```json
{
  "success": true,
  "scan_id": "...",
  "completed_phases": ["passive_recon", "subdomain_discovery"],
  "all_phases": ["passive_recon", "subdomain_discovery", "port_scanning", "http_fingerprinting", "vuln_scanning", "change_detection", "risk_scoring"],
  "progress_percent": 29
}
```

### 3. **Scan Phases (7 Total)**

The scanner tracks these phases:
1. **passive_recon** — Shodan, Censys, WHOIS
2. **subdomain_discovery** — Subfinder, crt.sh
3. **port_scanning** — Naabu
4. **http_fingerprinting** — HTTPX
5. **vuln_scanning** — Nuclei
6. **change_detection** — Diff against pre-scan state
7. **risk_scoring** — Risk calculation

---

## Usage Examples

### Scenario 1: Auto-Resume (NEW)
When a user clicks "Scan" on a domain with a failed scan:
```bash
POST /api/scans/full/example.com
→ Response:
{
  "success": true,
  "message": "Resuming failed scan for example.com",
  "scan_id": "507f1f77bcf86cd799439011",
  "resumed": true,
  "completed_phases": ["passive_recon", "subdomain_discovery", "port_scanning"],
  "status_url": "/api/scans/status/507f1f77bcf86cd799439011"
}
```
Scan automatically continues from phase 4 (skipping phases 0-3).

### Scenario 2: Check if a Scan Can Be Manually Resumed
```bash
curl "http://localhost:5000/api/scans/resume/507f1f77bcf86cd799439011/check"
```

### Scenario 3: Manually Resume a Failed Scan (Explicit Control)
```bash
curl -X POST "http://localhost:5000/api/scans/resume/507f1f77bcf86cd799439011/now"
```

### Scenario 4: Check Resume Progress
```bash
curl "http://localhost:5000/api/scans/resume/507f1f77bcf86cd799439011/phases"
```

---

## How It Works

### Normal Scan Flow
```
Start → Phase 0 ✔️ → Phase 1 ✔️ → Phase 2 ✔️ → Phase 3 ✔️ → Phase 4 ❌ CRASH!
        [save]       [save]       [save]       [save]
```

### Resume Flow
```
Check DB: completed = [0, 1, 2, 3]
Resume → Skip 0 ✓ → Skip 1 ✓ → Skip 2 ✓ → Skip 3 ✓ → Phase 4 ✔️ → Phase 5 ✔️ → Phase 6 ✔️
```

---

## Database Schema Addition

Each scan document now includes:

```javascript
{
  "_id": ObjectId("..."),
  "target_id": ObjectId("..."),
  "target_domain": "example.com",
  "status": "failed" | "running" | "completed",
  "phases_completed": [
    "passive_recon",
    "subdomain_discovery",
    "port_scanning"
  ],
  "last_checkpoint": ISODate("2026-04-03T07:45:20"),
  "started_at": ISODate("2026-04-03T07:15:00"),
  "completed_at": ISODate("2026-04-03T07:45:30"),
  "error_message": "Phase 4 failed: timeout",
  ...
}
```

---

## Benefits

| Scenario | Before | After |
|----------|--------|-------|
| 40-min scan fails at 35 min | Start over (0 → 40 min) | Resume at phase 5 (5 min) |
| Network timeout mid-scan | Data loss, lost time | Recovers partial results |
| Database interruption | Complete rescan | Resume from last checkpoint |
| Testing phases | Run full pipeline every time | Test individual phases |

---

## Implementation Details

### Phase Checkpointing Logic

When a phase completes successfully:
```python
phases_completed.append("phase_name")
mark_phase_completed(scan_id, "phase_name")  # ← NEW: saves to DB
```

On resume, at scan start:
```python
completed_phases_db = get_completed_phases(scan_id)  # ← NEW: loads from DB
# Skip already-completed phases
if "passive_recon" in completed_phases_db:
    logger.info("[RESUME] Skipping passive_recon (already completed)")
    # Jump to next phase
```

### Error Handling

- If a phase fails, it's NOT marked as completed
- The scan status remains "failed" 
- User must explicitly call `/resume/now` to try again
- Failed resume attempts don't block retries

---

## Future Enhancements

1. ✅ **Auto-Resume** (DONE): Automatically resume failed scans when user initiates new scan
2. **Partial Phase Recovery**: Save intermediate results within phases (e.g., first 100 subdomains of Nuclei scan)
3. **Pause/Resume**: Allow users to manually pause a running scan and resume later
4. **Resume History**: Track how many times a scan was resumed

---

## Testing the Feature

### Test Auto-Resume

1. **Start a scan**:
   ```bash
   curl -X POST "http://localhost:5000/api/scans/full/example.com"
   # Response includes: "scan_id": "AAA", "resumed": false
   ```

2. **Manually interrupt during Phase 3-4** (Ctrl+C, kill process, or simulate failure)
   - Scan marked as "failed"
   - Phases 0-3 marked as completed

3. **Initiate scan again** (user clicks scan button):
   ```bash
   curl -X POST "http://localhost:5000/api/scans/full/example.com"
   ```
   **Expected Response**:
   ```json
   {
     "success": true,
     "message": "Resuming failed scan for example.com",
     "scan_id": "AAA",
     "resumed": true,
     "completed_phases": ["passive_recon", "subdomain_discovery", "port_scanning", "http_fingerprinting"]
   }
   ```
   ✅ **Auto-resume activated!** Same scan ID returns, continues from Phase 5

4. **Monitor progress**:
   ```bash
   curl "http://localhost:5000/api/scans/status/AAA"
   # Will show Phase 5: "vuln_scanning" instead of Phase 0
   ```

### Test Manual Resume (Explicit Control)

1. **Check if resumable**:
   ```bash
   curl "http://localhost:5000/api/scans/resume/{scan_id}/check"
   ```

2. **Resume manually**:
   ```bash
   curl -X POST "http://localhost:5000/api/scans/resume/{scan_id}/now"
   ```

3. **Monitor progress**:
   ```bash
   curl "http://localhost:5000/api/scans/status/{scan_id}"
   ```

---

## Files Modified

- `database/scans_db.py` — Added checkpoint functions (80+ lines), NEW: `get_failed_scan_with_completed_phases()` for auto-resume
- `core/scanner.py` — Added phase resumability support (50+ lines)
- `routes/scans.py` — Updated `/api/scans/full/<domain>` endpoint with auto-resume logic
- `routes/scan_resumability.py` — NEW: Resume API endpoints (130+ lines)
- `app.py` — Registered resumability blueprint
- `RESUMABILITY.md` — This documentation (updated with auto-resume details)
