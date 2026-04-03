# scanners/subdomain_scanner.py

import subprocess
import json
import requests
from datetime import datetime
from config import Config
from database.connection import get_db


# ─── Subfinder ───────────────────────────────────────────────────────────

def parse_subfinder_output(raw_output):
    """Parse JSONL output from Subfinder."""
    if not raw_output:
        return []

    subdomains = []
    for line in raw_output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            if "host" in data:
                subdomains.append(data["host"].lower())
        except json.JSONDecodeError:
            if line and not line.startswith("{"):
                subdomains.append(line.lower())

    return subdomains


def run_subfinder(domain):
    """Run Subfinder to enumerate subdomains for a given domain."""
    print(f"  [subfinder] Scanning {domain}...")

    try:
        result = subprocess.run(
            [Config.SUBFINDER_PATH, "-d", domain, "-silent", "-oJ"],
            capture_output=True,
            text=True,
            timeout=Config.SCAN_TIMEOUT
        )

        subdomains = parse_subfinder_output(result.stdout)
        subdomains = list(set(subdomains))
        subdomains.sort()

        print(f"  [subfinder] Found {len(subdomains)} subdomains")
        return subdomains

    except subprocess.TimeoutExpired:
        print(f"  [subfinder] Timeout after {Config.SCAN_TIMEOUT}s")
        return []
    except FileNotFoundError:
        print(f"  [subfinder] Not found at {Config.SUBFINDER_PATH}")
        return []
    except Exception as e:
        print(f"  [subfinder] Error: {e}")
        return []


# ─── crt.sh (Certificate Transparency) ───────────────────────────────────

def _extract_issuer_org(issuer_name):
    """
    Extract organization from issuer DN string.
    e.g. "C=US, O=Let's Encrypt, CN=R3" → "Let's Encrypt"
    """
    if not issuer_name:
        return "Unknown"
    try:
        if "O=" in issuer_name:
            org = issuer_name.split("O=")[1].split(",")[0].strip()
            return org if org else "Unknown"
    except (IndexError, AttributeError):
        pass
    return "Unknown"


def run_crtsh(domain):
    """
    Query crt.sh certificate transparency logs.

    Returns:
        tuple: (subdomains_list, certificates_list)

    Captures full certificate metadata for intelligence:
    - Issuer organization (CA mapping)
    - Validity dates (expiration monitoring)
    - Common name + SANs (attack surface mapping)
    - Wildcard detection
    """
    print(f"  [crt.sh] Querying {domain}...")

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)

        if response.status_code != 200:
            print(f"  [crt.sh] HTTP {response.status_code}")
            return [], []

        data = response.json()
        subdomains = set()
        certificates = []
        seen_serials = set()

        for entry in data:
            name = entry.get("name_value", "")

            # ── Extract subdomains (existing logic) ──
            for line in name.splitlines():
                line = line.strip().lower()
                if line.startswith("*"):
                    continue
                if line.endswith(domain.lower()):
                    subdomains.add(line)

            # ── Extract certificate data (NEW) ──
            serial = entry.get("serial_number", "")
            if not serial or serial in seen_serials:
                continue
            seen_serials.add(serial)

            common_name = (entry.get("common_name", "") or "").lower()

            # Parse SAN domains from name_value
            san_list = []
            for line in name.splitlines():
                line = line.strip().lower()
                if line and line.endswith(domain.lower()):
                    san_list.append(line)
            san_list = sorted(set(san_list))

            # Extract issuer organization
            issuer_name = entry.get("issuer_name", "")
            issuer_org = _extract_issuer_org(issuer_name)

            certificates.append({
                "serial_number": serial,
                "common_name": common_name,
                "san_domains": san_list,
                "issuer_name": issuer_name,
                "issuer_org": issuer_org,
                "not_before": entry.get("not_before"),
                "not_after": entry.get("not_after"),
                "crtsh_id": entry.get("id"),
                "issuer_ca_id": entry.get("issuer_ca_id"),
                "target_domain": domain,
                "is_wildcard": common_name.startswith("*."),
            })

        # Sort by issued date descending, keep most recent 500
        certificates.sort(
            key=lambda c: c.get("not_before") or "",
            reverse=True
        )
        certificates = certificates[:500]

        print(
            f"  [crt.sh] Found {len(subdomains)} subdomains, "
            f"{len(certificates)} unique certificates"
        )
        return list(subdomains), certificates

    except requests.Timeout:
        print("  [crt.sh] Timeout")
        return [], []
    except requests.RequestException as e:
        print(f"  [crt.sh] Request error: {e}")
        return [], []
    except json.JSONDecodeError:
        print("  [crt.sh] Invalid JSON response")
        return [], []
    except Exception as e:
        print(f"  [crt.sh] Error: {e}")
        return [], []


# ─── Main Scanner Function ───────────────────────────────────────────────

def scan_subdomains(domain):
    """
    Run all subdomain enumeration sources and return merged results.

    Sources:
    - Subfinder (local tool)
    - crt.sh (certificate transparency)

    Returns:
    {
        "success": True/False,
        "domain": "example.com",
        "subdomains": ["sub1.example.com", ...],
        "count": 45,
        "certificates": [...],
        "sources": {"subfinder": 30, "crtsh": 20}
    }
    """
    print(f"\n[*] Starting subdomain enumeration for: {domain}")
    domain = domain.lower().strip()

    # Run all sources
    subfinder_results = run_subfinder(domain)
    crtsh_results, certificates = run_crtsh(domain)

    # Merge and deduplicate
    all_subdomains = set()
    all_subdomains.update(subfinder_results)
    all_subdomains.update(crtsh_results)

    # Filter: must end with domain, no wildcards
    filtered = []
    for sub in all_subdomains:
        sub = sub.strip().lower()
        if not sub:
            continue
        if sub.startswith("*"):
            continue
        if not sub.endswith(domain):
            continue
        filtered.append(sub)

    filtered = sorted(set(filtered))

    print(f"[*] Total unique subdomains: {len(filtered)}")
    print(f"[*] Total unique certificates: {len(certificates)}")

    return {
        "success": True,
        "domain": domain,
        "subdomains": filtered,
        "count": len(filtered),
        "certificates": certificates,
        "sources": {
            "subfinder": len(subfinder_results),
            "crtsh": len(crtsh_results)
        }
    }


# ─── Save Subdomains to Database ─────────────────────────────────────────

def save_subdomains(domain, subdomains):
    """Upsert subdomains into MongoDB."""
    if not subdomains:
        print("[*] No subdomains to save")
        return 0

    db = get_db()
    saved = 0
    new_count = 0

    for sub in subdomains:
        try:
            result = db[Config.SUBDOMAINS_COLLECTION].update_one(
                {"subdomain": sub},
                {
                    "$set": {
                        "subdomain": sub,
                        "target_domain": domain,
                        "status": "active",
                        "last_seen": datetime.utcnow()
                    },
                    "$setOnInsert": {
                        "first_seen": datetime.utcnow()
                    }
                },
                upsert=True
            )
            saved += 1
            if result.upserted_id:
                new_count += 1
        except Exception as e:
            print(f"  [save] Error saving {sub}: {e}")

    print(f"[*] Saved {saved} subdomains ({new_count} new)")
    return saved


# ─── Save Certificates to Database ───────────────────────────────────────

def save_certificates(domain, certificates):
    """
    Upsert certificate transparency data into MongoDB.

    Deduplicates by serial_number + target_domain.
    Stores full cert metadata for intelligence display.
    """
    if not certificates:
        print("[*] No certificates to save")
        return 0

    db = get_db()
    saved = 0
    new_count = 0

    for cert in certificates:
        try:
            result = db["certificates"].update_one(
                {
                    "serial_number": cert["serial_number"],
                    "target_domain": domain
                },
                {
                    "$set": {
                        **cert,
                        "last_seen": datetime.utcnow()
                    },
                    "$setOnInsert": {
                        "first_seen": datetime.utcnow()
                    }
                },
                upsert=True
            )
            saved += 1
            if result.upserted_id:
                new_count += 1
        except Exception as e:
            print(f"  [save] Error saving cert {cert.get('serial_number', '?')}: {e}")

    print(f"[*] Saved {saved} certificates ({new_count} new)")
    return saved


# ─── Full Scan + Save ────────────────────────────────────────────────────

def run_subdomain_scan(domain, save=True):
    """
    Complete subdomain scan workflow:
    1. Run all enumeration sources
    2. Merge and deduplicate
    3. Save subdomains to database
    4. Save certificates to database

    Returns scan result dict.
    """
    result = scan_subdomains(domain)

    if save and result["success"]:
        # Save subdomains
        if result["subdomains"]:
            saved_count = save_subdomains(domain, result["subdomains"])
            result["saved"] = saved_count

        # Save certificates
        if result.get("certificates"):
            cert_count = save_certificates(domain, result["certificates"])
            result["certificates_saved"] = cert_count
            print(
                f"[*] Certificate summary: {cert_count} saved, "
                f"{sum(1 for c in result['certificates'] if c.get('is_wildcard'))} wildcard"
            )

    return result