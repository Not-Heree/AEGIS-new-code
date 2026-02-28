# scanners/subdomain_scanner.py

import subprocess
import json
import requests
from datetime import datetime
from config import Config
from database.connection import get_db


# ─── Subfinder ───────────────────────────────────────────────────────────

def parse_subfinder_output(raw_output):
    """
    Parse JSONL output from Subfinder.
    Each line is a JSON object with a 'host' field.
    Returns list of subdomains, skipping invalid lines.
    """
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
            # Fallback: treat as plain text subdomain
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
        subdomains = list(set(subdomains))  # Dedupe
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

def run_crtsh(domain):
    """Query crt.sh certificate transparency logs for subdomains."""
    print(f"  [crt.sh] Querying {domain}...")

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)

        if response.status_code != 200:
            print(f"  [crt.sh] HTTP {response.status_code}")
            return []

        data = response.json()
        subdomains = set()

        for entry in data:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lower()
                # Skip wildcards
                if line.startswith("*"):
                    continue
                # Must end with target domain
                if line.endswith(domain.lower()):
                    subdomains.add(line)

        result = list(subdomains)
        print(f"  [crt.sh] Found {len(result)} subdomains")
        return result

    except requests.Timeout:
        print("  [crt.sh] Timeout")
        return []

    except requests.RequestException as e:
        print(f"  [crt.sh] Request error: {e}")
        return []

    except json.JSONDecodeError:
        print("  [crt.sh] Invalid JSON response")
        return []

    except Exception as e:
        print(f"  [crt.sh] Error: {e}")
        return []


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
        "sources": {"subfinder": 30, "crtsh": 20}
    }
    """
    print(f"\n[*] Starting subdomain enumeration for: {domain}")
    domain = domain.lower().strip()

    # Run all sources
    subfinder_results = run_subfinder(domain)
    crtsh_results = run_crtsh(domain)

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

    # Sort and dedupe
    filtered = sorted(set(filtered))

    print(f"[*] Total unique subdomains: {len(filtered)}")

    return {
        "success": True,
        "domain": domain,
        "subdomains": filtered,
        "count": len(filtered),
        "sources": {
            "subfinder": len(subfinder_results),
            "crtsh": len(crtsh_results)
        }
    }


# ─── Save to Database ────────────────────────────────────────────────────

def save_subdomains(domain, subdomains):
    """
    Upsert subdomains into MongoDB.
    
    Returns count of saved subdomains.
    """
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


# ─── Full Scan + Save ────────────────────────────────────────────────────

def run_subdomain_scan(domain, save=True):
    """
    Complete subdomain scan workflow:
    1. Run all enumeration sources
    2. Merge and deduplicate
    3. Save to database (if save=True)
    
    Returns scan result dict.
    """
    # Run scan
    result = scan_subdomains(domain)

    # Save to DB
    if save and result["success"] and result["subdomains"]:
        saved_count = save_subdomains(domain, result["subdomains"])
        result["saved"] = saved_count

    return result