# test_nuclei.py (in project root)

from core.nuclei import run_nuclei, run_nuclei_quick

print("=" * 60)
print("  NUCLEI SCANNER TEST")
print("=" * 60)

target = input("Enter target URL or domain: ").strip()

if target:
    print(f"\nScanning: {target}")
    result = run_nuclei_quick([target])
    
    print(f"\n{'='*60}")
    print(f"SUCCESS: {result['success']}")
    print(f"FOUND: {result.get('count', 0)} vulnerabilities")
    print(f"BREAKDOWN: {result.get('severity_breakdown', {})}")
    
    if result.get('vulnerabilities'):
        print(f"\n--- Findings ---")
        for v in result['vulnerabilities'][:5]:
            print(f"\n[{v['severity'].upper()}] {v['name']}")
            print(f"  Host: {v.get('host', 'N/A')}")
            print(f"  URL: {v.get('url', 'N/A')}")
            print(f"  Fix: {v.get('remediation', {}).get('description', 'N/A')[:80]}")
    else:
        print("\nNo vulnerabilities found.")
else:
    print("No target provided.")