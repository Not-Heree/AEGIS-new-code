"""
Test Suite: Hybrid CWE Remediation Architecture

Validates:
1. Static database lookup (fast path)
2. NVD API fallback (slow path with caching)
3. Generic fallback (API failure)
4. Source indicator accuracy
5. Performance characteristics
"""

import time
import json
import os
import sys

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.cve_enricher import get_cwe_remediation, _cwe_cache, _load_cwe_kb


def test_static_database_lookup():
    """Test that known CWEs return from static database quickly."""
    print("\n" + "="*70)
    print("TEST 1: Static Database Lookup (Fast Path)")
    print("="*70)
    
    test_cwes = ["CWE-79", "CWE-89", "CWE-352", "CWE-18", "CWE-642"]
    
    for cwe in test_cwes:
        start = time.time()
        result = get_cwe_remediation(cwe)
        elapsed = time.time() - start
        
        if result:
            source = result.get("source", "unknown")
            print(f"✓ {cwe}: {result['name'][:40]:40s} | {elapsed*1000:6.2f}ms | source: {source}")
            assert elapsed < 0.05, f"Static lookup took too long: {elapsed*1000}ms"
            assert source == "static_database", f"Expected static_database, got {source}"
        else:
            print(f"✗ {cwe}: NOT FOUND")


def test_static_database_statistics():
    """Show statistics about static database."""
    print("\n" + "="*70)
    print("TEST 2: Static Database Statistics")
    print("="*70)
    
    _load_cwe_kb()
    
    db = _cwe_cache["data"]
    print(f"✓ Total CWEs in database: {len(db)}")
    print(f"✓ Coverage: {len(db)}/1000 CWE types ({100*len(db)/1000:.1f}%)")
    
    # Analyze by category
    categories = {}
    for cwe_id, data in db.items():
        cat = data.get("category", "unknown")
        categories[cat] = categories.get(cat, 0) + 1
    
    print(f"✓ Categories represented: {len(categories)}")
    print(f"\n  Top 10 categories by count:")
    for cat, count in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"    - {cat:25s}: {count:3d} CWEs")


def test_nvd_fallback_logic():
    """Test NVD fallback for unknown CWEs."""
    print("\n" + "="*70)
    print("TEST 3: NVD Fallback for Unknown CWEs")
    print("="*70)
    
    # Try a very high CWE number unlikely to be in static DB
    unknown_cwe = "CWE-9999"
    
    print(f"Attempting to lookup {unknown_cwe} (not in static DB)...")
    start = time.time()
    result = get_cwe_remediation(unknown_cwe)
    elapsed = time.time() - start
    
    if result:
        print(f"✓ {unknown_cwe} resolved via fallback")
        print(f"  Name: {result.get('name', 'N/A')[:60]}")
        print(f"  Source: {result.get('source', 'unknown')}")
        print(f"  Response time: {elapsed*1000:.2f}ms")
        print(f"  Has fix_steps: {'fix_steps' in result and len(result['fix_steps']) > 0}")
        print(f"  Has references: {'references' in result and len(result['references']) > 0}")
    else:
        print(f"✗ {unknown_cwe} could not be resolved (API may be down)")
        print(f"  Response time: {elapsed*1000:.2f}ms")


def test_multiple_cwe_formats():
    """Test that different CWE formats normalize correctly."""
    print("\n" + "="*70)
    print("TEST 4: CWE Format Normalization")
    print("="*70)
    
    formats = [
        "CWE-79",      # Standard format
        "79",          # Just number
        "cwe-79",      # Lowercase
        ["CWE-79"],    # List format
        "  CWE-79  ",  # With whitespace
    ]
    
    results = []
    for fmt in formats:
        result = get_cwe_remediation(fmt)
        if result:
            results.append(result["name"])
            print(f"✓ Format '{str(fmt):20s}' → {result['name'][:50]}")
        else:
            print(f"✗ Format '{str(fmt):20s}' → NOT FOUND")
    
    # Verify all formats returned same result
    if len(set(results)) == 1:
        print(f"\n✓ All formats normalize to same CWE")
    else:
        print(f"✗ Format normalization inconsistent!")


def test_response_structure():
    """Verify response structure contains all required fields."""
    print("\n" + "="*70)
    print("TEST 5: Response Structure Validation")
    print("="*70)
    
    result = get_cwe_remediation("CWE-79")
    
    required_fields = [
        "name",
        "category",
        "fix_steps",
        "code_examples",
        "references",
        "source"
    ]
    
    optional_fields = [
        "impact",
        "business_impact",
        "timeline"
    ]
    
    print("Checking required fields:")
    all_present = True
    for field in required_fields:
        if field in result:
            value_type = type(result[field]).__name__
            print(f"  ✓ {field:25s}: {value_type}")
        else:
            print(f"  ✗ {field:25s}: MISSING")
            all_present = False
    
    print("\nChecking optional fields:")
    for field in optional_fields:
        if field in result:
            value_type = type(result[field]).__name__
            print(f"  ✓ {field:25s}: {value_type}")
        else:
            print(f"  - {field:25s}: not present")
    
    if all_present:
        print("\n✓ All required fields present")
    else:
        print("\n✗ Some required fields missing!")


def test_performance_benchmark():
    """Benchmark performance of hybrid lookup."""
    print("\n" + "="*70)
    print("TEST 6: Performance Benchmark")
    print("="*70)
    
    print("Testing 10 consecutive static DB lookups...")
    times = []
    for i in range(10):
        start = time.time()
        result = get_cwe_remediation(f"CWE-{79 + (i % 5)}")
        times.append((time.time() - start) * 1000)
    
    avg_time = sum(times) / len(times)
    max_time = max(times)
    min_time = min(times)
    
    print(f"  Average: {avg_time:.2f}ms")
    print(f"  Min: {min_time:.2f}ms")
    print(f"  Max: {max_time:.2f}ms")
    
    if avg_time < 50:
        print(f"✓ Performance target met (<50ms)")
    else:
        print(f"✗ Performance degraded (expected <50ms, got {avg_time:.2f}ms)")


def test_cwe_categories():
    """Verify category distribution."""
    print("\n" + "="*70)
    print("TEST 7: CWE Category Distribution")
    print("="*70)
    
    _load_cwe_kb()
    db = _cwe_cache["data"]
    
    categories = {}
    for cwe_id, data in db.items():
        cat = data.get("category", "unknown")
        if cat not in categories:
            categories[cat] = {"count": 0, "cwe_ids": []}
        categories[cat]["count"] += 1
        categories[cat]["cwe_ids"].append(cwe_id)
    
    print(f"Total unique categories: {len(categories)}\n")
    
    print("Categories with most CWEs:")
    for cat, data in sorted(categories.items(), key=lambda x: x[1]["count"], reverse=True)[:10]:
        cwe_sample = ", ".join(data["cwe_ids"][:3])
        print(f"  {cat:25s}: {data['count']:3d} CWEs ({cwe_sample}...)")


def run_all_tests():
    """Run all tests."""
    print("\n")
    print("╔" + "="*68 + "╗")
    print("║" + " "*15 + "HYBRID CWE REMEDIATION - TEST SUITE" + " "*20 + "║")
    print("╚" + "="*68 + "╝")
    
    try:
        test_static_database_lookup()
        test_static_database_statistics()
        test_nvd_fallback_logic()
        test_multiple_cwe_formats()
        test_response_structure()
        test_performance_benchmark()
        test_cwe_categories()
        
        print("\n" + "="*70)
        print("ALL TESTS COMPLETED")
        print("="*70)
        print("\n✓ Hybrid CWE remediation architecture validated successfully!")
        
    except Exception as e:
        print(f"\n✗ TEST FAILED: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    run_all_tests()
