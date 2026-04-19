"""
Verification Script for Arjun-Nuclei Integration
================================================
Tests the core logic of SmartWordlistBuilder and AdaptiveRateLimiter.
"""

import sys
import os

# Add project root to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.smart_wordlist_builder import SmartWordlistBuilder
from core.adaptive_rate_limiter import AdaptiveRateLimiter
from config import Config

def test_wordlist_builder():
    print("\n[TEST] Testing SmartWordlistBuilder...")
    builder = SmartWordlistBuilder()
    
    # Test 1: Admin path
    admin_wl = builder.get_context_wordlist("https://example.com/admin/login")
    print(f"  Admin wordlist ({len(admin_wl)} params): {admin_wl[:5]}...")
    assert "username" in admin_wl
    assert "password" in admin_wl
    
    # Test 2: API path
    api_wl = builder.get_context_wordlist("https://example.com/api/v1/users")
    print(f"  API wordlist ({len(api_wl)} params): {api_wl[:5]}...")
    assert "api_key" in api_wl or "token" in api_wl
    
    # Test 3: Tech stack (WordPress)
    wp_wl = builder.get_context_wordlist("https://example.com/", tech_stack=["WordPress"])
    print(f"  WordPress wordlist ({len(wp_wl)} params): {wp_wl[:5]}...")
    assert "p" in wp_wl or "page_id" in wp_wl

    print("[SUCCESS] Wordlist Builder logic verified.")

def test_rate_limiter():
    print("\n[TEST] Testing AdaptiveRateLimiter...")
    limiter = AdaptiveRateLimiter("stealth")
    
    # Test 1: Baseline wait
    stats = limiter.get_stats()
    print(f"  Stealth rate: {stats['current_rate']} req/s")
    assert stats['current_rate'] == 2.0
    
    # Test 2: WAF response handling
    print("  Simulating 403 Forbidden...")
    status = limiter.handle_response(403)
    assert status == "SLOW_DOWN"
    new_stats = limiter.get_stats()
    print(f"  New rate: {new_stats['current_rate']} req/s (Health: {new_stats['health']})")
    assert new_stats['current_rate'] < 2.0
    
    # Test 3: Circuit Breaker
    print("  Simulating repeated WAF errors...")
    for _ in range(Config.ARJUN_CIRCUIT_BREAKER_LIMIT):
        status = limiter.handle_response(403)
    
    print(f"  Status after repeated errors: {status}")
    assert status == "ABORT"

    print("[SUCCESS] Rate Limiter logic verified.")

if __name__ == "__main__":
    try:
        test_wordlist_builder()
        test_rate_limiter()
        print("\n[COMPLETE] All core components verified successfully.")
    except Exception as e:
        print(f"\n[FAILED] Verification failed: {e}")
        sys.exit(1)
