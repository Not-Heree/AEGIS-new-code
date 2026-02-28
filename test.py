import requests
import json
from database.targets_db import add_target, delete_target

BASE_URL = "http://localhost:5000"

print("="*60)
print("TESTING ALL API ROUTES")
print("="*60)

# Test 1: Get dashboard summary
print("\n[TEST 1] GET /api/dashboard/summary")
response = requests.get(f"{BASE_URL}/api/dashboard/summary")
print(f"Status: {response.status_code}")
print(f"Response: {json.dumps(response.json(), indent=2)}")

# Test 2: Add a target via API
print("\n[TEST 2] POST /targets/add")
target_data = {"root_domain": "testdomain.com", "org_name": "Test Org"}
response = requests.post(f"{BASE_URL}/targets/add", json=target_data)
print(f"Status: {response.status_code}")
result = response.json()
print(f"Response: {json.dumps(result, indent=2)}")
target_id = result.get("target_id")

if target_id:
    # Test 3: Get all targets
    print("\n[TEST 3] GET /targets")
    response = requests.get(f"{BASE_URL}/targets")
    print(f"Status: {response.status_code}")
    print(f"Found {len(response.json())} targets")
    
    # Test 4: Get single target
    print(f"\n[TEST 4] GET /targets/{target_id}")
    response = requests.get(f"{BASE_URL}/targets/{target_id}")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    # Test 5: Get target dashboard
    print(f"\n[TEST 5] GET /api/dashboard/target/{target_id}")
    response = requests.get(f"{BASE_URL}/api/dashboard/target/{target_id}")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    
    # Test 6: Start a scan
    print(f"\n[TEST 6] POST /scans/start/{target_id}")
    response = requests.post(f"{BASE_URL}/scans/start/{target_id}")
    print(f"Status: {response.status_code}")
    scan_result = response.json()
    print(f"Response: {json.dumps(scan_result, indent=2)[:500]}...")
    
    # Test 7: Get scan history
    print(f"\n[TEST 7] GET /scans/{target_id}")
    response = requests.get(f"{BASE_URL}/scans/{target_id}")
    print(f"Status: {response.status_code}")
    scans = response.json()
    print(f"Found {len(scans)} scans")
    
    # Test 8: Get latest scan
    print(f"\n[TEST 8] GET /scans/{target_id}/latest")
    response = requests.get(f"{BASE_URL}/scans/{target_id}/latest")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)[:500]}...")
    
    # Test 9: Delete target
    print(f"\n[TEST 9] DELETE /targets/{target_id}")
    response = requests.delete(f"{BASE_URL}/targets/{target_id}")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")

print("\n" + "="*60)
print("ALL TESTS COMPLETE")
print("="*60)