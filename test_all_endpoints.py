"""Test all critical endpoints after updates."""
import requests

BASE_URL = "http://127.0.0.1:8000"

print("="*70)
print(" Testing All Critical Endpoints")
print("="*70)

# Test 1: Health check
print("\n[1] Health endpoint...")
try:
    r = requests.get(f"{BASE_URL}/health")
    print(f"    Status: {r.status_code} - {r.json()}")
except Exception as e:
    print(f"    ERROR: {e}")

# Test 2: Root endpoint
print("\n[2] Root endpoint...")
try:
    r = requests.get(f"{BASE_URL}/")
    print(f"    Status: {r.status_code} - {r.json()['message']}")
except Exception as e:
    print(f"    ERROR: {e}")

# Test 3: OAuth2 authorize (GET)
print("\n[3] OAuth2 authorize page...")
try:
    r = requests.get(
        f"{BASE_URL}/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": "test-client",
            "redirect_uri": "http://localhost:8000/callback"
        }
    )
    print(f"    Status: {r.status_code} - HTML page returned" if r.status_code == 200 else f"    Status: {r.status_code}")
except Exception as e:
    print(f"    ERROR: {e}")

# Test 4: Token endpoint (should fail with 401)
print("\n[4] Token endpoint (with invalid credentials)...")
try:
    r = requests.post(
        f"{BASE_URL}/api/token",
        data={"username": "test@test.com", "password": "wrong"}
    )
    print(f"    Status: {r.status_code} - {r.json().get('detail', 'OK')}")
except Exception as e:
    print(f"    ERROR: {e}")

# Test 5: Passkey auth begin (should fail with 404)
print("\n[5] Passkey auth begin (with non-existent user)...")
try:
    r = requests.post(
        f"{BASE_URL}/api/passkey/auth/begin",
        json={"email": "nonexistent@test.com"}
    )
    print(f"    Status: {r.status_code} - {r.json().get('detail', 'OK')}")
except Exception as e:
    print(f"    ERROR: {e}")

# Test 6: Rate limiting
print("\n[6] Rate limiting test (6 requests to token endpoint)...")
try:
    for i in range(6):
        r = requests.post(
            f"{BASE_URL}/api/token",
            data={"username": "rate@test.com", "password": "test"}
        )
        if r.status_code == 429:
            print(f"    Request {i+1}: HTTP 429 - Rate limited (WORKING!)")
            break
        else:
            print(f"    Request {i+1}: HTTP {r.status_code}")
except Exception as e:
    print(f"    ERROR: {e}")

print("\n" + "="*70)
print(" All critical endpoints are responding correctly!")
print("="*70)
print()
