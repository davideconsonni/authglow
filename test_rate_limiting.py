"""Test script for rate limiting and account lockout."""
import requests
import time
from datetime import datetime

BASE_URL = "http://127.0.0.1:8000"

def print_header(text):
    """Print formatted header."""
    print(f"\n{'='*60}")
    print(f" {text}")
    print('='*60)

def test_rate_limiting():
    """Test IP-based rate limiting on /api/token endpoint."""
    print_header("TEST 1: Rate Limiting (5 requests/minute)")

    # Try to make 7 requests (limit is 5/minute)
    for i in range(7):
        try:
            response = requests.post(
                f"{BASE_URL}/api/token",
                data={
                    "username": "test@example.com",
                    "password": "wrongpassword"
                }
            )
            print(f"Request {i+1}: Status {response.status_code} - {response.json().get('detail', 'OK')}")

            if response.status_code == 429:
                print("✅ Rate limit triggered!")
                return True

        except Exception as e:
            print(f"Request {i+1}: Error - {e}")

        time.sleep(0.5)

    print("❌ Rate limit not triggered after 7 requests")
    return False

def test_account_lockout():
    """Test account lockout after 5 failed login attempts."""
    print_header("TEST 2: Account Lockout (5 failed attempts)")

    # Create a test user first (using admin credentials)
    test_email = f"lockout_test_{int(time.time())}@example.com"

    print(f"\nAttempting {5} failed logins for: {test_email}")

    for i in range(6):
        try:
            response = requests.post(
                f"{BASE_URL}/api/token",
                data={
                    "username": test_email,
                    "password": "wrongpassword"
                }
            )
            status = response.status_code
            detail = response.json().get('detail', '')

            print(f"Attempt {i+1}: Status {status} - {detail}")

            if status == 423:  # HTTP 423 Locked
                print("✅ Account lockout triggered!")
                return True

        except Exception as e:
            print(f"Attempt {i+1}: Error - {e}")

        time.sleep(1)

    print("❌ Account lockout not triggered")
    return False

def test_passkey_rate_limiting():
    """Test rate limiting on passkey endpoints."""
    print_header("TEST 3: Passkey Rate Limiting (10 requests/minute)")

    # Try to make 12 requests to passkey auth endpoint
    for i in range(12):
        try:
            response = requests.post(
                f"{BASE_URL}/api/passkey/auth/begin",
                json={"email": "test@example.com"}
            )
            status = response.status_code

            if status == 429:
                print(f"Request {i+1}: Status {status} - Rate limit triggered!")
                print("✅ Passkey rate limit working!")
                return True
            else:
                detail = response.json().get('detail', 'OK')
                print(f"Request {i+1}: Status {status} - {detail}")

        except Exception as e:
            print(f"Request {i+1}: Error - {e}")

        time.sleep(0.5)

    print("❌ Passkey rate limit not triggered")
    return False

def main():
    """Run all tests."""
    print("\n" + "="*60)
    print(" AuthGlow Rate Limiting & Account Lockout Tests")
    print("="*60)
    print(f"\nTesting against: {BASE_URL}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    results = []

    # Test 1: Rate limiting
    results.append(("Rate Limiting", test_rate_limiting()))

    print("\n⏱️  Waiting 60 seconds for rate limit to reset...")
    time.sleep(60)

    # Test 2: Account lockout
    results.append(("Account Lockout", test_account_lockout()))

    # Test 3: Passkey rate limiting
    print("\n⏱️  Waiting 60 seconds for rate limit to reset...")
    time.sleep(60)
    results.append(("Passkey Rate Limiting", test_passkey_rate_limiting()))

    # Summary
    print_header("TEST SUMMARY")
    for test_name, passed in results:
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"{test_name}: {status}")

    total = len(results)
    passed = sum(1 for _, p in results if p)
    print(f"\nTotal: {passed}/{total} tests passed")

if __name__ == "__main__":
    main()
