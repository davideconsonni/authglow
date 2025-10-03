"""Quick test for rate limiting."""
import requests
import time

BASE_URL = "http://127.0.0.1:8000"

def test_rate_limiting():
    """Test IP-based rate limiting on /api/token endpoint (limit: 5/minute)."""
    print("\n" + "="*60)
    print(" Test: Rate Limiting on /api/token (5 requests/minute)")
    print("="*60)

    for i in range(7):
        try:
            response = requests.post(
                f"{BASE_URL}/api/token",
                data={
                    "username": "test@example.com",
                    "password": "wrongpassword"
                }
            )
            status = response.status_code
            detail = response.json().get('detail', 'OK')

            if status == 429:
                print(f"[PASS] Request {i+1}: Status {status} - Rate limit triggered after {i+1} requests!")
                return True
            else:
                print(f"   Request {i+1}: Status {status}")

        except Exception as e:
            print(f"   Request {i+1}: Error - {e}")

        time.sleep(0.3)

    print("[FAIL] Rate limit not triggered")
    return False

def test_account_lockout():
    """Test account lockout (5 failed attempts)."""
    print("\n" + "="*60)
    print(" Test: Account Lockout (5 failed attempts)")
    print("="*60)

    # Use a specific test email
    test_email = "admin@authglow.local"

    print(f"\nTrying failed logins for: {test_email}")

    for i in range(7):
        try:
            response = requests.post(
                f"{BASE_URL}/api/token",
                data={
                    "username": test_email,
                    "password": "definitelywrongpassword123"
                }
            )
            status = response.status_code
            detail = response.json().get('detail', '')

            if status == 423:
                print(f"[PASS] Attempt {i+1}: Status {status} - Account locked! (After {i+1} attempts)")
                return True
            else:
                print(f"   Attempt {i+1}: Status {status}")

        except Exception as e:
            print(f"   Attempt {i+1}: Error - {e}")

        time.sleep(0.5)

    print("[FAIL] Account lockout not triggered")
    return False

if __name__ == "__main__":
    print("\n" + "="*60)
    print(" AuthGlow Rate Limiting Quick Tests")
    print("="*60)

    # Test 1: Rate limiting (should trigger on 6th request)
    result1 = test_rate_limiting()

    print("\nWaiting 5 seconds before next test...\n")
    time.sleep(5)

    # Test 2: Account lockout (should trigger on 6th attempt)
    result2 = test_account_lockout()

    # Summary
    print("\n" + "="*60)
    print(" SUMMARY")
    print("="*60)
    print(f"Rate Limiting: {'[PASSED]' if result1 else '[FAILED]'}")
    print(f"Account Lockout: {'[PASSED]' if result2 else '[FAILED]'}")
    print()
