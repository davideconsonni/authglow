"""Test account lockout mechanism by bypassing rate limiting."""
import requests
import time

BASE_URL = "http://127.0.0.1:8000"

def test_account_lockout_direct():
    """Test account lockout by directly calling the storage methods."""
    print("\n" + "="*60)
    print(" Test: Account Lockout Verification")
    print("="*60)

    # We'll test with a real user
    test_email = "admin@authglow.local"

    print(f"\nAttempting 6 failed logins for: {test_email}")
    print("Note: Rate limiting will block after 5 requests/minute")
    print("Waiting 70 seconds between batches to reset rate limit...\n")

    # First batch: 5 requests
    print("Batch 1: 5 requests")
    for i in range(5):
        try:
            response = requests.post(
                f"{BASE_URL}/api/token",
                data={
                    "username": test_email,
                    "password": "wrongpassword123"
                }
            )
            print(f"  Request {i+1}: Status {response.status_code}")
            time.sleep(0.5)
        except Exception as e:
            print(f"  Request {i+1}: Error - {e}")

    print("\nWaiting 70 seconds for rate limit to reset...")
    time.sleep(70)

    # Second batch: 1 more request (6th attempt - should trigger lockout)
    print("\nBatch 2: Request 6 (should trigger lockout)")
    try:
        response = requests.post(
            f"{BASE_URL}/api/token",
            data={
                "username": test_email,
                "password": "wrongpassword123"
            }
        )
        status = response.status_code
        detail = response.json().get('detail', '')

        print(f"  Request 6: Status {status}")

        if status == 423:
            print("\n[PASS] Account lockout triggered correctly!")
            print(f"  Message: {detail}")
            return True
        else:
            print(f"\n[INFO] Status {status} - {detail}")
            print("Continuing to verify if account was locked...")

    except Exception as e:
        print(f"  Request 6: Error - {e}")

    # Try one more time to see if account is locked
    print("\nVerification: Trying with correct password to check if account is locked")
    time.sleep(2)

    try:
        response = requests.post(
            f"{BASE_URL}/api/token",
            data={
                "username": test_email,
                "password": "correctpasswordifknown"  # This will fail anyway but we check for 423
            }
        )
        status = response.status_code
        detail = response.json().get('detail', '')

        print(f"  Status: {status}")
        print(f"  Detail: {detail}")

        if status == 423 or "locked" in detail.lower():
            print("\n[PASS] Account is locked!")
            return True

    except Exception as e:
        print(f"  Error: {e}")

    print("\n[FAIL] Account lockout not confirmed")
    return False

if __name__ == "__main__":
    print("\n" + "="*60)
    print(" AuthGlow Account Lockout Test")
    print("="*60)
    print("\nThis test will take approximately 80 seconds...")

    result = test_account_lockout_direct()

    print("\n" + "="*60)
    print(f" RESULT: {'[PASSED]' if result else '[FAILED]'}")
    print("="*60)
    print()
