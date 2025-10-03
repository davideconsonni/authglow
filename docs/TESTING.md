# AuthGlow - Testing Guide

Complete guide for testing all AuthGlow features.

## Table of Contents

1. [Setup](#setup)
2. [Basic Authentication](#basic-authentication)
3. [OAuth2 Flows](#oauth2-flows)
4. [MFA (Two-Factor Authentication)](#mfa-two-factor-authentication)
5. [User Management](#user-management)
6. [Admin Portal](#admin-portal-coming-soon)
7. [Security Features](#security-features-coming-soon)
8. [Audit Logging](#audit-logging-coming-soon)
9. [Troubleshooting](#troubleshooting)

---

## Setup

### Prerequisites

1. **Install dependencies:**
   ```bash
   uv pip install -r requirements.txt
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   ```

   Edit `.env` and set:
   ```env
   SECRET_KEY=your-secret-key-min-32-chars-change-this
   JWT_SECRET_KEY=your-jwt-secret-min-32-chars-change-this
   ```

3. **Create admin user:**
   ```bash
   python create_admin.py
   ```

   Follow prompts to create admin account.

4. **Start application:**
   ```bash
   python main.py
   ```

   Application will be available at `http://localhost:8000`

5. **View API documentation:**
   - Interactive docs: http://localhost:8000/docs
   - Alternative docs: http://localhost:8000/redoc

---

## Basic Authentication

### Test 1: Health Check

**Request:**
```bash
curl http://localhost:8000/health
```

**Expected Response:**
```json
{"status": "healthy"}
```

### Test 2: Direct Token Authentication

Get an access token using email/password.

**Request:**
```bash
curl -X POST http://localhost:8000/api/token -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin@example.com" -d "password=YourPassword123!"
```

**Expected Response:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "expires_in": 1800,
  "refresh_token": "eyJhbGc...",
  "scope": "read write admin"
}
```

**Save the access_token for subsequent requests.**

### Test 3: Get Current User Info

**Request:**
```bash
curl -X GET http://localhost:8000/api/users/me -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Expected Response:**
```json
{
  "id": "uuid-here",
  "email": "admin@example.com",
  "is_active": true,
  "created_at": "2025-10-02T22:50:27.031498",
  "first_name": "Admin",
  "last_name": "User",
  "scopes": ["read", "write", "admin"],
  "mfa_enabled": false,
  "mfa_verified": false
}
```

---

## OAuth2 Flows

### Test 4: Authorization Code Flow

This is the standard OAuth2 flow for web applications.

#### Step 4.1: Start Authorization

**Open in browser:**
```
http://localhost:8000/oauth2/authorize?response_type=code&client_id=default-client-id&redirect_uri=http://localhost:8000/callback&scope=read&state=test123
```

**Expected:** Login page is displayed.

#### Step 4.2: Login

Enter credentials:
- Email: `admin@example.com`
- Password: `YourPassword123!`

**Expected:** Redirected to callback page with authorization code.

#### Step 4.3: Exchange Code for Token

Copy the authorization code from the callback page and run:

**Request:**
```bash
curl -X POST http://localhost:8000/oauth2/token -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=authorization_code" -d "code=YOUR_AUTH_CODE" -d "redirect_uri=http://localhost:8000/callback"
```

**Expected Response:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "expires_in": 1800,
  "refresh_token": "eyJhbGc...",
  "scope": "read write admin"
}
```

### Test 5: Refresh Token Flow

Use a refresh token to get a new access token.

**Request:**
```bash
curl -X POST http://localhost:8000/oauth2/token -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=refresh_token" -d "refresh_token=YOUR_REFRESH_TOKEN"
```

**Expected Response:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "expires_in": 1800,
  "refresh_token": "eyJhbGc...",
  "scope": "read write admin"
}
```

### Test 6: Client Credentials Flow

Service-to-service authentication.

**Request:**
```bash
curl -X POST http://localhost:8000/oauth2/token -H "Content-Type: application/x-www-form-urlencoded" -d "grant_type=client_credentials" -d "client_id=default-client-id" -d "client_secret=default-client-secret" -d "scope=read"
```

**Expected Response:**
```json
{
  "access_token": "eyJhbGc...",
  "token_type": "bearer",
  "expires_in": 1800,
  "scope": "read"
}
```

---

## MFA (Two-Factor Authentication)

### Test 7: MFA Enrollment

#### Step 7.1: Get Access Token

First, get an access token (see Test 2).

#### Step 7.2: Enroll MFA

**Request:**
```bash
curl -X POST http://localhost:8000/api/mfa/enroll -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Expected Response:**
```json
{
  "secret": "BASE32SECRETHERE",
  "qr_code": "data:image/png;base64,...",
  "backup_codes": [
    "ABCD-EFGH",
    "IJKL-MNOP",
    ...
  ]
}
```

**Important:** Save the backup codes in a secure location!

#### Step 7.3: Scan QR Code

1. Open Google Authenticator, Authy, or similar app on your phone
2. Choose "Add account" → "Scan QR code"
3. Options:
   - **Option A:** Save the `qr_code` base64 string to an HTML file and open in browser
   - **Option B:** Manually enter the `secret` in your authenticator app

#### Step 7.4: Verify First Code

Get the 6-digit code from your authenticator app and verify:

**Request:**
```bash
curl -X POST http://localhost:8000/api/mfa/verify -H "Authorization: Bearer YOUR_ACCESS_TOKEN" -H "Content-Type: application/json" -d "{\"code\":\"123456\"}"
```

Replace `123456` with the actual code from your app.

**Expected Response:**
```json
{
  "id": "uuid-here",
  "email": "admin@example.com",
  "mfa_enabled": true,
  "mfa_verified": true,
  ...
}
```

### Test 8: Login with MFA

#### Step 8.1: Start OAuth2 Flow

**Open in browser:**
```
http://localhost:8000/oauth2/authorize?response_type=code&client_id=default-client-id&redirect_uri=http://localhost:8000/callback&scope=read&state=test123
```

#### Step 8.2: Enter Credentials

Enter email and password.

**Expected:** MFA verification page is displayed.

#### Step 8.3: Enter MFA Code

1. Get 6-digit code from your authenticator app
2. Enter code in the MFA page
3. Optionally check "Trust this device for 30 days"
4. Click "Verify"

**Expected:** Redirected to callback with authorization code.

### Test 9: Login with Backup Code

Same as Test 8, but in Step 8.3:
1. Click "Use a backup code"
2. Enter one of your backup codes (format: XXXX-XXXX)
3. Click "Verify"

**Expected:** Successfully authenticated with backup code.

### Test 10: MFA Status

**Request:**
```bash
curl -X GET http://localhost:8000/api/mfa/status -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Expected Response:**
```json
{
  "enabled": true,
  "verified": true,
  "backup_codes_remaining": 10,
  "trusted_devices_count": 1
}
```

### Test 11: List Trusted Devices

**Request:**
```bash
curl -X GET http://localhost:8000/api/mfa/trusted-devices -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Expected Response:**
```json
[
  {
    "id": "device-uuid",
    "user_id": "user-uuid",
    "device_fingerprint": "hash...",
    "name": "Browser",
    "created_at": "2025-10-02T23:00:00",
    "expires_at": "2025-11-01T23:00:00",
    "last_used": "2025-10-02T23:00:00"
  }
]
```

### Test 12: Remove Trusted Device

**Request:**
```bash
curl -X DELETE http://localhost:8000/api/mfa/trusted-devices/DEVICE_ID -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Expected Response:**
```json
{"message": "Device removed successfully"}
```

### Test 13: Regenerate Backup Codes

**Request:**
```bash
curl -X POST http://localhost:8000/api/mfa/regenerate-backup-codes -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Expected Response:**
```json
{
  "message": "Backup codes regenerated successfully",
  "backup_codes": [
    "ABCD-EFGH",
    "IJKL-MNOP",
    ...
  ]
}
```

### Test 14: Disable MFA

**Request:**
```bash
curl -X DELETE http://localhost:8000/api/mfa/disable -H "Authorization: Bearer YOUR_ACCESS_TOKEN"
```

**Expected Response:**
```json
{"message": "MFA disabled successfully"}
```

---

## User Management

### Test 15: Invite New User

Requires admin access token.

**Request:**
```bash
curl -X POST http://localhost:8000/api/users/invite -H "Authorization: Bearer YOUR_ADMIN_TOKEN" -H "Content-Type: application/json" -d "{\"email\":\"newuser@example.com\",\"scopes\":[\"read\"],\"first_name\":\"John\",\"last_name\":\"Doe\"}"
```

**Expected Response:**
```json
{
  "id": "new-user-uuid",
  "email": "newuser@example.com",
  "is_active": true,
  "created_at": "2025-10-02T23:00:00",
  "first_name": "John",
  "last_name": "Doe",
  "scopes": ["read"],
  "mfa_enabled": false,
  "mfa_verified": false
}
```

**Note:** In production, the user would receive an email with temporary password. Currently displayed in logs for development.

### Test 16: List All Users

Requires admin access token.

**Request:**
```bash
curl -X GET http://localhost:8000/api/users?limit=10&offset=0 -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

**Expected Response:**
```json
[
  {
    "id": "uuid",
    "email": "user@example.com",
    "is_active": true,
    ...
  }
]
```

---

## Admin Portal (Coming Soon)

### Test 17: Access Admin Dashboard

**Browser:**
```
http://localhost:8000/admin
```

**Expected Features:**
- User statistics
- Recent logins
- User search and filtering
- Bulk user management
- Configuration UI
- Security events

---

## Security Features (Coming Soon)

### Test 18: Brute Force Protection

**Scenario:** Attempt multiple failed logins.

**Request (repeat 5+ times):**
```bash
curl -X POST http://localhost:8000/api/token -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin@example.com" -d "password=WrongPassword"
```

**Expected:** After threshold, account is temporarily locked or rate limited.

### Test 19: Rate Limiting

**Scenario:** Make rapid consecutive requests.

**Expected:** HTTP 429 (Too Many Requests) after threshold.

### Test 20: Anomaly Detection

**Scenario:** Login from unusual location/device.

**Expected:** Additional verification required or security alert.

### Test 21: CAPTCHA

**Scenario:** Login after failed attempts.

**Expected:** CAPTCHA challenge presented.

---

## Audit Logging (Coming Soon)

### Test 22: View Audit Logs

**Request:**
```bash
curl -X GET http://localhost:8000/api/audit/logs?user_id=USER_ID&limit=50 -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

**Expected Response:**
```json
[
  {
    "id": "log-uuid",
    "user_id": "user-uuid",
    "event_type": "login_success",
    "ip_address": "192.168.1.1",
    "user_agent": "Mozilla/5.0...",
    "timestamp": "2025-10-02T23:00:00",
    "metadata": {}
  }
]
```

### Test 23: Export Audit Logs

**Request:**
```bash
curl -X GET http://localhost:8000/api/audit/export?format=csv&start_date=2025-10-01&end_date=2025-10-31 -H "Authorization: Bearer YOUR_ADMIN_TOKEN"
```

**Expected:** CSV file download with audit logs.

---

## Troubleshooting

### Issue: "Invalid or expired token"

**Solution:**
- Token may have expired (default: 30 minutes)
- Get a new token using `/api/token` endpoint
- Check that token is included in `Authorization: Bearer TOKEN` header

### Issue: "MFA not properly configured"

**Solution:**
- Ensure MFA enrollment was completed (`/api/mfa/verify`)
- Check MFA status with `/api/mfa/status`
- Verify `mfa_verified` is `true`

### Issue: "Invalid MFA code"

**Solution:**
- Check time synchronization on your device
- TOTP codes are time-based (30-second window)
- Try waiting for next code generation
- Use backup code if authenticator is not accessible

### Issue: "Device not trusted"

**Solution:**
- Trusted devices expire after 30 days
- Re-authenticate with MFA and check "Trust this device"
- View trusted devices with `/api/mfa/trusted-devices`

### Issue: "Admin access required"

**Solution:**
- User must have `admin` scope
- Check user scopes with `/api/users/me`
- Admin users are created with `scopes: ["read", "write", "admin"]`

### Issue: bcrypt version warning

**Note:** The warning `(trapped) error reading bcrypt version` is harmless and can be ignored. It's an internal passlib warning that doesn't affect functionality.

---

## Test Automation

### Using Python Requests

```python
import requests

BASE_URL = "http://localhost:8000"

# Get token
response = requests.post(
    f"{BASE_URL}/api/token",
    data={
        "username": "admin@example.com",
        "password": "YourPassword123!"
    }
)
token = response.json()["access_token"]

# Get user info
response = requests.get(
    f"{BASE_URL}/api/users/me",
    headers={"Authorization": f"Bearer {token}"}
)
print(response.json())
```

### Using pytest

```python
# tests/test_mfa.py
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_mfa_enrollment():
    # Login
    response = client.post("/api/token", data={
        "username": "admin@example.com",
        "password": "YourPassword123!"
    })
    token = response.json()["access_token"]

    # Enroll MFA
    response = client.post(
        "/api/mfa/enroll",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    assert "qr_code" in response.json()
    assert "backup_codes" in response.json()
```

Run tests:
```bash
pytest tests/
```

---

## Performance Testing

### Load Testing with Apache Bench

```bash
# Test token endpoint
ab -n 1000 -c 10 -p token_data.txt -T application/x-www-form-urlencoded http://localhost:8000/api/token
```

### Load Testing with wrk

```bash
# Test health endpoint
wrk -t12 -c400 -d30s http://localhost:8000/health
```

---

## Security Testing

### Check for Common Vulnerabilities

```bash
# SQL Injection (should be safe - no SQL used)
curl -X POST http://localhost:8000/api/token -d "username=admin' OR '1'='1&password=test"

# XSS (should be sanitized)
curl -X POST http://localhost:8000/api/users/invite -H "Authorization: Bearer TOKEN" -d '{"email":"<script>alert(1)</script>@test.com"}'

# CSRF (should require proper headers)
curl -X POST http://localhost:8000/api/mfa/disable
```

---

## Notes

- Replace `YOUR_ACCESS_TOKEN`, `YOUR_ADMIN_TOKEN`, etc. with actual tokens
- Default OAuth2 credentials: `client_id=default-client-id`, `client_secret=default-client-secret`
- Change these in production via environment variables
- All timestamps are in UTC
- Token expiry: Access tokens (30 min), Refresh tokens (7 days), MFA sessions (5 min)
- Trusted devices expire after 30 days

---

**Last Updated:** October 2025
**AuthGlow Version:** 0.2.0 (with MFA)
