# Security Configuration Guide

This guide covers AuthGlow's security features and best practices for protecting your authentication system and user data.

---

## Security Philosophy

AuthGlow is built with security as a core principle:

- **Defense in Depth**: Multiple layers of security
- **Secure by Default**: Sensible defaults that enforce security
- **Transparency**: File-based storage makes auditing easy
- **Standards Compliance**: OAuth 2.0, OIDC, FIDO2/WebAuthn standards

---

## 1. Secret Key Management

### Critical: Change Default Keys

The most important security step is generating **strong, unique secret keys**.

### Required Keys

AuthGlow requires two separate keys:

```bash
# .env
SECRET_KEY=your-64-char-random-hex-string
JWT_SECRET_KEY=your-different-64-char-random-hex-string
```

**Why two keys?**
- `SECRET_KEY`: Signs session cookies and CSRF tokens
- `JWT_SECRET_KEY`: Signs OAuth/OIDC access and ID tokens

Separating these reduces risk if one is compromised.

### Generating Secure Keys

**Method 1: OpenSSL** (Linux/macOS)
```bash
openssl rand -hex 32
```

**Method 2: Python** (All platforms)
```python
import secrets
print(secrets.token_hex(32))
```

**Method 3: Node.js**
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### Key Rotation

To rotate keys without downtime:

1. **Generate new keys** using methods above
2. **Update production `.env`** with new values
3. **Restart AuthGlow**
4. **Old tokens become invalid** - users must re-authenticate

**Recommended rotation frequency**: Annually, or immediately if compromised.

### Key Storage Best Practices

✅ **Do**:
- Store keys in environment variables
- Use secret management (AWS Secrets Manager, HashiCorp Vault)
- Restrict access to production `.env` files
- Encrypt backups containing `.env`

❌ **Don't**:
- Commit keys to Git
- Share keys in Slack/email
- Use the same keys for dev/staging/production
- Store keys in application code

---

## 2. Password Security

### Password Hashing

AuthGlow uses **bcrypt** with automatic salt generation for password hashing.

**Configuration**: `authglow/services/password.py:9`
```python
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)
```

**Benefits**:
- Industry-standard algorithm
- Automatic salt generation
- Configurable work factor (cost)
- Resistant to rainbow table attacks

### Password Policy Configuration

Configure password complexity requirements via environment variables:

```bash
# .env
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=true
PASSWORD_REQUIRE_SPECIAL=true
```

### Policy Examples

**Default (Secure)**:
```bash
PASSWORD_MIN_LENGTH=8
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=true
PASSWORD_REQUIRE_SPECIAL=true
```
Example valid password: `MyP@ssw0rd`

**High Security (Enterprise)**:
```bash
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=true
PASSWORD_REQUIRE_SPECIAL=true
```
Example valid password: `Entr0pyS3cur!ty2025`

**Relaxed (Developer-Friendly)**:
```bash
PASSWORD_MIN_LENGTH=6
PASSWORD_REQUIRE_UPPERCASE=false
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=true
PASSWORD_REQUIRE_SPECIAL=false
```
Example valid password: `simple123`

**Passphrase-Friendly**:
```bash
PASSWORD_MIN_LENGTH=16
PASSWORD_REQUIRE_UPPERCASE=false
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_DIGITS=false
PASSWORD_REQUIRE_SPECIAL=false
```
Example valid password: `correct horse battery staple`

### Password Policy Recommendations

For **production systems**:
- Minimum 12 characters
- Require all character types (upper, lower, digit, special)
- Consider implementing password blacklists (common passwords)
- Encourage use of password managers

For **internal tools**:
- Minimum 8 characters
- Require at least 3 of 4 character types
- Allow passphrases (longer but easier to remember)

---

## 3. Account Lockout & Brute Force Protection

### Automatic Account Lockout

AuthGlow automatically locks accounts after failed login attempts.

**Default Configuration**:
- **Max attempts**: 5 failed logins
- **Lockout duration**: 15 minutes
- **Auto-unlock**: After lockout period expires

**Implementation**: `authglow/services/storage.py:146-165`

### How It Works

1. User fails login → `failed_login_attempts` counter increments
2. After 5 failures → `locked_until` set to `now + 15 minutes`
3. During lockout → All login attempts rejected with 423 status
4. After 15 minutes → Auto-unlock, counter resets

### Customizing Lockout Settings

Currently hardcoded. To customize, edit `authglow/services/storage.py`:

```python
# storage.py:146
async def record_failed_login(
    self,
    user_id: str,
    max_attempts: int = 10,  # Changed from 5
    lockout_duration_minutes: int = 30  # Changed from 15
):
```

**Future enhancement**: Make these configurable via environment variables.

### Security Notifications

Users receive email alerts when their account is locked:

**Template**: `authglow/templates/emails/security_alert.html`

Includes:
- Timestamp of lockout
- IP address of failed attempts
- Instructions to reset password

---

## 4. Rate Limiting

### Overview

AuthGlow uses **SlowAPI** (based on Flask-Limiter) for rate limiting.

**Global default**: 200 requests per hour per IP address

### Endpoint-Specific Limits

Different endpoints have tailored rate limits:

| Endpoint | Limit | Reason |
|----------|-------|--------|
| **Global** | 200/hour | Prevent general abuse |
| **Password Reset Request** | 5/hour | Prevent email flooding |
| **Password Reset Confirm** | 10/hour | Allow retries for typos |
| **Email Verification Send** | 10/hour | Prevent spam |
| **Email Verification Verify** | 5/hour | Prevent token guessing |
| **API Key Creation** | 10/hour | Prevent key farming |
| **Passkey Authentication** | 10/minute | Prevent brute force |
| **OAuth Authorization** | 10/minute | Prevent authorization spam |

### Configuration Location

**Global limiter**: `main.py:30`
```python
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per hour"])
```

**Per-endpoint**: Uses `@limiter.limit()` decorator

**Example** (`authglow/api/password_reset.py:52`):
```python
@limiter.limit("5/hour")
@router.post("/api/password/reset/request")
async def request_password_reset(...):
    ...
```

### Customizing Rate Limits

**Change global limit**:
```python
# main.py
limiter = Limiter(key_func=get_remote_address, default_limits=["500 per hour"])
```

**Change endpoint limit**:
```python
# authglow/api/password_reset.py
@limiter.limit("10/hour")  # Changed from 5/hour
@router.post("/api/password/reset/request")
```

### Rate Limit Response

When rate limit is exceeded, clients receive:

```json
{
  "error": "Rate limit exceeded",
  "detail": "5 per 1 hour"
}
```

**HTTP Status**: `429 Too Many Requests`

### Best Practices

1. **Adjust for your traffic**: High-volume apps may need higher limits
2. **Monitor rate limit hits**: Track 429 responses in logs
3. **Inform users**: Display rate limit info in error messages
4. **Use per-user limits**: For authenticated endpoints, consider limiting by user ID instead of IP
5. **Whitelist IPs**: For trusted services, bypass rate limiting

---

## 5. Audit Logging

### Overview

AuthGlow logs all security-relevant events to `data/users/audit_logs/`.

**Log format**: JSON files organized by year/month

### Events Logged

AuthGlow automatically logs:

- ✅ User registration (`user_created`)
- ✅ Successful logins (`login_success`)
- ✅ Failed logins (`login_failed`)
- ✅ Password resets (`password_reset`)
- ✅ Password changes (`password_changed`)
- ✅ Email changes (`email_changed`)
- ✅ MFA enabled/disabled (`mfa_enabled`, `mfa_disabled`)
- ✅ API key creation/deletion (`api_key_created`, `api_key_deleted`)
- ✅ OAuth consent grants/revocations
- ✅ Account lockouts (`account_locked`)

### Log Entry Structure

```json
{
  "id": "22dfbb1d-cecc-43e4-87d2-dafd1894999f",
  "timestamp": "2025-10-04T10:30:45.123456Z",
  "user_id": "117c39e4-8191-4df8-b5ce-104d7b7ecb4a",
  "email": "user@example.com",
  "event_type": "login_success",
  "ip_address": "192.168.1.100",
  "user_agent": "Mozilla/5.0 ...",
  "severity": "info",
  "metadata": {
    "mfa_used": true,
    "client_id": "web-app"
  }
}
```

### Severity Levels

- **`info`**: Normal operations (login, registration)
- **`warning`**: Suspicious activity (failed login, account locked)
- **`error`**: Security issues (multiple failed attempts)
- **`critical`**: Serious threats (account compromise attempts)

### Accessing Audit Logs

**Via Admin Panel**:
- Navigate to `/admin/audit`
- Filter by user, event type, date range, severity

**Via Filesystem**:
```bash
# View recent logs
find data/users/audit_logs -name "*.json" -mtime -1 -exec cat {} \;

# Count login events today
find data/users/audit_logs -name "*.json" -mtime -1 -exec cat {} \; | grep "login_success" | wc -l

# Find failed login attempts
find data/users/audit_logs -name "*.json" -exec cat {} \; | grep "login_failed"
```

**Via API** (requires admin token):
```bash
curl -X GET "http://localhost:8000/admin/audit/logs" \
  -H "Authorization: Bearer ADMIN_TOKEN" \
  -G \
  --data-urlencode "event_type=login_failed" \
  --data-urlencode "limit=50"
```

### Log Retention

**Default**: Logs are retained indefinitely

**Cleanup script**:
```python
# cleanup_old_logs.py
from authglow.services.audit import AuditService
import asyncio

async def cleanup():
    audit = AuditService()
    await audit.delete_old_logs(days=365)  # Delete logs older than 1 year
    print("Cleanup complete")

asyncio.run(cleanup())
```

**Recommended retention**:
- Development: 30 days
- Production: 1-2 years (or per compliance requirements)
- High-security: 5+ years

---

## 6. Security Notifications

### Automatic Email Alerts

Users receive email notifications for security-sensitive events:

| Event | Notification Sent |
|-------|-------------------|
| New login from unrecognized device | ✅ |
| Password changed | ✅ |
| Email address changed | ✅ (to both old and new) |
| MFA enabled | ✅ |
| MFA disabled | ✅ |
| API key created | ✅ |
| Account locked | ✅ |

### Implementation

**Service**: `authglow/services/security_notifications.py`

**Example** (password change):
```python
# After password update
notification_service = SecurityNotificationService()
await notification_service.send_password_changed_alert(
    user=user,
    ip_address=request.client.host
)
```

### Email Template

All security alerts use: `authglow/templates/emails/security_alert.html`

**Content includes**:
- Alert type (login, password change, etc.)
- Timestamp
- IP address
- Device/browser info (when available)
- "Was this you?" prompt
- Security action link (change password, review sessions)

### Customizing Notifications

Edit `authglow/templates/emails/security_alert.html` to:
- Add company branding
- Include additional context
- Provide specific recovery instructions
- Add support contact information

---

## 7. Token Security

### Access Token Configuration

```bash
# .env
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

### Recommendations by Environment

**Development**:
```bash
ACCESS_TOKEN_EXPIRE_MINUTES=60  # Longer for convenience
REFRESH_TOKEN_EXPIRE_DAYS=30
```

**Production (Standard)**:
```bash
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7
```

**Production (High Security)**:
```bash
ACCESS_TOKEN_EXPIRE_MINUTES=15  # Short-lived
REFRESH_TOKEN_EXPIRE_DAYS=1    # Require frequent re-auth
```

**Production (User-Friendly)**:
```bash
ACCESS_TOKEN_EXPIRE_MINUTES=60
REFRESH_TOKEN_EXPIRE_DAYS=30
```

### Token Algorithms

**Current**: `HS256` (HMAC with SHA-256, symmetric key)

**Pros**:
- Simple configuration
- Fast signing/verification
- Suitable for single-service deployments

**Cons**:
- Shared secret between AuthGlow and resource servers
- Secret must remain confidential

**Future enhancement**: `RS256` (RSA asymmetric keys)
- AuthGlow signs with private key
- Resource servers verify with public key (via JWKS)
- Better for microservices architectures

---

## 8. HTTPS and Transport Security

### Enforce HTTPS in Production

**Never** transmit authentication data over HTTP.

### Certificate Setup

Use Let's Encrypt for free SSL certificates:

```bash
sudo certbot certonly --nginx -d auth.yourdomain.com
```

Auto-renewal:
```bash
sudo certbot renew --dry-run
```

### HSTS (HTTP Strict Transport Security)

Configure in Nginx (from deployment guide):

```nginx
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
```

This forces browsers to always use HTTPS.

### Security Headers

AuthGlow's Nginx config includes essential security headers:

```nginx
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

**What they do**:
- **X-Frame-Options**: Prevent clickjacking
- **X-Content-Type-Options**: Prevent MIME sniffing
- **X-XSS-Protection**: Enable browser XSS filters
- **Referrer-Policy**: Control referrer information

---

## 9. Multi-Factor Authentication (MFA)

### Enable MFA for Admin Accounts

**Mandatory**: All admin accounts should use MFA.

### MFA Configuration

**Method**: TOTP (Time-based One-Time Password)
**Compatible apps**: Google Authenticator, Authy, 1Password

### User Enrollment

1. User navigates to `/mfa/setup`
2. Scans QR code with authenticator app
3. Enters 6-digit code to verify
4. Receives 10 backup codes (store securely)

### Backup Codes

**Location**: `data/users/mfa/backup_codes/{user_id}.json`

Each code:
- Single-use only
- Valid indefinitely
- Encrypted at rest

**Security note**: Backup codes should be treated like passwords.

---

## 10. OAuth Client Security

### Client Secret Management

OAuth client secrets are **bcrypt-hashed**, never stored in plaintext.

**Creation** (`authglow/services/oauth_client.py:27`):
```python
client.client_secret = hash_password(plaintext_secret)
```

### Redirect URI Validation

AuthGlow strictly validates redirect URIs to prevent open redirect attacks.

**Allowed**:
```
https://myapp.com/callback  ✅
http://localhost:3000/callback  ✅ (dev only)
```

**Blocked**:
```
https://evil.com/steal-tokens  ❌
http://myapp.com/callback  ❌ (HTTP in production)
```

### Client Configuration Best Practices

✅ **Do**:
- Use HTTPS for all redirect URIs in production
- Register exact redirect URIs (no wildcards)
- Use different clients for dev/staging/production
- Rotate client secrets annually

❌ **Don't**:
- Use `http://` in production
- Use wildcard redirect URIs
- Share client secrets across environments
- Commit client secrets to Git

---

## 11. Passkey (WebAuthn) Security

### Configuration

```bash
# .env
PASSKEY_RP_ID=yourdomain.com  # Must match your domain
PASSKEY_RP_NAME=Your Company Name
PASSKEY_ORIGIN=https://auth.yourdomain.com
```

### Security Features

**Built-in protections**:
- Public key cryptography (no shared secrets)
- Phishing-resistant (origin validation)
- Replay attack protection (challenge-response)
- Device-bound credentials

### Production Requirements

**HTTPS required**: Passkeys only work over HTTPS (except localhost).

**Domain matching**:
- `PASSKEY_RP_ID` must be the domain (e.g., `example.com`)
- `PASSKEY_ORIGIN` must include protocol and port (e.g., `https://auth.example.com`)

**Example**:
```bash
# Correct
PASSKEY_RP_ID=example.com
PASSKEY_ORIGIN=https://auth.example.com

# Wrong
PASSKEY_RP_ID=auth.example.com  # Too specific
PASSKEY_ORIGIN=http://auth.example.com  # HTTP not allowed
```

---

## 12. Security Checklist

### Pre-Production Checklist

- [ ] Generate unique `SECRET_KEY` and `JWT_SECRET_KEY`
- [ ] Set `DEBUG=false` and `APP_ENV=production`
- [ ] Configure password policy (min 12 chars recommended)
- [ ] Set up HTTPS with valid SSL certificate
- [ ] Configure rate limiting appropriately for traffic
- [ ] Set up audit log retention policy
- [ ] Enable security notifications (email configured)
- [ ] Review and customize security alert email templates
- [ ] Configure OAuth clients with HTTPS redirect URIs only
- [ ] Test MFA enrollment and recovery codes
- [ ] Verify Passkey configuration (if used)
- [ ] Set appropriate token expiration times
- [ ] Configure firewall rules (only 80, 443, 22)
- [ ] Set up fail2ban for SSH and HTTP
- [ ] Enable unattended security updates
- [ ] Configure backup encryption
- [ ] Document incident response procedures
- [ ] Test account lockout and recovery procedures

### Ongoing Security Tasks

**Weekly**:
- Review audit logs for suspicious activity
- Check rate limit violations

**Monthly**:
- Review user permissions and roles
- Audit OAuth client configurations
- Check for expired/unused API keys
- Review security alert patterns

**Quarterly**:
- Update dependencies (`pip list --outdated`)
- Review and test backup restoration
- Audit admin account access

**Annually**:
- Rotate `SECRET_KEY` and `JWT_SECRET_KEY`
- Rotate OAuth client secrets
- Security penetration testing
- Review and update password policies
- Audit log retention cleanup

---

## 13. Incident Response

### Suspected Key Compromise

1. **Immediately rotate keys**:
   ```bash
   # Generate new keys
   NEW_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
   NEW_JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")

   # Update .env
   sed -i "s/SECRET_KEY=.*/SECRET_KEY=$NEW_SECRET/" .env
   sed -i "s/JWT_SECRET_KEY=.*/JWT_SECRET_KEY=$NEW_JWT_SECRET/" .env

   # Restart service
   docker restart authglow
   ```

2. **Invalidate all sessions**: All users must re-authenticate
3. **Review audit logs** for unauthorized access
4. **Notify affected users** if data was accessed

### Suspected Account Compromise

1. **Lock the account**:
   ```bash
   # Via admin panel or directly edit user file
   # Set locked_until to far future date
   ```

2. **Review audit logs** for the user
3. **Contact user** via verified channel (not email)
4. **Force password reset** upon verification
5. **Enable MFA** before re-enabling account

### Brute Force Attack

1. **Check rate limiting** is active
2. **Review fail2ban rules**
3. **Analyze audit logs** for attack patterns
4. **Block attacker IPs** at firewall level:
   ```bash
   sudo ufw deny from 1.2.3.4
   ```
5. **Consider lowering rate limits** temporarily

---

## 14. Security Resources

### Recommended Reading

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/sp800-63b.html)

### Security Tools

- **Dependency scanning**: `pip-audit`, Snyk, Dependabot
- **Secret detection**: GitGuardian, TruffleHog
- **Penetration testing**: OWASP ZAP, Burp Suite
- **Log analysis**: ELK Stack, Splunk, Graylog

### Compliance Frameworks

If your deployment needs to meet compliance standards:

- **GDPR**: Enable audit logging, data export, right-to-delete
- **SOC 2**: Implement comprehensive logging, access controls
- **HIPAA**: Encrypt at rest/in transit, audit trails, BAA agreements
- **PCI-DSS**: For payment-related services

---

## Next Steps

- **[Production Deployment](./10-production-deployment.md)**: Secure deployment setup
- **[Email Configuration](./09-email-configuration.md)**: Configure security notifications
- **[Protecting Your APIs](./12-protecting-apis.md)**: Secure your resource servers
