# Audit Logging — AuthGlow

## Overview

AuthGlow implements a comprehensive, structured audit logging system designed for security monitoring, compliance, and operational visibility. The system follows OAuth2/OIDC compliance requirements and security best practices.

## Architecture

### Write-Only Design

The `AuditService` is **write-only** — it emits structured JSON to stdout via `structlog`. The application never reads audit logs back. Analysis, search, and retention are handled by the cloud platform (AWS CloudWatch, GCP Cloud Logging, Azure Monitor, Loki, Elasticsearch, etc.).

### Log Format

Each audit entry is a JSON object with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `event_type` | string | Enum from `AuditEventType` (e.g., `login_success`, `access_token_issued`) |
| `event_category` | string | Category: `auth`, `oauth2`, `admin`, `security`, `lifecycle`, `mfa`, `federation`, `api_key` |
| `user_id` | string | UUID of the user (optional) |
| `email` | string | User email (masked/hashed per config) |
| `session_id` | string | Session ID for correlation |
| `client_id` | string | OAuth2 client ID |
| `correlation_id` | string | Cross-request correlation (e.g., auth_code → token) |
| `ip_address` | string | Client IP (truncated to /24 for IPv4, /48 for IPv6) |
| `user_agent` | string | User agent (truncated to 256 chars) |
| `timestamp` | string | ISO 8601 UTC |
| `severity` | string | `info`, `warning`, `error`, `critical` |
| `request_id` | string | Correlation ID from middleware |
| `metadata` | object | Typed, structured metadata per event type |

### Example Log Entry

```json
{
  "event_type": "access_token_issued",
  "event_category": "oauth2",
  "user_id": "user_abc123",
  "email": "a1b2c3d4...",
  "client_id": "client_xyz",
  "correlation_id": "auth_code_123",
  "ip_address": "192.168.1.0/24",
  "user_agent": "Mozilla/5.0...",
  "timestamp": "2026-09-06T12:34:56.789Z",
  "severity": "info",
  "request_id": "req_abc",
  "metadata": {
    "token_id": "tok_xyz",
    "grant_type": "authorization_code",
    "scopes": ["read", "write"],
    "expires_in": 1800,
    "dpop_bound": false,
    "token_type": "access"
  }
}
```

## Event Taxonomy

### Authentication & Session (`auth`)
- `login_success` — Successful authentication (password, MFA, passkey, federated, device_code)
- `login_failed` — Failed authentication attempt
- `logout` — User-initiated, admin revoke, or session expiry
- `session_created` — Post-login, refresh
- `session_revoked` — Admin revoke, user logout, security action
- `account_locked` / `account_unlocked` — Brute force, admin action

### User Lifecycle (`lifecycle`)
- `user_registered` — Self-registration, admin creation, invite acceptance
- `user_invited` — Admin invitation sent
- `email_verification_sent` / `email_verified` — Verification flow
- `email_changed` — User/admin email change
- `profile_updated` — Profile field changes
- `password_changed` / `password_reset_requested` / `password_reset_completed`
- `password_expired` — Policy enforcement
- `account_deleted` — Self-service, admin, GDPR erasure

### MFA & Passkeys (`mfa`)
- `mfa_enabled` / `mfa_disabled` — TOTP enrollment/disable
- `mfa_verified` / `mfa_failed` — MFA challenge
- `backup_codes_generated` / `backup_code_used` / `backup_code_failed`
- `passkey_registered` / `passkey_authenticated` / `passkey_deleted` — WebAuthn
- `trusted_device_added` / `trusted_device_removed` / `trusted_device_expired`

### OAuth2/OIDC Protocol (`oauth2`)
- `authorization_code_issued` — `/oauth2/authorize` consent
- `authorization_code_redeemed` — Token endpoint (grant=auth_code)
- `access_token_issued` / `access_token_refreshed` / `id_token_issued`
- `refresh_token_issued` / `refresh_token_rotated`
- `access_token_revoked` / `refresh_token_revoked` — RFC 7009
- `token_introspected` — RFC 7662
- `consent_granted` / `consent_revoked` / `consent_updated`
- `device_code_created` / `device_code_authorized` / `device_code_denied` / `device_code_expired` — RFC 8628
- `client_credentials_token_issued` — RFC 6749 §4.4

### Admin Actions (`admin`)
- `admin_user_created` / `admin_user_updated` / `admin_user_deleted`
- `admin_password_reset` — Admin set-password
- `admin_scope_assigned` / `admin_scope_removed`
- `admin_mfa_reset` — Admin MFA disable
- `admin_consent_revoked` — Admin consent revocation
- `admin_token_revoked` — Admin token revocation

### API Keys (`api_key`)
- `api_key_created` / `api_key_revoked` / `api_key_expired`

### Security & Anomaly (`security`)
- `brute_force_detected` — Rate limit exceeded
- `suspicious_activity` — Impossible travel, new device/geo
- `concurrent_session_limit_exceeded`
- `rate_limit_exceeded`

### Federation (`federation`)
- `federated_login_initiated` / `federated_login_success` / `federated_login_failed`
- `federated_account_linked` / `federated_account_unlinked`

## PII Protection

### Email Masking (`audit_email_log_level`)
- `hash` (default) — 16-char HMAC, stable per email
- `mask` — Partial masking (e.g., `jo***@ex***.com`)
- `none` — Not allowed in production (VAPT-080)

### IP Truncation
- IPv4 → `/24` (e.g., `192.168.1.0/24`)
- IPv6 → `/48` (e.g., `2001:db8::/48`)

### User-Agent Truncation
- Max 256 chars, truncated with `…[truncated]` marker

### Metadata Scanning
Recursively scans metadata for:
- Fields containing "email" → masked per `audit_email_log_level`
- Values parsing as IP → truncated
- Strings > 256 chars → truncated

## Configuration

```python
# core/config.py
audit_enabled: bool = True
audit_email_log_level: str = "hash"  # "mask", "hash", "none"
audit_sample_rate: float = 1.0  # 0.0-1.0 for high-volume events

# Retention per category (days)
audit_retention_days_auth: int = 90
audit_retention_days_oauth2: int = 90
audit_retention_days_admin: int = 365
audit_retention_days_security: int = 730
audit_retention_days_lifecycle: int = 365
audit_retention_days_mfa: int = 365
audit_retention_days_federation: int = 365
audit_retention_days_api_key: int = 365
```

## Integration

### Adding Audit to an Endpoint

```python
from authglow.models.audit_events import AuditEventType
from authglow.models.audit_metadata import TokenIssuedMetadata
from authglow.services.audit import AuditService
from fastapi import Depends

@router.post("/my-endpoint")
async def my_endpoint(
    ...,
    audit_service: AuditService = Depends(get_audit_service),
):
    await audit_service.log_event(
        event_type=AuditEventType.ACCESS_TOKEN_ISSUED,
        user_id=user.id,
        email=user.email,
        client_id=client_id,
        correlation_id=auth_code.code,
        metadata=TokenIssuedMetadata(
            token_id=access_token_id,
            client_id=client_id,
            grant_type="authorization_code",
            scopes=scopes,
            expires_in=1800,
            dpop_bound=bool(dpop_proof),
            token_type="access",
        ),
    )
```

### Request Correlation

The `request_id` is automatically propagated via `structlog.contextvars` from the `RequestIDMiddleware` (VAPT-042). For multi-request flows (e.g., authorization code → token), pass `correlation_id` explicitly.

## Deployment

### Cloud Logging Integration

The JSON stdout output is compatible with:
- **AWS CloudWatch** — CloudWatch Agent
- **GCP Cloud Logging** — Logging Agent / OTEL
- **Azure Monitor** — Log Analytics Agent
- **Loki / Grafana** — Promtail
- **Elasticsearch** — Filebeat / OTEL Collector
- **Datadog** — Datadog Agent

### Retention

Configure retention in your log platform per category:
- Auth/OAuth2: 90 days
- Admin: 365 days
- Security: 730 days
- Lifecycle/MFA/Federation/API Key: 365 days

## Security Considerations

1. **No secrets in logs** — Never log tokens, passwords, secrets. Use token IDs only.
2. **PII masking** — Default `hash` level in production (VAPT-080).
3. **Write-only** — No read/delete methods exposed (VAPT-079).
4. **Request correlation** — `request_id` from middleware for traceability.
5. **Sampling** — Configurable `audit_sample_rate` for high-volume events.
6. **Tamper-evident** — Cloud platform provides integrity.

## Testing

```bash
# Unit tests
pytest tests/unit/test_audit.py -v

# Integration tests
pytest tests/integration/test_oauth2*.py -v
```

## Compliance

| RFC / Spec | Events Covered |
|------------|----------------|
| RFC 6749 §4.1 | `authorization_code_issued`, `authorization_code_redeemed` |
| RFC 6749 §5.1 | `access_token_issued`, `refresh_token_issued` |
| RFC 6749 §6 | `access_token_refreshed`, `refresh_token_rotated` |
| RFC 7009 | `access_token_revoked`, `refresh_token_revoked` |
| RFC 7662 | `token_introspected` |
| RFC 8628 | `device_code_*` |
| OIDC Core | `id_token_issued`, `consent_*` |
| RFC 9449 | DPoP binding in metadata |

## Troubleshooting

### Missing Audit Events
1. Check `audit_enabled` config
2. Verify `audit_sample_rate` (if < 1.0)
3. Check application logs for `AuditService` errors

### PII in Logs
1. Verify `audit_email_log_level != "none"` in production
2. Check metadata scanning for email/IP patterns

### Performance
- `audit_sample_rate` reduces volume for high-throughput endpoints
- Async logging — non-blocking on request path
- Target: p99 < 10ms

## Future Enhancements

- Queryable storage backend (Elasticsearch, Loki, ClickHouse)
- Admin UI for log search and export
- Real-time alerts (webhook/email) for critical events
- SIEM integration (Splunk, Datadog, etc.)