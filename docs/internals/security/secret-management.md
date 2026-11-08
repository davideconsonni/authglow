# Secret Management & Leak Prevention

This document defines the secrets policy, rotation procedures, and GitGuardian leak prevention guidelines for AuthGlow.

## Core Principle

**No real secret ever touches git history.** All credentials, keys, and tokens used in testing or development must be generated dynamically or use safe, documented placeholders.

## Security Controls in Place

- **Git Ignored Secrets**: `.env` is gitignored at the repository root.
- **Dynamic Test Keys**: RSA signing keys are generated at test runtime in `backend/tests/conftest.py:_generate_rsa_keys()` inside session-scoped temporary directories.
- **Template Configuration**: `.env.example` provides canonical templates with placeholder values only.
- **Automated Scanning**:
  - Pre-commit `gitleaks` hook (`.pre-commit-config.yaml`) prevents accidental commits containing key material.
  - Repository-level `.gitguardian.yaml` allowlists test-specific patterns to minimize false-positive alerts.

## Generating Secrets for Development

To generate cryptographically secure values for local `.env`:

```bash
# Symmetric SECRET_KEY (sessions, encrypted blobs)
python -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(48))"

# OAuth 2.0 client secret
python -c "import secrets; print('OAUTH2_CLIENT_SECRET=' + secrets.token_urlsafe(32))"
```

## Key Rotation Policy

| Secret | Rotation Frequency | Notes |
|---|---|---|
| `SECRET_KEY` | Major releases or immediately upon suspected leak | Invalidates all active sessions and encrypted blobs |
| `OAUTH2_CLIENT_SECRET` | Client request or suspected leak | Requires re-consent flow |
| JWT Signing Key | Automatic every 90 days (`jwt_auto_rotate=True`) | Multi-replica sync via keyring refresh probe |
| Email / SMS Credentials | Every 180 days or personnel changes | Configured via environment variables |

## Incident Response (Suspected Secret Leak)

1. **Immediate Revocation**: Invalidate or rotate the secret at the provider or service immediately.
2. **Rewrite History**:
   ```bash
   pip install git-filter-repo
   git filter-repo --invert-paths --path <file-or-glob>
   git push --force-with-lease
   ```
3. **Audit & Allowlist**: File a security post-mortem and update `.gitguardian.yaml` or `backend/tests/.gitleaks.toml` if caused by a false-positive heuristic.
4. **Keyring Rotation**: If a private signing key was exposed, rotate `keyring.json` and revoke compromised key IDs (`kid`).

## Writing Safe Test Fixtures

Most leak detection alerts in this repository stem from test fixtures matching generic-secret heuristics (e.g., standard RFC 6238 TOTP seed `JBSWY3DPEHPK3PXP`, mock bcrypt hashes).

When writing tests:
- **Reuse fixtures**: use `test_user`, `test_admin_user`, and `test_settings` from `backend/tests/conftest.py`.
- **Generate dynamically**: use `secrets.token_urlsafe(16)` rather than hardcoded mock strings.
- **Document exceptions**: if a test requires an explicit standard seed (e.g. RFC conformance), ensure it is allowlisted with a clarifying comment in `backend/tests/.gitleaks.toml`.

## Contributor Setup

```bash
pip install pre-commit
pre-commit install
pre-commit run gitleaks --all-files   # Initial scan
```
