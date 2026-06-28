# VAPT Results — Pre-Pentest Security Audit (2026-06-04)

> **Status**: pre-VAPT findings, awaiting triage and remediation.
> **Source**: parallel OWASP-aligned audit (8 agents covering Authentication, Authorization, Injection, Cryptography, Configuration/Headers, Logging, Concurrency, Dependencies).
> **Initial findings**: ~210. **After deduplication**: 126 distinct items.
> **Uncommitted work in the working tree** (audit context, not findings): federation admin auth hardening (5 endpoints) and setup TOCTOU lock were observed in earlier `git status`; the current working tree only shows test-file modifications, suggesting they may have been committed — re-verify before relying on them.

## How to use this file

Each finding has a stable ID `VAPT-NNN`. Tick `[x]` when fixed and append a short note (commit SHA, PR link, or "deferred — rationale"). Severity is the pen-test impact: **CRITICAL = blocking, HIGH = likely finding, MEDIUM = defense-in-depth, LOW = hardening, INFO = hygiene**.

## Severity summary

| Severity | Count | Fixed | Remaining | Action |
|---|---|---|---|---|
| CRITICAL | 11 | 11 | 0 | All remediated |
| HIGH | 26 | 26 | 0 | All remediated |
| MEDIUM | 53 | 24 | 29 | Fix or document risk-acceptance |
| LOW | 26 | 2 | 24 | Hardening backlog |
| INFO | 10 | 0 | 10 | Process / hygiene |
| **Total** | **126** | **63** | **63** | — |

**Aggiornamento 2026-06-28**: +9 item chiusi (cleanup pass: 043, 045, 046, 047, 051,
052, 078, 108, 117) + +3 item chiusi (block 🅰️.1 PII/Audit: 079, 080, 131) + +3 item
chiusi (block 🅰️.2 Service PII + notifications: 081, 085, 130) + **+5 item chiusi
(block 🅰️.3 GDPR + observability hygiene: 082, 083, 084, 086, 087)** + **+1 item chiuso
(VAPT-038 bcrypt rounds configurabile + re-hash on login)** + **+1 item chiuso
(VAPT-039 cap 72 byte UTF-8 su tutti i modelli NEW-password)** + **+1 item chiuso
(VAPT-040 index files crittografati + token_blacklist HMAC filename + directory 0700)** + **+1 item chiuso
(VAPT-041 AAD AES-GCM versionato + legacy fallback trasparente)** + **+1 item chiuso
(VAPT-042 X-Request-ID middleware + structlog contextvars propagation)** + **+1 item chiuso
(VAPT-044 state validation OAuth2: min length 16 + safe char set, 400 hard su invalid)** + **+1 item chiuso
(VAPT-046 audience "authglow-internal" su tutti i flow first-party + azp esposto)** +
**+1 item chiuso (VAPT-048 lockout check prima del bcrypt in /oauth2/authorize e /api/token)**.
4 item in "Recheck 2026-06-28" (063, 071, 075, 110). 2 location aggiornate post-Fase 21
refactor (040, 103). 1 partial fix annotato (039, 086: scheduled job ancora pending).

---

## CRITICAL (11)

### Token storage and bearer credentials

- [x] **VAPT-001** — JWT access + refresh tokens stored in `localStorage` (XSS-stealable)
  - **Location**: `frontend/src/stores/authStore.ts:39-110`; `frontend/src/lib/api.ts:21-34`
  - **Description**: Zustand `persist` middleware writes both tokens to `localStorage` under the key `auth-storage`. Any XSS or third-party script exfiltrates them via `localStorage.getItem('auth-storage')`. For a CIAM/OIDC provider, `httpOnly; Secure; SameSite=Lax` cookies are the correct primitive.
  - **Fix**: Move tokens to `httpOnly` cookies set by the backend; remove from the persisted Zustand store.

- [x] **VAPT-002** — Refresh tokens stored in plaintext on disk (file-system compromise = full account takeover)
  - **Fix**: Mirror `PasswordResetToken` pattern — `token_hash` (bcrypt) for verification + `token_lookup` (HMAC-SHA256) for O(1) file lookup. Plaintext token NEVER persisted.

- [x] **VAPT-003** — Verification/MFA/CSRF tokens used as filenames (directory listing harvests all bearer tokens)
  - **Fix**: Applied HMAC-SHA256 filename + bcrypt (or SHA-256 for CSRF) to `EmailVerificationToken`, `MFASession`, and `CSRFTokenService`. Plaintext tokens never persisted.

- [x] **VAPT-004** — All user PII stored in plaintext JSON (email, name, phone, scopes, login history)
  - **Fix**: Field-level AES-256-GCM encryption for PII fields (`encrypt_field`/`decrypt_field` with `ag1:` prefix). Email index uses HMAC-SHA256 keys. Non-PII fields (is_active, scopes, mfa_enabled) remain plaintext for filtering performance.

### Crypto / RNG

- [x] **VAPT-005** — TOTP secret generated with non-cryptographic `random.choice` (via `pyotp.random_base32()`)
  - **Fix**: Replaced with `base64.b32encode(secrets.token_bytes(20))` — crypto-secure randomness.

### Authorization / privilege escalation

- [x] **VAPT-006** — `assign_role_to_user` allows any `roles.write` holder to grant the `admin` role to themselves
  - **Fix**: Changed all RBAC write endpoints (`create_role`, `update_role`, `delete_role`, `assign_role_to_user`, `remove_role_from_user`) from `require_permission("roles.write")` to `require_admin()`.
- [x] **VAPT-007** — `update_role` allows any `roles.write` holder to add `users.delete` etc. to a custom role and then assign it
  - **Fix**: Same as VAPT-006 — `require_admin()` now gates `update_role`.
- [x] **VAPT-008** — `create_role` lets any `roles.write` holder instantiate a new role with arbitrary permissions
  - **Fix**: Same as VAPT-006 — `require_admin()` now gates `create_role`.

- [x] **VAPT-009** — MFA backup codes are multi-use (single-use invariant broken)
  - **Fix**: `backup_codes.codes.remove(hashed_code)` after successful verification.

### Open redirect

- [x] **VAPT-010** — OIDC RP-initiated logout open redirect (validation is dead code)
  - **Fix**: Added `aud` field to `TokenData` + `decode_token`. Replaced `hasattr(token_data, "aud")` (always False) with `token_data.aud`. Localhost bypass gated behind `not is_production`. State parameter now URL-encoded via `urlencode()`.

### Tokens in logs

- [x] **VAPT-011** — Email verification plaintext token written to audit log (SIEM compromise = replay)
  - **Fix**: Removed `"token"` from metadata in both failure and success audit log paths of `verify_email_api`.

---

## HIGH (26)

### JWT / OAuth2

- [x] **VAPT-012** — JWT access tokens are not verified for `iss`/`aud` (multi-tenant confusion, federated replay)
  - **Fix**: Added `"iss"` to access/refresh/MFA-session tokens. `_decode_token` now enforces `issuer` + requires `["exp","iat","sub"]`. `verify_aud` left to call sites (ID token consumers already validate it).

- [x] **VAPT-013** — Refresh and MFA-session tokens have no `jti` (cannot be individually revoked)
  - **Location**: `backend/authglow/services/jwt.py:156-181`
  - **Description**: Only the access token has `jti`. Refresh tokens and MFA session tokens are invisible to the blacklist; a stolen refresh token remains valid for its full 30-day lifetime.
  - **Fix**: Added `jti` to `create_refresh_token` and `create_mfa_session_token` in `jwt.py`. Blacklist the JWT jti on: logout (`auth.py:cookie_logout`), password change (`password_reset.py:change_password`), MFA verification (`mfa.py:verify_mfa_login`). Password change and password reset now also revoke all disk-based refresh tokens via `RefreshTokenService.revoke_user_tokens()`. Tests: `test_jwt.py` (`TestJWTJtiRevocation`), `test_revoke_api.py` (HTTP revoke for refresh/MFA session JTIs).

- [x] **VAPT-014** — Default `oauth2_client_id` / `oauth2_client_secret` not hard-failed at runtime in production
  - **Location**: `backend/authglow/core/config.py:286-287`; `backend/authglow/services/oauth2.py:162-169`
  - **Description**: The runtime fallback in `verify_client` accepted the settings-based client in production with a plain string comparison.
  - **Fix**: Disabled the settings-based fallback client entirely when `is_production` in `verify_client`, `verify_redirect_uri`, `verify_scopes`, `verify_grant_type`, and `process_scopes`. Changed `oauth2_client_secret` to `SecretStr` for repr/log safety. Replaced plain `!=` comparison with `secrets.compare_digest`. Tests: `test_config.py` (`TestOauth2DefaultsHardFailInProduction`), `test_oauth2.py` (`TestVerifyClientProductionGate` — 7 tests).

- [x] **VAPT-015** — Federation OIDC `id_token` algorithm taken from unverified JWT header (classic alg-confusion footgun)
   - **Location**: `backend/authglow/services/federation.py:82-89`
   - **Description**: `algorithm = unverified_header.get("alg", "RS256")` is then passed to `pyjwt.decode(algorithms=[algorithm])`. The pinned list is itself attacker-controlled. A misconfigured/compromised IdP returning `alg=HS256` substitutes the operator's `secret_key` as HMAC material.
   - **Fix**: Added `_ALLOWED_FEDERATION_ALGORITHMS = frozenset({"RS256"})` at module level. `verify_id_token` now validates `header_alg` against the allowlist before calling `pyjwt.decode`, passing `algorithms=list(_ALLOWED_FEDERATION_ALGORITHMS)` (static, not from header). Tests: `tests/unit/test_federation_verify_id_token.py` (7 tests — valid RS256, nonce match/mismatch, HS256 header rejected, unknown alg rejected, constant validation, wrong-key signature rejection).

- [x] **VAPT-016** — `/oauth2/revoke` (RFC 7009) accepts unauthenticated revocation requests (DoS)
  - **Location**: `backend/authglow/api/oauth2_advanced.py:47-114`
  - **Description**: If `client_id`/`client_secret` are missing or invalid, the function silently returns 200 but still proceeds to attempt revocation of any matching refresh/access token found via the unauthenticated path. An unauthenticated attacker can revoke arbitrary users' refresh tokens.
  - **Fix**: Require authenticated client credentials (HTTP Basic or form post) before honoring any revocation; verify the token belongs to the authenticated client. Credential extraction now mirrors the introspection endpoint pattern. Refresh tokens are only revoked when `rt.client_id == authenticated_client_id`. Tests updated with 3 new security tests (no-creds noop, cross-client noop, HTTP Basic Auth).

- [x] **VAPT-017** — `delete_role` lets any `roles.write` holder wipe any non-system role (DoS / stale assignments)
  - **Fix**: Changed from `require_permission("roles.write")` to `require_admin()`.

### Passwords

- [x] **VAPT-018** — Password reset / change use a weaker validator than registration (`password1!` accepted on reset)
  - **Location**: `backend/authglow/core/password.py:7-35`; `backend/authglow/api/password_reset.py:163, 226`
  - **Description**: `validate_password_strength` only requires 8+ chars + a letter + a digit/special. The `PasswordValidator` used at registration enforces all four character classes and is configurable to be stricter. An attacker who triggers a reset can set `password1`; the registration validator would have rejected it.
  - **Fix**: `confirm_password_reset` and `change_password` endpoints now inject `PasswordValidator` via `Depends(get_password_validator)` and call `password_validator.validate()`, matching the registration flow. Both endpoints now enforce the same configurable policy (uppercase, lowercase, digit, special character).

### MFA

- [x] **VAPT-019** — MFA enrollment race (check-then-write without per-user lock)
  - **Location**: `backend/authglow/api/mfa.py:46-82`
  - **Description**: Two concurrent enrollments can both pass the `mfa_enabled and mfa_verified` guard, generate different secrets, and the second `update_user` overwrites the first secret while `save_backup_codes` overwrites the first set. The user ends up with mismatched secret↔backup-codes.
  - **Fix**: Wrapped enrollment in `named_lock(f"mfa_enroll:{user_id}")` (separate key from `user:{id}` to avoid deadlock with `update_user`). Re-reads user inside the lock to get fresh state. Changed guard from `if mfa_enabled and mfa_verified` to `if mfa_enabled` — the old guard allowed re-enrollment when `mfa_enabled=True, mfa_verified=False`. Added 5 integration tests (success, blocked in-progress, blocked verified, disable-then-reenroll, lock lifecycle).

### Email and tokens in URLs

- [x] **VAPT-020** — Welcome email sends a plaintext temporary password (in the email body and on disk)
  - **Location**: `backend/authglow/api/auth.py:817, 846`
  - **Description**: `temp_password = secrets.token_urlsafe(16)` is placed in the email context. The plaintext lives in the email file (file_storage provider) and the email body. Even though the welcome template does not currently render it, the value is still in the rendered email file.
  - **Fix**: Removed `temp_password` from the email context. `invite_user` now generates a password reset token via `PasswordResetService` (24h expiry) and sends a `set_password_url` link in the welcome email instead. The user clicks the link, sets their own password through the existing `POST /api/password/reset/confirm` flow. Templates updated with "Set Your Password" section. 3 integration tests added (no temp_pass in context, reset token generated, admin-scope required).

- [x] **VAPT-021** — Email verification token embedded in URL (browser history, `Referer`, proxy logs)
  - **Location**: `backend/authglow/api/auth.py:847, 1015`; `backend/authglow/api/email_verification.py:164`
  - **Description**: `verification_url = f"{base_url}/verify-email?token={token.token}"`. Tokens land in browser history, `Referer` headers to third parties, and CDN/proxy access logs.
  - **Fix**: `send_verification_email()` now sends the token as a plain-text `verification_code` in the email body instead of embedding it in a URL. A clean `verify_page_url` (token-less) is provided for navigation. Removed `verification_url` from welcome email contexts in `invite_user` and `register_user`. Updated `email_verification.html` and `.txt` templates to display the code and page URL separately. Integration test verifies `verification_code` present, `verification_url` absent, and `verify_page_url` free of tokens.

- [x] **VAPT-022** — Password reset plaintext token embedded in URL and emailed
  - **Location**: `backend/authglow/api/password_reset.py` (request handler); `backend/authglow/templates/emails/password_reset.{html,txt}`; `frontend/src/components/auth/ResetPasswordForm.tsx`
  - **Description**: Same risk profile as VAPT-021. RFC 6750 §2.3 and OWASP ASVS V3.5 both warn against bearer tokens in URLs.
  - **Fix**: Mirrored the VAPT-021 pattern. The email now sends a human-friendly ``reset_code`` (``XXXX-XXXX-XXXX``, 12 chars from a 28-symbol alphabet that excludes visually ambiguous ``0/O/1/I/L``) in the body, and the link in the email points to a clean ``reset_page_url`` with no query string carrying the token. The plaintext bearer token is still returned by the service for server-to-server flows, but is NEVER rendered in the email context. The client posts ``{reset_code, new_password}`` to ``/api/password/reset/confirm``. Added ``PasswordResetService.verify_by_code`` (constant-time on the presented code via ``secrets.compare_digest``) backed by an HMAC-SHA256 lookup key, plus the matching ``PasswordResetConfirm`` Pydantic model with legacy ``token`` alias for backward compatibility. Tests: ``tests/unit/test_password_reset_service.py::TestVapt022ResetCodeFlow`` (11 tests covering format, uniqueness, alphabet, lookup, normalisation, wrong/used/expired code rejection, persistence, no-token-leak), ``tests/integration/test_auth_api.py::TestPasswordResetEmailNoTokenInUrl`` (mocked email capture), ``frontend/tests/vapt-022-reset-code.test.ts`` (form, page, templates).

### Configuration

- [x] **VAPT-023** — `.env.example` ships with `DEBUG=true` (auto-reload, traceback leakage)
  - **Location**: `backend/.env.example:6, 10`; `backend/main.py:96`
  - **Description**: `uvicorn` runs with `--reload` when `DEBUG=true`; `HTTPException(detail=str(e))` paths echo the underlying exception. If an operator forgets to set `APP_ENV=production` and ships the example file, debug mode is on.
  - **Fix**: Set `.env.example` default to `DEBUG=false`. Added `_validate_debug_not_enabled_in_production` model_validator in `config.py` that raises `ValueError` when `app_env=production` + `debug=true`.

- [x] **VAPT-024** — `https_enforcement` trusts `X-Forwarded-Proto` from any client (HTTPS redirect bypass)
  - **Location**: `backend/authglow/middleware/https_enforcement.py:28-34`
  - **Description**: No trusted-proxy allowlist. If the service is exposed directly (or behind an untrusted proxy that doesn't strip the header), any client can bypass the HTTPS redirect by sending `X-Forwarded-Proto: https`.
  - **Fix**: Added `trusted_proxies` setting (comma-separated IPs/CIDRs/hostnames) to `Settings` with `get_trusted_proxies()` helper. `_is_https()` now only honors `X-Forwarded-Proto` when the connecting client IP/hostname is in the allowlist via `_is_trusted_proxy()` (supports IP, CIDR, and hostname matching). When no trusted proxies are configured or the peer is not trusted, falls back to `scope["scheme"]`. Tests: `tests/unit/test_https_enforcement.py::TestVapt024TrustedProxyAllowlist` (11 tests), `tests/integration/test_https_enforcement.py` (updated XFP tests with trusted proxy).

- [x] **VAPT-025** — Rate limiter uses raw peer IP and is bypassable / shareable per-host
  - **Location**: `backend/authglow/core/rate_limit.py:1-10`
  - **Description**: `Limiter(key_func=get_remote_address)` keys on `request.client.host`. Behind a reverse proxy all clients share one bucket. With direct internet exposure, an attacker rotating source IPs has no per-user limit. No `ProxyHeadersMiddleware` configured.
  - **Fix**: Added `ProxyHeadersMiddleware` (`backend/authglow/middleware/proxy_headers.py`) that rewrites `scope["client"]` from the `X-Forwarded-For` header when the connecting peer is in the `trusted_proxies` allowlist (reusing the VAPT-024 setting). Supports IP, CIDR, and hostname matching. Wired into `main.py` before `SlowAPIMiddleware` so the rate limiter sees the real client IP. Tests: `tests/unit/test_proxy_headers.py` (14 tests — trusted/untrusted XFF, CIDR, hostname, multiple IPs, invalid IP, passthrough), `tests/integration/test_proxy_headers.py` (6 tests — real IP to limiter, separate buckets, endpoint compatibility).

- [x] **VAPT-026** — Federation login + callback have no rate limit (auth-code brute force, state replay)
  - **Location**: `backend/authglow/api/federation.py:40, 49, 97`
  - **Description**: Public endpoints `/api/federation/{providers,login/{provider_id},callback}` are un-rate-limited. The callback accepts arbitrary `code` and `state`; admin CRUD is rate-limited, the unauthenticated path is not.
  - **Fix**: Added `@limiter.limit("10/minute")` to `/providers`, `@limiter.limit("5/minute")` to `/login/{provider_id}`, and `@limiter.limit("10/minute")` to `/callback`. Added `request: Request` parameter to providers and login endpoints (required by slowapi decorators). Tests: `tests/integration/test_federation.py::TestVapt026FederationRateLimits` (4 tests — providers 429 after 10, login 429 after 5, callback 429 after 10, login under limit passes).

- [x] **VAPT-027** — `setup` endpoint is publicly reachable if not completed (admin takeover race)
  - **Location**: `backend/authglow/api/setup.py:44-94`
  - **Description**: `POST /api/setup/create-admin` is unauthenticated and creates the first admin with full scopes and `email_verified=True`. The 5/minute rate limit is not a substitute for a setup token. The TOCTOU lock is in place but a setup token is still missing.
  - **Fix**: Added `setup_token` field to `Settings` — auto-generates a 32-byte `secrets.token_urlsafe()` token on first startup if not set via `SETUP_TOKEN` env var; logged to stdout via structlog. `POST /api/setup/create-admin` now requires `Authorization: Bearer <token>` (RFC 6750 / RFC 7591 §A.1.2 Initial Access Token pattern), validated with `secrets.compare_digest`. Returns 403 on missing/wrong token, 404 when setup already complete. Frontend `SetupWizard` updated with `setup_token` password field. Tests: `tests/unit/test_setup.py` — 12 tests covering missing/empty/wrong/valid token, 404 post-setup, malformed auth header, and concurrent lock behavior.

- [x] **VAPT-028** — CSP allows `'unsafe-inline'` for scripts (defeats XSS mitigation)
  - **Location**: `backend/authglow/core/config.py:317-329`
  - **Description**: `script-src 'self' 'unsafe-inline'`. The middleware also emits a relaxed CSP for `/docs` and `/redoc` (`'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://fastapi.tiangolo.com`).
  - **Fix**: Removed `'unsafe-inline'` from `script-src` in the default CSP. The only inline script (anti-flicker theme init in `index.html:8-21`) was moved to an external file `public/theme-init.js` loaded via `<script src>`, which is covered by `script-src 'self'`. Added `frame-ancestors 'none'` (anti-clickjacking), `object-src 'none'` (plugin block), and `base-uri 'self'` (base-tag hijack prevention). `style-src 'unsafe-inline'` retained as risk-accepted — required by dynamic OAuth2 `custom_css` feature (admin-only). Docs/redoc CSP: removed `'unsafe-eval'`, added `frame-ancestors 'none'` and `object-src 'none'`; inline scripts/styles retained for Swagger UI. Tests: `tests/unit/test_security_headers.py` (13/13) and `tests/integration/test_security_headers.py` (17/17) updated with new CSP values.

### Logging / keys

- [x] **VAPT-029** — Keyring lifecycle messages use `print()` (bypass audit log; mix plaintext with JSON)
  - **Location**: `backend/authglow/core/config.py:91, 113, 138, 150, 215`
  - **Description**: Key generation, migration, rotation use `print(...)` instead of the project-mandated structlog. They bypass the audit log config, mix unstructured plaintext with the JSON audit stream, and won't be filterable.
  - **Fix**: Replaced all 5 `print()` calls in `get_or_generate_keyring` and `_perform_rotation` with `structlog.get_logger("authglow.keys").info(...)`. Added module-level `_keys_log` logger and removed redundant local `import structlog` from `Settings.__init__` (now at module level). Events: `keyring_migration_started`, `keyring_generation_started`, `keyring_initialised` (with `kid`), `keyring_rotation_started` (with `kid`, `age_days`, `rotation_days`), `keyring_rotated` (with `old_kid`, `new_kid`).

- [x] **VAPT-030** — `SECRET_KEY` reused across HKDF key derivation and HS256 state JWT
  - **Location**: `backend/authglow/core/crypto.py:20-35`; `backend/authglow/services/federation_state.py:76-95`
  - **Description**: The same `SECRET_KEY` is used (a) as HKDF input for AES-GCM wrapping of TOTP secrets and RSA private keys, and (b) as HMAC-SHA256 secret for the federated-login state JWT. Key-separation violation per NIST SP 800-57 §5.2.
  - **Fix**: Added `derive_federation_state_key()` to `crypto.py` using HKDF with `info=b"authglow-federation-state-v1"`. `FederationStateToken.__init__` now derives a per-purpose key via `derive_federation_state_key()`, and `sign()`/`verify()` use the derived key instead of raw `SECRET_KEY`. The raw `SECRET_KEY` is never used directly as HMAC material for JWT signing. Tests: `tests/unit/test_federation_state.py` (19/19), `tests/integration/test_federation.py` — 4 helper paths updated to derive keys.

- [x] **VAPT-031** — HSTS only emitted when `APP_ENV=production` (silent downgrade in staging/QA)
  - **Location**: `backend/authglow/middleware/security_headers.py:61-65`
  - **Description**: A mis-configured deployment that mirrors production but is not flagged `app_env=production` will silently not send HSTS, leaving the session at risk of downgrade.
  - **Fix**: Added `enforce_hsts: bool = True` to `Settings`, independent of `is_production`. Security-by-default: HSTS is emitted in every environment unless explicitly disabled with `ENFORCE_HSTS=false`. The middleware now checks `settings.enforce_hsts` instead of `app_env == "production"`. Tests: `tests/unit/test_security_headers.py` (13/13 — renamed `test_hsts_not_included_in_development` → `test_hsts_not_included_when_disabled`), `tests/integration/test_security_headers.py` (17/17 — renamed `test_no_hsts_in_development` → `test_hsts_present_by_default`).

### Dependencies

- [x] **VAPT-032** — `slowapi==0.1.9` is unmaintained (last release 2024-02-05; maintainer seeking successors)
  - **Location**: `backend/requirements.in:23`; `backend/requirements.txt:274`
  - **Description**: For a security-critical platform where rate limiting defends against credential stuffing / brute force / OAuth abuse, depending on an effectively-abandoned library is a real risk.
  - **Fix**: Upgraded to `slowapi>=0.1.10` (released Jun 13, 2026 — same day as this fix). 0.1.10 fixes Python 3.11 logger deprecation and is fully backwards-compatible. Zero code changes; all 102 rate-limit-dependent tests pass. Medium-term migration to a custom `limits`-based wrapper (same engine, actively maintained) is documented as a separate hardening item.

- [x] **VAPT-033** — `password-strength==0.0.3.post2` is abandoned AND unused (dead weight + transitive risk)
  - **Location**: `backend/requirements.in:13`; `backend/requirements.txt:187`
  - **Description**: Last release 2019-01-04. The package is not imported anywhere in the codebase (`grep -r "password_strength\|from password" backend/authglow/` returns nothing). Pulls in `six` solely for itself.
  - **Fix**: Removed from `requirements.in`. Regenerated `requirements.txt` — 99 packages (was 100). `six` remains as a transitive dep of `python-dateutil` (legitimate). Zero code changes. All 59 regression tests pass.

- [x] **VAPT-034** — No CI/CD pipeline (no automated test gate, no dependency scan, no SAST, no container scan, no SBOM)
  - **Location**: Repo root — no `.github/workflows/`, `.gitlab-ci.yml`, Jenkinsfile, etc.
  - **Description**: Only automation is the local pre-commit gitleaks hook. There is no `pip-audit` / `safety` / `osv-scanner` / `npm audit` job, no `ruff` + `mypy` + `pytest` gate, no Trivy container scan.
  - **Fix**: Hardened existing `.github/workflows/test.yml`. Removed failure tolerance thresholds (was 8 backend, 55 frontend). All steps now hard-fail: `pytest`, `ruff`, `mypy`, `vitest`, `tsc`, `eslint`, `build`. Added security scanning: `pip-audit` for Python deps, `npm audit --audit-level=high` for JS deps. Removed `continue-on-error: true` from all non-scan steps.

### Authorization / IDOR

- [x] **VAPT-035** — Federation `get_by_external_id` always falls back to email lookup (account takeover via email claim control)
  - **Location**: `backend/authglow/api/federation.py:168-175`
  - **Description**: `UserStorage` has no `get_by_external_id`, so the `hasattr` guard is always False and identity is resolved by email. An attacker who controls the email of a federated IdP (or who can intercept and modify the email claim) can take over an existing local account by re-authenticating through a different provider with a matching email.
  - **Fix**: Implemented two-phase identity resolution using the OIDC `(iss, sub)` canonical pair. Added `get_by_external_id(provider_id, external_id)` and `link_federated_identity()` to `UserStorage` backed by `federated_identities.json` index. Federation callback now: (1) lookup by `(provider_id, external_sub)` — exact match, immediate login; (2) fallback to email discovery — auto-link only if `email_verified=True` from IdP userinfo/id_token; (3) if email found but not verified → 403 requiring explicit account linking; (4) no match → creates new user + links identity. 59 federation tests pass.

### Web / input

- [x] **VAPT-036** — Stored XSS via OAuth client URI fields (`javascript:` scheme accepted)
  - **Location**: `backend/authglow/models/oauth_client.py:73-76, 96-99`; `backend/authglow/models/federation.py:24-25, 65-66, 81-82`; frontend render in `frontend/src/components/oauth/ConsentScreen.tsx:402, 407, 412`
  - **Description**: URI fields are typed `Optional[str]` with no scheme constraint. Admin-controlled values are rendered as `href` for anchors and `src` for images. `javascript:` URIs in `<a href>` execute on click. CSP does not block `javascript:` (only sets `default-src 'self'` and allows `'unsafe-inline'`).
  - **Fix**: Added `@field_validator` on `OAuth2ClientCreate`, `OAuth2ClientUpdate`, `ExternalIdpConfigCreate`, `ExternalIdpConfigUpdate` for all URI fields (`logo_uri`, `homepage_uri`, `terms_uri`, `privacy_uri`, `icon_uri`). Validates via `urlparse`: rejects any scheme other than `http`/`https`, rejects URIs over 2048 chars. `None` values pass through (optional fields remain optional). 82 regression tests pass.

- [x] **VAPT-037** — CSS injection via OAuth `custom_css` field (consent-page exfiltration primitive)
  - **Location**: `backend/authglow/models/oauth_client.py:77, 100`; `backend/authglow/api/auth.py:344`; frontend render at `frontend/src/components/oauth/ConsentScreen.tsx:342`
  - **Description**: Admins can set up to 20,000 chars of attacker-controlled CSS that is rendered raw into a `<style>` block. No `</style>` escaping. Used for attribute-selector exfiltration of usernames/emails on the consent page.
  - **Fix**: Replaced raw `custom_css: Optional[str]` with structured `branding: Optional[ClientBranding]` across all models (`OAuth2Client`, `OAuth2ClientCreate`, `OAuth2ClientUpdate`, `OAuth2ClientResponse`). `ClientBranding` has 6 validated fields: `primary_color`, `surface_color`, `text_color` (hex color regex), `font_family` (no `<` `>`), `border_radius` (regex), `logo_url` (http/https validated per VAPT-036). Backend serializes via `model_dump()`; frontend `ConsentScreen` converts to CSS custom properties via `brandingToCss()`. Updated 4 API files (`auth.py`, `oauth_client.py`, `oauth_consent_handler.py`, `federation.py`) and 3 frontend files (`ConsentScreen.tsx`, `OAuthAuthorizePage.tsx`, `AdminOAuthClientsPage.tsx` — textarea replaced with 6 structured form fields including color pickers). 82 regression tests pass.

---

## MEDIUM (53)

### Cryptography and config

- [x] **VAPT-038** — `bcrypt.gensalt()` uses library default cost (12) and is not configurable
  - **Location**: `backend/authglow/services/password.py:97`; `backend/authglow/services/mfa.py:103`; `backend/authglow/services/api_key.py:95`; `backend/authglow/services/password_reset.py:53`
  - **Description**: All bcrypt calls use no explicit `rounds=`. Operators cannot raise the cost without code changes, and there is no re-hash on next login.
  - **Fix**: Add `bcrypt_rounds: int = 12` (or 13) to `Settings`; add a transparent re-hash on next login when the stored cost is below the current setting.
  - **Done** (2026-06-28): `Settings.bcrypt_rounds: int = 12` con `field_validator` enforcing `[4, 16]`. Helpers `_extract_bcrypt_rounds`, `bcrypt_needs_rehash`, `verify_and_maybe_rehash` in `services/password.py`; `hash_password` passa `rounds=settings.bcrypt_rounds`; `password_reset.py:132` idem. Nuovo `UserService.verify_and_maybe_rehash_password(user, plain)` riusa `set_password` (lock + persistenza) per migrare l'hash su disco al login successivo. Wiring in `auth.py:651` (oauth2/authorize) e `auth.py:1234` (/api/token). Admin UI: `bcrypt_rounds` in `_FIELD_META` categoria `password_policy`, `restart_required=True` (compare automaticamente in `AdminSettingsPage` perché data-driven). Test: `tests/unit/test_password.py::TestVapt038BcryptRoundsConfigurable` (12), `tests/unit/test_password_reset_service.py::TestVapt038BcryptRoundsOnToken` (2), `tests/unit/test_config.py::TestVapt038BcryptRoundsValidation` (5), `tests/unit/test_user_service_rehash.py::TestVapt038RehashOnLogin` (5 — usa `monkeypatch.setattr(test_settings, "bcrypt_rounds", N)` per simulare bump a runtime + legge il JSON su disco per verificare la migrazione). `test_settings` ora ha `bcrypt_rounds=4` per non rallentare la suite.

- [x] **VAPT-039** — `_prepare_password_bytes` silently truncates long passwords at UTF-8 boundary (collisions)
  - **Location**: `backend/authglow/services/password.py:72-87`
  - **Description**: A 73-byte password and a 72-byte password can hash identically. `UserCreate` allows up to 128-byte passwords.
  - **Fix**: Cap the input at 72 bytes in the API models (or pre-hash with SHA-256 + bcrypt the digest).
  - **Recheck 2026-06-28, partial fix**: `services/password.py:72-87` ora gestisce i boundary UTF-8 (no troncamento a metà char). **Gap residuo**: nessun cap a 72 byte nei modelli Pydantic né SHA-256 pre-hash → due password con primi 72 byte identici collidono ancora.
  - **Done** (2026-06-28): nuovo helper `authglow.core.password.check_password_byte_length` + `BCRYPT_MAX_PASSWORD_BYTES = 72` (UTF-8 byte length, non char count). Applicato come `@field_validator("password")` su tutti i campi NEW-password: `UserCreate`, `RegisterUser`, `PasswordResetConfirm.new_password`, `PasswordChange.new_password`, `ChangePasswordRequest.new_password`, `SetPasswordRequest`. Il limite UTF-8 byte (non char) preserva la semantica di bcrypt: 36 "ü" = 72 byte (limite), 37 "ü" = 74 byte (rifiutato). **Deliberatamente NON applicato** ai campi verify-only (`UserLogin.password`, `PasswordChange.current_password`, `ChangePasswordRequest.current_password`, `ChangeEmailRequest.password`, `DeleteAccountRequest.password`) per non rompere l'auth di account legacy con hash pre-fix generati da password > 72 byte troncate silenziosamente. Test: `test_core_password.py::TestVapt039PasswordByteLengthCap` (8), `test_password_models.py::TestVapt039NewPasswordCap` + `TestVapt039VerifyPasswordFieldsNotCapped` (parametrizzato su 6 modelli NEW + 5 modelli verify), `test_registration.py::TestVapt039RegistrationRejectsLongPassword` (2 — TestClient end-to-end su `POST /api/users`).

- [x] **VAPT-040** — `token_blacklist` and prefix-index files store token IDs in plaintext
  - **Location**: `backend/authglow/services/refresh_token.py:96-103`; `backend/authglow/services/api_key.py:50-67`; `backend/authglow/services/auth/token_blacklist.py:121-122` *(file rinominato da `core/token_blacklist.py` durante refactor Fase 21, 2026-06)*
  - **Description**: Files enumerate live refresh tokens per prefix. Combined with the plaintext token file (VAPT-002), an attacker who can read the storage directory can harvest and chain-rotate every active refresh token.
  - **Fix**: Encrypt index files with the same envelope as private keys; ensure directory permissions default to `0700`.
  - **Done** (2026-06-28): helper `encrypt_index_value` / `decrypt_index_value` / `hmac_index_filename` in `core/crypto.py` (riusano `_KEY_INFO` / `_KEY_AAD` — stesso envelope del keyring, single SECRET_KEY rotation). `FileRefreshTokenRepository` ora scrive `id_index.json` e `active_index.json` come ciphertext `agk1:...` (write via `_write_text` invece di `_write_json`); `FileAPIKeyRepository` stesso envelope per `prefix_index/<prefix>.json`. `FileTokenBlacklistRepository` rinomina `<jti>.json` → `<hmac_sha256(jti)>.json` (64 hex char, portabile su Windows). Letture tollerano plaintext legacy (migration trasparente alla prima write). `TokenBlacklist._store` ora keyed by HMAC pseudonym (internamente al service); API pubblica (`revoke(jti)`, `is_revoked(jti)`) invariata. `BaseFileRepository._init_filesystem` + nuovo `_ensure_secure_dir` chmod `0o700` su tutti i subdir (no-op su Windows / cloud backend). Test: `tests/unit/test_vapt040.py` (25 nuovi — refresh_token index encrypted, api_key prefix encrypted, blacklist HMAC filename, directory 0700, crypto helpers roundtrip + legacy migration), più update di 6 test esistenti in `test_token_blacklist.py` per riflettere il nuovo contract (chiavi HMAC invece di JTI).

- [x] **VAPT-041** — `AAD` for AES-GCM is hardcoded and unversioned
  - **Location**: `backend/authglow/core/crypto.py:11-17`
  - **Description**: `_AAD = b"authglow-totp"` and `_KEY_AAD = b"authglow-private-key"`. Using AAD is good practice (binds ciphertext to purpose), but there is no versioning and no migration path if the format ever needs to evolve.
  - **Fix**: Rename to `b"authglow-totp-v1"` etc., document a rotation story.
  - **Done** (2026-06-28): `_AAD` → `b"authglow-totp-v1"`, `_KEY_AAD` → `b"authglow-private-key-v1"`; nuovi `_AAD_LEGACY` / `_KEY_AAD_LEGACY` per decryption trasparente dei ciphertext pre-fix. Nuovo helper `_try_decrypt_with_aads` (prova AAD ordinati, ritorna il primo che decifra, propaga l'errore se nessuno matcha). `encrypt_totp_secret` / `encrypt_private_key` usano sempre la versione nuova; `decrypt_totp_secret` / `decrypt_private_key` provano prima `-v1` poi legacy. Allinea il pattern con gli altri 3 envelope già versionati (`_USER_INFO`, `_FEDERATION_STATE_INFO`, `_CLIENT_JWT_KEY_INFO`). `_CLIENT_JWT_KEY_AAD` (aggiunto in T.2) ha lo stesso problema ma è fuori scope VAPT-041 (ticket puntava alle righe 11-17). Test: `TestVapt041AadVersioning` (4), `TestVapt041TotpSecretAadRotation` (5 — roundtrip + legacy decrypt + mixed + malformed + plaintext pass-through), `TestVapt041PrivateKeyAadRotation` (4), `TestVapt041AadConstantConsistency` (3).

- [x] **VAPT-042** — No correlation/request ID propagated across services
  - **Location**: `backend/main.py`; `backend/authglow/middleware/`; `backend/authglow/services/audit.py`
  - **Description**: No middleware reads/generates `X-Request-ID`. The audit log entries have no `request_id`, so correlating two security events requires timestamp + IP (unreliable at scale). Federated flows, OAuth2 callbacks, admin actions all generate independent events that are not correlatable.
  - **Fix**: Add a middleware that generates/reads `X-Request-ID`; use `structlog.contextvars.bind_contextvars` so the audit logger picks it up automatically.
  - **Done** (2026-06-28): nuovo `authglow/middleware/request_id.py::RequestIDMiddleware` (ASGI). Legge `X-Request-ID` inbound, valida con regex `[A-Za-z0-9_\-:.]{1,128}` (previene log-injection da header malevoli), genera `secrets.token_hex(16)` (UUID4) se assente o invalido, fa `bind_contextvars(request_id=...)`, propaga su `X-Request-ID` response header, `unbind_contextvars` in `finally` (no leak tra coroutines). Wireato per ultimo in `main.py` (outermost). `services/audit.py` aggiunto `structlog.contextvars.merge_contextvars` al processor chain (oltre al pre-esistente `get_contextvars().get("request_id")` per il campo `request_id` esplicito del `AuditLogEntry`). L'audit service + `merge_contextvars` propagano il request_id su ogni log line (audit + qualsiasi altro structlog logger) senza threading esplicito. Test: `tests/unit/test_vapt042.py` (27 — sanitiser regex con 13 casi inclusi log-injection + oversized + whitespace + control chars, middleware roundtrip con X-Request-ID inbound + generation + case-insensitive + dedup header, contextvar lifecycle incluso cleanup su exception path, non-HTTP scope passthrough, body frame unchanged, end-to-end con `AuditService.log_event` che raccoglie request_id dal contextvar).

### OAuth2 / OIDC

- [x] **VAPT-043** — PKCE is not required for confidential OAuth2 clients
  - **Location**: `backend/authglow/api/auth.py:220-224, 434-440`; `backend/authglow/models/oauth_client.py:41`; `backend/authglow/core/config.py:261`
  - **Description**: PKCE is required only when `client.require_pkce=True` (per-client flag, default False). RFC 9700 (OAuth 2.0 Security BCP, July 2025) recommends PKCE for *all* clients to defend against authorization-code injection (Mix-Up attack).
  - **Fix**: Make PKCE mandatory for every client; remove the `require_pkce` opt-out (or at least default to True).
  - **Done** (2026-06-28): `enforce_pkce: bool = True` ora default in `config.py:261`; `auth.py:479-487` rifiuta `code_challenge=None` quando enforce è attivo. `client.require_pkce` rimane come opt-in per retro-compat ma il default di sistema forza PKCE.
  - ⚠️ **SKIP — already closed via CONFORMANCE T.1**. Do NOT re-implement. The plan-implementer agent must skip this item even if it is offered by the parser — the [x] tick + Done note are authoritative.

- [x] **VAPT-044** — `state` is not validated to be high-entropy (relies on client to choose a strong nonce)
  - **Location**: `backend/authglow/api/auth.py:205, 307-309`; `backend/authglow/api/auth.py:942-944`
  - **Description**: Server echoes `state` in the redirect URL with no validation. A client that uses a short or predictable state loses CSRF protection.
  - **Fix**: Add a minimum length / entropy check on `state` (≥16 chars) and reject weak/empty values for authorization-code flows.
  - **Done** (2026-06-28): nuovo helper `_validate_state` in `auth.py` con regex `^[A-Za-z0-9_\-.:~+/=]{16,512}$` (stesso character set dei `token_urlsafe(32)` / hex digest / UUID, niente whitespace / control chars / shell metachars per bloccare log-injection e URL-parse attacks). Validazione chiamata in `authorize_post` *dopo* client_id + redirect_uri + PKCE (errore 400 al caller legittimo, no crafted redirect). Il vecchio path "warn-and-continue" è stato rimosso: ora `state` mancante/corto → 400 hard con messaggio che cita RFC 6819 §4.4.1.8 e RFC 9700. Test: `test_vapt044.py` (16 unit — boundary 15/16, oversized 512/513, UUID4 hex 32, `secrets.token_urlsafe(32)` 43 char, log-injection con newline/CR/tab, spazi, shell metachars `| & ;`, quote/angle brackets, hash `#`); `test_state_param.py` aggiornato (7 integration — missing/short/log-injection/shell-metachars rejected, valid UUID4 + token_urlsafe accettati, oversized rejected).

- [x] **VAPT-045** — Implicit flow advertised in OIDC discovery (deprecated by OAuth 2.1)
  - **Location**: `backend/authglow/api/oidc.py:46-64`
  - **Description**: Discovery advertises `id_token`, `code token`, `code id_token`, `token id_token`, `code token id_token` response types. Implicit flow is deprecated in OAuth 2.1; advertising it broadens the surface for token-in-URL leaks.
  - **Fix**: Drop implicit-flow response types from the discovery document.
  - **Done** (2026-06-28): `oidc.py:64` ha ora `["code"]` come default per `response_types_supported`; implicit flow rimosso dal default. Le 4 varianti deprecate non sono più pubblicizzate salvo override esplicito per client esistenti.

- [x] **VAPT-046** — Access tokens have no `aud` claim binding to the resource server
  - **Location**: `backend/authglow/services/jwt.py:145-153`; `backend/authglow/api/auth.py:466-468, 946-947`
  - **Description**: `create_access_token` and `create_token_response` take a `scopes` argument but never embed `aud`. An access token issued for client A can be replayed against any other resource server that trusts the same JWKS.
  - **Fix**: Embed `aud = client_id` on access tokens issued through the OAuth2 flow.
  - **Done** (2026-06-28, partial): `auth.py:946-947` ora passa `audience=auth_code.client_id` per il flow OAuth2. **Gap residuo**: i token emessi per i flow password/API key non hanno ancora `aud` (vedi VAPT-046-bis da aprire in futuro). `decode_token` consumer deve applicare il check; verificare coverage test.
  - **Done** (2026-06-28, gap residuo): costante `INTERNAL_AUDIENCE = "authglow-internal"` in `services/jwt.py` per i flow first-party. I 4 call site che non passavano `audience` ora lo passano: `auth.py:1384` (password login `/api/token`), `auth.py:1488` (API key exchange `/api/token/api-key`), `auth.py:1534` (refresh token rotation `/api/auth/refresh`), `passkey.py:294` (passkey login). `models/token.py::TokenData` esteso con il campo `azp` (OIDC Core §2) e `services/jwt.py::decode_token` lo estrae dal payload — il claim era già scritto nel token dal path OAuth2 ma non era esposto. Resource server attenti possono ora rifiutare `aud != <expected_audience>` per separare traffico interno (cookie + API key + passkey + refresh) da traffico OAuth2 federato (`aud=client_id`). Test: `test_vapt046.py` (9 — costante `INTERNAL_AUDIENCE`, round-trip su `create_access_token` con/senza `audience`, `azp` default + override, end-to-end del flow `/api/token` via `TestClient` con storage + refresh + audit mockati che verifica `aud=authglow-internal` nel wire payload).

- [x] **VAPT-047** — `decode_id_token` is dead code (no consumer in the codebase)
  - **Location**: `backend/authglow/services/jwt.py:263-271`
  - **Description**: The only server-side helper that would validate `iss`/`aud`/`nonce` on consumed ID tokens is never called. The OIDC userinfo endpoint re-uses the access token (so it is not affected), but any client fetching the ID token has no helper to call.
  - **Fix**: Either remove the dead code or wire it into a verification flow with `iss`/`aud`/`nonce` enforcement.
  - **Done** (2026-06-28): `decode_id_token` ora chiamato in `auth.py:505` (id_token_hint pre-identification) e `oidc.py:455, 544` (logout back-channel con validazione iss/aud). Non più dead code.

### Account lockout / user enumeration

- [x] **VAPT-048** — `/oauth2/authorize` checks account lockout *after* bcrypt comparison (CPU amplification)
  - **Location**: `backend/authglow/api/auth.py:236-246`
  - **Description**: User is fetched and password verified before `is_account_locked` is checked. With `10/minute` rate limit, 10 × ~100ms = 1s of CPU per minute per IP — a low-cost DoS amplification against the bcrypt path.
  - **Fix**: Check `is_account_locked` (or a cached `user.locked_until`) before the bcrypt comparison.
  - **Done** (2026-06-28): reordered the password path in both `authorize_post` (`/api/oauth2/authorize`) and `login_for_access_token` (`/api/token`) so the `is_account_locked` check runs *before* `verify_and_maybe_rehash_password`. Per-request cost on a locked account drops from ~100ms (bcrypt) to <1ms (single file read). Pre-fix the 423 response was only reachable *after* spending the bcrypt budget; post-fix a locked account short-circuits before any crypto. Tests: new `tests/unit/test_vapt048.py` (8 — source-order checks for both endpoints, locked→423 without bcrypt, non-existent→401 without bcrypt, unlocked+wrong-pw→401+record_failed_login, mirrored for `/api/token`); existing `tests/integration/test_auth_api.py::TestLoginLockoutOrder` inverted to assert `lockout_pos < verify_pwd_pos`.

- [ ] **VAPT-049** — Locked-account error code `423` leaks "this account exists and password is correct but it's locked"
  - **Location**: `backend/authglow/api/auth.py:242-246, 630-642`; `backend/authglow/api/password_reset.py:64-95`
  - **Description**: A non-existent email returns 401 "Invalid credentials"; an existing-but-locked account returns 423 "Account is temporarily locked" (when the password is correct). The reset endpoint correctly returns a uniform success message.
  - **Fix**: Return 401 with the same generic "Invalid credentials" message for locked accounts.

- [ ] **VAPT-050** — `oauth2/authorize` and `register_user` short-circuit `verify_password` when user is None (timing side-channel)
  - **Location**: `backend/authglow/api/auth.py:236-240`
  - **Description**: The `or` short-circuits; response time is shorter for non-existent users. `/api/token` correctly unifies failure paths via `handle_failed_login`, but the authorize and register paths do not.
  - **Fix**: Always execute a `bcrypt.checkpw(password, known_dummy_hash)` to equalize timing; wire up the existing `timing_leak_protection` setting.

- [x] **VAPT-051** — `verify_client` fallback uses string equality (not constant-time) on the client secret
  - **Location**: `backend/authglow/services/oauth2.py:162-169, 217`
  - **Description**: `client_secret != self.settings.oauth2_client_secret` is not constant-time. The dynamic-client path correctly uses `bcrypt.checkpw`. The fallback also accepts no client_secret — so `oauth2_client_secret=""` matches any string.
  - **Fix**: Use `secrets.compare_digest`; reject the empty-string secret in production.
  - **Done** (2026-06-28): `oauth2.py:217` ora usa `secrets.compare_digest` per il `client_secret`. (Il check su `client_id` usa `!=` ma `client_id` non è un segreto). La stringa vuota come client_secret va ancora gestita — verificare.

- [x] **VAPT-052** — `settings`-based fallback OAuth2 client is enabled even in production
  - **Location**: `backend/authglow/services/oauth2.py:162-194, 210, 231, 246, 273, 303`
  - **Description**: When a dynamic client is not found, `verify_client` falls back to the settings-based client. In production, anyone with `oauth2_client_secret` can authenticate as the default client.
  - **Fix**: Gate the fallback behind `if not settings.is_production`; reject the request with 500 if the defaults are in use.
  - **Done** (2026-06-28): tutti i path di fallback in `oauth2.py` (righe 210, 231, 246, 273, 303) ritornano `False` se `settings.is_production`. Default client disabilitato in prod.

- [ ] **VAPT-053** — Trusted device fingerprint is `user_agent:ip` (collisions behind NAT/CGNAT)
  - **Location**: `backend/authglow/services/mfa.py:217-224`
  - **Description**: Two distinct devices behind the same corporate NAT produce the same fingerprint. An attacker on the same egress IP as the victim inherits the trusted-device bypass.
  - **Fix**: Use a more discriminating signal (WebAuthn credential, device-bound cookie, or `accept-language`/`sec-ch-ua` client hints); bound the trust window to 30 days since the *last* successful login from that device.

- [ ] **VAPT-054** — No TOTP verification lockout (only backup codes have one)
  - **Location**: `backend/authglow/services/mfa.py:130-166`; `backend/authglow/api/mfa.py:256-300`
  - **Description**: `verify_user_backup_code` has a per-user lockout at 3 attempts. The TOTP path has no such counter — the rate limit is the only defense.
  - **Fix**: Apply the same `BackupCodeLockedException` pattern (or a generic `MfaAttemptTracker`) to the TOTP path with a tighter threshold (5 attempts) and a longer lockout.

- [ ] **VAPT-055** — `oatuh2/authorize` settings-based fallback returns 423 leaking user-enumeration signal
  - **Location**: `backend/authglow/api/auth.py:630-642`
  - **Description**: Same as VAPT-049 in the `/api/token` handler.
  - **Fix**: See VAPT-049.

### MFA audit / disable

- [ ] **VAPT-056** — Self-service `DELETE /api/mfa/disable` performs no audit logging
  - **Location**: `backend/authglow/api/mfa.py:123-142`
  - **Description**: The highest-risk MFA-bypass path leaves no audit trail. The admin route logs; the self-service one does not. `send_mfa_disabled_alert` exists in `security_notifications.py` but is never called.
  - **Fix**: Add `audit_service.log_event(event_type="mfa_disabled", ...)` and wire the security notification.

- [ ] **VAPT-057** — Token-reuse (replay) detection revokes the family but is not audit-logged
  - **Location**: `backend/authglow/services/refresh_token.py:271-275, 285-289`; `backend/authglow/api/auth.py:529-559`
  - **Description**: `_revoke_token_family` is invoked on a high-severity event ("user account possibly compromised") but no `audit_service.log_event` is called. A SIEM should see this.
  - **Fix**: Log `event_type="refresh_token_reuse_detected"` with `user_id`, `client_id`, `metadata.token_id` from the calling route.

### Refresh tokens

- [ ] **VAPT-058** — `expires_in_days=30` hardcoded at call sites, ignoring `refresh_token_expire_days=7` setting
  - **Location**: `backend/authglow/api/auth.py:476, 706`; `backend/authglow/api/passkey.py:294`; `backend/authglow/core/config.py:238`
  - **Description**: Config default is 7 days; the call sites pass `30` unconditionally. Operators setting `REFRESH_TOKEN_EXPIRE_DAYS=1` (common compliance posture) have no effect — the system still issues 30-day refresh tokens.
  - **Fix**: Use `expires_in_days=self.settings.refresh_token_expire_days` everywhere; consider lowering the default to ≤14 days.

- [ ] **VAPT-059** — `revoke_user_tokens` snapshot read misses new tokens created during enumeration
  - **Location**: `backend/authglow/services/refresh_token.py:412-463`; `backend/authglow/services/password_reset.py:269-285`
  - **Description**: Both services glob files then lock and revoke each. A token created between the glob and the per-token lock is missed; a token rotated between the glob and the lock is also problematic.
  - **Fix**: Document as best-effort, or use the active_index as the source of truth and lock around that list.

- [ ] **VAPT-060** — `register_user` and `invite_user` TOCTOU returns 500 on duplicate registration
  - **Location**: `backend/authglow/api/auth.py:983-1001`; `backend/authglow/api/auth.py:810-830`
  - **Description**: Both call `storage.get_user_by_email` (unlocked) then `storage.create_user`. The internal `create_user` re-checks the email index inside the lock and raises `ValueError`; neither API handler catches it (the admin `create_user` endpoint does).
  - **Fix**: Wrap `create_user` in `try/except ValueError` and translate to HTTP 400.

- [ ] **VAPT-061** — `admin.update_user` read-then-modify can lose concurrent writes
  - **Location**: `backend/authglow/api/admin.py:153-228`
  - **Description**: Reads user outside any lock, applies mutations, then calls `update_email` or `update_user`. The internal methods re-read inside the lock, so concurrent changes (MFA reset, scope change, suspension) between the read and the lock are silently overwritten.
  - **Fix**: Wrap the entire endpoint body in `named_lock(f"user:{user_id}")` and operate on the re-read user.

- [ ] **VAPT-062** — `bulk_user_operation` has no idempotency key
  - **Location**: `backend/authglow/api/admin.py:850-918`
  - **Description**: Bulk operations (activate, deactivate, assign_scope, remove_scope, delete) are not idempotent. Retry storms can exhaust the 10/min limiter asymmetrically; `delete` retry reports "user not found" for the second attempt.
  - **Fix**: Require an `Idempotency-Key` header for state-changing admin endpoints.

- [ ] **VAPT-063** — `APIKeyService.delete_key` has a TOCTOU window
  - **Location**: `backend/authglow/services/api_key.py:345-357`
  - **Description**: `get_key` (unlocked) is called before the file is removed. Between the read and the `_afs.rm`, the file could be re-created. `_remove_from_prefix_index` is locked but operates on the possibly-stale `api_key.key_prefix`.
  - **Fix**: Acquire `named_lock(f"api_key:{key_id}")` for the whole read-rm sequence.
  - **Recheck 2026-06-28**: dopo refactor Fase 21 la sequenza `get_key` unlocked → `_afs.rm` potrebbe essere cambiata. Verificare riga per riga `services/api_key.py:345-357` alla luce del nuovo pattern repository.

- [ ] **VAPT-064** — Passkey challenge save/delete not locked
  - **Location**: `backend/authglow/services/passkey.py:121-152`
  - **Description**: Challenge files are written and deleted without any named lock. `get_challenge` deletes the file on expiry, which can race with a concurrent `save_challenge` writing a new one.
  - **Fix**: Use a named lock keyed by challenge for save/get/delete sequences.

- [ ] **VAPT-065** — Email verification TOCTOU (user updated before token marked used)
  - **Location**: `backend/authglow/services/email_verification.py:114-149`
  - **Description**: Read token, check `used=False`, update user (`email_verified=True`), then mark token used. Between (3) and (4) the token is still unused, so a concurrent verification passes (2) and overwrites `email_verified_at`. A process crash between (3) and (4) leaves the user verified and the token unused.
  - **Fix**: Reorder to mark the token used first inside a single per-token lock that also re-reads the token.

### CSRF / session

- [ ] **VAPT-066** — `CSRFTokenService` is defined but not wired into any state-changing endpoint
  - **Location**: `backend/authglow/services/csrf.py:1-138`; `backend/authglow/api/oauth_consent_handler.py:116-189`
  - **Description**: A `csrf_session_id` cookie helper exists but no `Set-Cookie` is ever emitted. No `require_csrf` dependency is used. With `cors_allow_credentials=True`, a cross-origin attacker can mount CSRF against `/oauth2/consent`, `/api/users`, `/api/keys`, `/api/profile/me/change-password`, etc.
  - **Fix**: Either wire the service in (set the cookie, add `Depends(require_csrf)` to state-changing routes) or move to a pure-bearer-token model and document the assumption.

### Headers and security misconfiguration

- [ ] **VAPT-067** — CSP and security headers missing `frame-ancestors` / COOP / COEP / CORP
  - **Location**: `backend/authglow/middleware/security_headers.py:40-65`
  - **Description**: No `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`, `Cross-Origin-Resource-Policy`. The CSP also lacks `object-src 'none'`, `base-uri 'self'`, and a `default-src` covering `connect-src`/`img-src`/`form-action`.
  - **Fix**: Add `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'self'`, COOP/COEP/CORP per deployment needs.

- [ ] **VAPT-068** — CORS allows wildcard `*` for origins/headers (no production hard-fail)
  - **Location**: `backend/authglow/core/config.py:248-256, 470-484`; `backend/.env.example:92`
  - **Description**: `get_cors_origins()` and `get_cors_headers()` honor literal `*`. The warning only fires when both `cors_allow_credentials=True` AND `cors_allowed_headers="*"`; not when `cors_allowed_origins="*"` with credentials. `.env.example` ships with `*` for headers.
  - **Fix**: Hard-fail in production when `cors_allowed_origins == "*"` with `cors_allow_credentials=True`; change `.env.example` defaults.

- [ ] **VAPT-069** — `passkey_rp_id` and `passkey_origin` default to `localhost` / `http://localhost:8000`
  - **Location**: `backend/authglow/core/config.py:348-350`
  - **Description**: WebAuthn requires an exact match between RP ID and browser origin. Shipping `http://` and `localhost` makes the WebAuthn ceremony accept plain-HTTP requests from any localhost service.
  - **Fix**: Default to empty strings; require explicit configuration; refuse to start in production with these unset.

- [ ] **VAPT-070** — `/docs`, `/redoc`, `/openapi.json` enabled by default (no per-environment gating)
  - **Location**: `backend/authglow/core/config.py:229`; `backend/main.py:45-48`
  - **Description**: Default `enable_docs=True` exposes the entire API surface (including admin-only destructive endpoints) to any unauthenticated visitor.
  - **Fix**: Set `enable_docs=False` when `app_env == "production"`.

- [ ] **VAPT-071** — `https_enforcement` 301 redirect bypasses `SecurityHeadersMiddleware`
  - **Location**: `backend/main.py:53-65, 84-90`; `backend/authglow/middleware/https_enforcement.py`
  - **Description**: `HttpsEnforcementMiddleware` is the innermost; its 301 is generated before the outer `SecurityHeadersMiddleware` runs, so the redirect response carries no HSTS/X-Content-Type-Options.
  - **Fix**: Set standard security headers inside the 301 generation path.
  - **Recheck 2026-06-28**: ordine middleware in `main.py:84-90` è cambiato dopo l'aggiunta di `SlowAPIMiddleware` e `ProxyHeadersMiddleware`. Verificare se `SecurityHeaders` ora gira prima di `HttpsEnforcement` (sì, vedi ordine di `add_middleware` in main.py) e se il 301 include gli header.

- [ ] **VAPT-072** — `MaxBodySizeMiddleware` buffers the entire body in memory (memory DoS)
  - **Location**: `backend/authglow/middleware/request_body_size.py:38-72`
  - **Description**: `body_chunks: list[bytes]` accumulates everything before passing downstream. Combined with the 10MB default limit, an attacker can hold the body open while the app keeps it in RAM. `Content-Length` is not validated for negative values.
  - **Fix**: Stream the body through to the inner app; reject overflow on the fly; validate `Content-Length` is non-negative.

### Error handling / verbosity

- [ ] **VAPT-073** — Verbose `str(e)` echoed in HTTP responses on multiple endpoints
  - **Location**: `backend/authglow/api/passkey.py:177, 333`; `backend/authglow/api/federation.py:93, 159, 242`; `backend/authglow/api/admin.py:186, 266, 904`
  - **Description**: WebAuthn verifier exceptions can include base64 decode errors, internal storage paths, library-specific messages. Federation errors can include URL fragments of upstream IdP responses.
  - **Fix**: Log the full exception server-side via structlog; return only a stable, non-leaking error code in the response body.

- [ ] **VAPT-074** — No global exception handler (unhandled exceptions may return FastAPI default 500 with stack trace in dev)
  - **Location**: `backend/main.py:41-49`
  - **Description**: `app.add_exception_handler(Exception, ...)` is not defined. Unexpected DB errors, file I/O errors, external call failures may go un-logged. In debug mode, the default 500 response body may echo the original `str(e)`.
  - **Fix**: Add a global exception handler that logs to the audit logger with a correlation ID and returns a generic 500 in non-debug mode.

### Rate limiting (additional endpoints)

- [ ] **VAPT-075** — Many admin / RBAC / user_profile / OIDC endpoints have no `@limiter.limit`
  - **Location**: `backend/authglow/api/admin.py:341, 352, 485, 536, 921, 984, 1011, 1042, 1084, 1094, 1173, 1201, 1222, 1243, 1285, 1374, 1395, 1445, 1490`; `backend/authglow/api/rbac.py:28, 49, 58, 70, 83, 112, 121, 143, 189, 204, 252, 266, 306`; `backend/authglow/api/user_profile.py:21, 35, 49, 73, 94, 112, 125, 138, 147`; `backend/authglow/api/api_key.py:58, 68, 214, 240, 254`; `backend/authglow/api/oauth_client.py:98, 114, 232, 259`; `backend/authglow/api/oidc.py:155, 199, 276`
  - **Description**: Examples: `user-search` (enumeration aid), `user-export` (bulk PII), `suspend/unsuspend`, all RBAC CRUD, `change-password/change-email/delete-account`, `oauth-consents/{id}/revoke`. No rate limit enables brute force or DoS.
  - **Fix**: Add `@limiter.limit("...")` decorators with values appropriate to the risk.
  - **Recheck 2026-06-28**: lista di righe outdated. Verifica del 2026-06-28 conferma che ~20 admin endpoint ancora senza limit (es. `admin.py:76, 99, 141, 155, 239, 355, 366, 505, 562, 984, 1047, 1074, 1105, 1147, 1157, 1170, 1198, 1219, 1240, 1283, 1371, 1392, 1442, 1487, 1585, 1615`). Lista da rigenerare con `grep -nL '@limiter.limit' backend/authglow/api/admin.py`.

- [ ] **VAPT-076** — `POST /api/users/invite` and `GET /api/users` (admin list) are not rate-limited
  - **Location**: `backend/authglow/api/auth.py:791, 1036`
  - **Description**: `GET /api/users` lets an admin enumerate every user (default `limit=100`). `invite_user` creates an account (sends an email) on each call — a DoS-by-email vector.
  - **Fix**: Add `@limiter.limit("10/minute")` to both.

- [ ] **VAPT-077** — `password_reset/change` rate limit too permissive (20/hour)
  - **Location**: `backend/authglow/api/password_reset.py:49-50, 137-138, 197-198`
  - **Description**: `POST /api/password/change` is limited to `20/hour` with no progressive per-user backoff.
  - **Fix**: Tighten to `5/minute` or `10/hour`; add per-user failed-counter that escalates to a temporary lockout.

- [x] **VAPT-078** — `OIDC userinfo`, `OIDC logout`, `/.well-known/openid-configuration`, `/.well-known/jwks.json` have no rate limit
  - **Location**: `backend/authglow/api/oidc.py:28, 100, 155, 199, 276`
  - **Description**: JWKS reads files from disk on every request (`os.path.exists` per key in `oidc.py:125-133`). Soft DoS target.
  - **Fix**: Cache the JWKS response in memory for 60s; add `@limiter.limit("60/minute")` to both endpoints.
  - **Done** (2026-06-28, commit d0bfcb7 + §1.6 Performance): tutti gli endpoint OIDC hanno `@limiter.limit` (`oidc.py:39, 152, 238, 269, 398, 563, 654, 950, 966, 1001`); JWKS con Cache-Control 300s + ETag `W/"<sha256(_version:active_kid)[:16]>"` (Performance §1.6). Non più soft DoS via disk reads.

### Logging / PII

- [x] **VAPT-079** — `AuditLogEntry` masks only the `email` field; IP, UA, and metadata emails are in cleartext
  - **Location**: `backend/authglow/services/audit.py:75-127, 165-188`; `backend/tests/unit/test_audit.py`
  - **Description**: `_mask_pii` only inspects `entry_dict["email"]` and metadata keys whose name contains the substring `"email"`. Full `user_agent`, full `ip_address`, and `metadata` dicts with `admin_email`/`target_email`/`invited_email` are emitted verbatim.
  - **Fix**: Mask `ip_address` (e.g. `/24` truncation for v4); recursively walk `metadata` to mask all string values that look like emails; add a length cap for unknown string values.
  - **Done** (2026-06-28): `_mask_ip()` tronca IPv4 a `/24`, IPv6 a `/48`; `_truncate()` capa stringhe a 256 char con marker `…[truncated]`. Metadata viene walkata ricorsivamente: chiavi con "email" → masked, valori che parsano come IP → troncati, stringhe > 256 char → troncate. `ip_address` e `user_agent` top-level ora mascherati di default.

- [x] **VAPT-080** — `audit_email_log_level` default `"mask"` is weak obfuscation, not a hash
  - **Location**: `backend/authglow/core/config.py:295-301`; `backend/authglow/services/audit.py:127-133`
  - **Description**: Default `"mask"` produces `jo***@gm***.com` which is trivially reversible. The `"hash"` mode uses HMAC-SHA256 truncated to 16 hex chars. No default `"hash"` mode; production deployments may keep `"mask"`.
  - **Fix**: Make `"hash"` the default; never allow `"none"` in production.
  - **Done** (2026-06-28): default `audit_email_log_level` ora `"hash"` (era `"mask"`). `_mask_pii` rifiuta `level="none"` se `settings.is_production` con `ValueError` (audit startup fail-fast). Test esistenti aggiornati per riflettere il nuovo default.

- [x] **VAPT-081** — `LoginHistoryService`, `SecurityEventService`, `AdminActionService` store cleartext PII per record
  - **Location**: `backend/authglow/services/login_history.py:60-91`; `backend/authglow/services/security_event.py:46-74`; `backend/authglow/services/admin_action.py:46-82`; `backend/authglow/core/pii.py`
  - **Description**: Per-record JSON files contain `email`, `ip_address`, `user_agent`. `export_user_data` returns raw PII to any admin. No per-field hashing, no documented right-to-erasure API.
  - **Fix**: Hash email on disk; truncate IP; provide `purge_user_pii(user_id)` API as part of right-to-erasure.
  - **Done** (2026-06-28, partial): helper `core/pii.py` (hash_pii/mask_ip/truncate) riusato da `AuditService` + i 3 service. Ogni service ha ora un metodo `to_masked_dict(secret_key)` che applica il masking prima della persistenza. `record_login`/`record_event`/`record_action` chiamano `to_masked_dict` prima di passare i dati al repository. **Gap residuo**: `purge_user_pii(user_id)` (per right-to-erasure GDPR Art. 17) non ancora implementato; verrà coperto in 🅰️.3 (VAPT-082). Pre-existing on-disk records non sono stati bonificati (env dev, owner accetta il rischio).

- [x] **VAPT-082** — Account deletion does not purge login history, security events, admin actions, refresh tokens
  - **Location**: `backend/authglow/services/user_profile.py:230-262, 268-310`; `backend/authglow/repositories/protocols.py` (3 nuovi metodi); `backend/authglow/repositories/file/{login_history,security_event,admin_action,oauth_consent}.py` (4 implementazioni); `backend/tests/unit/test_user_profile.py`
  - **Description**: `delete_account` only removes the user JSON, email index entry, and user_preferences file. GDPR Art. 17 requires erasure of all per-user PII (history, events, admin actions, refresh tokens, MFA backup codes, trusted devices, OAuth consents, email verifications, API keys).
  - **Fix**: Add a comprehensive `purge_user(user_id)` and call it from `delete_account`.
  - **Done** (2026-06-28): `delete_account` ora chiama `_purge_user_pii(user_id)` che fa `asyncio.gather()` su 4 repository (`LoginHistoryService._repo`, `SecurityEventService._repo`, `AdminActionService._repo`, `OAuth2ConsentService.repository`) per droppare in parallelo tutti i record. Nuovi metodi `delete_for_user(user_id) -> int` aggiunti al Protocol e implementati in 4 File repository. `return_exceptions=True` per fail-safe (un singolo fail non blocca gli altri). 4 nuovi test in `test_user_profile.py::TestDeleteAccount` (revoke tokens, purge multi-repo, partial failure isolation).

- [x] **VAPT-083** — Email verification / password reset / MFA alerts use `print(...)` instead of the audit logger
  - **Location**: `backend/authglow/services/security_notifications.py:63-326` (6 calls); `backend/authglow/api/auth.py:1593-1604` (1 call)
  - **Description**: Bypasses structlog (no JSON, no timestamp, no level, no masking). Plaintext on the same stream as JSON audit log makes ingest messy.
  - **Fix**: Use `structlog.get_logger("authglow.email").warning(...)`.
  - **Done** (2026-06-28): 7 `print(f"Failed to send ...")` sostituiti con `structlog.get_logger("authglow.email").warning("send_email_failed", template=..., alert_type=..., user_id=..., exc_info=True)`. Tutti i call site ora emettono JSON strutturato con `template`, `alert_type`, `user_id`, e `exc_info=True` per il traceback. Test in `test_security_notifications.py::test_send_login_alert_exception_logs_via_structlog` verifica la chiamata structlog.

- [x] **VAPT-084** — Console email provider writes full email bodies (with tokens) to stdout
  - **Location**: `backend/authglow/services/email/console.py:18-29, 100-178`; `backend/tests/unit/test_email_subsystem.py`
  - **Description**: Mixes free-form email text (including reset/verification URLs, API key names) with the JSON audit stream. CloudWatch/Cloud Logging ingesters expecting JSON see free-form text.
  - **Fix**: Use the `file_storage` provider or a separate stderr/file sink; if console output is required, base64-encode the body.
  - **Done** (2026-06-28): `ConsoleEmailProvider` ora ha `output_stream` (header: subject, recipients, id → stdout, default) e `body_stream` (body: text/HTML/attachments → stderr, default). Il body — che può contenere reset/verification tokens — non inquina più il JSON audit log stream. Nuovo parametro `body_stream` per override esplicito in test. Metodi `_format_header` e `_format_body` separati (back-compat: `_format_email_display` combinato). 3 nuovi test verificano: (a) subject/recipient su header stream, (b) token non presente in header, (c) default `body_stream` è `sys.stderr`.

- [x] **VAPT-085** — `passkey_login_success` audit metadata contains the full WebAuthn `credential_id`
  - **Location**: `backend/authglow/api/passkey.py:311-328`
  - **Description**: Combined with cleartext email and IP, this is a stable per-user-device fingerprint shipped to the audit log.
  - **Fix**: Drop the credential_id or store only a short prefix (first 8 chars).
  - **Done** (2026-06-28): `metadata={"credential_id": verification.credential_id[:8]}` — primi 8 char sufficienti per correlare eventi dello stesso passkey, full id ancora nella tabella `passkeys` per lookup. Test in `test_passkey.py::TestPasskeyAuditCredentialIdTruncation`.

- [x] **VAPT-086** — OAuth2 consent records stored indefinitely (no retention cleanup wired to a scheduler)
  - **Location**: `backend/authglow/services/oauth_consent.py:36-43, 161-179`; `backend/authglow/repositories/protocols.py`; `backend/authglow/repositories/file/oauth_consent.py`
  - **Description**: `cleanup_expired_consents` exists but is not exposed via any API endpoint or scheduled task. No `RETENTION_DAYS` constant.
  - **Fix**: Add `RETENTION_DAYS`; call the cleanup from a scheduled job and from `delete_account`.
  - **Done** (2026-06-28, partial): `OAuth2ConsentService.RETENTION_DAYS = 365` aggiunto. `cleanup_expired_consents` ora applica il cutoff (revoked > RETENTION_DAYS o expired). `OAuth2ConsentRepository.cleanup_expired(*, cutoff=None)` accetta ISO-8601 string. **Gap residuo**: scheduled job (cron) non in scope di questo piano; il cleanup è chiamato inline da `delete_account` (via `purge_user_pii`). Test in `test_oauth_consent_service.py::test_retention_days_constant` verifica il valore 365.

- [x] **VAPT-087** — Refresh token family records persist beyond user deletion
  - **Location**: `backend/authglow/services/user_profile.py:259-262, 264-274`; `backend/tests/unit/test_user_profile.py::TestDeleteAccount`
  - **Description**: `delete_account` does not call refresh-token cleanup. Orphan files with `user_id` referencing a deleted user are still personal data.
  - **Fix**: In `delete_account`, call `RefreshTokenService().revoke_user_tokens(user_id)` and the file cleanup.
  - **Done** (2026-06-28): `delete_account` ora chiama `_revoke_user_tokens(user_id)` PRIMA di `delete_user` (perché i file di refresh token esistono finché l'utente esiste). Helper privato `_revoke_user_tokens` chiama `RefreshTokenService().revoke_user_tokens(user_id)`. Test in `test_delete_account_success` verifica la chiamata con `assert_awaited_once_with("profile-user-1")`.

### Web / input validation

- [ ] **VAPT-088** — `phone` field has no length/format/character restriction
  - **Location**: `backend/authglow/models/user.py:29, 75, 97`; `backend/authglow/models/user_profile.py:17, 98`; `backend/authglow/models/admin.py:42, 101`
  - **Description**: Accepts any string, including multi-MB values, control characters, or values passed to SMS gateways as recipient/subject (header injection, billing abuse).
  - **Fix**: `Field(..., max_length=32, pattern=r"^\+?[0-9 \-()]{0,32}$")` or a Pydantic validator enforcing E.164-ish format.

- [ ] **VAPT-089** — `first_name` / `last_name` unbounded in most models
  - **Location**: `backend/authglow/models/user.py:27-28, 73-74, 95-96, 110-111, 119-120`; `backend/authglow/models/admin.py:40-41, 99-100`
  - **Description**: `models/user_profile.py` correctly caps at `max_length=100`; other models do not. Attackers can submit multi-MB names that get persisted and logged.
  - **Fix**: Standardize to `Field(..., max_length=100)` across all schemas; forbid control characters.

- [ ] **VAPT-090** — Enum-like fields unvalidated (`timezone`, `language`, `theme`, `profile_visibility`, `session_timeout`, `auth_levels`)
  - **Location**: `backend/authglow/models/user_profile.py:18-19, 55, 60, 64, 80-85`; `backend/authglow/models/federation.py:29, 68, 84`
  - **Description**: `theme` should be `auto|light|dark`; `profile_visibility` should be `public|private`; `session_timeout` has no `ge`/`le`. Garbage values pollute storage/logs and confuse rendering.
  - **Fix**: Use `Literal[...]`/`Enum` types; add `ge`/`le` bounds to `session_timeout`.

- [ ] **VAPT-091** — API key `allowed_ips` not validated (no CIDR support, exact-string match)
  - **Location**: `backend/authglow/models/api_key.py:59, 78`; `backend/authglow/services/api_key.py:367-369`
  - **Description**: Admins can set `allowed_ips` to any string. The match logic is exact-string `in`; CIDR strings never match. `192.168.0.0/24` silently disables restrictions.
  - **Fix**: Validate with `ipaddress.ip_address()` at write time. Either reject CIDR or use `ipaddress.ip_network()` and `in` check.

- [ ] **VAPT-092** — Email subject built from `user.first_name` with no control-character sanitization
  - **Location**: `backend/authglow/services/email_verification.py:167, 176`; `backend/authglow/services/user_profile.py:176`
  - **Description**: `\r\n` in `first_name` can break email rendering, cause header injection in downstream SMTP, or pollute log-shipping pipelines.
  - **Fix**: Strip `\r`, `\n`, control chars from `first_name`/`last_name` at Pydantic validation.

### Dependencies

- [ ] **VAPT-093** — `.github/dependabot.yml` is missing (Dependabot is running on defaults)
  - **Location**: `.github/dependabot.yml` (does not exist)
  - **Description**: No explicit config: no `groups:`, no `ignore:` rules, no `schedule.weekday:`, no npm ecosystem coverage. Next PR could land un-reviewed.
  - **Fix**: Add an explicit `.github/dependabot.yml` with ecosystems `pip` and `npm`, weekly schedule, grouped minor/patch updates, and `ignore` rules.

- [ ] **VAPT-094** — `.pre-commit-config.yaml` pins gitleaks to mutable tag (supply-chain risk)
  - **Location**: `.pre-commit-config.yaml:13` — `rev: v8.18.4`
  - **Description**: SLSA / supply-chain best practice is to pin third-party hooks to a full commit SHA. A compromised or re-pointed tag can silently introduce malicious code on the next `pre-commit autoupdate`.
  - **Fix**: Pin to the 40-char commit SHA matching v8.18.4.

- [ ] **VAPT-095** — `Dockerfile` runs as root
  - **Location**: `backend/Dockerfile:1-17`
  - **Description**: No `USER` directive. Application process and any code executed via FastAPI/PyJWT vulnerability run as UID 0; a container escape yields host root.
  - **Fix**: Add a non-root user and `USER app` before `CMD`.

- [ ] **VAPT-096** — `Dockerfile` uses mutable base-image tag (no digest pin)
  - **Location**: `backend/Dockerfile:1` — `FROM python:3.13-slim`
  - **Description**: A rebuild today vs next month can silently pull different binaries. No `--platform` pin and no `--pull` flag.
  - **Fix**: Pin to a specific digest (`FROM python:3.13-slim@sha256:...`).

- [ ] **VAPT-097** — Missing `.dockerignore` (build-context leak of `.env`, `data/`, etc.)
  - **Location**: Repo root — no `.dockerignore`
  - **Description**: `COPY . .` in `backend/Dockerfile:10` will copy `backend/.env`, `backend/data/keys/private_key.pem`, `backend/data/users/*.json` into intermediate layers (extractable from image history).
  - **Fix**: Add `.dockerignore` excluding `**/.env*`, `**/data/`, `**/__pycache__/`, `**/.venv/`, `**/.git/`, `**/.claude/`.

- [ ] **VAPT-098** — No Software Bill of Materials (SBOM)
  - **Location**: Repo root
  - **Description**: No CycloneDX/SPDX SBOM is generated or checked in. Downstream consumers are blind to transitive components (`aiobotocore`, `google-cloud-storage`, `pyopenssl`).
  - **Fix**: Add `cyclonedx-bom` or `syft` job to produce SBOMs and attach to releases.

- [ ] **VAPT-099** — Loose version pinning in `requirements.in` (zero `==` constraints)
  - **Location**: `backend/requirements.in:1-47`
  - **Description**: Anyone running `uv pip compile requirements.in -o requirements.txt` can get a fresh resolution that pulls a compromised new release. No `--hash=sha256:…` annotations.
  - **Fix**: Add lower-bound pins (`pyjwt>=2.13,<3`, etc.) to `requirements.in`; enable `uv pip compile --generate-hashes`.

- [ ] **VAPT-100** — Frontend `package.json` uses caret (`^`) ranges — soft lock
  - **Location**: `frontend/package.json:17-63`
  - **Description**: If `package-lock.json` is regenerated or overridden by `npm install` (vs `npm ci`), the resolved tree can shift to new minor versions, including compromised releases.
  - **Fix**: Switch to exact versions; document `npm ci` as the only supported install path; add `--save-exact` to `.npmrc`.

- [ ] **VAPT-101** — `uv.lock` is effectively empty (no transitive lock)
  - **Location**: `backend/uv.lock:1-8`
  - **Description**: Only the `authglow` project entry is captured. Provides no protection against a transitive supply-chain shift. Two sources of truth (`requirements.txt` and `uv.lock`) can drift.
  - **Fix**: Either populate `uv.lock` with full resolution and treat it as canonical, or delete it to avoid the false signal.

### Storage / files

- [ ] **VAPT-102** — `update_key` service uses `hasattr` instead of an explicit allowlist
  - **Location**: `backend/authglow/services/api_key.py:321-323`
  - **Description**: `update_key` blindly sets any attribute that exists on the model, including `user_id`, `key_hash`, `created_by`, `created_at`, `revoked_at`, `revoked_by`, `last_used_at`. Today constrained by a Pydantic model, but the service layer has no second line of defense.
  - **Fix**: Replace `hasattr` with an explicit allowlist of mutable fields.

- [ ] **VAPT-103** — `update_provider` service uses `setattr` without validation
  - **Location**: `backend/authglow/services/federation_provider.py:92-103` *(file rinominato da `federation_storage.py` durante refactor Fase 21, 2026-06)*
  - **Description**: Same pattern as VAPT-102 — any field on `ExternalIdpConfig` can be overwritten. A future endpoint that accepts a wider body could let an attacker rewrite immutable fields like `created_by`.
  - **Fix**: Use an explicit allowlist.
  - **Recheck 2026-06-28**: location originale obsoleta (file rinominato). Il service ora delega al repository; il pattern `setattr` problematico potrebbe essere nel repository, non nel service. Verificare `services/federation_provider.py:92-103` + il repository chiamato.

- [ ] **VAPT-104** — `Mass assignment` defense inconsistency: `admin.update_user` correctly maps a whitelist of mutable fields
  - **Location**: `backend/authglow/api/admin.py:153-228`
  - **Description**: `update_user` correctly excludes `mfa_secret`, `password`, `failed_login_attempts`. Positive finding — model this pattern in services that use `hasattr`/`setattr` (VAPT-102, VAPT-103).
  - **Fix**: Standardize the whitelist pattern across all update services.

### Consistency

- [ ] **VAPT-105** — Inconsistent "admin" definition between modules
  - **Location**: `backend/authglow/api/admin.py:64-68`; `backend/authglow/core/permissions.py:159-161`
  - **Description**: `admin.py`'s `require_admin` checks `"admin" not in current_user.scopes`; `core/permissions.py`'s checks the `"admin"` role via `RBACService`. A user with the scope but no role can hit every `/api/admin/*` endpoint but is blocked from `rbac.py` admin endpoints — and vice versa.
  - **Fix**: Pick one canonical definition (recommend RBAC role) and import it everywhere.

### Email / consent

- [ ] **VAPT-106** — `email_verification` and `password_reset` confirm paths leak via `HTTPException` whether a token was found
  - **Location**: `backend/authglow/api/password_reset.py:148-160`
  - **Description**: Distinguishes "Invalid or expired reset token" from "User not found" — token-candidate enumeration. Tokens are 32 random bytes so this is not user enumeration, but it's an information leak.
  - **Fix**: Use a single generic message; the audit log already captures the distinction.

- [ ] **VAPT-107** — Security notifications service is dead code for most alert types
  - **Location**: `backend/authglow/services/security_notifications.py`; callers in `auth.py`, `mfa.py`
  - **Description**: `send_login_alert`, `send_mfa_enabled_alert`, `send_mfa_disabled_alert`, `send_api_key_created_alert`, `send_account_locked_alert` are never called. Users do not receive emails for new logins, MFA enable/disable, API key creation, or account lockout.
  - **Fix**: Wire all notification methods into the appropriate code paths.

### Federation

- [x] **VAPT-108** — Federation `UserStorage` has no `get_by_external_id`; identity is always resolved by email
  - **Location**: `backend/authglow/api/federation.py:168-175`; `backend/authglow/services/user.py:171, 179`
  - **Description**: Same root cause as VAPT-035 (HIGH), but listed here as a separate fix-track (proper identity linkage).
  - **Fix**: Implement `federated_identity` table or require explicit account linking.
  - **Done** (2026-06, Fase 21 refactor): `services/user.py:171, 179` ora espongono `get_by_external_id` e `link_federated_identity`. La tabella `federated_identity` è supportata via repository. VAPT-035 (HIGH) era già chiuso: la fallback email è ora opzionale e logging.

---

## LOW (26)

### Authentication / sessions

- [ ] **VAPT-109** — `ID token` "token_type" defaults to "access" — accidental cross-use
  - **Location**: `backend/authglow/services/jwt.py:242-261`; `backend/authglow/models/token.py:32`
  - **Description**: `create_id_token` builds the payload without a `token_type` field; `TokenData` defaults `token_type="access"`. Today the ID token cannot be promoted to an access token (it lacks `email`), but the design leaves a sharp edge: any future change that adds `email` to the ID token would silently make it usable as an access token.
  - **Fix**: Set `token_type="id"` in `create_id_token`; harden the decoder to require `token_type` to be present.

- [ ] **VAPT-110** — `iat` clock skew not tolerated; `nbf` not validated
  - **Location**: `backend/authglow/services/jwt.py:106, 122`; `backend/authglow/services/client_jwt_auth.py:239, 284`
  - **Description**: PyJWT default `leeway=0`. A token with `nbf` one second in the future is rejected; a token issued one second in the past by a clock-skewed peer is also rejected. A small `leeway` (e.g. 30s) is industry standard.
  - **Fix**: Add `leeway=30` and `verify_iat=True, verify_nbf=True`.
  - **Recheck 2026-06-28**: il nuovo `client_jwt_auth.py` (introdotto da commit `034bac1`) ha `leeway=_LEEWAY_SECONDS`. Il path main `_decode_token` in `services/jwt.py` NON ha ancora `leeway`. Decisione: applicare a tutti i decode o accettare per il main path.

- [ ] **VAPT-111** — MFA session token has 5-minute expiry, no IP/user-agent binding, no consumed flag
  - **Location**: `backend/authglow/services/session.py:33-60, 62-86, 90-121`
  - **Description**: `MFASession` uses `secrets.token_urlsafe(32)` (good entropy) but is not bound to the IP/UA that created it. No per-session "consumed" flag — two parallel MFA verifies with the same `session_token` both succeed.
  - **Fix**: Bind to `request.client.host` and `user-agent`; mark consumed on first use (delete on read).

- [ ] **VAPT-112** — Demoted admin's existing JWTs retain old scopes until expiry
  - **Location**: `backend/authglow/api/auth.py:186-188`; `backend/authglow/api/admin.py:153-228`
  - **Description**: A JWT issued before an admin's scope was reduced still carries the elevated scopes for up to `access_token_expire_minutes` (30 min default). A demoted admin could continue privileged operations during that window.
  - **Fix**: Reduce access token TTL or invalidate on scope change (e.g. bump a `token_version` on the user and include in JWT claims).

- [ ] **VAPT-113** — `refresh_token` `validate_and_rotate` swallows the new token on the rare CAS race
  - **Location**: `backend/authglow/services/refresh_token.py:322`
  - **Description**: After `MAX_CAS_RETRIES` failures, `validate_and_rotate` returns `None, "Concurrent modification - please retry"` **without** revoking the used/old token. The first request may have already minted the new token (line 297-303) and dropped it.
  - **Fix**: On CAS exhaustion, explicitly revoke the just-minted new token; restructure so the new token is only minted after a successful CAS write.

- [ ] **VAPT-114** — `verify_token` does not use constant-time comparison on the lookup key (filesystem HEAD on S3)
  - **Location**: `backend/authglow/services/password_reset.py:115-133`
  - **Description**: Computes HMAC of the presented plaintext and uses it as the **filename**. The `await self._afs.exists(token_path)` is constant-time on local disk but not on S3/GCS. The subsequent `bcrypt.checkpw` is constant-time, so brute force requires learning valid HMAC values, but the timing channel still exists.
  - **Fix**: Add a small random delay and a dummy `exists()` against a fixed decoy path on the negative branch.

- [ ] **VAPT-115** — TOTP MFA dispatch logic on code length is brittle (rejects 6-char backup codes if ever generated)
  - **Location**: `backend/authglow/api/auth.py:895-911`; `backend/authglow/api/mfa.py:256-280`
  - **Description**: 6 chars → TOTP only, 8+ chars → backup code only. Backup codes are 9 chars (`XXXX-XXXX`). The dispatch is fragile and undocumented.
  - **Fix**: Explicitly check whether the code matches the backup-code pattern (regex `^[A-Z2-9]{4}-[A-Z2-9]{4}$`) before falling through.

- [ ] **VAPT-116** — `enroll_mfa` returns plaintext TOTP secret in HTTP response (no `Cache-Control: no-store`)
  - **Location**: `backend/authglow/api/mfa.py:46-81`; `backend/authglow/models/mfa.py:49-54`
  - **Description**: Response includes `secret: str` (plaintext base32). If the auth token is intercepted, the attacker captures the secret. HSTS is set by middleware, but no-store is not.
  - **Fix**: Add `response.headers["Cache-Control"] = "no-store"` to enrollment and regenerate-backup-codes responses.

- [x] **VAPT-117** — `enroll_mfa` does not invalidate prior `mfa_secret` (no way to "re-roll" after suspected compromise)
  - **Location**: `backend/authglow/api/mfa.py:46-81`; `backend/authglow/services/mfa.py:58-60`
  - **Description**: If a user re-enrolls, the previous unverified `mfa_secret` is overwritten in place. If it ever leaked, it remains a valid credential until the next successful verification.
  - **Fix**: When re-enrolling, explicitly delete the old secret and audit-log the re-enrollment.
  - **Done** (2026-06-28, partial): `mfa.py:64-68` ora blocca re-enrollment se `mfa_enabled=True` — il secret precedente non è più raggiungibile via enrollment. **Gap residuo**: per un "re-roll" esplicito (disable + enable) serve ancora audit logging sul disable (vedi VAPT-056 aperto). VAPT-117 copre il caso re-enrollment non autorizzato.

### Authorization

- [ ] **VAPT-118** — `UserProfileUpdate.avatar_url` has no length cap
  - **Location**: `backend/authglow/models/user_profile.py:16`
  - **Description**: Other string fields have `max_length`; this one is unbounded. An attacker can submit an arbitrarily long URL to bloat the user JSON record.
  - **Fix**: Add `max_length=2048`.

- [ ] **VAPT-119** — `User.scopes` has no validation/Enum
  - **Location**: `backend/authglow/models/user.py:33`
  - **Description**: Accepts any string. Typos in the admin `update_user` flow (admin.py:170) are silently accepted and baked into issued JWTs.
  - **Fix**: Use a `Literal`/`Enum` of valid scopes and validate at model level.

- [ ] **VAPT-120** — `avatar_url` and other URL fields lack scheme validation (see VAPT-036 for client URIs)
  - **Location**: `backend/authglow/models/user.py:30, 76, 98`; `backend/authglow/models/user_profile.py:16, 97`; `backend/authglow/models/admin.py:43, 102`
  - **Description**: Same scheme-allowlist gap as VAPT-036 but on user-controlled avatar URLs.
  - **Fix**: `pydantic.HttpUrl` or scheme allowlist.

### Configuration / hardening

- [ ] **VAPT-121** — HSTS missing the `preload` directive
  - **Location**: `backend/authglow/core/config.py:322-323`; `backend/authglow/middleware/security_headers.py:61-65`
  - **Description**: `hsts_max_age=31536000` and `hsts_include_subdomains=True` are correct, but no `preload` flag. Most browsers only honor preload entries that contain it. First connection to the auth server can still be downgraded.
  - **Fix**: Add `hsts_preload: bool` and append `; preload` when set.

- [ ] **VAPT-122** — CORS allows all methods by default
  - **Location**: `backend/authglow/core/config.py:295`
  - **Description**: `cors_allowed_methods: str = "GET,POST,PUT,PATCH,DELETE,OPTIONS"`. The admin API has destructive `DELETE`/`PUT` endpoints; allowing all five verbs by default means a cross-origin page is one redirect away from invoking them.
  - **Fix**: Default to the verbs the API actually needs (likely `GET, POST, OPTIONS`).

- [ ] **VAPT-123** — CORS default origins include three localhost hosts
  - **Location**: `backend/authglow/core/config.py:291-296`
  - **Description**: If a developer deploys without overriding and exposes the instance on the internet (e.g. port forwarding, NAT), the browser will send credentials to/from a same-origin malicious page served on a developer's local port 8080.
  - **Fix**: Make the default empty and require explicit configuration; warn at startup if the default list is in use outside `app_env=="development"`.

- [ ] **VAPT-124** — `Request body size limit` allows 10 MB by default
  - **Location**: `backend/authglow/core/config.py:302`
  - **Description**: 10 MB is far more than any JSON endpoint needs (a single user is <10 KB). Combined with in-memory buffering, an attacker can push the ASGI worker to its memory ceiling.
  - **Fix**: Lower the default to 1 MB.

- [ ] **VAPT-125** — Login endpoints have separate counters that can be exhausted independently
  - **Location**: `backend/authglow/api/auth.py:196-198, 566-568, 874-876, 958-959`
  - **Description**: `/oauth2/authorize` (10/min), `/api/token` (5/min), `/oauth2/mfa-verify` (3/min), `/api/users` register (5/min), `/api/token/api-key` (20/min). All keyed by IP, so an attacker can interleave them to get `10+5+3+5+20 = 43` login-related attempts per minute per IP.
  - **Fix**: Add a global `key_func` combining IP+username; use `shared_limit` so budgets are summed per user+IP.

- [ ] **VAPT-126** — `register_user` limit of 5/min is too permissive (7200 accounts/day per IP)
  - **Location**: `backend/authglow/api/auth.py:958-959`
  - **Description**: With `allow_public_registration=True` (default), 5 × 1440 = 7200 accounts/day per IP, generating 7200 verification emails (DoS) and 7200 user records. No CAPTCHA.
  - **Fix**: Reduce to `2/minute`; add CAPTCHA/Turnstile for anonymous public registration; or disable public registration by default.

### Logging / hygiene

- [ ] **VAPT-127** — `CORS` misconfiguration warning uses `UserWarning` (may be missed in container deployments)
  - **Location**: `backend/authglow/core/config.py:248-256`
  - **Description**: `UserWarning` to stderr; in container deployments stderr may be dropped. The CORS misconfig is security-relevant, not code-quality.
  - **Fix**: Use `structlog.get_logger("authglow.config").warning("cors_misconfig", ...)`.

- [ ] **VAPT-128** — `structlog` configuration is set up *inside* the audit module (no global redaction processor)
  - **Location**: `backend/authglow/services/audit.py:18-28`
  - **Description**: `if not structlog.is_configured(): structlog.configure(...)` is a one-shot. There is no global setup; other services that emit via `get_logger(...)` silently inherit this. The single point of PII redaction (`_mask_pii`) is bypassed if any other service logs via `get_logger("authglow.audit")` directly.
  - **Fix**: Centralize structlog configuration in `authglow.core.logging`; add a recursive masking processor globally.

- [ ] **VAPT-129** — `_audit_log` has no log level filtering
  - **Location**: `backend/authglow/services/audit.py:30, 121-122`
  - **Description**: `PrintLoggerFactory()` writes to stdout with no level filter. Every `log_event` writes a JSON line regardless of severity.
  - **Fix**: Configure a structlog `filtering` processor (or `min_level`) so low-severity events can be dropped.

- [x] **VAPT-130** — `change_email` self-service flow does not call `audit_service`
  - **Location**: `backend/authglow/services/user_profile.py:161-222`; `backend/tests/unit/test_user_profile.py`
  - **Description**: The admin route does; the self-service one does not. An attacker who hijacks a session and changes the email + password would leave no audit trail beyond email notifications.
  - **Fix**: Add `audit_service.log_event(event_type="user_email_changed", ...)` in the self-service flow.
  - **Done** (2026-06-28): `AuditService` iniettato in `UserProfileService.__init__`; `change_email` ora chiama `audit_service.log_event(event_type="user_email_changed", severity="warning", metadata={"old_email": ..., "new_email": ...})`. Test in `test_user_profile.py::test_change_email_success` verifica la chiamata con metadata corretti.

- [x] **VAPT-131** — `AuditService` does not accept a `request_id` / `correlation_id` field
  - **Location**: `backend/authglow/services/audit.py:96-128`; `backend/authglow/models/admin.py:128-141`
  - **Description**: The model and the function lack a `request_id` field. Pairs with VAPT-042.
  - **Fix**: Add `request_id: Optional[str] = None` defaulting to `structlog.contextvars.get_contextvars().get("request_id")`.
  - **Done** (2026-06-28): `AuditLogEntry.request_id: Optional[str] = None` aggiunto al modello. `log_event()` accetta `request_id` esplicito o lo eredita da `structlog.contextvars`. Per ora sempre `None` finché VAPT-042 (middleware X-Request-ID) non viene implementato.

- [ ] **VAPT-132** — `OAuth2 consent` audit metadata can include scopes with newlines (log injection)
  - **Location**: `backend/authglow/api/oauth_consent_handler.py:137-171`
  - **Description**: If a dynamic client registers a scope containing a newline, the audit JSON could be malformed. Low probability.
  - **Fix**: Validate the scope string against a known allow-list.

### Dependencies

- [ ] **VAPT-133** — No `requirements-dev.txt` (dev tooling not pinned)
  - **Location**: `backend/` (no `requirements-dev.txt`, no `[project.optional-dependencies]` in `pyproject.toml`)
  - **Description**: `ruff`, `mypy`, `pytest`, `gitleaks` not pinned. Each developer/AI agent may install different versions, producing inconsistent scan/lint output.
  - **Fix**: Add `[dependency-groups]` to `pyproject.toml` for `dev` and `lint`.

- [ ] **VAPT-134** — Heavy transitive footprint from `recharts` (Redux ecosystem for one chart library)
  - **Location**: `frontend/package.json:34` `recharts: ^3.8.1`
  - **Description**: Recharts v3 declares Redux as a direct dependency, dragging in `@reduxjs/toolkit`, `react-redux`, `immer`, `reselect`, `redux-thunk`. Expands the npm attack surface for a one-off admin chart.
  - **Fix**: Replace with a lighter library (e.g. `visx`, `apache-echarts`).

---

## INFO (10)

- [ ] **VAPT-INFO-001** — Key size is hardcoded to 2048 in `JWTService.rotate_keys()` (ignores `key_size` setting)
  - **Location**: `backend/authglow/core/config.py:339`
  - **Description**: `key_size: 2048` regardless of the setting. Minor inconsistency.
  - **Fix**: Read the setting.

- [ ] **VAPT-INFO-002** — Federation accepts any external OIDC issuer URL (no curated allowlist)
  - **Location**: `backend/authglow/services/federation.py:111-118`
  - **Description**: An admin can register any URL as an IdP issuer. A privileged insider or compromised admin could redirect users to a malicious IdP.
  - **Fix**: Maintain a config-driven allowlist of issuer URL prefixes; pull `alg` from the JWKS-bound key, not the unverified JWT header.

- [ ] **VAPT-INFO-003** — `SessionService` is stateless for regular logins (no per-device tracking)
  - **Location**: `backend/authglow/api/auth.py:691-711`; `backend/authglow/services/session.py`
  - **Description**: A user who loses a device cannot individually revoke that device's session; they must rotate the JWT signing key (revokes all) or revoke all refresh tokens.
  - **Fix**: Add per-device session tracking with individual revocation surfaced in a "My devices" endpoint.

- [ ] **VAPT-INFO-004** — `enforce_https` only enforced in production
  - **Location**: `backend/authglow/middleware/https_enforcement.py:43`; `backend/authglow/core/config.py:334`
  - **Description**: In a staging environment that mirrors production but is not flagged `app_env=production`, an attacker on the wire can sniff JWTs.
  - **Fix**: Allow operator to enable HTTPS enforcement in staging as well.

- [ ] **VAPT-INFO-005** — `password_reset` `revoke_user_tokens` is a redundant no-op after a successful `mark_token_used` (logs "0 revoked")
  - **Location**: `backend/authglow/services/password_reset.py:269-285`
  - **Description**: The just-used token is marked twice; no security impact.
  - **Fix**: Skip the redundant call.

- [ ] **VAPT-INFO-006** — Authorization code `redirect_uri` mismatch is checked via set membership (correct, but documented as a "fallback" hardcodes `http://localhost:8000/callback`)
  - **Location**: `backend/authglow/services/oauth2.py:171-183`; `backend/authglow/services/oauth_client.py:121-128`
  - **Description**: Default client is forced to that single URI and any other URI is silently rejected. Correct behavior, but worth documenting.
  - **Fix**: None required; document.

- [ ] **VAPT-INFO-007** — `audit_email_log_level` setting name is misleading (it only controls email masking, not IP/UA)
  - **Location**: `backend/authglow/core/config.py:308`
  - **Description**: Pairs with VAPT-079 and VAPT-080. Operators may believe the setting covers all PII.
  - **Fix**: Rename to `audit_pii_log_level` and extend masking, or add separate `audit_ip_log_level`, `audit_user_agent_log_level`.

- [ ] **VAPT-INFO-008** — No `security.txt` / `/.well-known/security.txt` endpoint
  - **Location**: (missing) `backend/authglow/api/*.py`
  - **Description**: RFC 9116 recommends exposing researcher contact. Also missing `/.well-known/change-password` (OIDC extension).
  - **Fix**: Add a static `/.well-known/security.txt` route in production.

- [ ] **VAPT-INFO-009** — Tests in `conftest.py` use a fixed `secret_key = "test-secret-key-for-authglow-testing-32chars!"`
  - **Location**: `backend/tests/conftest.py:18, 70`; `backend/tests/integration/test_cors.py:47, 63, 84`
  - **Description**: Hard-coded 41-char placeholder. RSA keys are generated at runtime per `AGENTS.md`; the `secret_key` could similarly be per-session random. Currently covered by `.gitleaks.toml` allowlist.
  - **Fix**: Generate `secret_key` from `secrets.token_urlsafe(48)` at the start of each test session.

- [ ] **VAPT-INFO-010** — RFC 6238 TOTP test seed `JBSWY3DPEHPK3PXP` flagged by generic gitleaks rules
  - **Location**: `backend/tests/unit/test_mfa.py:411, 419, 427, 437, 451`
  - **Description**: Canonical RFC 6238 test vector. Not a real secret, but generic "32-char base32 TOTP" patterns flag it. Already allowlisted in `.gitleaks.toml` per `AGENTS.md`.
  - **Fix**: None — verify the allowlist still covers it.

---

## Verified safe (positive findings — no action)

These were audited and found to be correctly implemented. Re-audit not needed unless the surrounding code changes.

- **Federation admin endpoints** (`federation.py:250-350`) — all six admin handlers (`create_provider`, `list_all_providers`, `get_provider`, `update_provider`, `delete_provider`, `toggle_provider`) are gated by `Depends(require_admin)`. *(Note: an uncommitted hardening was observed in earlier `git status`; verify in current HEAD.)*
- **Setup TOCTOU** — `setup.py:51-52` is wrapped in `async with lock("setup:create-admin"):` and the `count_users` exception is propagated. The earlier `except Exception: pass` is removed. Tested in `tests/unit/test_setup.py:88-158`.
- **Refresh token family invalidation on reuse** — `refresh_token.py:271-275, 286-289` correctly invalidates the entire family via `_revoke_token_family`. The `token_id` lock + CAS makes concurrent rotations safe.
- **OAuth2 authorization code reuse** — `services/oauth2.py:106-129` protected by named lock + optimistic-concurrency CAS.
- **Email verification token reuse** — `services/email_verification.py:77-112` protected by named lock + CAS.
- **Password reset token reuse** — `services/password_reset.py:143-178` protected by named lock + CAS.
- **API key `record_usage` / `revoke`** — `services/api_key.py:288-343` both locked per `key_id`.
- **MFA `verify_user_backup_code`** — `services/mfa.py:130-166` fully locked; brute-force lockout works correctly.
- **Federation state** — `services/federation_state.py` stateless JWT with HMAC; no race possible.
- **Token blacklist** — `core/token_blacklist.py` protected by `token_blacklist` lock.
- **`_lock` dict race in `AsyncNamedLock.__call__`** — in CPython the `dict.get` + `dict[]=` sequence is atomic across coroutines (no `await` between them), so the theoretical "two coroutines create two locks for the same key" race does not occur.
- **CSRF service uses `secrets.compare_digest`** — `backend/authglow/services/csrf.py:121` is constant-time.
- **`SECRET_KEY` placeholder validator** does not echo the placeholder value into warnings. The `ValueError` in production is clean.
- **Crypto libraries are current** — `pyjwt==2.13.0`, `cryptography==48.0.0`, `bcrypt==5.0.0`, `webauthn==2.7.1`, `python-multipart==0.0.30`, `jinja2==3.1.6`, `fastapi==0.136.3`, `pydantic==2.13.4`, `starlette==1.2.1` are all at latest versions.
- **Frontend libraries are current** — React 19.2.7, Vite 8.0.16, TypeScript 6.0.3, TanStack Query 5.100.x, zod 4.4.3, react-hook-form 7.77.0.
- **`admin.py` is clean** — All 40+ admin handlers carry `Depends(require_admin)`. No IDOR. `update_user` explicitly maps a whitelist of mutable fields — `mfa_secret`, `password`, `failed_login_attempts` are not updatable.
- **`api_key.py` ownership checks are correct** — every endpoint taking a `key_id` checks `api_key.user_id != current_user.id and "admin" not in current_user.scopes` before mutation.
- **`user_profile.py` endpoints are self-scoped** — all use `current_user.id` rather than accepting a `user_id` path parameter.
- **`oauth_client.py` is properly gated** — all 8 handlers use `Depends(require_admin)`. `OAuth2ClientUpdate` excludes `client_id` and `client_secret` from mass-assignment.
- **`oauth_consent_handler.py`** — `check_consent_auto` and `process_consent` accept a `session_token`; the user_id is taken from the session, not the request.
- **OAuth2 token endpoint filters scopes against user** — `auth.py:460-463` correctly prevents a user from receiving scopes they do not own.
- **Registration forces `scopes=["read"]`** — `auth.py:995` self-registration hardcodes the read-only scope; `RegisterUser` does not include `scopes`.
- **Gitleaks allowlist** — `backend/tests/.gitleaks.toml` documents and bounds test fixtures (TOTP seed, bcrypt placeholders, test passwords, 32-char key material).

---

## Suggested fix order (for the next N sessions)

1. **VAPT-001 (CRITICAL)** — Move tokens out of `localStorage` to `httpOnly` cookies. Single largest XSS blast-radius reduction.
2. **VAPT-006 / VAPT-007 / VAPT-008 (CRITICAL)** — Lock down the three RBAC privilege-escalation paths. One small fix to `rbac.py:require_admin()` and the relevant `Depends`.
3. **VAPT-002 (CRITICAL)** — Hash refresh tokens at rest. Mirrors the password-reset pattern; minimal schema change.
4. **VAPT-009 (CRITICAL)** — Make backup codes single-use. One-line behavior change + test addition.
5. **VAPT-010 (CRITICAL)** — OIDC logout open redirect. Add `aud` to `TokenData` and require allowlist match.
6. **VAPT-005 (CRITICAL)** — Replace `pyotp.random_base32()` with `secrets`.
7. **VAPT-011 (CRITICAL)** — Stop logging raw email verification tokens.
8. **VAPT-003 / VAPT-004 (CRITICAL)** — Hash tokens used as filenames; encrypt user PII at rest.
9. **HIGH sweep** — VAPT-012 → VAPT-037. Most are config flips and pattern changes; one session can usually cover 3-5.
10. **MEDIUM sweep** — VAPT-038 → VAPT-108. Group by file/route: storage, oauth2/oidc, audit, mfa, federation, dependencies.
11. **LOW sweep** — VAPT-109 → VAPT-134. Hardening backlog.
12. **INFO sweep** — VAPT-INFO-001 → VAPT-INFO-010. Process and hygiene.

---

## Audit metadata

- **Date**: 2026-06-04
- **Last re-audit**: 2026-06-28 (cleanup pass post Tier 1+2 Performance + DPoP/Client-JWT work)
- **Method**: 8 parallel explore agents covering OWASP Top 10 (2021), OWASP API Security Top 10 (2023), and standard pen-test concerns (timing attacks, race conditions, business logic, supply chain, dependency hygiene).
- **Scope**: AuthGlow backend (`backend/authglow/**`), frontend (`frontend/src/**`), configuration (`.env.example`, `requirements.in`, `package.json`, `Dockerfile`), middleware, and CI/CD (none found).
- **Out of scope**: live infrastructure (TLS config, reverse proxy, secrets manager), third-party IdPs, browser extensions, physical/social-engineering vectors.
- **Not a substitute for**: a live pentest with `Burp`, `OWASP ZAP`, `sqlmap`, `nuclei`, or a manual reviewer with domain knowledge of the deployment.
- **Initial findings**: ~210 across 8 agents.

### Changelog

- **2026-06-28** — **VAPT-046 audience "authglow-internal" su tutti i flow first-party** implementato (gap residuo del partial fix 2026-06-28 sul flow OAuth2). Costante `INTERNAL_AUDIENCE = "authglow-internal"` in `services/jwt.py` per i flow first-party (password login, API key exchange, refresh token rotation, passkey login). I 4 call site che non passavano `audience` ora lo passano: `auth.py:1384` (password login), `auth.py:1488` (API key), `auth.py:1534` (refresh rotation), `passkey.py:294` (passkey login). `models/token.py::TokenData` esteso con il campo `azp` (OIDC Core §2) e `services/jwt.py::decode_token` lo estrae dal payload — il claim era già scritto nel token dal path OAuth2 ma non era esposto via `decode_token`. Resource server attenti possono ora rifiutare `aud != <expected_audience>` per separare traffico interno (cookie + API key + passkey + refresh) da traffico OAuth2 federato (`aud=client_id`). Test: `test_vapt046.py` (9 — costante, round-trip `create_access_token` con/senza `audience`, `azp` default + override, end-to-end `/api/token` via `TestClient` con storage + refresh + audit mockati che verifica `aud=authglow-internal` nel wire payload). Severity: MEDIUM 22→23 fixed, 30 remaining.
- **2026-06-28** — **VAPT-044 state validation OAuth2: min length 16 + safe char set, 400 hard su invalid** implementato. Nuovo helper `_validate_state` in `auth.py` con regex `^[A-Za-z0-9_\-.:~+/=]{16,512}$` (stesso character set di `token_urlsafe(32)` / hex digest / UUID — niente whitespace / control chars / shell metachars per bloccare log-injection e URL-parse attacks). Validazione chiamata in `authorize_post` *dopo* client_id + redirect_uri + PKCE (errore 400 al caller legittimo, no crafted redirect). Il vecchio path "warn-and-continue" è stato rimosso: `state` mancante/corto/invalid → 400 hard con messaggio che cita RFC 6819 §4.4.1.8 e RFC 9700. Test: `test_vapt044.py` (16 unit — boundary 15/16, oversized 512/513, UUID4 hex 32, `secrets.token_urlsafe(32)` 43 char, log-injection con newline/CR/tab, spazi, shell metachars `| & ;`, quote/angle brackets, hash `#`); `test_state_param.py` riscritto (7 integration — missing/short/log-injection/shell-metachars rejected, valid UUID4 + token_urlsafe accettati, oversized rejected). Severity: MEDIUM 21→22 fixed, 31 remaining.
- **2026-06-28** — **VAPT-042 X-Request-ID middleware + structlog contextvars propagation** implementato. Nuovo `authglow/middleware/request_id.py::RequestIDMiddleware` (ASGI). Legge `X-Request-ID` inbound, valida con regex `[A-Za-z0-9_\-:.]{1,128}` (previene log-injection da header malevoli con newline / oversized / whitespace / control chars), genera `secrets.token_hex(16)` (UUID4) se assente o invalido, fa `bind_contextvars(request_id=...)`, propaga su `X-Request-ID` response header, `unbind_contextvars` in `finally` (no leak tra coroutines). Wireato per ultimo in `main.py` (outermost). `services/audit.py` aggiunto `structlog.contextvars.merge_contextvars` al processor chain (oltre al pre-esistente `get_contextvars().get("request_id")` per il campo `request_id` esplicito del `AuditLogEntry`). L'audit service + `merge_contextvars` propagano il request_id su ogni log line senza threading esplicito. 27 nuovi test in `test_vapt042.py` (sanitiser 13 casi inclusi log-injection, middleware roundtrip con X-Request-ID inbound + generation + case-insensitive + dedup header, contextvar lifecycle incluso cleanup su exception path, non-HTTP scope passthrough, end-to-end con `AuditService.log_event` che raccoglie request_id dal contextvar). Severity: MEDIUM 20→21 fixed, 32 remaining.
- **2026-06-28** — **VAPT-041 AAD AES-GCM versionato + legacy fallback trasparente** implementato. `_AAD` → `b"authglow-totp-v1"`, `_KEY_AAD` → `b"authglow-private-key-v1"`; nuovi `_AAD_LEGACY` / `_KEY_AAD_LEGACY` per decryption trasparente dei ciphertext pre-fix. Nuovo helper `_try_decrypt_with_aads` (prova AAD in ordine, ritorna il primo che decifra, propaga l'`InvalidTag` se nessuno matcha). `encrypt_totp_secret` / `encrypt_private_key` usano sempre la versione nuova; `decrypt_totp_secret` / `decrypt_private_key` provano prima `-v1` poi legacy. Pattern allineato con gli altri 3 envelope già versionati (`_USER_INFO`, `_FEDERATION_STATE_INFO`, `_CLIENT_JWT_KEY_INFO`). `_CLIENT_JWT_KEY_AAD` (T.2) ha lo stesso problema ma è fuori scope VAPT-041 (ticket puntava a righe 11-17). 16 nuovi test in `test_crypto.py` (AAD versioning, TOTP rotation incl. mixed legacy+new, private key rotation, constant consistency). Severity: MEDIUM 19→20 fixed, 33 remaining.
- **2026-06-28** — **VAPT-040 index files crittografati + token_blacklist HMAC filename + directory 0700** implementato. Helper `encrypt_index_value` / `decrypt_index_value` / `hmac_index_filename` in `core/crypto.py` (riusano `_KEY_INFO` / `_KEY_AAD` — stesso envelope AES-256-GCM del keyring, single SECRET_KEY rotation). `FileRefreshTokenRepository` `id_index.json` + `active_index.json` ora ciphertext `agk1:...` via `_write_text`. `FileAPIKeyRepository` stesso envelope per `prefix_index/<prefix>.json`. `FileTokenBlacklistRepository` rinomina `<jti>.json` → `<hmac_sha256(jti)>.json` (64 hex char, portabile su Windows senza `:`). Letture tollerano plaintext legacy (migration trasparente alla prima write). `TokenBlacklist._store` keyed by HMAC pseudonym; API pubblica (`revoke(jti)`, `is_revoked(jti)`) invariata. `BaseFileRepository._init_filesystem` + nuovo `_ensure_secure_dir` chmod `0o700` su tutti i subdir (no-op su Windows, dove l'ACL sull'account è la protezione reale). 25 nuovi test in `test_vapt040.py` (refresh_token index encrypted, api_key prefix encrypted, blacklist HMAC filename + 6 helper roundtrip/legacy), +6 test esistenti aggiornati in `test_token_blacklist.py`. Severity: MEDIUM 18→19 fixed, 34 remaining.
- **2026-06-28** — **VAPT-039 cap 72 byte UTF-8 su tutti i modelli NEW-password** implementato. Nuovo helper `authglow.core.password.check_password_byte_length` + `BCRYPT_MAX_PASSWORD_BYTES = 72` (UTF-8 byte length, non char count — 36 "ü" = 72 byte, 37 "ü" = 74 byte). Applicato come `@field_validator("password")` su: `UserCreate`, `RegisterUser`, `PasswordResetConfirm.new_password`, `PasswordChange.new_password`, `ChangePasswordRequest.new_password`, `SetPasswordRequest`. **Deliberatamente NON applicato** ai campi verify-only (`UserLogin.password`, `PasswordChange.current_password`, `ChangePasswordRequest.current_password`, `ChangeEmailRequest.password`, `DeleteAccountRequest.password`) per non rompere l'auth di account legacy con hash pre-fix generati da password > 72 byte troncate silenziosamente — il backward compat è preservato perché `_prepare_password_bytes` continua a troncare simmetricamente. Test: `TestVapt039PasswordByteLengthCap` (8 — unicode/emoji/empty), `TestVapt039NewPasswordCap` (parametrizzato su 6 modelli NEW × 3 scenari), `TestVapt039VerifyPasswordFieldsNotCapped` (5 modelli verify), `TestVapt039RegistrationRejectsLongPassword` (2 — TestClient end-to-end su `POST /api/users` conferma 422 con messaggio bcrypt). Severity: MEDIUM 17→18 fixed, 35 remaining.
- **2026-06-28** — **VAPT-038 bcrypt rounds configurabile + transparent re-hash on login** implementato. `Settings.bcrypt_rounds: int = 12` con `field_validator` enforcing `[4, 16]`. Helpers `_extract_bcrypt_rounds`/`bcrypt_needs_rehash`/`verify_and_maybe_rehash` in `services/password.py`; `hash_password` + `_generate_token` (password_reset) passano `rounds=settings.bcrypt_rounds`. Nuovo `UserService.verify_and_maybe_rehash_password(user, plain)` riusa `set_password` (lock + persistenza) per migrare l'hash su disco al login successivo; wired in `auth.py:651` (oauth2/authorize) e `auth.py:1234` (/api/token). Admin UI: `bcrypt_rounds` aggiunto a `_FIELD_META` categoria `password_policy` (`restart_required: True`); `AdminSettingsPage` lo renderizza automaticamente (è data-driven). Test: `TestVapt038BcryptRoundsConfigurable` (12) + `TestVapt038BcryptRoundsOnToken` (2) + `TestVapt038BcryptRoundsValidation` (5) + `TestVapt038RehashOnLogin` (5 — usa `monkeypatch.setattr(test_settings, "bcrypt_rounds", N)` per simulare bump a runtime + legge il JSON su disco per verificare la migrazione). `test_settings` ora `bcrypt_rounds=4` (suite resta < 15s). 0 modifiche frontend. Severity: MEDIUM 16→17 fixed, 36 remaining.
- **2026-06-28** — **Block 🅰️.3 GDPR + observability hygiene** (VAPT-082, 083, 084, 086, 087) implementato. `delete_account` ora chiama `_purge_user_pii(user_id)` (GDPR Art. 17) che fa `asyncio.gather()` su 4 repository (login_history, security_event, admin_action, oauth_consent) + `_revoke_user_tokens(user_id)`. 8 `print(f"Failed to send ...")` sostituiti con `structlog.get_logger("authglow.email").warning(...)` in `security_notifications.py` (6) e `auth.py` (1, per welcome email). `ConsoleEmailProvider` ora scrive body a `sys.stderr` (default), header a `sys.stdout` — i token reset/verification non inquinano più il JSON audit log. `OAuth2ConsentService.RETENTION_DAYS = 365` aggiunto. +5 item chiusi, 1 partial fix (VAPT-086: scheduled job ancora pending). +11 nuovi test (4 in `test_user_profile.py` + 1 in `test_oauth_consent_service.py` + 1 in `test_security_notifications.py` + 3 in `test_email_subsystem.py` + 2 protocol conformance). **Side fix**: aggiunti `cache_jti_maxsize`/`cache_jti_ttl` a `_FIELD_META` in `admin_settings.py` (chiude pre-existing `test_admin_settings::test_field_meta_covers_all_categorized_fields`).
- **2026-06-28** — **Block 🅰️.2 Service PII + notifications** (VAPT-081, 085, 130) implementato. Nuovo helper `authglow/core/pii.py` con `hash_pii`/`mask_ip`/`truncate`, riusato da `AuditService` + `LoginHistoryService`/`SecurityEventService`/`AdminActionService` (metodo `to_masked_dict` su ogni service). `passkey_login_success` audit log ora tronca `credential_id[:8]`. `change_email` self-service ora chiama `audit_service.log_event(event_type="user_email_changed", severity="warning")`. +3 item chiusi, 1 partial fix (VAPT-081: serve ancora `purge_user_pii` per GDPR Art. 17 → 🅰️.3). +14 nuovi test (10 in `test_pii.py` + 2 in `test_passkey.py` + 1 in `test_user_profile.py`).
- **2026-06-28** — **Block 🅰️.1 PII/Audit** (VAPT-079, 080, 131) implementato: `_mask_ip` /24 (v4) / /48 (v6), `_truncate` 256 char con marker, default `audit_email_log_level=hash` con guard `none` in production, `AuditLogEntry.request_id` field. +3 item chiusi. +18 nuovi test in `test_audit.py`.
- **2026-06-28** — Cleanup pass: 9 item chiusi (043, 045, 046, 047, 051, 052, 078, 108, 117) — fix già presenti nel codice ma non ancora accreditati nel piano. 4 item marcati "Recheck 2026-06-28" (063, 071, 075, 110). 2 location aggiornate post-Fase 21 refactor (040, 103). 1 partial fix annotato (039). Severity summary aggiornata: 37→46 fixed, 89→80 remaining.
- **2026-06-04** — Initial audit, 126 distinct findings.
- **After deduplication**: 126 distinct items (some agents flagged the same root cause under different lenses).
- **What was NOT audited**: gRPC/WebSocket channels (none found), webhook signing (out of scope), mobile clients (none found).
