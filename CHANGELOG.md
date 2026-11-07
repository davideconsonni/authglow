# Changelog

## [Unreleased]

### Fixed
- Concurrent writes to different records no longer serialize behind a single process-wide lock: CAS (optimistic-concurrency) writes in the file storage layer take a per-record-path lock, so refresh-token rotation, authorization-code redemption, and other record writes on different records proceed in parallel under load.
- Email-index and federated-identity lookups no longer re-read and re-parse the entire index file on every request cache miss. The file storage layer keeps one process-wide repository per index with a periodic staleness probe (configurable via `STORAGE_INDEX_REFRESH_SECONDS`, default 60, `0` disables), so the login hot path reads the whole index at most once per interval per replica instead of once per miss; write paths still merge against on-disk content, so records created by other replicas are never lost. Cross-replica visibility of new signups/federated links is now bounded by the probe interval (same trade-off already documented for the JWT keyring).
- Password-reset token issuance/verification and API-key creation/rotation no longer run bcrypt on the event loop (~200-300 ms of dead latency for every in-flight request per call). All bcrypt work now runs on a dedicated CPU-sized thread pool (one worker per core), separated from the widened default executor that serves file/network I/O, so login bursts can no longer queue record reads behind hashing jobs.
- Timing side-channel on credential endpoints (VAPT-050): a login with an unknown email and an expired-password change for an unknown account now pay a real bcrypt comparison against a throwaway dummy hash, so unknown-user responses are indistinguishable from wrong-password ones by latency. Gated by the existing `TIMING_LEAK_PROTECTION` setting (on by default).
- The JWT revocation blacklist no longer grows unboundedly on disk: entries whose token expiry has passed are now deleted by a periodic background sweep (every `TOKEN_BLACKLIST_CLEANUP_SECONDS`, default 900, `0` disables), so startup re-hydration cost stays roughly constant with deploy age. Every replica sweeps idempotently; expired entries were already ignored by in-memory checks, so no revocation window changes.

## [0.2.1] - 2026-11-05

### Fixed
- Pin Starlette <1.8.0 to resolve a breaking incompatibility between Starlette 1.10 `FileResponse` and `BaseHTTPMiddleware` (slowapi) that caused 502 Bad Gateway / crashes on SPA file routes (`/dashboard`, `/auth`, etc.).

## [0.2.0] - 2026-11-05

### Added
- AuthGlow black-box checktool console CLI (`checktool/`) for end-to-end verification against live instances.
- Extended test suites and coverage across API endpoints, admin actions, OAuth flows, and repository protocols.
- API proxy configuration support and verification tests.

### Changed
- Upgraded backend dependencies (FastAPI 0.162, Starlette 1.10, Pydantic 2.14, Pytest 9.2, Pillow 13.0, etc.) and frontend dependencies (Vite 8.3, Vitest 5.1, Radix UI primitives, React Hook Form 7.91, etc.).
- Python runtime floor raised to Python 3.13.

### Fixed
- Passkey login no longer issues tokens for deactivated accounts (401) and returns a structured suspension deadline (423) that the UI renders in local time; the same suspension payload is now shared by the password, federated, MFA and passkey flows.
- OAuth2 token endpoint now enforces the exact registered `token_endpoint_auth_method` (client_secret_basic only via HTTP Basic, client_secret_post only via form body, JWT methods only via assertion, `none` without secret; one method per request). Clients using the wrong channel now get `invalid_client` and must switch to the registered method.
- Admin user actions (suspend/unsuspend, create, delete, update, failed-attempts reset, revoke-all sessions, bulk operations) now appear in the profile Security Events tab, not just the audit log.

## [0.1.0] - 2026-09-14

First public release of AuthGlow: self-hosted identity with no database to manage (file-based storage).

### Added
- Sign-in: email+password with reset/verification, WebAuthn passkeys, TOTP + backup codes + trusted devices, phone OTP, OIDC federation (Google, Entra ID, Apple, GitHub, Keycloak, CIE/SPID).
- OAuth2/OIDC server: Authorization Code + PKCE, Client Credentials, refresh-token rotation with reuse detection, introspection, revocation, logout, PAR, Device Grant, DPoP, scoped API keys.
- Admin console: users, OAuth2 clients, sessions, consents, API keys, roles/RBAC, signing keys, audit log; per-client branding and white-labeling.
- Operations: single container (API+UI on one port), rate limiting, CSRF, security headers, HTTPS enforcement, structured audit log, OAuth Playground, demo mode.

Full details: `docs/product/reference/features.md`.
