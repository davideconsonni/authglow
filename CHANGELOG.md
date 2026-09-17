# Changelog

## [Unreleased]

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

Full details: `docs/reference/features.md`.
