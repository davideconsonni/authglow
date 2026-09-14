# Changelog

## [Unreleased]

## [0.1.0] - 2026-09-14

First public release of AuthGlow: self-hosted identity with no database to manage (file-based storage).

### Added
- Sign-in: email+password with reset/verification, WebAuthn passkeys, TOTP + backup codes + trusted devices, phone OTP, OIDC federation (Google, Entra ID, Apple, GitHub, Keycloak, CIE/SPID).
- OAuth2/OIDC server: Authorization Code + PKCE, Client Credentials, refresh-token rotation with reuse detection, introspection, revocation, logout, PAR, Device Grant, DPoP, scoped API keys.
- Admin console: users, OAuth2 clients, sessions, consents, API keys, roles/RBAC, signing keys, audit log; per-client branding and white-labeling.
- Operations: single container (API+UI on one port), rate limiting, CSRF, security headers, HTTPS enforcement, structured audit log, OAuth Playground, demo mode.

Full details: `docs/reference/features.md`.
