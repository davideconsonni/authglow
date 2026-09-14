# Changelog

## [Unreleased]

## [0.1.0] - 2026-09-14

Prima release pubblica di AuthGlow: identity self-hosted senza database (storage su file).

### Added
- Sign-in: email+password con reset/verifica, passkey WebAuthn, TOTP + backup code + trusted device, OTP telefono, federazione OIDC (Google, Entra ID, Apple, GitHub, Keycloak, CIE/SPID).
- OAuth2/OIDC server: Authorization Code + PKCE, Client Credentials, refresh rotation con reuse detection, introspection, revocation, logout, PAR, Device Grant, DPoP, API key scoped.
- Admin console: utenti, client OAuth2, sessioni, consensi, API key, ruoli/RBAC, chiavi di firma, audit log; branding per-client e white-label.
- Operations: single-container (API+UI su una porta), rate limiting, CSRF, security header, HTTPS enforcement, audit strutturato, OAuth Playground, demo mode.

Dettaglio completo: `docs/reference/features.md`.
