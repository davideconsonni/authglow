# AuthGlow — Supported Flows

This directory documents every authentication/authorization flow
supported by AuthGlow: **how** it is implemented, the **standard** it
follows, and — where applicable — the **custom differences** from that
standard.

> **Language note (AGENTS.md):** the repo uses English for code and
> documentation. Files in this directory are written in English.

Each file uses the same structure:

| Section            | Content |
|--------------------|---------|
| **Standard**       | The reference RFC / specification. |
| **Actors**         | A Mermaid sequence diagram showing the parties involved. |
| **How we support it** | Endpoints involved, request/response sequence, parameters. |
| **Conformance**    | What is standard, what is stricter, what is custom. |
| **Endpoints**      | Endpoint table (method + path). |

## Flow index

| Flow | File | Standard | Main difference from the standard |
|------|------|----------|------------------------------------|
| Authorization Code + PKCE | [`authorization-code-pkce.md`](authorization-code-pkce.md) | RFC 6749 §4.1, RFC 7636 | PKCE **mandatory** for ALL clients (incl. confidential), `S256` only |
| Client Credentials | [`client-credentials.md`](client-credentials.md) | RFC 6749 §4.4 | Scopes strictly validated; supports `client_assertion` (RFC 7523) |
| Refresh Token Rotation | [`refresh-token-rotation.md`](refresh-token-rotation.md) | RFC 6749 §6, OAuth BCP | Automatic rotation + **reuse detection** (family revocation) |
| Device Authorization Grant | [`device-authorization.md`](device-authorization.md) | RFC 8628 | Approval endpoints require an authenticated user session |
| First-party browser login | [`first-party-browser-login.md`](first-party-browser-login.md) | — (NOT OAuth2) | Custom `/api/token`, httpOnly cookies, frontend-only |
| Revocation / Introspection | [`revocation-introspection.md`](revocation-introspection.md) | RFC 7009, RFC 7662 | Conformant; access-token revocation via JTI blacklist |
| OIDC UserInfo | [`oidc-userinfo.md`](oidc-userinfo.md) | OIDC Core §5.1 | Supports the `claims` request parameter (§5.5) |
| OIDC RP-Initiated Logout | [`oidc-logout.md`](oidc-logout.md) | OIDC RP-Initiated Logout 1.0 | `id_token_hint` required for redirect; front-channel via iframe |

## Cross-cutting mechanisms

| Mechanism | File | Standard |
|-----------|------|----------|
| Client authentication methods | [`client-auth-methods.md`](client-auth-methods.md) | RFC 7591 §2, RFC 7523 |
| DPoP (sender-constrained tokens) | [`dpop.md`](dpop.md) | RFC 9449 |

## Common conventions (apply to every flow)

- **UTC on concile** — no naive datetimes anywhere.
- **Token storage**: JWT access token (per-client lifetime), refresh token
  with rotation, short-lived authorization code.
- **Rate limiting** per IP (or per token) on every flow endpoint.
- **Audit logging** (structlog) on every consent/revoke/token event.
- Time-based expiry everywhere; no persistent server-side session.

---

> Primary reference: [`docs/FEATURES.md`](../FEATURES.md) — the complete
> endpoint + feature catalog.