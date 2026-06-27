# AuthGlow — Feature Reference

> **Status**: 2026-06-27. Living document maintained as part of
> `CONFORMANCE_REMEDIATION_PLAN.md` workstream U.4.
>
> **Scope**: user-facing feature catalogue of the AuthGlow
> Identity Provider. Documents the OAuth 2.0 / OIDC Core / FAPI
> capabilities exposed to Relying Parties (client applications).

This document is the catalogue of **what client applications can
rely on**. For the security policy and threat model see
[`docs/SECURITY.md`](SECURITY.md). For FAPI 2.0 gap analysis see
[`docs/FAPI.md`](FAPI.md).

---

## 1. Supported OAuth 2.0 / OIDC Standards

| Standard                                    | Version  | Status                  |
|---------------------------------------------|----------|-------------------------|
| OAuth 2.0                                   | RFC 6749 | Compliant (no ROPC)     |
| OAuth 2.0 Authorization Server Metadata      | RFC 8414 | Compliant               |
| OIDC Core 1.0                               | Spec 1.0 | Compliant               |
| OIDC Discovery 1.0                          | Spec 1.0 | Compliant               |
| OIDC Dynamic Client Registration            | RFC 7591 | Compliant               |
| OIDC DCR Management                          | RFC 7592 | Compliant               |
| PKCE                                        | RFC 7636 | Mandatory, S256 only    |
| Token Revocation                            | RFC 7009 | Compliant               |
| Token Introspection                         | RFC 7662 | Compliant               |
| OAuth Assertion Framework                   | RFC 7521 | Compliant (T.2)         |
| JWT Profile for OAuth 2.0 Client Auth       | RFC 7523 | Compliant (T.2)         |
| Device Authorization Grant                  | RFC 8628 | Compliant (S)           |
| DPoP (sender-constrained tokens)            | RFC 9449 | Compliant, ES256 (T.3)  |
| FAPI 2.0 Security Profile                    | Part 2   | Partial — see FAPI.md   |
| OAuth 2.0 Security BCP                       | RFC 9700 | Compliant               |

---

## 2. Supported Grant Types

| Grant                                           | Token Endpoint        | Notes                                                                |
|-------------------------------------------------|-----------------------|----------------------------------------------------------------------|
| `authorization_code`                            | `/oauth2/token`       | PKCE **mandatory** (RFC 7636, S256 only).                           |
| `refresh_token`                                 | `/oauth2/token`       | Single-use rotation. Reuse detection revokes the chain (RFC 6749 §10.4). |
| `client_credentials`                            | `/oauth2/token`       | Confidential clients only. No `none` with this grant (workstream P). |
| `urn:ietf:params:oauth:grant-type:device_code` | `/oauth2/token`       | RFC 8628. Polling endpoint: `POST /oauth2/device/token`.            |

**Not supported** (rejected with HTTP 400):

- `password` (Resource Owner Password Credentials) — ROPC is
  deprecated in OAuth 2.1 and disallowed by the OAuth 2.0
  Security BCP. See `docs/SECURITY.md` for the rationale.
- `implicit` — deprecated by OAuth 2.0 Security BCP. Workstream E
  removed it.

---

## 3. Client Authentication Methods

Per `RFC 7591 §2` and FAPI 2.0 §5.2.1, the `token_endpoint_auth_method`
field on a client registration declares how the client authenticates
to the token endpoint. AuthGlow supports the following methods
(workstream T.2):

| Method                | Algorithm | Use case                                                              |
|-----------------------|-----------|-----------------------------------------------------------------------|
| `client_secret_basic` | (secret)  | Standard HTTP Basic auth. Server stores a bcrypt hash of the secret.   |
| `client_secret_post`  | (secret)  | Client secret in the form body. Same hashing as Basic.                 |
| `client_secret_jwt`   | HS256     | FAPI-aligned symmetric client auth (RFC 7523). Key is server-minted.  |
| `private_key_jwt`     | RS256     | FAPI-aligned asymmetric client auth. Public JWK registered at DCR.   |
| `none`                | —         | Public clients only. PKCE mandatory.                                   |

**Token endpoint auth method discovery** (RFC 8414):

```json
{
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "none"
  ]
}
```

### 3.1 `client_secret_jwt` (HS256, RFC 7523)

The client signs a JWT with a per-client symmetric key. The server
mints the key at client creation and shows it to the admin exactly
once. The plaintext key is never persisted; only a Fernet-encrypted
copy is stored on disk.

The JWT must include `iss`, `sub`, `aud`, `exp`, and `jti` claims.
The `aud` claim must equal the token endpoint URL
(`{issuer}/oauth2/token`). Replay protection enforces single-use
`jti` values.

### 3.2 `private_key_jwt` (RS256, RFC 7523)

The client registers a public JWK at DCR time and signs the JWT with
the matching private key. The JWK is embedded in `OAuth2Client.public_jwk`
and validated for shape (kty, n/e for RSA).

The JWT verification rules are the same as `client_secret_jwt`.

---

## 4. DPoP — Sender-Constrained Tokens (RFC 9449)

DPoP binds an access token to a key pair, so a stolen bearer token
alone is insufficient to call the resource server. The client
signs a small JWT ("DPoP proof") on every request; the server
verifies it.

**Configuration per client** (admin UI):

- `dpop_bound: bool` — opt-in flag. Default `false`.

When `dpop_bound=true`:

- The token endpoint requires a DPoP proof JWT in the `DPoP:`
  header on every request. ES256 only.
- The access token is issued with `cnf={"jkt": "<thumbprint>"}`
  (RFC 7800) and `token_type=DPoP` (instead of `Bearer`).
- The UserInfo endpoint requires a fresh DPoP proof with `ath`
  bound to the access token's SHA-256.

**DPoP proof claims** (workstream T.3):

- `htm` — HTTP method (e.g. `POST`).
- `htu` — full URL of the request target.
- `iat` — issued-at timestamp (proofs are short-lived, max 120s).
- `jti` — unique per proof; replay protection via in-process cache.
- `jwk` — public key (in JWT header).

**Discovery** (RFC 9449 §8):

```json
{
  "dpop_signing_alg_values_supported": ["ES256"]
}
```

---

## 5. OIDC ID Token Claims

The ID Token (`create_id_token` in `services/jwt.py`) supports the
following claims. All claims marked **required** are always set;
**optional** claims are only set when the corresponding scope or
parameter was supplied.

| Claim       | Required | Source                                            | Standard                  |
|-------------|:--------:|---------------------------------------------------|---------------------------|
| `iss`       | ✅       | `Settings.issuer`                                 | OIDC Core §2              |
| `sub`       | ✅       | `user_id`                                         | OIDC Core §2              |
| `aud`       | ✅       | `client_id` (or `azp` for multi-audience)         | OIDC Core §2              |
| `exp`       | ✅       | now + configurable ID token lifetime              | OIDC Core §2              |
| `iat`       | ✅       | now                                               | OIDC Core §2              |
| `auth_time` | —        | `user.last_login`                                 | OIDC Core §2              |
| `nonce`     | —        | from authorization request                        | OIDC Core §2              |
| `acr`       | —        | `services/acr.py:compute_acr` (T.2 / workstream F) | OIDC Core §2              |
| `amr`       | —        | auth methods used (`["pwd"]`, `["pwd","mfa"]`, …) | OIDC Core §2              |
| `azp`       | —        | client_id (set alongside `aud` for OAuth2 flows)   | OIDC Core §2              |
| `sid`       | —        | session id (workstream L)                         | OIDC Session Mgmt §5.1   |
| `at_hash`   | —        | left-half SHA-256 of `access_token` (workstream M) | OIDC Core §3.1.3.6        |
| `c_hash`    | —        | left-half SHA-256 of `authorization_code` (M)     | OIDC Core §3.3.2.11       |

**ACR mapping** (`services/acr.py`):

| Auth path                                | `acr` value         | `amr` value             |
|------------------------------------------|--------------------|--------------------------|
| Password only                            | `1`                | `["pwd"]`                |
| Password + TOTP / backup code            | `2`                | `["pwd", "mfa"]`         |
| Password + WebAuthn / Passkey            | `3`                | `["pwd", "mfa"]`         |
| (No authentication — `prompt=none`)      | `0`                | `[]`                     |

---

## 6. OIDC Authorization Request Parameters

The authorization endpoint (`POST /oauth2/authorize`) supports:

| Parameter          | Required (default)   | Notes                                                                       |
|--------------------|----------------------|-----------------------------------------------------------------------------|
| `response_type`    | `code` (only)        | Implicit is rejected.                                                       |
| `client_id`        | ✅                   | Must match a registered client.                                             |
| `redirect_uri`     | ✅                   | Exact match against `client.redirect_uris`. HTTPS only (localhost exception). |
| `scope`            | ✅ (typically `openid`) | Standard OIDC scopes.                                                   |
| `state`            | recommended          | Validated, persisted on `AuthorizationCode`.                                |
| `code_challenge`   | ✅ (with `S256`)     | PKCE mandatory.                                                              |
| `code_challenge_method` | `S256` (only)   | `plain` rejected.                                                            |
| `nonce`            | optional             | Echoed in ID Token.                                                         |
| `prompt`           | optional             | `none`, `login`, `consent`, `select_account` (workstream G).              |
| `max_age`          | optional             | Forces re-auth if `auth_time` is older (workstream H).                     |
| `id_token_hint`    | optional             | Pre-fills the login form (workstream I).                                    |
| `acr_values`       | optional             | Requested Authentication Context Class.                                     |
| `login_hint`       | optional             | Pre-fills the email.                                                        |
| `ui_locales`       | optional             | UI language preference.                                                     |

---

## 7. OIDC UserInfo Endpoint

`GET /oauth2/userinfo` returns the standard OIDC claims scoped to
the granted `scope`. The endpoint requires:

- **Bearer access token** in `Authorization: Bearer <token>` header.
- For **DPoP-bound tokens**: also `DPoP:` header with a fresh proof
  containing `ath` matching the token's SHA-256.

**Scopes and claims**:

| Scope        | Claims added to UserInfo                                            |
|--------------|---------------------------------------------------------------------|
| `openid`     | `sub`                                                                |
| `profile`    | `name`, `given_name`, `family_name`, `picture`, `locale`, `updated_at` |
| `email`      | `email`, `email_verified`                                            |
| `phone`      | `phone_number`, `phone_number_verified`                             |
| `address`    | `address` (RFC 5646)                                                |

---

## 8. OIDC Session Management & Logout

| Endpoint                  | Method | Notes                                                                       |
|---------------------------|--------|-----------------------------------------------------------------------------|
| `GET /oauth2/logout`      | GET    | RP-Initiated Logout. Validates `id_token_hint`, `post_logout_redirect_uri`.  |
| `POST /oauth2/logout`     | POST   | Same as GET. Required by some clients (workstream D audit logging).        |
| Front-channel logout      | —      | HTML with `<iframe>` for each `frontchannel_logout_uri` (workstream L).    |
| Back-channel logout       | —      | Endpoint stored on the client; **session tracking is deferred** (no `sid`-aware back-channel). |

**Logout parameters**:
- `id_token_hint` (recommended) — the previously issued ID Token.
- `post_logout_redirect_uri` — must match `allowed_post_logout_redirect_uris` (strict equality).
- `state` — opaque value, returned to the client after redirect.

---

## 9. Discovery (`/.well-known/openid-configuration`)

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/oauth2/authorize",
  "token_endpoint": "https://auth.example.com/oauth2/token",
  "userinfo_endpoint": "https://auth.example.com/oauth2/userinfo",
  "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
  "registration_endpoint": "https://auth.example.com/oauth2/register",
  "scopes_supported": ["openid", "profile", "email", "phone", "address", "offline_access"],
  "response_types_supported": ["code"],
  "response_modes_supported": ["query", "fragment", "form_post"],
  "grant_types_supported": [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code"
  ],
  "subject_types_supported": ["public"],
  "id_token_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "client_secret_jwt",
    "private_key_jwt",
    "none"
  ],
  "dpop_signing_alg_values_supported": ["ES256"],
  "code_challenge_methods_supported": ["S256"],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr",
    "sid", "name", "given_name", "family_name", "middle_name", "nickname",
    "preferred_username", "profile", "picture", "website", "email",
    "email_verified", "gender", "birthdate", "zoneinfo", "locale",
    "phone_number", "phone_number_verified", "address", "updated_at"
  ],
  "revocation_endpoint": "https://auth.example.com/oauth2/revoke",
  "introspection_endpoint": "https://auth.example.com/oauth2/introspect",
  "end_session_endpoint": "https://auth.example.com/oauth2/logout",
  "device_authorization_endpoint": "https://auth.example.com/oauth2/device/authorize"
}
```

---

## 10. Rate Limiting (workstream O)

| Endpoint                                  | Rate limit           |
|-------------------------------------------|----------------------|
| `GET /.well-known/openid-configuration`   | 60/minute per IP     |
| `GET /.well-known/jwks.json`              | 60/minute per IP     |
| `GET /oauth2/userinfo`                    | 120/minute per IP    |
| `GET /oauth2/logout`                      | 30/minute per IP     |
| `POST /oauth2/logout`                     | 30/minute per IP     |
| `POST /oauth2/register`                   | 60/minute per IP     |
| `GET /oauth2/register/{id}`               | 120/minute per IP    |
| `PUT /oauth2/register/{id}`               | 60/minute per IP     |
| `DELETE /oauth2/register/{id}`            | 20/minute per IP     |
| `POST /oauth2/device/authorize`           | (per-client)         |
| `POST /oauth2/jwks/status`                | 60/minute per IP     |
| `GET /oauth2/jwks/status`                 | 60/minute per IP     |

---

## 11. FAPI 2.0 Capability Summary

For financial-grade deployments, AuthGlow currently supports:

| FAPI 2.0 requirement                       | Status    | Where                                        |
|--------------------------------------------|-----------|----------------------------------------------|
| Asymmetric client auth (`private_key_jwt`)  | ✅        | workstream T.2 — `OAuth2Client.public_jwk`  |
| Symmetric client auth (`client_secret_jwt`) | ✅        | workstream T.2 — `OAuth2Client.client_secret_jwt_key` |
| PKCE with S256                              | ✅        | `Settings.enforce_pkce` (default `True`)    |
| `state` parameter validation                | ✅        | workstream Q                                |
| `redirect_uri` exact match (no wildcards)  | ✅        | `core/url_validation`                       |
| HTTPS-only redirect URIs                     | ✅        | `api/oidc.py:_validate_redirect_uri`        |
| `amr` and `acr` claim propagation            | ✅        | workstream F                                |
| `at_hash` / `c_hash` on ID Token            | ✅        | workstream M                                |
| Refresh token rotation (single-use)         | ✅        | `RefreshTokenService.validate_and_rotate`    |
| DPoP sender-constrained tokens              | ✅        | workstream T.3                              |
| PAR (Pushed Authorization Requests)         | ❌        | Follow-up — see `docs/FAPI.md` §6.1         |
| JARM (JWT-secured Auth Response)            | ❌        | Follow-up — see `docs/FAPI.md` §6.2         |
| mTLS client authentication                  | ❌        | Follow-up — see `docs/FAPI.md` §6.3         |
| Code lifetime ≤ 30s                         | 🟡        | Configurable — set `OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES=0.5` |

See [`docs/FAPI.md`](FAPI.md) for the full gap analysis and roadmap.

---

## 12. Change Log

| Date       | Change                                                                     | Source    |
|------------|----------------------------------------------------------------------------|-----------|
| 2026-06-27 | Initial document (workstream U.4).                                         | CONFORMANCE_REMEDIATION_PLAN |
| 2026-06-27 | T.2 / T.3 features added: client JWT auth methods, DPoP, `cnf` claim.     | CONFORMANCE_REMEDIATION_PLAN |

Updates to this document are committed via PR; the linked
`CONFORMANCE_REMEDIATION_PLAN.md` is the source of truth for the
overall roadmap.
