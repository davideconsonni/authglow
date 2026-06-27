# AuthGlow — FAPI 2.0 Conformance Gap Analysis

> **Status**: 2026-06-27. Living document maintained as part of
> `CONFORMANCE_REMEDIATION_PLAN.md` workstream T.4.
>
> **Source standards**:
> - **FAPI 2.0 Security Profile** (Part 2): <https://openid.net/specs/openid-financial-api-part-2-1_0.html>
> - **FAPI 1.0 Advanced** (Part 1, §8 sender-constrained): <https://openid.net/specs/openid-financial-api-part-1-1_0.html>
> - **OAuth 2.0 Security BCP** (RFC 9700): <https://datatracker.ietf.org/doc/html/rfc9700>
> - **DPoP** (RFC 9449), **JWT-Bearer** (RFC 7523), **PKCE** (RFC 7636),
>   **MTLS client auth** (RFC 8705), **JARM** (RFC 9396), **PAR** (RFC 9126).

---

## 1. Executive Summary

AuthGlow implements the **core FAPI 2.0 Security Profile** (Part 2)
for the OAuth 2.0 / OIDC core flow. The following requirements are
**fully met**:

- Asymmetric client authentication (`private_key_jwt`, `client_secret_jwt`)
- PKCE with `S256` (mandatory for all clients)
- `iss` / `aud` / `nonce` / `exp` / `iat` claims on the ID Token
- `amr` and `acr` claim propagation (T.2 of the conformance plan)
- Refresh token rotation with single-use enforcement
- `redirect_uri` exact-match enforcement (no wildcards)
- HTTPS-only `redirect_uri` (http allowed for `localhost` in dev)
- `state` parameter validation (RFC 6819 §4.4.1.8) and persistence
  on the authorization code
- `prompt` parameter handling (`none`, `login`, `consent`, `select_account`)
- `max_age` parameter handling
- `id_token_hint` handling
- DPoP-bound access tokens (RFC 9449) with `cnf` claim (T.3)
- Standard OAuth 2.0 error codes with `WWW-Authenticate` headers
- Code lifetime: default 10 minutes (configurable, max 1 hour)

The following **gaps** are documented below with the rationale for
deferring them and a roadmap for closing them:

| Gap                                              | Severity | Status         |
|--------------------------------------------------|----------|----------------|
| PAR (RFC 9126, Pushed Authorization Requests)     | P1       | Not implemented |
| JARM (RFC 9396, JWT-secured Authorization Response) | P2     | Not implemented |
| mTLS client authentication (RFC 8705)            | P2       | Not implemented |
| Holder-of-Key (beyond DPoP)                       | P3       | Not implemented |
| Authorization code lifetime ≤ 30s (FAPI 2.0 §5.2.3) | P2    | Default 10 min, configurable |
| `tls_client_certificate_bound_access_tokens`     | P3       | Not implemented |

**FAPI 2.0 Security Profile "Read-Only" mode is achievable today**
with one operator-driven configuration tweak
(`oauth2_authorization_code_expire_minutes=0.5` or lower) and a
documented decision to defer the P1/P2/P3 items.

---

## 2. Scope of this Analysis

This document covers:

1. **FAPI 2.0 Security Profile** (the headline target for
   financial-grade deployments) — Part 2 of the FAPI spec.
2. **FAPI 1.0 Advanced** features (Part 1, §8) that FAPI 2.0 builds
   on — sender-constrained access tokens (DPoP, mTLS).
3. **Related OAuth 2.0 / OIDC features** that are pre-requisites or
   strongly recommended by FAPI 2.0 (DPoP, PKCE, audience binding,
   error responses).

It does NOT cover:

- **FAPI-CIBA** (Client-Initiated Backchannel Authentication) — out
  of scope for AuthGlow's current product direction.
- **FAPI eKYC** / **FAPI ID2** — different use case.
- **PSD2 / RTS** specific requirements (e.g. strong customer
  authentication) — those are policy-layer decisions delegated to
  the Relying Party, not the OP.

---

## 3. Conformance Matrix

Legend: ✅ implemented · 🟡 partial · ❌ not implemented · — N/A

### 3.1 Client Registration (FAPI 2.0 §5.2.1)

| Requirement                                         | Status | Implementation                                                  |
|-----------------------------------------------------|:------:|-----------------------------------------------------------------|
| Confidential clients use `private_key_jwt` or `client_secret_jwt` | ✅ | `OAuth2Client.token_endpoint_auth_method` enum, T.2 of the plan. |
| Public clients use `none` with PKCE                 | ✅     | `is_confidential=False` + `enforce_pkce=True` (default).         |
| JWK / public key advertised by the client            | ✅     | `public_jwk` on `OAuth2Client`; embedded for `private_key_jwt`. |
| Client secret confidentiality                       | ✅     | Bcrypt-hashed (legacy). Fernet-encrypted for `client_secret_jwt_key` (T.2). |
| Client ID / Secret issuance shown once               | ✅     | `OAuth2ClientWithSecret` returned only at creation / rotation. |
| HTTPS-only redirect_uris (except `localhost`)       | ✅     | `_validate_redirect_uri` in `api/oidc.py:register_oauth_client`. |
| No wildcard redirect_uris                           | ✅     | Exact-match in authorization flow + DCR validation.              |
| `software_statement` validation if present          | ✅     | PyJWT decode in DCR validation (FAPI 2.0 §5.2.1 §5).           |

### 3.2 Authorization Request (FAPI 2.0 §5.2.2)

| Requirement                                         | Status | Implementation                                                  |
|-----------------------------------------------------|:------:|-----------------------------------------------------------------|
| PKCE with `S256` for all clients                    | ✅     | `enforce_pkce=True` (default); `code_challenge_method="S256"` only. |
| `state` parameter required, validated, persisted    | ✅     | `AuthorizationCode.state`; warning logged if missing.            |
| `redirect_uri` exact match                         | ✅     | `auth_code.redirect_uri != redirect_uri → 400` in `token_endpoint`. |
| `response_type=code` only                           | ✅     | `implicit` grant rejected (CONFORMANCE workstream E).           |
| `prompt` parameter (`none`, `login`, `consent`, `select_account`) | ✅ | `authorize_post` + `oauth2_mfa_verify` handlers (workstream G). |
| `max_age` parameter                                 | ✅     | `authorize_post` re-auth flow (workstream H).                   |
| `id_token_hint` parameter                           | ✅     | `authorize_post` pre-fill (workstream I).                      |
| `acr_values` parameter                              | 🟡     | Currently the AS maps auth methods to ACR (workstream F).       |
| `claims` parameter (request specific claims)        | ❌     | Not implemented.                                                 |
| `request` parameter (JAR / PAR)                     | ❌     | Not implemented. See §6.1.                                      |
| `request_uri` parameter (PAR)                       | ❌     | Not implemented. See §6.1.                                      |

### 3.3 Authorization Response (FAPI 2.0 §5.2.3)

| Requirement                                         | Status | Implementation                                                  |
|-----------------------------------------------------|:------:|-----------------------------------------------------------------|
| Authorization code single-use                       | ✅     | `mark_code_as_used`; `used=True` rejects re-use.                 |
| Code lifetime ≤ 30s (FAPI 2.0 §5.2.3)              | 🟡     | Default 10 min. Configurable via `oauth2_authorization_code_expire_minutes`. Set to 0.5 to satisfy FAPI strictly. |
| `iss` parameter in authorization response            | 🟡     | Validated on token request via `expected_aud` (workstream A).   |
| `c_hash` claim on ID Token                          | ✅     | `create_id_token` computes `c_hash` from authorization code.    |
| `at_hash` claim on ID Token                         | ✅     | `create_id_token` computes `at_hash` from access token.         |
| `aud` claim contains the client_id                  | ✅     | `aud=auth_code.client_id` on ID Token (workstream A).           |
| `response_mode=form_post`                           | ✅     | Listed in `response_modes_supported` (discovery).               |
| `response_mode=jwt` (JARM)                          | ❌     | Not implemented. See §6.2.                                      |

### 3.4 Token Endpoint (FAPI 2.0 §5.2.4, §5.2.6)

| Requirement                                         | Status | Implementation                                                  |
|-----------------------------------------------------|:------:|-----------------------------------------------------------------|
| `client_secret_jwt` (HS256) for confidential clients | ✅     | `services/client_jwt_auth.py` (workstream T.2).                  |
| `private_key_jwt` (RS256) for confidential clients  | ✅     | `services/client_jwt_auth.py` (workstream T.2).                  |
| `none` for public clients + PKCE                     | ✅     | `enforce_pkce=True`.                                            |
| `iss` / `sub` / `aud` claims on access token        | ✅     | `create_access_token` sets all three (workstream A).            |
| Sender-constrained access token (DPoP)              | ✅     | `cnf.jkt` claim + `dpop_bound` flag (workstream T.3).            |
| Refresh token rotation with single-use              | ✅     | `RefreshTokenService.validate_and_rotate` rotates on use.       |
| Refresh token revocation (sender-constrained = cnf) | 🟡     | Refresh tokens are not bound to a key.                          |
| DPoP proof required on token request (DPoP-bound)   | ✅     | `_require_dpop_proof_if_bound` in `api/auth.py` (workstream T.3). |
| `c_hash` validation on code → token request          | ❌     | `c_hash` is computed but not bound to the code.                 |
| Introspection endpoint                              | ✅     | `POST /oauth2/introspect`.                                      |
| Revocation endpoint                                 | ✅     | `POST /oauth2/revoke`.                                           |

### 3.5 Refresh Token (FAPI 2.0 §5.2.5)

| Requirement                                         | Status | Implementation                                                  |
|-----------------------------------------------------|:------:|-----------------------------------------------------------------|
| Refresh token single-use (rotation)                 | ✅     | `validate_and_rotate` invalidates the old token.                 |
| Sender-constrained OR rotation                      | 🟡     | Rotation is in place; DPoP binding for refresh tokens is TBD.   |
| Reuse detection (RFC 6749 §10.4)                    | ✅     | If a rotated token is re-used, the entire chain is revoked.      |

### 3.6 Sender-Constrained Access Tokens (FAPI 1.0 Advanced §8 / FAPI 2.0 §5.2.7)

| Requirement                                         | Status | Implementation                                                  |
|-----------------------------------------------------|:------:|-----------------------------------------------------------------|
| DPoP (RFC 9449) on resource requests                 | ✅     | `services/dpop.py` + UserInfo integration (workstream T.3).       |
| `cnf` claim on access token                         | ✅     | `{"jkt": "<thumbprint>"}` in `create_token_response` (T.3).        |
| ES256 only (FAPI 2.0 minimum)                       | ✅     | `_ALLOWED_DPOP_ALG = "ES256"`.                                  |
| JWK embedded in DPoP proof header                   | ✅     | `verify_dpop_proof` reads `jwk` from JWT header.                |
| Replay protection on `jti` claim                    | ✅     | `jti_cache` with `dpop:` namespace (workstream T.3).            |
| `ath` claim binds proof to access token             | ✅     | `_ath_for` in `services/dpop.py` + `verify_dpop_proof`.         |
| mTLS client authentication (RFC 8705)               | ❌     | Not implemented. See §6.3.                                      |
| `tls_client_certificate_bound_access_tokens`        | ❌     | Not implemented. See §6.3.                                      |

### 3.7 ID Token (FAPI 2.0 §5.2.8 / OIDC Core §2)

| Requirement                                         | Status | Implementation                                                  |
|-----------------------------------------------------|:------:|-----------------------------------------------------------------|
| `iss` matches discovery `issuer`                     | ✅     | `_encode_token` sets `iss=settings.issuer`.                      |
| `aud` contains the client_id                        | ✅     | `create_id_token` passes `client_id`.                            |
| `sub` is the user_id                                | ✅     | `create_id_token` passes `user_id`.                             |
| `exp` / `iat` are set                               | ✅     | Standard JWT timestamps.                                        |
| `nonce` is reflected when supplied                  | ✅     | `create_id_token` honors `nonce` parameter.                     |
| `auth_time` is set on re-auth                       | ✅     | `create_id_token` honors `auth_time`.                            |
| `acr` is set                                        | ✅     | `create_id_token` honors `acr` (workstream F).                  |
| `amr` is set                                        | ✅     | `create_id_token` honors `amr` (workstream F).                  |
| `at_hash` is present when access token issued        | ✅     | `create_id_token` with `access_token=` param.                   |
| `c_hash` is present when issued from code           | ✅     | `create_id_token` with `authorization_code=` param.             |
| `sid` is set for back-channel logout                 | ✅     | `create_id_token` includes `sid` (workstream L).                |

### 3.8 UserInfo (FAPI 2.0 §5.2.9)

| Requirement                                         | Status | Implementation                                                  |
|-----------------------------------------------------|:------:|-----------------------------------------------------------------|
| Bearer access token authentication                  | ✅     | Standard `HTTPBearer` + manual DPoP scheme support.             |
| DPoP proof on DPoP-bound access tokens              | ✅     | `userinfo` handler verifies proof when `cnf` is present (T.3).  |
| Claims scoped to requested scope                    | ✅     | `OIDCService.get_user_info` filters by scopes.                  |
| `sub` is the user_id                                | ✅     | Standard.                                                       |
| HTTPS endpoint                                      | ✅     | Inherits from `Settings.issuer`.                                |

### 3.9 Discovery (FAPI 2.0 §5.2.10)

| Requirement                                         | Status | Implementation                                                  |
|-----------------------------------------------------|:------:|-----------------------------------------------------------------|
| All required endpoints advertised                   | ✅     | `OpenIDConfiguration` in `api/oidc.py`.                         |
| `token_endpoint_auth_methods_supported` lists FAPI-allowed methods | ✅ | `client_secret_basic`, `client_secret_post`, `client_secret_jwt`, `private_key_jwt`, `none` (workstream T.2). |
| `dpop_signing_alg_values_supported`                 | ✅     | `["ES256"]` (workstream T.3).                                    |
| `id_token_signing_alg_values_supported`             | ✅     | `[settings.jwt_algorithm]` (RS256 by default).                  |
| `grant_types_supported`                             | ✅     | `authorization_code`, `refresh_token`, `client_credentials`, `urn:ietf:params:oauth:grant-type:device_code`. |
| `subject_types_supported`                           | ✅     | `["public"]`.                                                    |
| `claims_supported`                                  | ✅     | OIDC standard + FAPI-relevant (`acr`, `amr`, `sid`, `nonce`).   |
| `code_challenge_methods_supported`                  | ✅     | `["S256"]` (no `plain`).                                         |
| `pushed_authorization_request_endpoint`             | ❌     | Not implemented. See §6.1.                                      |
| `require_pushed_authorization_requests`              | ❌     | Not implemented. See §6.1.                                      |
| `authorization_signed_response_alg_values_supported` | ❌     | Not implemented. See §6.2.                                      |

### 3.10 Logout (OIDC Session Management / FAPI 2.0 §5.2.12)

| Requirement                                         | Status | Implementation                                                  |
|-----------------------------------------------------|:------:|-----------------------------------------------------------------|
| RP-Initiated Logout (OIDC)                           | ✅     | `GET /oauth2/logout`, `POST /oauth2/logout` (workstream D).      |
| `post_logout_redirect_uri` validation               | ✅     | Strict equality against `allowed_post_logout_redirect_uris` (workstream D). |
| Front-channel logout                                | ✅     | HTML with `<iframe>` (workstream L).                            |
| Back-channel logout                                 | 🟡     | Endpoint is defined on the client but session tracking is missing. |
| `sid` claim propagation                             | ✅     | `create_id_token` includes `sid` (workstream L).                |
| `iss` parameter on logout request                   | ✅     | Validated via `expected_aud` on token decode.                    |

### 3.11 Error Responses (RFC 6749 §5.2 + FAPI 2.0 §5.2.4)

| Requirement                                         | Status | Implementation                                                  |
|-----------------------------------------------------|:------:|-----------------------------------------------------------------|
| Standard OAuth 2.0 error codes                      | ✅     | `invalid_request`, `invalid_client`, `invalid_grant`, etc.     |
| `WWW-Authenticate` header on 401                    | ✅     | `Bearer realm="OAuth2"`, `DPoP algs="ES256"`.                   |
| `error_description` in response body                | ✅     | Used consistently.                                               |
| `error_uri` in response body                        | ❌     | Not used (no online docs URL configured).                        |

---

## 4. Sender-Constrained Tokens — Deep Dive

FAPI 2.0 §5.2.7 mandates that the access token be bound to the
client's key. The two standards-compliant options are DPoP and
mTLS. AuthGlow implements **DPoP only** in this revision.

### 4.1 DPoP (RFC 9449) — Implemented

The flow:

1. **Token request**: the client generates an ES256 key pair, signs
   a DPoP proof JWT containing the public key (`jwk` header) plus
   the request context (`htm`, `htu`, `iat`, `jti`), and sends the
   proof in the `DPoP:` header.
2. **Server side**: `services/dpop.py` verifies the proof, computes
   the JWK thumbprint (RFC 7638), and includes `cnf={"jkt": ...}`
   in the access token. The `token_type` is set to `DPoP` instead
   of `Bearer`.
3. **Resource request**: the client sends the access token via
   `Authorization: DPoP <token>` + a fresh DPoP proof with `ath`
   bound to the token's SHA-256.
4. **Replay protection**: each `jti` is recorded in `jti_cache`
   under the `dpop:` namespace, evicted automatically when the
   proof's lifetime window expires.

Configuration:

- `Settings.dpop_bound: bool` per client (opt-in).
- `Settings.dpop_signing_alg_values_supported = ["ES256"]` (only
  ES256 is implemented; EdDSA and PS256 are deferred).
- `Settings.cache_jti_maxsize = 10000`, `cache_jti_ttl = 3600`
  (in-process cache; multi-instance deployments need to coordinate
  the cache via Redis or similar — TBD).

### 4.2 mTLS (RFC 8705) — Not Implemented

mTLS-based client authentication and certificate-bound access
tokens are the alternative path. **We do not implement mTLS** for
the following reasons:

- DPoP provides equivalent security guarantees with simpler
  operational model (no client cert distribution).
- mTLS requires a private PKI on the AS side to issue / manage
  client certificates, which is out of AuthGlow's current scope.
- The two paths are functionally equivalent from a security
  standpoint (FAPI 2.0 accepts either).

If a customer needs mTLS, the implementation path is:

1. Add a TLS terminator (e.g. Envoy, nginx) in front of the AS
   that validates client certificates and forwards them via
   `X-Client-Cert` or `X-SSL-Client-Cert` headers.
2. Add a new client auth method `tls_client_auth` to the
   `OAuth2Client.token_endpoint_auth_method` enum.
3. On token requests, verify the certificate hash against the
   registered thumbprint.
4. Issue the access token with `cnf={"x5t#S256": "<cert-thumbprint>"}`.
5. Resource server verification mirrors the DPoP path.

See [RFC 8705](https://datatracker.ietf.org/doc/html/rfc8705) for
the spec.

---

## 5. Refresh Token Strategy

FAPI 2.0 §5.2.5 allows refresh tokens **only** if they are
sender-constrained or rotated. AuthGlow implements **rotation**
(single-use, with reuse detection per RFC 6749 §10.4):

- `RefreshTokenService.create_refresh_token` mints a new token and
  records it on disk.
- `RefreshTokenService.validate_and_rotate` validates the bearer
  token, marks it used, and issues a new one.
- If a previously-rotated token is presented, the **entire
  refresh-token chain is revoked** (reuse detection).

The DPoP binding for refresh tokens is **not** in place: a refresh
token can be exchanged by any party holding the token alone. This
is acceptable for rotation-based strategies per FAPI 2.0 §5.2.5,
but operators who want stronger guarantees should also enable
`dpop_bound` on the client. Future work could mint refresh tokens
with their own `cnf` claim.

---

## 6. Gap Roadmap

### 6.1 PAR (Pushed Authorization Requests, RFC 9126) — P1

**Why deferred**: PAR is a "nice to have" for high-security
deployments where the AS needs to validate the auth request
**before** the user sees the consent screen. It is recommended by
FAPI 2.0 Part 2 §5.2.1 for the "Read and Write" profile, but not
required for "Read-Only".

**Implementation cost**: medium-high (~3-4 days). Requires:

- New endpoint `POST /oauth2/par` accepting the same parameters
  as the authorization request.
- Return a `request_uri` that the client uses in the
  authorization request.
- Modify the authorize endpoint to accept `request_uri` and
  look up the pushed parameters.
- New DCR field for the `pushed_authorization_request_endpoint`
  (already in `OpenIDConfiguration`).
- Add `require_pushed_authorization_requests` setting for strict
  mode.
- Migration: existing clients keep working; PAR is opt-in per
  client.

**Risks**:
- Storage: pushed requests are short-lived (≤ 90s) but need a
  TTL eviction strategy.
- The pushed request is bound to the client_id; cross-client
  reuse must be rejected.

### 6.2 JARM (JWT-secured Authorization Response Mode, RFC 9396) — P2

**Why deferred**: JARM is optional in FAPI 2.0. The current
`response_mode=query` with `code` is the standard, well-tested
mode. JARM adds signed JWT responses (instead of plain
`?code=...&state=...` redirects), which is useful for clients
that need cryptographic proof of the auth response.

**Implementation cost**: medium (~2 days). Requires:

- New `response_mode=jwt` support on the authorization endpoint.
- Sign the response with the AS's key (`kid` in the JWS header).
- Add `authorization_signed_response_alg_values_supported` to
  discovery.

**Risks**:
- Existing clients need to upgrade to verify the JWS.
- Cross-cutting change: the `authorize_post` response is currently
  a 302 redirect; JARM would return a page that redirects with
  the JWS.

### 6.3 mTLS Client Authentication (RFC 8705) — P2

See §4.2 for the full rationale. Implementation cost: medium
(~2-3 days) including:

- TLS termination with client cert extraction.
- New `token_endpoint_auth_method=tls_client_auth` and
  `self_signed_tls_client_auth`.
- `cnf={"x5t#S256": "..."}` on the access token.
- Resource server certificate validation.

### 6.4 Authorization Code Lifetime ≤ 30s — P2 (config-only)

The FAPI 2.0 §5.2.3 requirement is that the authorization code
expires in **at most 30 seconds**. AuthGlow's default is 10
minutes, configurable via
`oauth2_authorization_code_expire_minutes`.

To comply with FAPI 2.0 strictly, operators set:

```bash
# .env
OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES=0.5
```

This is a configuration-only fix; no code change is required. The
workstream is listed here as a P2 because we should:

1. Lower the **default** to 1 minute (or 30 seconds) in the
   production config template.
2. Document the FAPI 2.0 value in the discovery or a separate
   conformance flag.
3. Add a `Settings.fapi_strict_code_lifetime: bool` setting that,
   when True, hard-caps the value at 30 seconds.

### 6.5 Holder-of-Key beyond DPoP — P3

FAPI 1.0 Advanced §8.2.1 mentions "Holder-of-Key" as a
sender-constrained mechanism that can be implemented via several
techniques. DPoP satisfies this requirement. Other Holder-of-Key
mechanisms (e.g. JWE-encrypted access tokens, key-bound JWTs) are
not in scope for the current AuthGlow roadmap.

### 6.6 `claims` parameter — P3

The OIDC `claims` parameter lets the client request specific
claims (e.g. `claims={"id_token": {"acr": {"essential": true,
"values": ["urn:mace:incommon:iap:silver"]}}}`). This is useful
for high-trust scenarios where the AS enforces a specific ACR.

**Implementation cost**: low-medium (~1 day). Requires:

- Parse the `claims` parameter on the authorization request.
- Forward the request to the login flow.
- Enforce `acr` / `auth_time` constraints on the ID Token.

---

## 7. Configuration for FAPI 2.0 Strict Mode

To deploy AuthGlow in FAPI 2.0 "Read-Only" mode today, an
operator must set the following environment variables:

```bash
# .env
OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES=0.5   # FAPI §5.2.3: ≤ 30s
DPOP_SIGNING_ALG_VALUES_SUPPORTED=ES256       # discovery (already default)
ENFORCE_PKCE=true                             # already default
```

Per-client settings (admin UI):

- `token_endpoint_auth_method` = `private_key_jwt` (recommended)
  or `client_secret_jwt` (acceptable).
- `dpop_bound` = `true` (recommended for high-security).
- `public_jwk` populated for `private_key_jwt`.
- `redirect_uris` use exact HTTPS URLs.

The DCR endpoint already enforces all of the above except the
FAPI 2.0 code lifetime (config-only).

---

## 8. Test Plan

End-to-end conformance tests live in
[`docs/CONFORMANCE_TEST_PLAN.md`](CONFORMANCE_TEST_PLAN.md) and
are exercised by the `tests/integration/test_dcr_*.py`,
`tests/integration/test_token_endpoint_*.py`, and
`tests/integration/test_userinfo_*.py` suites. Per
`CONFORMANCE_REMEDIATION_PLAN.md`, every workstream that ships
new behaviour must include integration tests that exercise the
new path through the FastAPI app.

Unit tests for the cryptographic core live in
`tests/unit/test_client_jwt_auth.py` (T.2) and
`tests/unit/test_dpop.py` (T.3).

---

## 9. Change Log

| Date       | Change                                                       | Author    |
|------------|--------------------------------------------------------------|-----------|
| 2026-06-27 | Initial gap analysis (workstream T.4).                      | AuthGlow  |
| 2026-06-27 | Linked to CONFORMANCE_REMEDIATION_PLAN.md T.2 + T.3.         | AuthGlow  |

Updates to this document are committed via PR; the linked
`CONFORMANCE_REMEDIATION_PLAN.md` is the source of truth for the
overall roadmap.
