# Changelog

All notable changes to AuthGlow are documented in this file. The
format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

> **Note**: this changelog starts with the **conformance workstream
> release** (U.5). The historical pre-conformance changelog lives
> in the git history and is intentionally not back-ported here.

---

## [Unreleased] — Conformance Workstream (A → T + U.3-U.5)

The unreleased section aggregates the entire conformance
remediation workstream documented in
[`docs/plans/CONFORMANCE_REMEDIATION_PLAN.md`](plans/CONFORMANCE_REMEDIATION_PLAN.md).
After this release, AuthGlow is OIDC Core 1.0 + OAuth 2.0
Security BCP compliant, with FAPI 2.0 partial coverage
(see [`docs/FAPI.md`](FAPI.md) for the gap analysis).

### Breaking Changes

These changes are **breaking** for client applications that relied
on the old behaviour. Operators running an existing deployment
MUST audit their clients before upgrading.

#### Removed features

- **`password` grant** (Resource Owner Password Credentials) on
  `/oauth2/token` — rejected with HTTP 400 "Unsupported grant_type".
  ROPC is deprecated in OAuth 2.1 and disallowed by the OAuth 2.0
  Security BCP. Migration: move clients to `authorization_code` +
  PKCE. (workstream T.1)
- **`implicit` grant** — discovery and DCR reject the value;
  existing clients with `grant_types=["implicit", ...]` will fail
  to load. Migration: drop `implicit` from `grant_types`; move to
  `authorization_code` + PKCE. (workstream E)

#### Behaviour changes

- **PKCE mandatory for all clients** (`Settings.enforce_pkce=True`).
  New clients are created with `require_pkce=True`. Existing
  clients are auto-migrated by `scripts/migrate_enforce_pkce.py`.
  Clients that did not previously send a `code_challenge` will
  now receive HTTP 400. Migration: implement PKCE on the client
  side. (workstream B)
- **`post_logout_redirect_uri` strict validation**. The redirect
  URI is now compared strictly against the client's
  `allowed_post_logout_redirect_uris`. Dev-mode bypass has been
  removed. Migration: operators MUST populate
  `allowed_post_logout_redirect_uris` for every client that uses
  RP-Initiated Logout. (workstream D)
- **Authorization code requires `openid` scope binding for OIDC
  flows** (workstream F). The `acr` / `amr` claim is now derived
  from the auth path and propagated to the ID Token. No migration
  needed for clients; existing ID Tokens start carrying these
  claims after the upgrade.

### Added Features

#### OAuth 2.0 / OIDC Core

- **`client_secret_jwt` (HS256)** client authentication
  ([RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)).
  The server mints a per-client symmetric key at DCR time and
  returns it once in the create response. (workstream T.2)
- **`private_key_jwt` (RS256)** client authentication
  ([RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523)).
  The client registers a public JWK at DCR time. (workstream T.2)
- **JWT-Bearer auth on DCR Management** (RFC 7592). Clients using
  `client_secret_jwt` or `private_key_jwt` can now manage their
  own registration via `GET/PUT/DELETE /oauth2/register/{id}`
  with a Bearer JWT. (workstream T.2)
- **DPoP-bound access tokens** ([RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)).
  ES256 only. The token endpoint requires a DPoP proof JWT on
  every request from `dpop_bound=true` clients; the access
  token is issued with `cnf={"jkt": "..."}` (RFC 7800) and
  `token_type=DPoP`. The UserInfo endpoint enforces the proof.
  (workstream T.3)

#### OIDC ID Token claims (workstream F, L, M)

- `acr` — Authentication Context Class Reference (mapped from
  auth path: `0` none, `1` password, `2` pwd+mfa, `3` pwd+webauthn).
- `amr` — Authentication Methods References (`["pwd"]`,
  `["pwd","mfa"]`, etc.).
- `sid` — Session ID (for back-/front-channel logout).
- `at_hash` — left-half SHA-256 of the access token
  (OIDC Core §3.1.3.6).
- `c_hash` — left-half SHA-256 of the authorization code
  (OIDC Core §3.3.2.11).

#### OIDC Authorization Request parameters

- **`prompt`** (`none`, `login`, `consent`, `select_account`) —
  workstream G.
- **`max_age`** — forces re-auth if `auth_time` is older than
  the supplied value — workstream H.
- **`id_token_hint`** — pre-fills the login form when the user
  lands on the authorize page — workstream I.

#### Token management

- **Persistent token blacklist** (multi-instance visibility via
  file-based storage). RFC 7009. (workstream J)
- **Single-use refresh tokens** with reuse detection. If a
  rotated refresh token is presented a second time, the entire
  chain is revoked. (workstream J)
- **JWKS status endpoint** `GET /oauth2/jwks/status` — public
  endpoint advertising the status (active, verifying, revoked)
  of every key in the keyring. RFC 7517. (workstream R)

#### Other

- **DCR hardening** — `none` rejected with `client_credentials`
  grant; metadata URIs must be HTTPS; `software_statement` must
  be a valid JWT. (workstream P)
- **Rate limiting** on all OIDC core endpoints. (workstream O)
- **`state` parameter validation** with audit logging on
  missing `state`. (workstream Q)
- **Front-channel logout** via HTML with `<iframe>` for each
  registered `frontchannel_logout_uri`. (workstream L)
- **Device Authorization Grant** (RFC 8628). UI:
  `/device`. (workstream S)

#### Documentation

- [`docs/SECURITY.md`](SECURITY.md) — updated with the full list
  of conformance fixes (workstream A–S, T). (U.3)
- [`docs/FEATURES.md`](FEATURES.md) — feature catalogue. (U.4)
- [`docs/FAPI.md`](FAPI.md) — FAPI 2.0 gap analysis with roadmap.
  (T.4)

### Internal

- **Repository pattern** for all 22 entities (Fase 21 of the
  refactor). Services depend on `Protocol`s, not file-based
  implementations. Conformance tests cover all 22 protocols.
- **In-process TTL cache** (`cachetools.TTLCache`) reused for
  user, refresh-token, and JTI replay protection. Configurable
  via `Settings.cache_*`.
- **Service-layer CAS retry loop** in `RefreshTokenService` and
  `OAuth2ClientStorage` to handle concurrent writes across
  multiple instances.

### Migration Guide for Operators

If you are upgrading from a pre-conformance version, follow these
steps in order:

1. **Backup the data directory** (`data/users`, `data/keys`).
2. **Upgrade the code** (`git pull` + reinstall dependencies).
3. **Run the migration**:
   ```bash
   # Dry-run
   python -m scripts.migrate_remove_implicit_grant
   python -m scripts.migrate_enforce_pkce
   # Apply
   python -m scripts.migrate_remove_implicit_grant --apply
   python -m scripts.migrate_enforce_pkce --apply
   ```
   The U.1 orchestrator (deferred — see
   [`CONFORMANCE_REMEDIATION_PLAN.md`](plans/CONFORMANCE_REMEDIATION_PLAN.md))
   will eventually run all of these in one command.
4. **For each OAuth2 client**:
   - Drop `implicit` from `grant_types` (the migration script does
     this for you).
   - Set `require_pkce=true` (the migration script does this).
   - Populate `allowed_post_logout_redirect_uris` (no migration
     script — must be done manually per client).
5. **For FAPI 2.0 deployment** (optional): see
   [`docs/FAPI.md`](FAPI.md) §7 for the operator configuration
   (`OAUTH2_AUTHORIZATION_CODE_EXPIRE_MINUTES=0.5`,
   `token_endpoint_auth_method=private_key_jwt`,
   `dpop_bound=true`).
6. **Verify** by running the test plan in
   [`docs/CONFORMANCE_TEST_PLAN.md`](CONFORMANCE_TEST_PLAN.md):
   ```bash
   pytest -q --tb=line -n auto
   ```

### Deprecations

- `Settings.oauth2_client_secret` is still available for
  legacy first-party login (`POST /api/token`) but MUST be
  overridden in production. The token endpoint refuses the
  default value.
- `Settings.is_production` is the canonical production flag.
  Several security checks (e.g. default client credentials, OAuth2
  fallback client) hard-fail when this is `True`.

### Known Limitations

- **PAR (RFC 9126)**, **JARM (RFC 9396)**, **mTLS client auth
  (RFC 8705)** are **not implemented**. See
  [`docs/FAPI.md`](FAPI.md) for the roadmap.
- **Back-channel logout** does not propagate `sid` because session
  tracking is not implemented. (workstream L)
- **The DPoP replay cache is in-process** (`jti_cache`). In
  multi-instance deployments without a shared cache, a replayed
  DPoP proof could be accepted on a different instance. Mitigate
  by deploying a shared cache (Redis) or restricting to a single
  instance. (workstream T.3)

---

## [0.0.0] — Pre-conformance baseline

Initial AuthGlow codebase. The historical changelog is preserved
in the git history (`git log --oneline --grep="..."`) and is
intentionally not back-ported to this file. See
[`docs/SECURITY.md`](SECURITY.md) for the pre-conformance security
posture and the rationale for the workstream.
