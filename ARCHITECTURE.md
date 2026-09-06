# ARCHITECTURE.md

Quick orientation: where things live and how they connect.
For code style, naming, and test commands see `AGENTS.md`.

## Quick Reference — Where to Add What

| Task                                   | Place                                                                                                  |
|----------------------------------------|--------------------------------------------------------------------------------------------------------|
| New API endpoint                       | `backend/authglow/api/<module>.py` → define `router`, then `app.include_router()` in `backend/main.py` |
| New business logic                     | `backend/authglow/services/<module>.py` — one class per file                                           |
| New data model / schema                | `backend/authglow/models/<module>.py` — Pydantic model                                                 |
| New storage backend                    | `backend/authglow/repositories/<backend>/<entity>.py` + 1 line in `dependencies.py`                    |
| Change config / env vars               | `backend/authglow/core/config.py` (`Settings` model) + `.env.example`                                  |
| New middleware                         | `backend/authglow/middleware/<name>.py` + register in `main.py`                                        |
| New core utility (crypto, cache, etc.) | `backend/authglow/core/<module>.py`                                                                    |
| New test (unit)                        | `backend/tests/unit/test_<module>.py`                                                                  |
| New test (integration)                 | `backend/tests/integration/test_<flow>.py`                                                             |
| New page (frontend)                    | `frontend/src/pages/<PageName>.tsx` + route in `App.tsx` + path in `lib/constants.ts`                  |
| New page (admin, lazy-loaded)          | `frontend/src/pages/admin/<AdminPage>.tsx` + `React.lazy()` in `App.tsx`                               |
| New shared component                   | `frontend/src/components/shared/<Component>.tsx`                                                       |
| New auth component (forms, etc.)       | `frontend/src/components/auth/<Component>.tsx`                                                         |
| New UI primitive                       | `frontend/src/components/ui/<name>.tsx` (shadcn/ui pattern)                                            |
| New state store                        | `frontend/src/stores/<name>Store.ts` → Zustand                                                         |
| New API hook                           | `frontend/src/hooks/use<Name>.ts` → wraps `useApiQuery`/`useApiMutation`                               |
| New claim policy rule (backend)        | `backend/authglow/models/claim_policy.py` (template or `ClaimRule` + service `apply_template`)         |
| New API constant / route path          | `frontend/src/lib/constants.ts`                                                                        |
| HTTP client change                     | `frontend/src/lib/api.ts`                                                                              |

## Directory Map

```
authglow/
├── AGENTS.md                  # Code style, naming, test commands
├── ARCHITECTURE.md            # This file — structural map
├── DESIGN.md                  # Visual design system (colors, typography)
├── SECURITY.md                # Vulnerability reporting policy
├── Dockerfile                 # Single-container image: FastAPI + built SPA (one port, one process)
├── .dockerignore              # Build-context exclusions for the single-container image
├── docs/                      # Integration guides, feature catalog, plans, post-mortems
│   ├── FEATURES.md            # Complete feature catalog
│   ├── flows/                 # Per-flow guides: standard + custom behavior
├── backend/
│   ├── main.py                # App entry: FastAPI(), middleware stack, router mounts, SPA serving
│   ├── Dockerfile             # Backend-only image (pure REST API)
│   ├── .env.example           # All configurable settings template
│   └── authglow/
│       ├── api/               # 20 FastAPI routers (HTTP layer, one per domain)
│       ├── services/          # 45 modules / 50 classes (business logic, cross-entity coordination; auth/ + email/ subpackages)
│       ├── repositories/      # Storage abstraction (Protocols → File impls)
│       │   ├── protocols.py   # 30 Protocol contracts (@runtime_checkable)
│       │   ├── exceptions.py  # EntityNotFoundError, EntityAlreadyExistsError
│       │   ├── dependencies.py# Factory functions: get_<entity>_repository()
│       │   └── file/          # 25 File*Repository impls + BaseFileRepository (JSON on disk via fsspec)
│       ├── models/            # Pydantic request/response/domain models (24 modules)
│       ├── core/              # config, crypto, cache, concurrency, permissions, password, pii, datetime, async_io, http_client, jwt_singleton, rate_limit
│       └── middleware/        # Security headers, HTTPS enforcement, request size, request ID, proxy headers
├── frontend/
│   ├── src/
│   │   ├── App.tsx            # Routing, provider stack, route guards
│   │   ├── pages/             # Route-level components (auth/, admin/)
│   │   ├── components/        # ui/ (shadcn), layout/, shared/, auth/, admin/
│   │   ├── stores/            # Zustand: authStore, toastStore, playgroundStore
│       │   ├── hooks/             # useAuth, useApi, useTheme, useDocumentTitle, useDemoMeta, useDemoInbox
│   │   ├── lib/               # api.ts (HTTP client), constants.ts (ROUTES, API_URL), utils.ts, jwt.ts, loginStorage.ts
│   │   └── styles/            # globals.css (Tailwind + design tokens)
│   └── e2e/                   # Playwright E2E specs
└── images/                    # README screenshots
```

## Single-Container Deployment

AuthGlow ships as one image that exposes both the API and the React SPA on a
single port, under a single Uvicorn process — no nginx, no process manager, no
docker-compose. It runs unchanged on Cloud Run, ECS/Fargate, Fly.io, Railway,
Render, or any Docker host that injects a `$PORT` env var.

- **Two build targets**
  - `Dockerfile` (repo root) — **full app**: builds the SPA with `node:26-slim`,
    then a `python:3.13-slim` runtime copies `frontend/dist` to
    `FRONTEND_DIST_DIR=/app/frontend/dist` and serves both API and UI.
  - `backend/Dockerfile` — **API-only**: pure REST API + Swagger, for when a
    separate frontend already exists.
- **Single-origin SPA.** The frontend is built with relative API URLs
  (`API_URL = import.meta.env.VITE_API_URL ?? ''`), so SPA and API share one
  origin and cookies/CSRF need no cross-origin configuration.
- **SPA serving** lives in `backend/main.py`: when `frontend_dist_dir` is set and
  present, `/assets` is mounted and a `/{path:path}` catch-all — registered after
  all routers — serves the React shell for client-side routes (`/admin`,
  `/dashboard`, `/auth/login`, `/oauth2/authorize`, …) while `/api`, `/docs`,
  `/.well-known` and other `/oauth2/*` server endpoints keep 404ing on unknown
  paths. `FRONTEND_DIST_DIR=""` (default) disables it for backend-only deploys.
- **Runtime-only configuration.** Every setting is an env var (Pydantic
  `Settings`, `case_sensitive=False`); the image is immutable across
  dev/staging/prod. `PORT` comes from the platform; URL-bearing vars
  (`ISSUER`, `BASE_URL`, `FRONTEND_BASE_URL`, `OAUTH2_FIRST_PARTY_REDIRECT_URI`,
  `PASSKEY_RP_ID`, `PASSKEY_ORIGIN`) must point at the public origin.
- **State.** Users, sessions, and the JWT keyring live under `/app/data`
  (`STORAGE_PATH` / `keys_dir`). Mount a volume there, or set
  `STORAGE_BACKEND=s3|gcs|abfs` for serverless (see `repositories/file/`).
- Both images run as a non-root user (`USER appuser`) and ship a `HEALTHCHECK`
  against `/health`. CI (`container-smoke` job) builds the image and verifies
  SPA routes, hashed assets, OIDC discovery, API-404 behavior, and `$PORT`
  injection.

## Cache Backends

`backend/authglow/core/cache.py` exposes named asynchronous cache namespaces
through the `CacheBackend` protocol. `InMemoryCacheBackend` uses bounded TTL
eviction for local and test deployments; `RedisCacheBackend` uses the optional
`redis.asyncio` client for shared cache state across workers. Select the
implementation with `CACHE_BACKEND=memory|redis` and configure `REDIS_URL` when
using Redis. Services depend only on the namespace facade, not on either
backend implementation.

## Demo Mode

Demo mode is an **intentional public sandbox** for letting anonymous visitors
log in and try the product. It is **orthogonal to `app_env`** — a demo
deployment keeps `app_env=production`, so every production security validator
(SECRET_KEY strength, OAuth2 defaults, DEBUG) still applies. Demo mode adds two
behaviours on top:

1. **Seeded demo admin** — on startup the lifespan (`backend/main.py`) calls
   `seed_demo_user()` (`backend/authglow/services/demo.py`), which creates (or
   refreshes) the well-known demo user (`demo_user_email`, default
   `admin@example.com`) with `read/write/admin` scope. The password is generated
   at boot with `secrets.token_urlsafe(16)` and rotates on every restart; it is
   **never logged or persisted**. The seed is idempotent: on a stateless demo
   instance (no disk, e.g. Render free tier) the user is recreated after every
   reset without needing the setup token.
2. **Warning banner + demo credentials** — `GET /api/meta`
   (`backend/authglow/api/meta.py`, public, rate-limited `20/minute`) returns
   `demo_mode`, `demo_banner_text`, and — only when `demo_mode=true` — the demo
   email + boot-time password. The frontend surfaces a `warning` `Banner` on the
   login page, the OAuth authorize page, and inside `AppShell` for authenticated
   users.

Security rationale (why this is not a hole): the demo credential is rotated on
every boot (self-expiring), demo mode is off by default, and the intended
deployment has no persistent storage — a compromised demo admin cannot cause
lasting damage because all state is wiped on the next restart. Enable with
`demo_mode=true` (plus optional `demo_banner_text` / `demo_user_email`).

## Data Flow

### Backend: Request Lifecycle

```
HTTP Request
  │
  ▼
Middleware stack (applied in order):
  CORSMiddleware → ProxyHeaders → SlowAPI (rate limit)
  → SecurityHeaders (CSP/HSTS) → MaxBodySize → HTTPS enforcement → RequestID
  │
  ▼
FastAPI Router (api/<module>.py)
  @limiter.limit(...)       # rate limit
  Depends(get_<service>)    # dependency injection
  async def handler(...)    # parse input, delegate to service, return response
  │
  ▼
Service Layer (services/<module>.py)
  await self._user_repo.get_by_email(email)   # validate
  await self._token_repo.create(token)        # persist
  async with self._lock("user:<id>"):         # cross-entity coordination
  │
  ▼
Repository Layer (repositories/file/<entity>.py)
  await self._read_json(...)    # fsspec read
  await self._write_json_atomic(...)  # tmp+rename atomic write
  encrypt/decrypt PII fields   # if applicable (AES-256-GCM)
  │
  ▼
Storage (local filesystem, S3, GCS, Azure Blob via fsspec)
```

### Frontend: Protected Route Flow

```
User navigates to /dashboard
  │
  ▼
ProtectedRoute component
  1. Wait Zustand hydration (_hydrated)
  2. GET /api/users/me (always, to validate persisted state)
     ├── 200 → render children (AppShell > DashboardPage)
     └── 401 → attempt refresh: POST /api/auth/refresh
            ├── success → retry /api/users/me
            └── failure → dispatch auth:session-expired → redirect /auth/login
  │
  ▼
Page component
  useApiQuery<T>(['dashboard'], '/api/admin/stats')   # TanStack Query
  → api.ts auto-attaches credentials, handles 401 auto-refresh
```

## Architectural Principles

1. **Protocol-driven repositories** — Services depend on Protocol contracts, not concrete implementations. Adding a new storage backend (Postgres, Redis) requires only new `repositories/<backend>/` files — zero changes to services or API.

2. **Cross-entity coordination in services** — Atomicity across multiple entities (e.g., User + EmailIndex + FederatedIdentity) is enforced by `named_lock()` inside the service, not in repositories.

3. **Frontend state split** — Zustand for client state (auth, toasts), TanStack Query for server state (caching, refetching). HTTP-only cookies for auth tokens.

4. **Security-first** — PII encrypted at rest (AES-256-GCM), bcrypt for credentials, RS256 JWT with auto-rotation, CSP/HSTS/CORS middleware, rate limiting, account lockout.

5. **All filesystem access goes through fsspec** — the `BaseFileRepository` base class owns the fsspec filesystem selection (`storage_backend`) and the `AsyncFileSystem` wrapper. Direct `os.path` / `open()` in repository code is a violation. Every entity, including the JWT keyring (`repositories/file/keystore.py`), rides on fsspec via `BaseFileRepository` and honours `STORAGE_BACKEND` like the rest. The keyring uses a `_version` field in `keyring.json` for object-store atomicity (CAS via `_write_json_versioned`).

6. **CPU-bound work off the event loop** — bcrypt (`services/password.py:hash_password_async` / `verify_password_async`) and fsspec I/O (`core/async_io.py:AsyncFileSystem`) are offloaded to the default thread pool via `asyncio.to_thread`. All async request handlers must use the `*_async` variants of these helpers. The sync `hash_password` / `verify_password` remain available for CLI scripts and offline jobs.

7. **Default-safe enforcement** — AuthGlow is hardened at the framework layer, not at the call site. Examples: PKCE enforced for every authorization-code flow (`enforce_pkce=True`), implicit grant rejected at the model layer, ROPC rejected at the token endpoint, refresh-token rotation with reuse-detection family-revocation, **RFC 9207 `iss` parameter on every authorization response** (success and error, including consent- and MFA-completed flows — mix-up mitigation / FAPI 2.0 prerequisite, advertised via `authorization_response_iss_parameter_supported`), **audience/ownership binding shared by revocation and introspection** (RFC 7662 §2.2: aud-bearing tokens only to their audience, aud-less tokens only to the first-party client — unauthorized introspections answer `{"active": false}`, never an error), **refresh tokens gated on `offline_access`** (OIDC Core §11: the `authorization_code` and `device_code` branches issue a refresh token only when the granted scopes include `offline_access` — access-token-only response otherwise, no error; the first-party dashboard requests it via `FIRST_PARTY_OAUTH_SCOPES`), and **API-key BOPLA + IP allowlist enforced by default** (see "API Key Hardening" below). New features must follow the same pattern: declare a policy, enforce it in the service, not in the route handler.

8. **Multi-replica JWT keyring coherence** — the process-wide `JWTService` snapshot (`core/jwt_singleton.py`) is invalidated in-process by `rotate_keys`/`revoke_key` and, additionally, re-validated by a TTL staleness probe: every `jwt_keyring_refresh_seconds` (default 60, `0` disables) `get_jwt_service()` re-reads `keyring.json` via `KeyStoreRepository.read_keyring_fresh()` (cheap JSON index read — no PEM reads, no AES decrypt) and rebuilds the snapshot when another replica rotated, revoked, or bootstrapped a key. Because every auth path and the JWKS endpoints go through `get_jwt_service()`, a single probe point bounds cross-replica incoherence to one interval. Concurrent cold boots converge via the CAS on `_version` (`bootstrap_if_missing` reloads and accepts the winner's keyring on `ConcurrentWriteError`).

## API Key Hardening

Two material gaps were closed in a single hardening pass:

- **BOPLA scope-subset enforcement** (OWASP API3:2023) — `services/api_key.py:_enforce_scope_subset(requested, caller_scopes, is_admin)` is invoked from `create_key` and `update_key`. Admins bypass; non-admin callers can only mint or update a key with scopes that are a strict subset of their own. Filtered scopes are logged at `warning` severity and surfaced in the create response as `requested_scopes / granted_scopes / filtered_scopes` so the SPA can render a UX warning.
- **IP allowlist enforced on the real-auth path** — `services/api_key.py:validate_and_track(key, ip, ua)` is the single, race-safe entry point for API-key authentication. It replaces the old `validate_key` + `record_usage` pair (which only the second one updated stats and neither one enforced `allowed_ips`). Both `get_current_user` and `/api/token/api-key` route through it. An empty `allowed_ips` list means "no restriction"; any non-empty list is **fail-closed** (an `ip_address=None` request is rejected).

The POST response model `APIKeyCreateResponse` extends `APIKeyWithSecret` with the three scope-transparency fields. The wire format is backward-compatible: existing clients that ignore the new fields continue to work.

## Key Files

| File                                                | Why important                                                                             |
|-----------------------------------------------------|-------------------------------------------------------------------------------------------|
| `backend/main.py`                                   | All middleware registration and router mounts                                             |
| `backend/authglow/core/config.py`                   | `Settings` class — all env vars read here                                                 |
 | `backend/authglow/repositories/protocols.py`        | All storage contracts (32 Protocols)                                                      |
 | `backend/authglow/repositories/dependencies.py`     | Factory functions (one per entity)                                                        |
 | `backend/authglow/services/user.py`                 | Canonical service: cross-entity coordination pattern                                      |
 | `backend/authglow/services/claim_policy.py`         | Per-client claim policy: turns declarative rules into namespaced JWT claims (OIDC §5.1.2) |
 | `backend/authglow/models/claim_policy.py`           | Pydantic schemas + built-in templates (rbac-roles, user-tenant, ...)                      |
 | `backend/authglow/api/device_auth.py`               | Device Authorization Grant (RFC 8628) endpoints + verification UI API                     |
 | `backend/authglow/api/claim_policy.py`              | Claim policy CRUD per client + admin templates                                            |
 | `backend/authglow/services/dpop.py`                 | DPoP proof verification (RFC 9449), `cnf`/`ath` binding                                   |
 | `backend/authglow/services/client_jwt_auth.py`      | `client_secret_jwt` / `private_key_jwt` client auth (RFC 7523)                            |
 | `backend/authglow/services/acr.py`                  | ACR/AMR computation for ID tokens                                                         |
 | `backend/authglow/services/auth/token_blacklist.py` | Access-token `jti` blacklist (logout, revoke-all, MFA session replay)                     |
 | `backend/authglow/services/rate_limit_config.py`    | Admin rate-limit config: persists + live-patches the slowapi limiter (enabled + overrides) |
 | `backend/authglow/services/settings_override.py`    | Admin `Settings` overrides: persists + `setattr`s the live `Settings` singleton           |
 | `backend/authglow/api/admin_settings.py`            | Admin settings GET/PATCH + rate-limits GET/PUT config endpoints                           |
| `backend/authglow/api/meta.py`                      | Public `GET /api/meta` (demo mode banner + credentials)                                   |
| `backend/authglow/services/demo.py`                 | Idempotent demo-admin seed (boot-time password, never logged)                             |
| `frontend/src/App.tsx`                              | All routes, providers, guards                                                             |
| `frontend/src/lib/api.ts`                           | HTTP client with auto-refresh, 429 handling, session-expired dispatch                     |
| `frontend/src/lib/constants.ts`                     | `ROUTES` object and `API_URL`                                                             |

## Claim Policy System (OIDC §5.1.2 namespacing)

Per-OAuth2-client declarative rules that decide which custom
claims (RBAC roles, RBAC permissions, user attributes, static
values) are embedded in access tokens / ID tokens / UserInfo
responses, and where the values come from.

**Layout**

* Model: `authglow/models/claim_policy.py` — `ClaimRule`,
  `ClientClaimPolicy`, `BUILTIN_TEMPLATES`,
  `OIDC_STANDARD_CLAIMS` whitelist.
* Repository: `authglow/repositories/file/claim_policy.py` —
  one JSON file per `client_id` under
  `<storage_path>/client_claim_policies/<client_id>.json`.
* Service: `authglow/services/claim_policy.py` —
  `ClaimPolicyService.build_claims(user, client_id, scopes,
  target) -> dict`. Reads RBAC roles + permissions for the
  user, applies the saved policy rules, filters by
  `target` (`ACCESS_TOKEN` / `ID_TOKEN` / `USERINFO`) and
  `required_scope`, returns the extra-claims dict to merge
  into the token payload.
* JWT plumbing: `authglow/services/jwt.py` —
  `create_access_token` and `create_id_token` accept
  `extra_claims: Optional[Dict[str, Any]]`. The JWT service
  silently filters reserved claims (`iss`, `sub`, `aud`,
  `exp`, `iat`, `jti`, `azp`, `cnf`, `token_type`) to keep
  the cryptographic anchors under its sole control.
  `decode_token` populates `TokenData.extra_claims` with
  every non-reserved payload key.

**Default behaviour** (no saved policy, no `client_id` —
applies to first-party flows: password login, API-key
exchange, refresh, passkey, federation, MFA): the
namespaced RBAC roles + permissions claim pair is emitted
into the access token, against
`settings.claim_namespace` (default
`https://authglow.example.com/claims`).

**Reserved-claim namespacing rule** (OIDC §5.1.2): every
non-OIDC-standard claim name MUST be a URI. Enforced at
the model layer by `_validate_claim_name` — plain claim
names like `roles`, `org_id`, `plan` are
rejected unless they are in the `OIDC_STANDARD_CLAIMS`
whitelist (which only contains the OIDC Core / RFC 9068 /
RFC 9449 standard names).

## Audit Logging

AuthGlow implements a comprehensive, structured audit logging system via
`authglow/services/audit.py` — write-only, stdout JSON via `structlog`,
compatible with AWS CloudWatch, GCP Cloud Logging, Azure Monitor, Loki,
Elasticsearch, and other cloud logging platforms.

### Design Principles

1. **Write-only** — The app never reads audit logs back. Analysis, search, and
   retention are handled by the cloud platform. No read/delete methods exposed.
2. **Structured JSON** — Every event is a single JSON line with typed fields,
   compatible with cloud logging agents (CloudWatch Agent, Fluent Bit, OTEL
   Collector, Promtail, Filebeat).
3. **PII Protection** — Email masking (`hash`/`mask`/`none`), IP truncation
   (IPv4 `/24`, IPv6 `/48`), User-Agent truncation (256 chars). Recursive
   metadata scanning catches email/IP patterns in nested objects.
4. **Request Correlation** — `request_id` from `RequestIDMiddleware` (VAPT-042)
   propagated via `structlog.contextvars`. Multi-request flows (auth_code →
   token) use explicit `correlation_id`.
5. **OAuth2/OIDC Compliance** — Events mapped to RFC sections (6749, 6750, 7009,
   7662, 8628, 9068, 9449, OIDC Core).

### Event Categories

| Category | Events | Retention |
|----------|--------|-----------|
| `auth` | login_success, login_failed, logout, session_created, session_revoked, account_locked/unlocked | 90 days |
| `oauth2` | authorization_code_issued/redeemed, access_token_issued/refreshed/revoked, id_token_issued, refresh_token_issued/rotated/revoked, consent_granted/revoked, device_code_*, client_credentials_token_issued, token_introspected | 90 days |
| `admin` | admin_user_created/updated/deleted, admin_password_reset, admin_scope_assigned/removed, admin_mfa_reset, admin_consent_revoked, admin_token_revoked, admin_role_assigned/removed | 365 days |
| `security` | brute_force_detected, suspicious_activity, concurrent_session_limit_exceeded, rate_limit_exceeded | 730 days |
| `lifecycle` | user_registered/invited, email_verification_sent/verified, email_changed, profile_updated, password_changed/reset, account_deleted | 365 days |
| `mfa` | mfa_enabled/disabled/verified/failed, backup_codes_generated/used/failed, passkey_registered/authenticated/deleted, trusted_device_added/removed/expired | 365 days |
| `federation` | federated_login_initiated/success/failed, federated_account_linked/unlinked | 365 days |
| `api_key` | api_key_created/used/revoked/expired | 365 days |

### Key Files

| File | Purpose |
|------|---------|
| `backend/authglow/services/audit.py` | `AuditService` — write-only, structlog JSON, PII masking, sampling |
| `backend/authglow/models/audit_events.py` | `AuditEventType` enum (~60 events, 8 categories) with `category` and `default_severity` properties |
| `backend/authglow/models/audit_metadata.py` | Typed Pydantic metadata schemas per event category + `validate_metadata()` |
| `backend/authglow/models/admin.py` | `AuditLogEntry` model (extended: `session_id`, `client_id`, `correlation_id`, `event_category`) |
| `backend/authglow/core/config.py` | Audit config: `audit_enabled`, `audit_email_log_level`, `audit_sample_rate`, retention per category |
| `backend/authglow/services/user.py` | Account lockout audit in `record_failed_login` / `reset_failed_login_attempts` |

### Configuration

```python
# core/config.py
audit_enabled: bool = True
audit_email_log_level: str = "hash"  # "mask", "hash", "none" (VAPT-080: none not allowed in production)
audit_sample_rate: float = 1.0  # 0.0-1.0 for high-volume events

# Retention per category (days)
audit_retention_days_auth: int = 90
audit_retention_days_oauth2: int = 90
audit_retention_days_admin: int = 365
audit_retention_days_security: int = 730
audit_retention_days_lifecycle: int = 365
audit_retention_days_mfa: int = 365
audit_retention_days_federation: int = 365
audit_retention_days_api_key: int = 365
```

### Production Hardening

- `audit_email_log_level="none"` rejected in production (VAPT-080)
- Default `hash` level (VAPT-080: stable 16-char HMAC per email)
- Sampling for high-volume events (token refresh)
- No secrets in logs — token IDs only

### Future: Queryable UI (Phase 7)

Current implementation is write-only to stdout. For queryable admin UI:
1. Add storage backend (Elasticsearch, Loki, ClickHouse, Postgres)
2. Implement `GET /api/admin/audit-logs` with filters
3. Build `AdminAuditLogsPage.tsx` with table, filters, export
4. Real-time alerts via webhook for `critical`/`error` severity

## Maintenance

After adding, removing, or renaming a structural module (new API router, service,
repository, store, page), update the Directory Map and Quick Reference table above.
