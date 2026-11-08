# ARCHITECTURE.md

Quick orientation: where things live and how they connect.
For code style, naming, and test commands see `AGENTS.md`.

## Quick Reference — Where to Add What

| Task | Place |
|---|---|
| New API endpoint | `backend/authglow/api/<module>.py` → define `router`, then `app.include_router()` in `backend/main.py` |
| New business logic | `backend/authglow/services/<module>.py` — one class per file |
| New data model / schema | `backend/authglow/models/<module>.py` — Pydantic model |
| New storage backend | `backend/authglow/repositories/<backend>/<entity>.py` + 1 line in `dependencies.py` |
| Change config / env vars | `backend/authglow/core/config.py` (`Settings` model) + `.env.example` |
| New middleware | `backend/authglow/middleware/<name>.py` + register in `main.py` |
| New core utility (crypto, cache, etc.) | `backend/authglow/core/<module>.py` |
| New test (unit) | `backend/tests/unit/test_<module>.py` |
| New test (integration) | `backend/tests/integration/test_<flow>.py` |
| New page (frontend) | `frontend/src/pages/<PageName>.tsx` + route in `App.tsx` + path in `lib/constants.ts` |
| New page (admin, lazy-loaded) | `frontend/src/pages/admin/<AdminPage>.tsx` + `React.lazy()` in `App.tsx` |
| New shared component | `frontend/src/components/shared/<Component>.tsx` |
| New auth component (forms, etc.) | `frontend/src/components/auth/<Component>.tsx` |
| New UI primitive | `frontend/src/components/ui/<name>.tsx` (shadcn/ui pattern) |
| New state store | `frontend/src/stores/<name>Store.ts` → Zustand |
| New API hook | `frontend/src/hooks/use<Name>.ts` → wraps `useApiQuery`/`useApiMutation` |
| New claim policy rule (backend) | `backend/authglow/models/claim_policy.py` (template or `ClaimRule` + service `apply_template`) |
| New custom claim resolver | `register_claim_resolver("<name>", async_fn)` in `backend/authglow/services/claim_policy.py` |
| New phone verification provider | `backend/authglow/services/phone/<name>.py` → subclass `PhoneVerificationProvider`, add to `factory.py` |
| New email provider | `backend/authglow/services/email/<name>.py` → subclass `EmailProvider`, register in `factory.py` |
| HTTP client change | `frontend/src/lib/api.ts` |

## Directory Map

```
authglow/
├── AGENTS.md                  # Bootstrap instructions, commands, testing rules
├── ARCHITECTURE.md            # Structural orientation & component map
├── DESIGN.md                  # Visual design system (tokens, colors)
├── SECURITY.md                # Vulnerability reporting policy
├── Dockerfile                 # Single-container image (FastAPI + built SPA)
├── docs/                      # Modular documentation & guides (3 pillars)
│   ├── product/               # Product docs (getting-started, reference, flows, guides)
│   ├── project/               # Project ops (plans, vapt, analysis)
│   └── internals/             # Engineering deep-dives (architecture, security, guides)
├── .claude/skills/            # Portable agent skills (Agent Skills standard)
├── backend/
│   ├── main.py                # App entry: FastAPI(), middleware stack, router mounts, SPA serving
│   └── authglow/
│       ├── api/               # FastAPI routers (HTTP layer)
│       ├── services/          # Business logic, cross-entity coordination
│       ├── repositories/      # Storage abstraction (Protocols -> File impls)
│       ├── models/            # Pydantic request/response/domain models
│       ├── core/              # Config, crypto, cache, rate limits, async I/O
│       └── middleware/        # Security headers, CSRF, request ID, proxy headers
└── frontend/src/
    ├── App.tsx                # Routing, provider stack, route guards
    ├── pages/                 # Route components (auth/, admin/)
    ├── components/            # ui/, layout/, shared/, auth/, admin/
    ├── stores/                # Zustand client stores
    ├── hooks/                 # Custom React hooks
    └── lib/                   # api.ts, constants.ts, utils.ts
```

## Core Data Flows

### Backend: Request Lifecycle

```
HTTP Request
  │
  ▼
Middleware stack: CORSMiddleware → ProxyHeaders → SlowAPI → SecurityHeaders → MaxBodySize → HTTPS → RequestID
  │
  ▼
FastAPI Router (api/<module>.py) — auth validation, schema parsing, dependency injection
  │
  ▼
Service Layer (services/<module>.py) — business logic, cross-entity named_lock() coordination
  │
  ▼
Repository Layer (repositories/file/<entity>.py) — Pydantic serialization, atomic fsspec I/O
  │
  ▼
Storage (Local filesystem, S3, GCS, Azure Blob via fsspec)
```

### Frontend: Protected Route Flow

```
User navigates to route
  │
  ▼
ProtectedRoute component
  1. Wait Zustand hydration (_hydrated)
  2. GET /api/users/me (validate persisted state)
     ├── 200 → render page components
     └── 401 → attempt POST /api/auth/refresh (success: retry /me, failure: redirect /auth/login)
  │
  ▼
Page component (TanStack Query for remote state caching via api.ts)
```

## Architectural Principles

1. **Protocol-Driven Repositories**: Services depend on `typing.Protocol` contracts, never concrete storage classes. Storage backends are selected via `Settings.repository_backend` in `repositories/dependencies.py`.
2. **Cross-Entity Atomicity in Services**: Multi-entity coordination is managed via `named_lock()` in the service layer, keeping repositories decoupled.
3. **State Split in Frontend**: Zustand handles client-only state; TanStack Query manages server cache and data fetching.
4. **Security by Default**: All OAuth2 authorization-code flows enforce PKCE (`enforce_pkce=True`). Refresh tokens rotate with family revocation. RFC 9207 `iss` included in all authorization responses.
5. **Offload CPU-Bound Operations**: Password hashing (bcrypt) and filesystem I/O run off the main event loop via `asyncio.to_thread`.
6. **Multi-Replica Keyring Coherence**: The `JWTService` singleton re-probes `keyring.json` periodically (`jwt_keyring_refresh_seconds`) to reload foreign rotations across replicas.

## Specialized Documentation (Deep Dives)

Detailed architectural specifications are organized into standalone documents:

| Topic | Document | Content |
|---|---|---|
| **Repository Pattern** | [`docs/internals/architecture/repository-pattern.md`](docs/internals/architecture/repository-pattern.md) | 36 protocols, fsspec base class, pluggable backends, LRU bypass |
| **RBAC Authorization** | [`docs/internals/architecture/rbac-authorization.md`](docs/internals/architecture/rbac-authorization.md) | Permission vocabulary, Administrator role, anti-lockout rules |
| **Claim Policies** | [`docs/internals/architecture/claim-policy.md`](docs/internals/architecture/claim-policy.md) | OIDC §5.1.2 namespacing, custom resolvers, token claims |
| **Deployment & Sandbox** | [`docs/internals/architecture/deployment.md`](docs/internals/architecture/deployment.md) | Single-container Docker, cache backends (Redis/Memory), Demo mode |
| **Audit Logging** | [`docs/internals/guides/audit-logging.md`](docs/internals/guides/audit-logging.md) | Write-only JSON format, event taxonomy, PII masking, CloudWatch/Loki |
| **Secret Management** | [`docs/internals/security/secret-management.md`](docs/internals/security/secret-management.md) | GitGuardian rules, secret generation, rotation policy, test fixtures |
| **OAuth2 / OIDC Flows** | [`docs/product/flows/README.md`](docs/product/flows/README.md) | RFC flow guides (PKCE, PAR, DPoP, Device Grant, Introspection) |

## Maintenance

After adding, removing, or renaming a structural module (new API router, service, repository, store, page), update the Quick Reference table and Directory Map above.
