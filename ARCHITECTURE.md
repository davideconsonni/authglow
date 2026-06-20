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
| New API constant / route path          | `frontend/src/lib/constants.ts`                                                                        |
| HTTP client change                     | `frontend/src/lib/api.ts`                                                                              |

## Directory Map

```
authglow/
├── AGENTS.md                  # Code style, naming, test commands
├── ARCHITECTURE.md            # This file — structural map
├── DESIGN.md                  # Visual design system (colors, typography)
├── FEATURES.md                # Complete feature catalog
├── SECURITY.md                # Vulnerability reporting policy
├── docs/                      # Integration guides, post-mortems, plans
├── backend/
│   ├── main.py                # App entry: FastAPI(), middleware stack, router mounts
│   ├── .env.example           # All configurable settings template
│   └── authglow/
│       ├── api/               # 16 FastAPI routers (HTTP layer, one per domain)
│       ├── services/          # 27 service classes (business logic, cross-entity coordination)
│       ├── repositories/      # Storage abstraction (Protocols → File impls)
│       │   ├── protocols.py   # 25 Protocol contracts (@runtime_checkable)
│       │   ├── exceptions.py  # EntityNotFoundError, EntityAlreadyExistsError
│       │   ├── dependencies.py# Factory functions: get_<entity>_repository()
│       │   └── file/          # 23 File*Repository impls (JSON on disk via fsspec)
│       ├── models/            # Pydantic request/response/domain models
│       ├── core/              # config.py, crypto.py, cache.py, concurrency.py, permissions.py
│       └── middleware/        # Security headers, HTTPS enforcement, request size, proxy
├── frontend/
│   ├── src/
│   │   ├── App.tsx            # Routing, provider stack, route guards
│   │   ├── pages/             # Route-level components (auth/, admin/)
│   │   ├── components/        # ui/ (shadcn), layout/, shared/, auth/, admin/
│   │   ├── stores/            # Zustand: authStore, toastStore, playgroundStore
│   │   ├── hooks/             # useAuth, useApi, useTheme, useDocumentTitle
│   │   ├── lib/               # api.ts (HTTP client), constants.ts (ROUTES, API_URL), utils.ts
│   │   └── styles/            # globals.css (Tailwind + design tokens)
│   └── e2e/                   # Playwright E2E specs
└── images/                    # README screenshots
```

## Data Flow

### Backend: Request Lifecycle

```
HTTP Request
  │
  ▼
Middleware stack (applied in order):
  CORSMiddleware → ProxyHeaders → SlowAPI (rate limit)
  → SecurityHeaders (CSP/HSTS) → MaxBodySize → HTTPS enforcement
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

## Key Files

| File                                            | Why important                                                         |
|-------------------------------------------------|-----------------------------------------------------------------------|
| `backend/main.py`                               | All middleware registration and router mounts                         |
| `backend/authglow/core/config.py`               | `Settings` class — all env vars read here                             |
| `backend/authglow/repositories/protocols.py`    | All storage contracts (25 Protocols)                                  |
| `backend/authglow/repositories/dependencies.py` | Factory functions (one per entity)                                    |
| `backend/authglow/services/user.py`             | Canonical service: cross-entity coordination pattern                  |
| `frontend/src/App.tsx`                          | All routes, providers, guards                                         |
| `frontend/src/lib/api.ts`                       | HTTP client with auto-refresh, 429 handling, session-expired dispatch |
| `frontend/src/lib/constants.ts`                 | `ROUTES` object and `API_URL`                                         |

## Maintenance

After adding, removing, or renaming a structural module (new API router, service,
repository, store, page), update the Directory Map and Quick Reference table above.
