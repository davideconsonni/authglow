# Deployment, Caching & Sandbox Architecture

This document describes AuthGlow's deployment topology, container packaging, cache backends, and public sandbox demo mode.

## Single-Container Deployment

AuthGlow is designed to ship as a single container image serving both the FastAPI REST API and the compiled React SPA on a single port under a single Uvicorn process. It requires no reverse proxy (nginx), process manager, or docker-compose orchestration.

It runs unchanged on AWS ECS/Fargate, Google Cloud Run, Fly.io, Railway, Render, or any container environment injecting a `$PORT` environment variable.

### Build Targets

- **Full Application (`Dockerfile`)**:
  - Multi-stage build: compiles the SPA using `node:26-slim`.
  - Final stage copies `frontend/dist` to `FRONTEND_DIST_DIR=/app/frontend/dist` in a `python:3.13-slim` base image.
  - Serves both API endpoints and the React single-page application from the same origin.
- **API-Only (`backend/Dockerfile`)**:
  - Python-only image serving the pure REST API and OpenAPI Swagger documentation.
  - Used when the frontend is hosted on a separate CDN or external origin.

### Single-Origin Routing

- The frontend is built with relative API paths (`API_URL = import.meta.env.VITE_API_URL ?? ''`).
- API and SPA share the exact same origin; cookies and CSRF tokens avoid cross-origin and third-party cookie restrictions.
- In `backend/main.py`, static assets are mounted under `/assets`, while a catch-all route `/{path:path}` serves the React entry point (`index.html`) for client-side routing.
- Reserved server routes (`/api`, `/docs`, `/.well-known`, `/oauth2/*`) preserve standard 404 responses for unmapped paths.

### Immutable Configuration

Every setting is configurable via environment variables mapped to the Pydantic `Settings` model:
- `PORT`: Injected by hosting platforms.
- `STORAGE_PATH` / `KEYS_DIR`: Directory for file repositories and keyring (mount a volume for persistence).
- `STORAGE_BACKEND`: `file` (local), `s3`, `gcs`, or `abfs` via fsspec.
- Public URLs: `ISSUER`, `BASE_URL`, `FRONTEND_BASE_URL`, `PASSKEY_RP_ID`, `PASSKEY_ORIGIN`.

Both Docker images run as an unprivileged user (`USER appuser`) and include a native `HEALTHCHECK` against `/health`.

### Process Scaling

By default every container runs a **single Uvicorn process** (one event loop). The images expose
`UVICORN_WORKERS` (default `1`), passed to `uvicorn --workers`, so multiple worker processes can run
inside one container — deliberately opt-in, not a default.

- **Replicas are the recommended path.** Cloud Run, Fly.io, Railway, ECS and friends scale by running
  more instances of the image; several platforms (Cloud Run first) allocate CPU per instance in a way
  that makes in-container workers useless. The app is already built for multiple independent
  processes sharing storage: JSON record writes are atomic and carry an optimistic `_version` for
  compare-and-swap, and the JWT keyring and root-index caches re-probe the storage layer on a fixed
  interval, so no in-process coordination is required across replicas or workers.
- **Before raising `UVICORN_WORKERS`**, account for the state that is per-process and would be
  multiplied by N:
  - In-memory caches (`CACHE_BACKEND=memory`) become N private copies with no shared invalidation —
    set `CACHE_BACKEND=redis` instead.
  - Rate-limiter counters are per-process, so an effective limit becomes N × the configured one —
    use a shared storage backend before relying on limits.
  - Background maintenance tasks (blacklist sweeper, admin-config refresher) run once per process;
    they are idempotent, but N× the same work.
- **Storage-level races behave like multi-replica:** the read-modify-write on the refresh-token index
  files is serialized by an in-process lock plus atomic writes. That is safe between workers on the
  same host only as much as it is between replicas on a shared volume — increasing workers increases
  the number of concurrent writers, it does not add cross-process mutual exclusion.

`UVICORN_WORKERS` is read by the images' `CMD`; the application settings do not consume it.

## Cache Backends

AuthGlow abstracts cache operations in `backend/authglow/core/cache.py` via the `CacheBackend` protocol:

- **`InMemoryCacheBackend`**: Local bounded TTL eviction cache for single-process and test environments.
- **`RedisCacheBackend`**: Shared asynchronous cache using `redis.asyncio` for multi-worker and multi-replica deployments.
- **Configuration**: Selected via `CACHE_BACKEND=memory|redis` and `REDIS_URL`. Business services consume the namespace facade and remain agnostic of the underlying backend.

## Demo Sandbox Mode

Demo mode is an isolated public sandbox mode allowing anonymous visitors to explore AuthGlow without pre-provisioned credentials.

- **Production Security Maintained**: Demo mode is orthogonal to `app_env`. A demo instance runs with `app_env=production`, ensuring all cryptographic and OAuth2 validators remain enforced.
- **Ephemeral Credentials**: On startup, `seed_demo_user()` creates or resets a demo user (`admin@example.com`) assigned the "Authglow Administrator" RBAC role. The password is generated in memory using `secrets.token_urlsafe(16)` and is **never persisted or logged**.
- **Public Meta Endpoint**: `GET /api/meta` returns `demo_mode=true` and temporary credentials to render a warning banner in the SPA.
- **Stateless Isolation**: When deployed on ephemeral infrastructure (e.g. Render free tier), state resets on container restart, eliminating lasting impact from sandbox activity.
