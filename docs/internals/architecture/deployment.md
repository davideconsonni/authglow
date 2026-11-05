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
