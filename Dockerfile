# syntax=docker/dockerfile:1.7
# =============================================================================
# AuthGlow — single portable image (FastAPI backend + built SPA frontend).
#
# One container, one port, no reverse proxy and no extra services needed. It
# runs unchanged on Cloud Run, GKE, EKS, ECS, any Docker host — anything that
# runs a container and injects a $PORT env var. The FastAPI app serves the
# API routes AND the pre-built React app (single-origin, cookies just work).
#
#   docker build  -t authglow .
#   docker run    -p 8080:8080 -e PORT=8080 -e SECRET_KEY=... authglow
# =============================================================================

# ---- Stage 1: build the frontend -------------------------------------------
# Matches the `engines` requirement in frontend/package.json (node >=26.7.0).
FROM node:26-slim AS frontend-build
WORKDIR /app/frontend

COPY frontend/package*.json ./
RUN npm ci --no-audit --no-fund

COPY frontend/ ./
# VITE_API_URL is intentionally NOT set: the SPA is built with the relative,
# same-origin API base (see frontend/src/lib/constants.ts), so this single
# image works behind any public URL without a rebuild.
RUN npm run build

# ---- Stage 2: runtime (FastAPI + SPA assets) --------------------------------
FROM python:3.13-slim AS runtime
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PORT=8080 \
    FRONTEND_DIST_DIR=/app/frontend/dist

# System deps for build/ssh wheels are pulled by pip; Python only deps below.
COPY backend/requirements.txt ./
RUN pip install -r requirements.txt

COPY backend/ ./
COPY --from=frontend-build /app/frontend/dist /app/frontend/dist

# Runtime state (users, keys, sessions) is volume-mounted here or on GCS.
RUN mkdir -p /app/data /app/data/keys \
    && chmod 700 /app/data \
    && useradd --system --create-home --uid 1000 appuser \
    && chown -R appuser:appuser /app/data

# Run as an unprivileged user: a container escape must not yield host root
# (VAPT-095). The app only ever writes under /app/data.
USER appuser

EXPOSE 8080

# $PORT comes from the platform (Cloud Run, Railway…) or is set at runtime.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD python -c "import os,urllib.request;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8080')+'/health',timeout=2)"

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT}"]