"""Main FastAPI application for AuthGlow."""

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from slowapi.middleware import SlowAPIMiddleware

from authglow.api.admin import router as admin_router
from authglow.api.admin_settings import router as admin_settings_router
from authglow.api.api_key import router as api_key_router
from authglow.api.auth import router as auth_router
from authglow.api.claim_policy import router as claim_policy_router
from authglow.api.demo import router as demo_router
from authglow.api.device_auth import router as device_auth_router
from authglow.api.email_verification import router as email_verification_router
from authglow.api.error_handlers import register_global_error_handler
from authglow.api.federation import router as federation_router
from authglow.api.meta import router as meta_router
from authglow.api.mfa import router as mfa_router
from authglow.api.oauth2_advanced import router as oauth2_advanced_router
from authglow.api.oauth_client import router as oauth_client_router
from authglow.api.oauth_consent_handler import router as consent_router
from authglow.api.oauth_errors import register_oauth2_error_handler
from authglow.api.oidc import router as oidc_router
from authglow.api.passkey import router as passkey_router
from authglow.api.password_reset import router as password_reset_router
from authglow.api.rbac import router as rbac_router
from authglow.api.setup import router as setup_router
from authglow.api.user_profile import router as user_profile_router
from authglow.api.webhooks import router as webhooks_router
from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.middleware.csrf import CSRFMiddleware
from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware
from authglow.middleware.proxy_headers import ProxyHeadersMiddleware
from authglow.middleware.request_body_size import MaxBodySizeMiddleware
from authglow.middleware.request_id import RequestIDMiddleware
from authglow.middleware.security_headers import SecurityHeadersMiddleware
from authglow.services.auth.token_blacklist import token_blacklist

settings = get_settings()

logger = structlog.get_logger("authglow.audit")

# Default ``ThreadPoolExecutor`` size used by ``asyncio.to_thread`` for
# off-loading blocking I/O (bcrypt, fsspec, PII decrypt, sync RSA parse).
# CPython's default is ``min(32, cpu+4)`` workers; we widen it to
# ``min(32, cpu*4)`` (Tier 2.1) so that bursts of concurrent
# ``/oauth2/token`` requests — each doing bcrypt + 5 PII decrypts — do
# not queue behind an undersized pool. Capped at 32 to stay within
# the documented asyncio ``ThreadPoolExecutor`` ceiling.
_DEFAULT_EXECUTOR_WORKERS = min(32, (os.cpu_count() or 1) * 4)


async def _admin_config_refresher(*services) -> None:
    """Periodically re-apply persisted admin runtime configuration.

    Lets every worker (not just the one that handled the PUT) converge
    on the latest rate-limit config and settings overrides within
    ``admin_config_refresh_seconds``. Each tick re-reads the small
    config documents and re-applies them only when they actually
    changed (change detection inside the services). Errors are logged
    and swallowed: a failed refresh must never take the worker down.
    """
    interval = max(5, settings.admin_config_refresh_seconds)
    while True:
        await asyncio.sleep(interval)
        for service in services:
            try:
                await service.refresh_if_changed()
            except Exception:
                logger.warning(
                    "admin_config_refresh_failed",
                    service=type(service).__name__,
                )


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Widen the default ``ThreadPoolExecutor`` for this event loop. Must run
    # before the first ``asyncio.to_thread`` call so the new pool is used
    # by the subsequent ``startup_hydrate`` and all request handling.
    # No explicit shutdown — Python >=3.9 (``asyncio.Runner``) closes the
    # default executor when the loop closes, so HUP/SIGTERM cleans up
    # automatically.
    asyncio.get_running_loop().set_default_executor(
        ThreadPoolExecutor(max_workers=_DEFAULT_EXECUTOR_WORKERS),
    )
    await token_blacklist().startup_hydrate()

    # ------------------------------------------------------------------
    # Admin runtime configuration (rate limits + settings overrides).
    #
    # Applied BEFORE serving requests so persisted admin changes
    # survive deploys/restarts: the limiter gets its persisted enabled
    # flag and per-route overrides; the Settings singleton gets its
    # persisted admin overrides. A background refresher then re-reads
    # both documents every ``admin_config_refresh_seconds`` so every
    # node converges without a restart.
    # ------------------------------------------------------------------
    from authglow.services.rate_limit_config import RateLimitConfigService
    from authglow.services.settings_override import (
        SettingsOverrideService,
        capture_pristine,
    )

    rate_limit_config_service = RateLimitConfigService()
    rate_limit_config_service.bind_app(app)
    await rate_limit_config_service.refresh_if_changed()

    settings_override_service = SettingsOverrideService()
    # Snapshot env-derived values BEFORE overrides are applied so that
    # "remove override" can restore the env-derived value later.
    capture_pristine(settings_override_service.settings)
    await settings_override_service.refresh_if_changed()

    refresher_task = asyncio.create_task(
        _admin_config_refresher(rate_limit_config_service, settings_override_service)
    )

    # ------------------------------------------------------------------
    # Demo mode bootstrap (INTENTIONAL public sandbox — see
    # ``authglow.services.demo`` for the security rationale).
    #
    # Seeds the well-known demo admin and stores its plaintext password
    # on ``app.state`` so the rate-limited ``GET /api/meta`` endpoint can
    # expose it to anonymous visitors. The password is generated at boot
    # (rotates on every restart) and is NEVER logged.
    # ------------------------------------------------------------------
    if settings.demo_mode:
        from authglow.services.demo import seed_demo_user

        app.state.demo_password = await seed_demo_user(settings=settings)
        logger.warning(
            "DEMO_MODE_ENABLED",
            demo_user_email=settings.demo_user_email,
            demo_banner_text=settings.demo_banner_text,
            note=(
                "Public sandbox admin; password exposed via GET /api/meta only; "
                "data is ephemeral and reset on restart."
            ),
        )
    else:
        app.state.demo_password = None
    yield

    refresher_task.cancel()
    try:
        await refresher_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title=settings.app_name,
    description="AuthGlow - A lightweight, self-hostable CIAM and OAuth2/OIDC provider.",
    version="0.1.0",
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url="/redoc" if settings.enable_docs else None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
    lifespan=lifespan,
)

app.state.limiter = limiter

# RFC 6749 §5.2: protocol endpoints answer with a top-level
# {"error": ..., "error_description": ...} body instead of FastAPI's
# default {"detail": ...} envelope.
register_oauth2_error_handler(app)
register_global_error_handler(app)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.get_cors_methods(),
    allow_headers=settings.get_cors_headers(),
)

app.add_middleware(ProxyHeadersMiddleware)

app.add_middleware(SlowAPIMiddleware)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(MaxBodySizeMiddleware)
app.add_middleware(HttpsEnforcementMiddleware)
app.add_middleware(CSRFMiddleware)
# VAPT-042: RequestIDMiddleware is added LAST so it is the
# outermost wrapper. The contextvar is set before any other
# middleware or the app code runs, so every structlog
# log line emitted during the request lifecycle
# (including the audit service) carries the correlation
# ID. The response header is appended to ``http.response.start``
# on the way out, after the downstream stack has run.
app.add_middleware(RequestIDMiddleware)

app.include_router(setup_router, tags=["Setup"])
app.include_router(auth_router, tags=["Authentication"])
app.include_router(mfa_router, tags=["MFA"])
app.include_router(admin_router, tags=["Admin"])
app.include_router(admin_settings_router, tags=["Admin Settings"])
app.include_router(passkey_router, tags=["Passkeys"])
app.include_router(oauth_client_router, tags=["OAuth2 Clients"])
app.include_router(api_key_router, tags=["API Keys"])
app.include_router(password_reset_router, tags=["Password Reset"])
app.include_router(email_verification_router, tags=["Email Verification"])
app.include_router(consent_router, tags=["OAuth2 Consent"])
app.include_router(rbac_router, tags=["RBAC"])
app.include_router(user_profile_router, tags=["User Profile"])
app.include_router(webhooks_router, tags=["Webhooks"])
app.include_router(oidc_router, tags=["OpenID Connect"])
app.include_router(oauth2_advanced_router, tags=["OAuth2 Advanced"])
app.include_router(federation_router, tags=["Federation"])
app.include_router(device_auth_router, tags=["Device Authorization"])
app.include_router(claim_policy_router, tags=["Claim Policy"])
app.include_router(meta_router, tags=["Meta"])
app.include_router(demo_router, tags=["Demo"])


@app.get("/")
async def root():
    if _enable_frontend:
        index = os.path.join(_dist, "index.html")
        if os.path.isfile(index):
            return FileResponse(index)
    return {"status": "ok", "app": "AuthGlow API"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


# ---------------------------------------------------------------------------
# Single-container mode (backend + frontend): serve the built SPA.
#
# Started only when ``FRONTEND_DIST_DIR`` is set and points to a directory
# (done by the combined image). This enables the hashed ``/assets`` mount and
# a SPA catch-all for client-side routes, WITHOUT touching the API. The
# catch-all is registered last so every router above keeps matching first;
# backend-only namespaces still 404 on unknown paths instead of returning the
# HTML shell. When ``frontend_dist_dir`` is empty the block is a no-op.
# ---------------------------------------------------------------------------
_dist = settings.frontend_dist_dir
_enable_frontend = bool(_dist and os.path.isdir(_dist))
if _dist and not _enable_frontend:
    logger.warning(
        "FRONTEND_DIST_DIR is set but the directory is missing; running API-only",
        frontend_dist_dir=_dist,
    )
if _dist and os.path.isdir(_dist):
    _dist = os.path.abspath(_dist)
    _assets = os.path.join(_dist, "assets")
    if os.path.isdir(_assets):
        app.mount("/assets", StaticFiles(directory=_assets), name="assets")

    # SPA client-side pages that live under the REST /oauth2 namespace and must
    # be served by the shell; every other /oauth2 path is a server endpoint.
    _SPA_OAUTH_PAGES = {"/oauth2/authorize", "/oauth2/device/verify"}

    @app.get("/{path:path}", include_in_schema=False)
    async def spa_fallback(path: str):
        first = path.split("/", 1)[0].lower() if path else ""
        if first in ("api", "well-known", "docs", "redoc", "openapi.json") or (
            first == "oauth2" and "/" + path not in _SPA_OAUTH_PAGES
        ):
            raise HTTPException(status_code=404, detail="Not Found")
        if path and os.path.isfile(os.path.join(_dist, path)):
            return FileResponse(os.path.join(_dist, path))
        index = os.path.join(_dist, "index.html")
        if os.path.isfile(index):
            return FileResponse(index)
        raise HTTPException(status_code=404, detail="Not Found")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=settings.debug)
