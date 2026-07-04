"""Main FastAPI application for AuthGlow."""

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.middleware import SlowAPIMiddleware

from authglow.api.admin import router as admin_router
from authglow.api.admin_settings import router as admin_settings_router
from authglow.api.api_key import router as api_key_router
from authglow.api.auth import router as auth_router
from authglow.api.claim_policy import router as claim_policy_router
from authglow.api.device_auth import router as device_auth_router
from authglow.api.email_verification import router as email_verification_router
from authglow.api.federation import router as federation_router
from authglow.api.mfa import router as mfa_router
from authglow.api.oauth2_advanced import router as oauth2_advanced_router
from authglow.api.oauth_client import router as oauth_client_router
from authglow.api.oauth_consent_handler import router as consent_router
from authglow.api.oidc import router as oidc_router
from authglow.api.passkey import router as passkey_router
from authglow.api.password_reset import router as password_reset_router
from authglow.api.rbac import router as rbac_router
from authglow.api.setup import router as setup_router
from authglow.api.user_profile import router as user_profile_router
from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware
from authglow.middleware.proxy_headers import ProxyHeadersMiddleware
from authglow.middleware.request_body_size import MaxBodySizeMiddleware
from authglow.middleware.request_id import RequestIDMiddleware
from authglow.middleware.security_headers import SecurityHeadersMiddleware
from authglow.services.auth.token_blacklist import token_blacklist

settings = get_settings()

# Default ``ThreadPoolExecutor`` size used by ``asyncio.to_thread`` for
# off-loading blocking I/O (bcrypt, fsspec, PII decrypt, sync RSA parse).
# CPython's default is ``min(32, cpu+4)`` workers; we widen it to
# ``min(32, cpu*4)`` (Tier 2.1) so that bursts of concurrent
# ``/oauth2/token`` requests — each doing bcrypt + 5 PII decrypts — do
# not queue behind an undersized pool. Capped at 32 to stay within
# the documented asyncio ``ThreadPoolExecutor`` ceiling.
_DEFAULT_EXECUTOR_WORKERS = min(32, (os.cpu_count() or 1) * 4)


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
    yield


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
app.include_router(oidc_router, tags=["OpenID Connect"])
app.include_router(oauth2_advanced_router, tags=["OAuth2 Advanced"])
app.include_router(federation_router, tags=["Federation"])
app.include_router(device_auth_router, tags=["Device Authorization"])
app.include_router(claim_policy_router, tags=["Claim Policy"])


@app.get("/")
async def root():
    return {"status": "ok", "app": "AuthGlow API"}


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=settings.debug)
