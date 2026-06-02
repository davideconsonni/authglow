"""Main FastAPI application for AuthGlow."""

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from fastapi.templating import Jinja2Templates

from slowapi.middleware import SlowAPIMiddleware

from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.middleware.security_headers import SecurityHeadersMiddleware
from authglow.middleware.request_body_size import MaxBodySizeMiddleware
from authglow.middleware.https_enforcement import HttpsEnforcementMiddleware
from authglow.api.auth import router as auth_router
from authglow.api.user_profile import router as user_profile_router
from authglow.api.mfa import router as mfa_router
from authglow.api.passkey import router as passkey_router
from authglow.api.password_reset import router as password_reset_router
from authglow.api.email_verification import router as email_verification_router
from authglow.api.admin import router as admin_router
from authglow.api.api_key import router as api_key_router
from authglow.api.oauth_client import router as oauth_client_router
from authglow.api.rbac import router as rbac_router
from authglow.api.oidc import router as oidc_router
from authglow.api.setup import router as setup_router
from authglow.api.oauth_consent_handler import router as consent_router
from authglow.api.oauth2_advanced import router as oauth2_advanced_router

# Load settings. Key generation is now handled within the Settings class.
settings = get_settings()

app = FastAPI(
    title=settings.app_name,
    description="AuthGlow - A lightweight, self-hostable CIAM and OAuth2/OIDC provider.",
    version="0.1.0",
    docs_url="/docs" if settings.enable_docs else None,
    redoc_url="/redoc" if settings.enable_docs else None,
    openapi_url="/openapi.json" if settings.enable_docs else None,
)

# Wire up rate limiter
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)


# CORS middleware - Configured from environment variables for security
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.get_cors_origins(),
    allow_credentials=settings.cors_allow_credentials,
    allow_methods=settings.get_cors_methods(),
    allow_headers=settings.get_cors_headers(),
)

# Security headers middleware - OWASP-recommended response headers
app.add_middleware(SecurityHeadersMiddleware)

# Request body size limiter - rejects payloads exceeding MAX_REQUEST_BODY_SIZE_MB
app.add_middleware(MaxBodySizeMiddleware)

# HTTPS enforcement - redirects HTTP to HTTPS in production
app.add_middleware(HttpsEnforcementMiddleware)

# Mount static files
app.mount("/static", StaticFiles(directory="authglow/static"), name="static")

# Include routers
app.include_router(setup_router, tags=["Setup"])  # Setup first for priority
app.include_router(auth_router, tags=["Authentication"])
app.include_router(mfa_router, tags=["MFA"])
app.include_router(admin_router, tags=["Admin"])
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

templates = Jinja2Templates(directory="authglow/templates")


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Landing page."""
    ui_context = settings.ui_context
    return templates.TemplateResponse(request, "landing.html", context={**ui_context})


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host=settings.host, port=settings.port, reload=settings.debug)
