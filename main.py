"""Main FastAPI application for AuthGlow."""

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from authglow.api.auth import router as auth_router
from authglow.api.mfa import router as mfa_router
from authglow.api.admin import router as admin_router
from authglow.api.passkey import router as passkey_router
from authglow.api.oauth_client import router as oauth_client_router
from authglow.api.api_key import router as api_key_router
from authglow.api.password_reset import router as password_reset_router
from authglow.api.email_verification import router as email_verification_router
from authglow.api.oauth_consent_handler import router as oauth_consent_router
from authglow.api.oauth2_advanced import router as oauth2_advanced_router
from authglow.api.rbac import router as rbac_router
from authglow.api.user_profile import router as user_profile_router
from authglow.core.config import get_settings

# Create FastAPI app
settings = get_settings()

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per hour"])

app = FastAPI(
    title="AuthGlow",
    description="Serverless CIAM with OAuth2 support",
    version="0.1.0",
    debug=settings.debug
)

# Add rate limiter to app state
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="authglow/static"), name="static")

# Include routers
app.include_router(auth_router, tags=["Authentication"])
app.include_router(mfa_router, tags=["MFA"])
app.include_router(admin_router, tags=["Admin"])
app.include_router(passkey_router, tags=["Passkeys"])
app.include_router(oauth_client_router, tags=["OAuth2 Clients"])
app.include_router(api_key_router, tags=["API Keys"])
app.include_router(password_reset_router, tags=["Password Reset"])
app.include_router(email_verification_router, tags=["Email Verification"])
app.include_router(oauth_consent_router, tags=["OAuth2 Consent"])
app.include_router(oauth2_advanced_router, tags=["OAuth2 Advanced"])
app.include_router(rbac_router, tags=["RBAC"])
app.include_router(user_profile_router, tags=["User Profile"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "AuthGlow - Serverless CIAM",
        "version": "0.1.0",
        "docs": "/docs"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug
    )
