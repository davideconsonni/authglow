"""Main FastAPI application for AuthGlow."""

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from authglow.api.auth import router as auth_router
from authglow.api.mfa import router as mfa_router
from authglow.api.admin import router as admin_router
from authglow.core.config import get_settings

# Create FastAPI app
settings = get_settings()
app = FastAPI(
    title="AuthGlow",
    description="Serverless CIAM with OAuth2 support",
    version="0.1.0",
    debug=settings.debug
)

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
