"""Initial setup API endpoints."""

from fastapi import APIRouter, HTTPException, status, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, EmailStr
from typing import Optional

from authglow.models.user import User
from authglow.services.storage import UserStorage
from authglow.services.password import hash_password, PasswordValidator
from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter

router = APIRouter(tags=["Setup"])
templates = Jinja2Templates(directory="authglow/templates")


class CreateAdminRequest(BaseModel):
    """Request to create initial admin user."""

    email: EmailStr
    password: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None


@router.get("/api/setup/check")
@limiter.limit("20/minute")
async def check_setup_needed(request: Request):
    """Check if initial setup is needed."""
    storage = UserStorage()

    # Count users
    try:
        users = await storage.list_users(limit=1)
        needs_setup = len(users) == 0
    except:
        needs_setup = True

    return {
        "needs_setup": needs_setup,
        "message": "Initial setup required"
        if needs_setup
        else "Setup already completed",
    }


@router.post("/api/setup/create-admin")
@limiter.limit("5/minute")
async def create_admin_user(request: Request, admin_request: CreateAdminRequest):
    """Create the initial administrator user."""
    storage = UserStorage()

    # Check if any users exist
    try:
        users = await storage.list_users(limit=1)
        if len(users) > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Setup already completed. Users already exist in the system.",
            )
    except HTTPException:
        raise
    except:
        # If error listing users, assume empty and continue
        pass

    # Validate password
    validator = PasswordValidator()
    is_valid, errors = validator.validate(admin_request.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password validation failed: {'; '.join(errors)}",
        )

    # Check if email already exists (shouldn't happen, but safety check)
    existing_user = await storage.get_user_by_email(admin_request.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
        )

    # Create admin user
    admin_user = User(
        email=admin_request.email,
        hashed_password=hash_password(admin_request.password),
        first_name=admin_request.first_name,
        last_name=admin_request.last_name,
        scopes=["read", "write", "admin"],
        is_active=True,
        email_verified=True,  # Auto-verify first admin
        is_invited=False,
    )

    await storage.create_user(admin_user)

    return {
        "message": "Administrator account created successfully",
        "user_id": admin_user.id,
        "email": admin_user.email,
    }


# Setup page route (on root, not under /api)
@router.get("/setup", response_class=HTMLResponse, include_in_schema=False)
@limiter.limit("20/minute")
async def setup_page(request: Request):
    """Initial setup page."""
    storage = UserStorage()

    # Check if setup is needed
    try:
        users = await storage.list_users(limit=1)
        if len(users) > 0:
            # Setup already completed, redirect to login
            return RedirectResponse(url="/login", status_code=302)
    except:
        pass  # If error, show setup page

    settings = get_settings()
    return templates.TemplateResponse(
        "setup.html", {"request": request, **settings.get_ui_context()}
    )
