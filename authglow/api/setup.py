"""Initial setup API endpoints."""

from typing import Optional

from fastapi import APIRouter, HTTPException, Request, status
from pydantic import BaseModel, EmailStr

from authglow.core.rate_limit import limiter
from authglow.models.user import User
from authglow.services.password import PasswordValidator, hash_password
from authglow.services.storage import UserStorage

router = APIRouter(tags=["Setup"])


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

    try:
        user_count = await storage.count_users()
        needs_setup = user_count == 0
    except Exception:
        needs_setup = True

    return {
        "needs_setup": needs_setup,
        "message": "Initial setup required" if needs_setup else "Setup already completed",
    }


@router.post("/api/setup/create-admin")
@limiter.limit("5/minute")
async def create_admin_user(request: Request, admin_request: CreateAdminRequest):
    """Create the initial administrator user."""
    storage = UserStorage()

    try:
        user_count = await storage.count_users()
        if user_count > 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Setup already completed. Users already exist in the system.",
            )
    except HTTPException:
        raise
    except Exception:
        pass

    validator = PasswordValidator()
    is_valid, errors = validator.validate(admin_request.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password validation failed: {'; '.join(errors or [])}",
        )

    existing_user = await storage.get_user_by_email(admin_request.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User with this email already exists",
        )

    admin_user = User(
        email=admin_request.email,
        hashed_password=hash_password(admin_request.password),
        first_name=admin_request.first_name,
        last_name=admin_request.last_name,
        scopes=["read", "write", "admin"],
        is_active=True,
        email_verified=True,
        is_invited=False,
    )

    await storage.create_user(admin_user)

    return {
        "message": "Administrator account created successfully",
        "user_id": admin_user.id,
        "email": admin_user.email,
    }
