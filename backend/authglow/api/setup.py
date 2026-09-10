"""Initial setup API endpoints."""

import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr

from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.models.audit_events import AuditEventType
from authglow.models.audit_metadata import AdminRoleMetadata
from authglow.models.rbac import ADMIN_ROLE_NAME
from authglow.models.user import User
from authglow.services.audit import AuditService
from authglow.services.password import PasswordValidator, hash_password_async
from authglow.services.rbac import RBACService
from authglow.services.user import UserService

# Back-compat alias for Fase 21 transition window
UserStorage = UserService

router = APIRouter(tags=["Setup"])
setup_security = HTTPBearer(auto_error=False)


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
async def create_admin_user(
    request: Request,
    admin_request: CreateAdminRequest,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(setup_security),
):
    """Create the initial administrator user.

    Requires a one-time setup token in the Authorization header
    (Bearer <token>). The token is printed to stdout on first startup
    or configured via the SETUP_TOKEN environment variable.

    Uses a named lock to prevent concurrent admin creation (TOCTOU protection).
    After setup is complete, this endpoint returns 404.
    """
    settings = get_settings()
    expected_token = settings.setup_token

    if not expected_token:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Setup token is not configured on the server.",
        )
    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Setup token is required to create the initial admin account.",
        )
    if not secrets.compare_digest(credentials.credentials, expected_token):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid setup token.",
        )

    lock = named_lock()
    async with lock("setup:create-admin"):
        storage = UserStorage()

        user_count = await storage.count_users()
        if user_count > 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Setup endpoint is not available.",
            )

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
            hashed_password=await hash_password_async(admin_request.password),
            first_name=admin_request.first_name,
            last_name=admin_request.last_name,
            # OAuth scopes stay OAuth-only (D4). Admin authority is
            # RBAC-driven: the role is assigned right below.
            scopes=["read", "write"],
            is_active=True,
            email_verified=True,
            is_invited=False,
            is_bootstrap=True,
        )

        await storage.create_user(admin_user)

        # Assign the Authglow Administrator role (idempotent) so the
        # first user is born as platform administrator.
        rbac = RBACService()
        admin_role_id = await rbac.ensure_admin_role()
        await rbac.assign_role_to_user_idempotent(
            user_id=admin_user.id,
            role_id=admin_role_id,
            actor_id=admin_user.id,
        )
        await AuditService().log_event(
            event_type=AuditEventType.ADMIN_ROLE_ASSIGNED,
            user_id=admin_user.id,
            email=admin_user.email,
            metadata=AdminRoleMetadata(
                target_user_id=admin_user.id,
                target_user_email_hash=admin_user.email,
                admin_user_id=admin_user.id,
                admin_user_email_hash=admin_user.email,
                role=ADMIN_ROLE_NAME,
            ),
        )

        return {
            "message": "Administrator account created successfully",
            "user_id": admin_user.id,
            "email": admin_user.email,
        }
