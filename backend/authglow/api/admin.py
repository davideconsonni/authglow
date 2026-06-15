"""Admin portal API endpoints."""

import os
from datetime import datetime, timedelta
from typing import Optional, TypedDict

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from authglow.api.auth import get_current_user
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.core.rate_limit import limiter
from authglow.models.admin import (
    AdminUserDetail,
    BulkUserOperation,
    DashboardStats,
    PaginatedResponse,
    SetPasswordRequest,
    SuspendRequest,
    UserUpdate,
)
from authglow.models.user import User, UserCreate, UserResponse
from authglow.services.audit import AuditService
from authglow.services.email_verification import EmailVerificationService
from authglow.services.jwt import JWTService
from authglow.services.mfa import MFAService
from authglow.services.oauth_consent import OAuth2ConsentService
from authglow.services.passkey import PasskeyService
from authglow.services.password import PasswordValidator, hash_password
from authglow.services.password_reset import PasswordResetService
from authglow.services.refresh_token import RefreshTokenService
from authglow.services.user import UserService

# Back-compat alias for Fase 21 transition window
UserStorage = UserService

router = APIRouter()


def get_user_storage():
    """Get user storage instance."""
    return UserStorage()


def get_audit_service():
    """Get audit service instance."""
    return AuditService()


def get_mfa_service():
    """Get MFA service instance."""
    return MFAService()


def get_passkey_service():
    """Get passkey service instance."""
    settings = get_settings()
    return PasskeyService(
        rp_id=settings.passkey_rp_id,
        rp_name=settings.passkey_rp_name,
        origin=settings.passkey_origin,
    )


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin scope."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# API Endpoints


@router.get("/api/admin/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
):
    """Get dashboard statistics."""
    stats = await storage.get_user_stats()
    total_users = stats["total"]

    mfa_percentage = (stats["mfa"] / total_users * 100) if total_users > 0 else 0

    return DashboardStats(
        total_users=total_users,
        active_users=stats["active"],
        inactive_users=stats["inactive"],
        users_with_mfa=stats["mfa"],
        mfa_percentage=round(mfa_percentage, 2),
        new_users_today=stats["new_today"],
        new_users_this_week=stats["new_week"],
        new_users_this_month=stats["new_month"],
    )


@router.get("/api/admin/users/search")
async def search_users(
    search: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    mfa_enabled: Optional[bool] = Query(None),
    email_verified: Optional[bool] = Query(None),
    scopes: Optional[str] = Query(None),
    created_after: Optional[datetime] = Query(None),
    created_before: Optional[datetime] = Query(None),
    last_login_after: Optional[datetime] = Query(None),
    last_login_before: Optional[datetime] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
):
    """Search and filter users with server-side pagination."""
    scope_list: Optional[list[str]] = None
    if scopes:
        scope_list = [s.strip() for s in scopes.split(",") if s.strip()]

    users, total = await storage.list_users(
        limit=limit,
        offset=offset,
        search=search,
        is_active=is_active,
        mfa_enabled=mfa_enabled,
        email_verified=email_verified,
        scopes=scope_list,
        created_after=created_after,
        created_before=created_before,
        last_login_after=last_login_after,
        last_login_before=last_login_before,
    )

    items = []
    for user in users:
        items.append(AdminUserDetail.from_user(user))

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/api/admin/users/{user_id}", response_model=AdminUserDetail)
async def get_user_detail(
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
):
    """Get detailed user information."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    return AdminUserDetail.from_user(user)


@router.put("/api/admin/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    update_data: UserUpdate,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Update user details."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if update_data.is_active is not None:
        user.is_active = update_data.is_active
    if update_data.email_verified is not None:
        user.email_verified = update_data.email_verified
    if update_data.scopes is not None:
        user.scopes = update_data.scopes
    if update_data.first_name is not None:
        user.first_name = update_data.first_name
    if update_data.last_name is not None:
        user.last_name = update_data.last_name
    if update_data.phone is not None:
        user.phone = update_data.phone
    if update_data.avatar_url is not None:
        user.avatar_url = update_data.avatar_url

    email_changed = update_data.email is not None and update_data.email != user.email
    if email_changed:
        new_email = update_data.email
        assert new_email is not None  # narrowed by email_changed
        try:
            updated_user = await storage.update_email(user_id, new_email)
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))

        if updated_user is None:
            raise HTTPException(status_code=404, detail="User not found")
        user = updated_user

        if not update_data.email_verified:
            verification_service = EmailVerificationService()
            token = await verification_service.create_verification_token(user)
            await verification_service.send_verification_email(user, token.token)
    else:
        user = await storage.update_user(user)

    await audit_service.log_event(
        event_type="user_updated",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "target_user_id": user_id,
            "target_user_email": user.email,
            "changes": update_data.model_dump(exclude_none=True),
        },
    )

    from authglow.services.admin_action import AdminActionService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="user_updated",
        target_user_id=user_id,
        target_user_email=user.email,
        details=update_data.model_dump(exclude_none=True),
    )

    if email_changed:
        from authglow.services.security_event import SecurityEventService

        await SecurityEventService().record_event(
            user_id=user_id,
            event_type="email_changed_by_admin",
            email=user.email,
            description="Email changed by admin",
            metadata={"admin_email": current_user.email, "new_email": update_data.email},
        )

    return UserResponse(**user.model_dump())


@router.post("/api/admin/users/create", status_code=201)
async def create_user(
    body: UserCreate,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Create a new user with a password (admin only)."""
    existing = await storage.get_user_by_email(body.email)
    if existing:
        raise HTTPException(status_code=400, detail="User with this email already exists")

    validator = PasswordValidator()
    is_valid, errors = validator.validate(body.password)
    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=f"Password does not meet requirements: {'; '.join(errors or [])}",
        )

    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        first_name=body.first_name,
        last_name=body.last_name,
        phone=body.phone,
        avatar_url=body.avatar_url,
        scopes=body.scopes,
        is_invited=False,
        email_verified=body.email_verified,
    )

    try:
        user = await storage.create_user(user)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not body.email_verified:
        verification_service = EmailVerificationService()
        token = await verification_service.create_verification_token(user)
        await verification_service.send_verification_email(user, token.token)

    await audit_service.log_event(
        event_type="user_created_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "created_user_id": user.id,
            "created_user_email": user.email,
        },
        severity="info",
    )

    from authglow.services.admin_action import AdminActionService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="user_created",
        target_user_id=user.id,
        target_user_email=user.email,
    )

    return UserResponse(**user.model_dump())


@router.delete("/api/admin/users/{user_id}")
@limiter.limit("20/minute")  # Max 20 user deletions per minute per IP
async def delete_user(
    request: Request,
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
    mfa_service: MFAService = Depends(get_mfa_service),
):
    """Delete a user."""
    if user_id == current_user.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_federated:
        raise HTTPException(
            status_code=400,
            detail="Federated accounts are managed externally and cannot be deleted from AuthGlow",
        )

    # Delete user and associated data
    await storage.delete_user(user_id)
    await mfa_service.delete_backup_codes(user_id)

    # Log action
    await audit_service.log_event(
        event_type="user_deleted",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"target_user_id": user_id, "target_user_email": user.email},
        severity="warning",
    )

    from authglow.services.admin_action import AdminActionService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="user_deleted",
        target_user_id=user_id,
        target_user_email=user.email,
    )

    return {"message": "User deleted successfully"}


@router.get("/api/admin/users/{user_id}/passkeys")
async def get_user_passkey_count(
    user_id: str,
    current_user: User = Depends(require_admin),
    passkey_service: PasskeyService = Depends(get_passkey_service),
):
    """Get passkey count for a user."""
    passkeys = await passkey_service.get_user_passkeys(user_id)
    return {"count": len(passkeys)}


@router.get("/api/admin/users/{user_id}/passkeys/list")
async def get_user_passkeys_list(
    user_id: str,
    current_user: User = Depends(require_admin),
    passkey_service: PasskeyService = Depends(get_passkey_service),
):
    """Get full list of passkeys for a user."""
    from authglow.models.passkey import PasskeyResponse

    passkeys = await passkey_service.get_user_passkeys(user_id)
    return [
        PasskeyResponse(
            credential_id=pk.credential_id,
            name=pk.name,
            created_at=pk.created_at,
            last_used_at=pk.last_used_at,
            device_type=pk.device_type,
            transports=pk.transports,
            backup_eligible=pk.backup_eligible,
            backup_state=pk.backup_state,
        )
        for pk in passkeys
    ]


@router.delete("/api/admin/users/{user_id}/passkeys/{credential_id}")
@limiter.limit("30/minute")  # Max 30 passkey deletions per minute per IP
async def delete_user_passkey(
    request: Request,
    user_id: str,
    credential_id: str,
    current_user: User = Depends(require_admin),
    passkey_service: PasskeyService = Depends(get_passkey_service),
    audit_service: AuditService = Depends(get_audit_service),
    storage: UserStorage = Depends(get_user_storage),
):
    """Delete a user's passkey (admin only)."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    success = await passkey_service.delete_passkey(user_id, credential_id)

    if not success:
        raise HTTPException(status_code=404, detail="Passkey not found")

    # Log action
    await audit_service.log_event(
        event_type="admin_deleted_passkey",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "target_user_id": user_id,
            "target_user_email": user.email,
            "credential_id": credential_id,
        },
        severity="warning",
    )

    from authglow.services.admin_action import AdminActionService
    from authglow.services.security_event import SecurityEventService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="passkey_deleted",
        target_user_id=user_id,
        target_user_email=user.email,
        details={"credential_id": credential_id},
    )
    await SecurityEventService().record_event(
        user_id=user_id,
        event_type="passkey_removed_by_admin",
        email=user.email,
        description="Passkey removed by admin",
        metadata={"admin_email": current_user.email, "credential_id": credential_id},
    )

    return {"message": "Passkey deleted successfully"}


@router.post("/api/admin/users/{user_id}/reset-mfa")
@limiter.limit("20/minute")  # Max 20 MFA resets per minute per IP
async def reset_user_mfa(
    request: Request,
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
    mfa_service: MFAService = Depends(get_mfa_service),
):
    """Reset MFA for a user."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_federated:
        raise HTTPException(
            status_code=400,
            detail="MFA for federated accounts is managed by the identity provider",
        )

    # Reset MFA
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_verified = False
    await storage.update_user(user)
    await mfa_service.delete_backup_codes(user_id)

    # Log action
    await audit_service.log_event(
        event_type="mfa_reset_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"target_user_id": user_id, "target_user_email": user.email},
        severity="warning",
    )

    from authglow.services.admin_action import AdminActionService
    from authglow.services.security_event import SecurityEventService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="mfa_reset",
        target_user_id=user_id,
        target_user_email=user.email,
    )
    await SecurityEventService().record_event(
        user_id=user_id,
        event_type="mfa_reset_by_admin",
        email=user.email,
        description="MFA reset by admin",
        metadata={"admin_email": current_user.email},
    )

    return {"message": "MFA reset successfully"}


@router.post("/api/admin/users/{user_id}/disable-mfa")
async def disable_user_mfa(
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
    mfa_service: MFAService = Depends(get_mfa_service),
):
    """Disable MFA for a user without deleting backup codes."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled for this user")

    if user.is_federated:
        raise HTTPException(
            status_code=400,
            detail="MFA for federated accounts is managed by the identity provider",
        )

    # Disable MFA (keep backup codes intact)
    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_verified = False
    await storage.update_user(user)

    await audit_service.log_event(
        event_type="mfa_disabled_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"target_user_id": user_id, "target_user_email": user.email},
        severity="warning",
    )

    from authglow.services.admin_action import AdminActionService
    from authglow.services.security_event import SecurityEventService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="mfa_disabled",
        target_user_id=user_id,
        target_user_email=user.email,
    )
    await SecurityEventService().record_event(
        user_id=user_id,
        event_type="mfa_disabled_by_admin",
        email=user.email,
        description="MFA disabled by admin",
        metadata={"admin_email": current_user.email},
    )

    return {"message": "MFA disabled successfully"}


@router.post("/api/admin/users/{user_id}/regenerate-backup-codes")
async def regenerate_user_backup_codes(
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
    mfa_service: MFAService = Depends(get_mfa_service),
):
    """Regenerate backup codes for a user."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_federated:
        raise HTTPException(
            status_code=400,
            detail="MFA for federated accounts is managed by the identity provider",
        )

    # Generate new backup codes
    backup_codes = mfa_service.generate_backup_codes(10)

    # Save new backup codes (replaces old ones)
    await mfa_service.save_backup_codes(user_id, backup_codes)

    await audit_service.log_event(
        event_type="backup_codes_regenerated_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"target_user_id": user_id, "target_user_email": user.email},
        severity="warning",
    )

    from authglow.services.admin_action import AdminActionService
    from authglow.services.security_event import SecurityEventService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="backup_codes_regenerated",
        target_user_id=user_id,
        target_user_email=user.email,
    )
    await SecurityEventService().record_event(
        user_id=user_id,
        event_type="backup_codes_regenerated_by_admin",
        email=user.email,
        description="Backup codes regenerated by admin",
        metadata={"admin_email": current_user.email},
    )

    return {
        "message": "Backup codes regenerated successfully",
        "backup_codes": backup_codes,
    }


# --- Phase 2: Password and Credentials ---


@router.post("/api/admin/users/{user_id}/set-password")
@limiter.limit("30/minute")
async def set_user_password(
    request: Request,
    user_id: str,
    body: SetPasswordRequest,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Set a new password for a user (admin only)."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_federated:
        raise HTTPException(
            status_code=400,
            detail="Federated accounts are managed externally. This operation is not applicable.",
        )

    validator = PasswordValidator()
    is_valid, errors = validator.validate(body.password)
    if not is_valid:
        raise HTTPException(
            status_code=400,
            detail=f"Password does not meet requirements: {'; '.join(errors or [])}",
        )

    hashed = hash_password(body.password)
    updated = await storage.set_password(user_id, hashed, require_change=body.require_change)
    if not updated:
        raise HTTPException(status_code=404, detail="User not found")

    await audit_service.log_event(
        event_type="password_set_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "target_user_id": user_id,
            "target_user_email": user.email,
            "require_change": body.require_change,
        },
        severity="warning",
    )

    from authglow.services.admin_action import AdminActionService
    from authglow.services.security_event import SecurityEventService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="password_set",
        target_user_id=user_id,
        target_user_email=user.email,
        details={"require_change": body.require_change},
    )
    await SecurityEventService().record_event(
        user_id=user_id,
        event_type="password_changed_by_admin",
        email=user.email,
        description="Password set by admin",
        metadata={"admin_email": current_user.email},
    )

    return {"message": "Password set successfully"}


@router.post("/api/admin/users/{user_id}/send-password-reset")
@limiter.limit("10/minute")
async def send_password_reset(
    request: Request,
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Send a password reset email to a user (admin only)."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_federated:
        raise HTTPException(
            status_code=400,
            detail="Federated accounts are managed externally. This operation is not applicable.",
        )

    reset_service = PasswordResetService()
    token, plaintext, reset_code = await reset_service.create_reset_token(
        user_id=user.id,
        email=user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    from authglow.services.email.factory import get_email_service

    email_service = get_email_service()
    reset_page_url = f"{get_settings().frontend_base_url}/auth/reset-password"
    await email_service.send_template(
        to=[user.email],
        subject="Password Reset Request - AuthGlow",
        template_name="password_reset",
        context={
            "user_name": user.first_name or user.email.split("@")[0],
            "reset_page_url": reset_page_url,
            "reset_code": reset_code,
            "company_name": get_settings().company_name,
            "expires_in_minutes": 30,
        },
    )

    await audit_service.log_event(
        event_type="password_reset_sent_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "target_user_id": user_id,
            "target_user_email": user.email,
        },
        severity="warning",
    )

    from authglow.services.admin_action import AdminActionService
    from authglow.services.security_event import SecurityEventService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="password_reset_sent",
        target_user_id=user_id,
        target_user_email=user.email,
    )
    await SecurityEventService().record_event(
        user_id=user_id,
        event_type="password_reset_sent_by_admin",
        email=user.email,
        description="Password reset email sent by admin",
        metadata={"admin_email": current_user.email},
    )

    return {"message": "Password reset email sent"}


@router.post("/api/admin/users/{user_id}/expire-password")
@limiter.limit("30/minute")
async def expire_user_password(
    request: Request,
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Force a user's password to expire (admin only)."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.is_federated:
        raise HTTPException(
            status_code=400,
            detail="Federated accounts are managed externally. This operation is not applicable.",
        )

    user.password_expired = True
    await storage.update_user(user)

    await audit_service.log_event(
        event_type="password_expired_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"target_user_id": user_id, "target_user_email": user.email},
        severity="warning",
    )

    from authglow.services.admin_action import AdminActionService
    from authglow.services.security_event import SecurityEventService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="password_expired",
        target_user_id=user_id,
        target_user_email=user.email,
    )
    await SecurityEventService().record_event(
        user_id=user_id,
        event_type="password_expired_by_admin",
        email=user.email,
        description="Password expired by admin",
        metadata={"admin_email": current_user.email},
    )

    return {"message": "Password expired successfully"}


@router.post("/api/admin/users/{user_id}/unlock")
@limiter.limit("30/minute")
async def unlock_user_account(
    request: Request,
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Unlock a user's account (admin only)."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await storage.reset_failed_login_attempts(user_id)

    await audit_service.log_event(
        event_type="account_unlocked_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"target_user_id": user_id, "target_user_email": user.email},
        severity="warning",
    )

    from authglow.services.admin_action import AdminActionService
    from authglow.services.security_event import SecurityEventService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="account_unlocked",
        target_user_id=user_id,
        target_user_email=user.email,
    )
    await SecurityEventService().record_event(
        user_id=user_id,
        event_type="account_unlocked_by_admin",
        email=user.email,
        description="Account unlocked by admin",
        metadata={"admin_email": current_user.email},
    )

    return {"message": "Account unlocked successfully"}


@router.post("/api/admin/users/{user_id}/reset-failed-attempts")
@limiter.limit("30/minute")
async def reset_failed_attempts(
    request: Request,
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Reset failed login attempts for a user without unlocking (admin only)."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    await storage.clear_failed_login_attempts(user_id)

    await audit_service.log_event(
        event_type="failed_attempts_reset_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"target_user_id": user_id, "target_user_email": user.email},
        severity="info",
    )

    from authglow.services.admin_action import AdminActionService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="failed_attempts_reset",
        target_user_id=user_id,
        target_user_email=user.email,
    )

    return {"message": "Failed attempts reset successfully"}


@router.post("/api/admin/users/bulk", response_model=dict)
@limiter.limit("10/minute")  # Max 10 bulk operations per minute per IP
async def bulk_user_operation(
    request: Request,
    operation: BulkUserOperation,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Perform bulk operations on users."""

    class _BulkResults(TypedDict):
        success: int
        failed: int
        errors: list[str]

    results: _BulkResults = {"success": 0, "failed": 0, "errors": []}

    for user_id in operation.user_ids:
        try:
            user = await storage.get_user(user_id)
            if not user:
                results["failed"] += 1
                results["errors"].append(f"User {user_id} not found")
                continue

            if operation.operation == "activate":
                user.is_active = True
            elif operation.operation == "deactivate":
                if user_id == current_user.id:
                    results["failed"] += 1
                    results["errors"].append("Cannot deactivate your own account")
                    continue
                if user.is_federated:
                    results["failed"] += 1
                    results["errors"].append(
                        f"Federated user {user.email}: deactivation is managed externally"
                    )
                    continue
                user.is_active = False
            elif operation.operation == "assign_scope":
                if operation.scope and operation.scope not in user.scopes:
                    user.scopes.append(operation.scope)
            elif operation.operation == "remove_scope":
                if operation.scope and operation.scope in user.scopes:
                    user.scopes.remove(operation.scope)
            elif operation.operation == "delete":
                if user_id == current_user.id:
                    results["failed"] += 1
                    results["errors"].append("Cannot delete your own account")
                    continue
                if user.is_federated:
                    results["failed"] += 1
                    results["errors"].append(
                        f"Federated user {user.email}: cannot be deleted from AuthGlow"
                    )
                    continue
                await storage.delete_user(user_id)
                results["success"] += 1
                continue

            await storage.update_user(user)
            results["success"] += 1

        except Exception as e:
            results["failed"] += 1
            results["errors"].append(f"Error processing {user_id}: {str(e)}")

    # Log action
    await audit_service.log_event(
        event_type="bulk_user_operation",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "operation": operation.operation,
            "user_count": len(operation.user_ids),
            "results": results,
        },
    )

    return results


@router.get("/api/admin/sessions")
async def get_active_sessions(
    email: Optional[str] = Query(None),
    type: str = Query("all"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_admin),
):
    """Get all active sessions and refresh tokens with pagination."""
    refresh_token_service = RefreshTokenService()
    user_storage = UserStorage()

    user_id = None
    if email:
        found_user = await user_storage.get_user_by_email(email)
        if not found_user:
            return {
                "sessions": [],
                "total_sessions": 0,
                "total_refresh_tokens": 0,
                "unique_users": 0,
                "limit": limit,
                "offset": offset,
            }
        user_id = found_user.id

    page_tokens, total_matching = await refresh_token_service.list_all_tokens(
        active_only=True, limit=limit, offset=offset, user_id=user_id
    )

    sessions_list = []
    unique_users = set()

    for rt in page_tokens:
        user = await user_storage.get_user(rt.user_id)
        if not user:
            continue

        unique_users.add(rt.user_id)
        sessions_list.append(
            {
                "id": rt.token_id,
                "type": "refresh",
                "user_email": user.email,
                "client": rt.client_id,
                "created_at": rt.created_at.isoformat(),
                "expires_at": rt.expires_at.isoformat() if rt.expires_at else None,
                "last_used_at": rt.used_at.isoformat() if rt.used_at else None,
                "ip_address": rt.issued_ip,
                "scopes": rt.scopes,
            }
        )

    return {
        "sessions": sessions_list,
        "total_sessions": total_matching,
        "total_refresh_tokens": total_matching,
        "unique_users": len(unique_users),
        "limit": limit,
        "offset": offset,
    }


@router.post("/api/admin/tokens/refresh/{token_id}/revoke")
async def revoke_refresh_token_admin(
    token_id: str,
    current_user: User = Depends(require_admin),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Revoke a refresh token (admin)."""
    refresh_token_service = RefreshTokenService()

    rt = await refresh_token_service.get_refresh_token_by_id(token_id)
    if not rt:
        raise HTTPException(status_code=404, detail="Token not found")

    success = await refresh_token_service.revoke_token_by_id(token_id, reason="Revoked by admin")

    if success:
        await audit_service.log_event(
            event_type="refresh_token_revoked_by_admin",
            user_id=current_user.id,
            email=current_user.email,
            metadata={"token_id": token_id, "target_user_id": rt.user_id},
            severity="warning",
        )

    return {"message": "Token revoked successfully"}


@router.get("/api/admin/users/{user_id}/sessions")
async def get_user_sessions(
    user_id: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_admin),
):
    """Get active sessions for a specific user."""
    refresh_token_service = RefreshTokenService()

    page_tokens, total = await refresh_token_service.list_all_tokens(
        active_only=True, limit=limit, offset=offset, user_id=user_id
    )

    items = []
    for rt in page_tokens:
        items.append(
            {
                "id": rt.token_id,
                "client_id": rt.client_id,
                "scopes": rt.scopes,
                "created_at": rt.created_at.isoformat(),
                "expires_at": rt.expires_at.isoformat() if rt.expires_at else None,
                "last_used_at": rt.used_at.isoformat() if rt.used_at else None,
                "ip_address": rt.issued_ip,
            }
        )

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("/api/admin/users/{user_id}/sessions/revoke-all")
async def revoke_all_user_sessions(
    user_id: str,
    current_user: User = Depends(require_admin),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Revoke all sessions for a specific user."""
    refresh_token_service = RefreshTokenService()
    user_storage = UserStorage()

    target_user = await user_storage.get_user(user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    revoked_count = await refresh_token_service.revoke_user_tokens(user_id)

    await audit_service.log_event(
        event_type="all_user_sessions_revoked_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "target_user_id": user_id,
            "target_email": target_user.email,
            "revoked_count": revoked_count,
        },
        severity="warning",
    )

    from authglow.services.admin_action import AdminActionService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="all_sessions_revoked",
        target_user_id=user_id,
        target_user_email=target_user.email,
        details={"revoked_count": revoked_count},
    )

    return {"message": f"Revoked {revoked_count} session(s)", "revoked_count": revoked_count}


@router.post("/api/admin/sessions/cleanup")
async def cleanup_expired_sessions(current_user: User = Depends(require_admin)):
    """Clean up expired sessions and tokens."""
    refresh_token_service = RefreshTokenService()

    deleted = await refresh_token_service.cleanup_expired_tokens()

    return {"deleted": deleted, "message": f"Cleaned up {deleted} expired tokens"}


@router.get("/api/admin/oauth-consents")
async def get_oauth_consents_admin(
    email: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_admin),
):
    """Get all OAuth2 consents with pagination."""
    consent_service = OAuth2ConsentService()
    items, total = await consent_service.list_all_for_admin(limit=limit, offset=offset, email=email)
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("/api/admin/oauth-consents/{consent_id}/revoke")
async def revoke_consent_admin(
    consent_id: str,
    current_user: User = Depends(require_admin),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Revoke an OAuth2 consent (admin)."""
    consent_service = OAuth2ConsentService()

    success = await consent_service.revoke_consent(consent_id)

    if not success:
        raise HTTPException(status_code=404, detail="Consent not found")

    await audit_service.log_event(
        event_type="oauth_consent_revoked_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"consent_id": consent_id},
        severity="info",
    )

    return {"message": "Consent revoked successfully"}


# --- Phase 6: Audit & Activity ---


@router.get("/api/admin/users/{user_id}/login-history")
async def get_user_login_history(
    user_id: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
):
    """Get login history for a specific user."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    from authglow.services.login_history import LoginHistoryService

    login_svc = LoginHistoryService()
    items, total = await login_svc.get_login_history(user_id, limit=limit, offset=offset)

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/api/admin/users/{user_id}/security-events")
async def get_user_security_events(
    user_id: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
):
    """Get security events for a specific user."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    from authglow.services.security_event import SecurityEventService

    event_svc = SecurityEventService()
    items, total = await event_svc.get_security_events(user_id, limit=limit, offset=offset)

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.get("/api/admin/users/{user_id}/oauth-consents")
async def get_user_oauth_consents(
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
):
    """Get OAuth2 consents for a specific user."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    from authglow.services.oauth_consent import OAuth2ConsentService

    consent_svc = OAuth2ConsentService()
    consents = await consent_svc.list_user_consents(user_id)

    result = []

    from authglow.services.oauth_client import OAuth2ClientStorage

    client_storage = OAuth2ClientStorage()

    for c in consents:
        client = await client_storage.get_client(c.client_id)
        result.append(
            {
                "consent_id": c.consent_id,
                "client_id": c.client_id,
                "client_name": client.client_name if client else c.client_id,
                "scopes": c.scopes,
                "granted_at": c.granted_at.isoformat(),
                "expires_at": c.expires_at.isoformat() if c.expires_at else None,
                "revoked": c.revoked,
                "revoked_at": c.revoked_at.isoformat() if c.revoked_at else None,
            }
        )

    return result


# --- Phase 7: Advanced ---


@router.get("/api/admin/users/{user_id}/export")
async def export_user_data(
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
):
    """Export all data for a specific user as JSON."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    from authglow.core.config import get_settings as _get_settings
    from authglow.services.admin_action import AdminActionService
    from authglow.services.login_history import LoginHistoryService
    from authglow.services.oauth_client import OAuth2ClientStorage
    from authglow.services.oauth_consent import OAuth2ConsentService
    from authglow.services.passkey import PasskeyService
    from authglow.services.security_event import SecurityEventService

    login_history, lh_total = await LoginHistoryService().get_login_history(user_id, limit=500)
    security_events, se_total = await SecurityEventService().get_security_events(user_id, limit=500)
    admin_actions, aa_total = await AdminActionService().get_admin_actions(user_id, limit=500)

    from authglow.services.refresh_token import RefreshTokenService

    page_tokens, sessions_total = await RefreshTokenService().list_all_tokens(
        active_only=False, limit=500, user_id=user_id
    )

    settings = _get_settings()
    passkey_svc = PasskeyService(
        rp_id=settings.passkey_rp_id,
        rp_name=settings.passkey_rp_name,
        origin=settings.passkey_origin,
    )
    passkeys = [
        {
            "credential_id": pk.credential_id,
            "name": pk.name,
            "device_type": pk.device_type,
            "created_at": pk.created_at.isoformat(),
            "last_used_at": pk.last_used_at.isoformat() if pk.last_used_at else None,
        }
        for pk in await passkey_svc.get_user_passkeys(user_id)
    ]

    consent_svc = OAuth2ConsentService()
    client_storage = OAuth2ClientStorage()
    consents = []
    for c in await consent_svc.list_user_consents(user_id):
        client = await client_storage.get_client(c.client_id)
        consents.append(
            {
                "consent_id": c.consent_id,
                "client_id": c.client_id,
                "client_name": client.client_name if client else c.client_id,
                "scopes": c.scopes,
                "granted_at": c.granted_at.isoformat(),
                "revoked": c.revoked,
            }
        )

    return {
        "exported_at": utcnow().isoformat(),
        "user": user.model_dump(mode="json"),
        "login_history": {"items": login_history, "total": lh_total},
        "security_events": {"items": security_events, "total": se_total},
        "admin_actions": {"items": admin_actions, "total": aa_total},
        "sessions": {
            "items": [
                {
                    "id": rt.token_id,
                    "client": rt.client_id,
                    "scopes": rt.scopes,
                    "created_at": rt.created_at.isoformat(),
                    "last_used_at": rt.used_at.isoformat() if rt.used_at else None,
                    "ip_address": rt.issued_ip,
                    "revoked": rt.revoked,
                }
                for rt in page_tokens
            ],
            "total": sessions_total,
        },
        "passkeys": passkeys,
        "oauth_consents": consents,
    }


@router.get("/api/admin/users/{user_id}/admin-actions")
async def get_user_admin_actions(
    user_id: str,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
):
    """Get admin actions for a specific user."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    from authglow.services.admin_action import AdminActionService

    svc = AdminActionService()
    items, total = await svc.get_admin_actions(user_id, limit=limit, offset=offset)

    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.post("/api/admin/users/{user_id}/suspend")
async def suspend_user(
    user_id: str,
    body: SuspendRequest,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Temporarily suspend a user's account."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    suspended_until = utcnow() + timedelta(hours=body.duration_hours)
    user.suspended_until = suspended_until
    await storage.update_user(user)

    await audit_service.log_event(
        event_type="user_suspended",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "target_user_id": user_id,
            "target_user_email": user.email,
            "duration_hours": body.duration_hours,
            "suspended_until": suspended_until.isoformat(),
        },
        severity="warning",
    )

    from authglow.services.admin_action import AdminActionService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="user_suspended",
        target_user_id=user_id,
        target_user_email=user.email,
        details={
            "duration_hours": body.duration_hours,
            "suspended_until": suspended_until.isoformat(),
        },
    )

    return {
        "message": "User suspended successfully",
        "suspended_until": suspended_until.isoformat(),
    }


@router.post("/api/admin/users/{user_id}/unsuspend")
async def unsuspend_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Remove temporary suspension from a user's account."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.suspended_until:
        raise HTTPException(status_code=400, detail="User is not suspended")

    user.suspended_until = None
    await storage.update_user(user)

    await audit_service.log_event(
        event_type="user_unsuspended",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "target_user_id": user_id,
            "target_user_email": user.email,
        },
        severity="info",
    )

    from authglow.services.admin_action import AdminActionService

    await AdminActionService().record_action(
        admin_user_id=current_user.id,
        admin_email=current_user.email,
        action_type="user_unsuspended",
        target_user_id=user_id,
        target_user_email=user.email,
    )

    return {"message": "User unsuspended successfully"}


# --- JWK Key Management ---


@router.get("/api/admin/jwk-keys")
async def get_jwk_keys(
    current_user: User = Depends(require_admin),
):
    """Get all JWK keys in the keyring."""
    jwt_service = JWTService()
    info = jwt_service.get_keyring_info()

    keys_list = []
    for kid, meta in info["keys"].items():
        pub_path = os.path.join(get_settings().keys_dir, kid, "public_key.pem")
        has_file = os.path.exists(pub_path)
        try:
            with open(pub_path, "rb") as f:
                from cryptography.hazmat.backends import default_backend
                from cryptography.hazmat.primitives import serialization

                pub_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
                key_size = getattr(pub_key, "key_size", None)
        except Exception:
            key_size = meta.get("key_size", None)

        keys_list.append(
            {
                "kid": kid,
                "status": meta.get("status"),
                "created_at": meta.get("created_at"),
                "retired_at": meta.get("retired_at"),
                "revoked_at": meta.get("revoked_at"),
                "algorithm": meta.get("algorithm"),
                "key_size": key_size,
                "file_exists": has_file,
                "is_active": kid == info["active_kid"],
            }
        )

    keys_list.sort(key=lambda k: k.get("created_at", ""), reverse=True)
    return {"active_kid": info["active_kid"], "keys": keys_list}


@router.post("/api/admin/jwk-keys/rotate")
@limiter.limit("5/minute")
async def rotate_jwk_keys(
    request: Request,
    current_user: User = Depends(require_admin),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Rotate the active JWK signing key."""
    jwt_service = JWTService()
    result = jwt_service.rotate_keys()

    await audit_service.log_event(
        event_type="jwk_key_rotated",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"old_kid": result["old_kid"], "new_kid": result["new_kid"]},
        severity="warning",
    )

    return {
        "message": "JWK key rotated successfully",
        "old_kid": result["old_kid"],
        "new_kid": result["new_kid"],
    }


@router.post("/api/admin/jwk-keys/{kid}/revoke")
@limiter.limit("5/minute")
async def revoke_jwk_key(
    kid: str,
    request: Request,
    current_user: User = Depends(require_admin),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Revoke a JWK key. Active key cannot be revoked."""
    jwt_service = JWTService()
    success = jwt_service.revoke_key(kid)

    if not success:
        raise HTTPException(
            status_code=400,
            detail="Cannot revoke key: either it is the active key or it does not exist",
        )

    await audit_service.log_event(
        event_type="jwk_key_revoked",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"kid": kid},
        severity="warning",
    )

    return {"message": f"JWK key {kid} revoked successfully"}
