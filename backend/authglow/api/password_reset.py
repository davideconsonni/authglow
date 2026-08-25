"""Password reset API endpoints."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from authglow.api.auth import _clear_auth_cookies, get_current_user, get_password_validator
from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.models.password_reset import (
    ExpiredPasswordChange,
    PasswordChange,
    PasswordResetConfirm,
    PasswordResetRequest,
    PasswordResetResponse,
    PasswordResetToken,
)
from authglow.models.user import User
from authglow.services.audit import AuditService
from authglow.services.email import EmailService
from authglow.services.email.factory import get_email_service
from authglow.services.password import (
    PasswordValidator,
    hash_password_async,
    verify_password_async,
)
from authglow.services.password_reset import PasswordResetService
from authglow.services.user import UserService

# Back-compat alias for Fase 21 transition window
UserStorage = UserService

router = APIRouter()

settings = get_settings()


def get_reset_service() -> PasswordResetService:
    """Get password reset service instance."""
    return PasswordResetService()


def get_user_storage() -> UserStorage:
    """Get user storage instance."""
    return UserStorage()


def get_audit_service() -> AuditService:
    """Get audit service instance."""
    return AuditService()


# Public endpoints


@router.post("/api/password/reset/request", response_model=PasswordResetResponse)
@limiter.limit("5/hour")  # Strict rate limit to prevent abuse
async def request_password_reset(
    request: Request,
    reset_request: PasswordResetRequest,
    reset_service: PasswordResetService = Depends(get_reset_service),
    user_storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
    email_service: EmailService = Depends(get_email_service),
):
    """Request a password reset token.

    Rate limit: 5 requests per hour per IP.
    Always returns success to prevent email enumeration.
    """
    # Always return success message (prevent email enumeration)
    success_response = PasswordResetResponse(
        message="If this email exists, a password reset link will be sent",
        email=reset_request.email,
        expires_in_minutes=30,
    )

    # Try to find user
    user = await user_storage.get_user_by_email(reset_request.email)

    if not user:
        # Log attempt with non-existent email
        await audit_service.log_event(
            event_type="password_reset_failed",
            email=reset_request.email,
            metadata={"reason": "user_not_found"},
            severity="warning",
            ip_address=request.client.host if request.client else None,
        )
        return success_response

    if not user.is_active:
        # Don't send reset for inactive accounts
        await audit_service.log_event(
            event_type="password_reset_failed",
            user_id=user.id,
            email=user.email,
            metadata={"reason": "account_inactive"},
            severity="warning",
            ip_address=request.client.host if request.client else None,
        )
        return success_response

    # Revoke any existing active tokens for this user
    await reset_service.revoke_user_tokens(user.id)

    # Create new reset token
    token, plaintext_token, reset_code = await reset_service.create_reset_token(
        user_id=user.id,
        email=user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        expires_in_minutes=30,
    )

    # Send password reset email
    # VAPT-022: do NOT embed the plaintext token in the URL. The link
    # points to a clean page; the human-friendly reset code is rendered
    # in the email body and entered by the user.
    reset_page_url = f"{settings.frontend_base_url}/auth/reset-password"

    await email_service.send_template(
        to=[user.email],
        subject="Reset Your Password - AuthGlow",
        template_name="password_reset",
        context={
            "user_name": user.first_name or user.email.split("@")[0],
            "reset_page_url": reset_page_url,
            "reset_code": reset_code,
            "expires_in_minutes": 30,
        },
        from_email=settings.email_from_address,
        from_name=settings.email_from_name,
    )

    # Log successful request
    await audit_service.log_event(
        event_type="password_reset_requested",
        user_id=user.id,
        email=user.email,
        metadata={"token_id": token.token_id},
        ip_address=request.client.host if request.client else None,
    )

    return success_response


@router.post("/api/password/reset/confirm")
@limiter.limit("10/hour")  # Allow multiple attempts in case of typos
async def confirm_password_reset(
    request: Request,
    reset_confirm: PasswordResetConfirm,
    reset_service: PasswordResetService = Depends(get_reset_service),
    user_storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
    password_validator: PasswordValidator = Depends(get_password_validator),
):
    """Confirm password reset with the human-friendly reset code (VAPT-022)."""
    # Verify code (VAPT-022: no bearer token in URL, code lives in body)
    token = await reset_service.verify_by_code(reset_confirm.reset_code)

    if not token:
        await audit_service.log_event(
            event_type="password_reset_failed",
            metadata={"reason": "invalid_or_expired_code"},
            severity="warning",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset code",
        )

    # Validate password strength
    is_valid, errors = password_validator.validate(reset_confirm.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="; ".join(errors) if errors else "Password does not meet requirements",
        )

    # Get user
    user = await user_storage.get_user(token.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Hash new password
    hashed_password = await hash_password_async(reset_confirm.new_password)

    # Update user password
    user.hashed_password = hashed_password
    await user_storage.update_user(user)

    # Mark token as used
    await reset_service.mark_token_used(token.token_lookup)

    # Revoke any other active password-reset tokens for this user
    await reset_service.revoke_user_tokens(user.id)

    # Revoke all active refresh tokens so the previous session is invalidated
    from authglow.services.refresh_token import RefreshTokenService

    rt_service = RefreshTokenService()
    await rt_service.revoke_user_tokens(user.id)

    # Log successful reset
    await audit_service.log_event(
        event_type="password_reset_completed",
        user_id=user.id,
        email=user.email,
        metadata={"token_id": token.token_id, "sessions_revoked": True},
        ip_address=request.client.host if request.client else None,
    )

    return {"message": "Password reset successful"}


@router.post("/api/password/change")
@limiter.limit("20/hour")
async def change_password(
    request: Request,
    response: Response,
    password_change: PasswordChange,
    current_user: User = Depends(get_current_user),
    user_storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
    password_validator: PasswordValidator = Depends(get_password_validator),
):
    """Change password for authenticated user.

    Requires current password for verification.  Revokes all existing
    sessions (access token JTI blacklist + all refresh tokens) so an
    attacker with a stolen token cannot retain access.
    """
    from authglow.core.jwt_singleton import get_jwt_service
    from authglow.services.auth.token_blacklist import token_blacklist as get_blacklist

    settings = get_settings()

    # Verify current password
    if not await verify_password_async(
        password_change.current_password, current_user.hashed_password
    ):
        await audit_service.log_event(
            event_type="password_change_failed",
            user_id=current_user.id,
            email=current_user.email,
            metadata={"reason": "incorrect_current_password"},
            severity="warning",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password is incorrect",
        )

    # Validate new password strength
    is_valid, errors = password_validator.validate(password_change.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="; ".join(errors) if errors else "Password does not meet requirements",
        )

    # Check if new password is same as current
    if await verify_password_async(password_change.new_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )

    # Hash new password
    hashed_password = await hash_password_async(password_change.new_password)

    # Update user password
    current_user.hashed_password = hashed_password
    await user_storage.update_user(current_user)

    # Revoke all sessions: blacklist current access token JTI, revoke all refresh tokens
    auth_header = request.headers.get("Authorization", "")
    access_token = auth_header[7:] if auth_header.startswith("Bearer ") else None
    if not access_token:
        access_token = request.cookies.get(settings.auth_cookie_access_name)
    if access_token:
        jwt_svc = await get_jwt_service()
        at_data = jwt_svc.decode_token(access_token)
        if at_data and at_data.jti:
            await get_blacklist().revoke(at_data.jti, at_data.exp.timestamp())

    from authglow.services.refresh_token import RefreshTokenService

    rt_service = RefreshTokenService()
    await rt_service.revoke_user_tokens(current_user.id)

    _clear_auth_cookies(response, settings)

    # Log successful change
    await audit_service.log_event(
        event_type="password_changed",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"sessions_revoked": True},
        ip_address=request.client.host if request.client else None,
    )

    return {"message": "Password changed successfully"}


@router.post("/api/auth/expired-password/change")
@limiter.limit("5/minute")
async def change_expired_password(
    request: Request,
    payload: ExpiredPasswordChange,
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
    password_validator: PasswordValidator = Depends(get_password_validator),
):
    """Complete a forced password change for an admin-expired account.

    Reached when ``POST /api/oauth2/authorize`` returns
    ``{"password_expired": true}``. Re-verifies the current password (the
    caller never holds a session), applies the same strength policy as every
    other password setter, and clears the ``password_expired`` flag via
    ``set_password(require_change=False)``.
    """
    user = await storage.get_user_by_email(payload.email)
    if (
        user is None
        or not user.is_active
        or not await verify_password_async(payload.current_password, user.hashed_password)
    ):
        await audit_service.log_event(
            event_type="expired_password_change_failed",
            email=payload.email,
            metadata={"reason": "invalid_credentials"},
            severity="warning",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.password_expired:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password change is not required for this account",
        )

    is_valid, errors = password_validator.validate(payload.new_password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="; ".join(errors) if errors else "Password does not meet requirements",
        )

    if await verify_password_async(payload.new_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )

    hashed_password = await hash_password_async(payload.new_password)

    # set_password acquires the per-user lock and resets the expiry flag
    # (``password_expired = require_change``) plus ``password_changed_at``.
    await storage.set_password(user.id, hashed_password, require_change=False)

    await audit_service.log_event(
        event_type="password_changed_after_expiry",
        user_id=user.id,
        email=user.email,
        metadata={},
        ip_address=request.client.host if request.client else None,
    )

    return {"message": "Password changed successfully. You can now sign in."}


# Admin endpoints


@router.get("/api/admin/password-resets", response_model=List[PasswordResetToken])
async def list_password_resets(
    active_only: bool = False,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    reset_service: PasswordResetService = Depends(get_reset_service),
):
    """List all password reset tokens (admin only)."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    tokens = await reset_service.list_all_tokens(
        active_only=active_only, limit=limit, offset=offset
    )

    return tokens


@router.get(
    "/api/admin/users/{user_id}/password-resets",
    response_model=List[PasswordResetToken],
)
async def list_user_password_resets(
    user_id: str,
    active_only: bool = True,
    current_user: User = Depends(get_current_user),
    reset_service: PasswordResetService = Depends(get_reset_service),
):
    """List password reset tokens for a specific user (admin only)."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    tokens = await reset_service.list_user_tokens(user_id, active_only=active_only)
    return tokens


@router.post("/api/admin/users/{user_id}/revoke-resets")
async def revoke_user_password_resets(
    user_id: str,
    current_user: User = Depends(get_current_user),
    reset_service: PasswordResetService = Depends(get_reset_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Revoke all active password reset tokens for a user (admin only).
    Accepts either user_id or email as the path parameter."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    # Resolve email to user_id if needed
    target_id = user_id
    if "@" in user_id:
        user_storage = UserStorage()
        user = await user_storage.get_user_by_email(user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
        target_id = user.id

    count = await reset_service.revoke_user_tokens(target_id)

    # Log admin action
    await audit_service.log_event(
        event_type="admin_revoked_password_resets",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"target_user_id": user_id, "revoked_count": count},
    )

    return {"message": f"Revoked {count} password reset tokens"}


@router.delete("/api/admin/password-resets/{token_id}")
async def delete_password_reset(
    token_id: str,
    current_user: User = Depends(get_current_user),
    reset_service: PasswordResetService = Depends(get_reset_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Delete a single password reset token (admin only)."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    success = await reset_service.delete_token(token_id)
    if not success:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Token not found")

    await audit_service.log_event(
        event_type="admin_deleted_password_reset",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"token_id": token_id},
    )

    return {"message": "Token deleted successfully"}


@router.post("/api/admin/password-resets/cleanup")
async def cleanup_password_resets(
    current_user: User = Depends(get_current_user),
    reset_service: PasswordResetService = Depends(get_reset_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Cleanup expired password reset tokens (admin only)."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    deleted_count = await reset_service.cleanup_expired_tokens()

    # Log cleanup
    await audit_service.log_event(
        event_type="admin_cleaned_password_resets",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"deleted_count": deleted_count},
    )

    return {"message": f"Cleaned up {deleted_count} expired tokens"}


@router.get("/api/admin/password-resets/stats")
async def get_password_reset_stats(
    current_user: User = Depends(get_current_user),
    reset_service: PasswordResetService = Depends(get_reset_service),
):
    """Get password reset statistics (admin only)."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    stats = await reset_service.get_stats()
    return stats
