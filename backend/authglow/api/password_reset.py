"""Password reset API endpoints."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, status

from authglow.api.auth import get_current_user
from authglow.core.config import get_settings
from authglow.core.password import validate_password_strength
from authglow.core.rate_limit import limiter
from authglow.models.password_reset import (
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
from authglow.services.password import hash_password, verify_password
from authglow.services.password_reset import PasswordResetService
from authglow.services.storage import UserStorage

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
    token, plaintext_token = await reset_service.create_reset_token(
        user_id=user.id,
        email=user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        expires_in_minutes=30,
    )

    # Send password reset email
    reset_url = f"{settings.base_url}/password/reset?token={plaintext_token}"

    await email_service.send_template(
        to=[user.email],
        subject="Reset Your Password - AuthGlow",
        template_name="password_reset",
        context={
            "user_name": user.first_name or user.email.split("@")[0],
            "reset_url": reset_url,
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
):
    """Confirm password reset with token and set new password."""
    # Verify token
    token = await reset_service.verify_token(reset_confirm.token)

    if not token:
        await audit_service.log_event(
            event_type="password_reset_failed",
            metadata={"reason": "invalid_or_expired_token"},
            severity="warning",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token",
        )

    # Validate password strength
    is_valid, message = validate_password_strength(reset_confirm.new_password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    # Get user
    user = await user_storage.get_user(token.user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    # Hash new password
    hashed_password = hash_password(reset_confirm.new_password)

    # Update user password
    user.hashed_password = hashed_password
    await user_storage.update_user(user)

    # Mark token as used
    await reset_service.mark_token_used(token.token_lookup)

    # Revoke any other active tokens for this user
    await reset_service.revoke_user_tokens(user.id)

    # Log successful reset
    await audit_service.log_event(
        event_type="password_reset_completed",
        user_id=user.id,
        email=user.email,
        metadata={"token_id": token.token_id},
        ip_address=request.client.host if request.client else None,
    )

    return {"message": "Password reset successful"}


@router.post("/api/password/change")
@limiter.limit("20/hour")
async def change_password(
    request: Request,
    password_change: PasswordChange,
    current_user: User = Depends(get_current_user),
    user_storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Change password for authenticated user.

    Requires current password for verification.
    """
    # Verify current password
    if not verify_password(password_change.current_password, current_user.hashed_password):
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
    is_valid, message = validate_password_strength(password_change.new_password)
    if not is_valid:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=message)

    # Check if new password is same as current
    if verify_password(password_change.new_password, current_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be different from current password",
        )

    # Hash new password
    hashed_password = hash_password(password_change.new_password)

    # Update user password
    current_user.hashed_password = hashed_password
    await user_storage.update_user(current_user)

    # Log successful change
    await audit_service.log_event(
        event_type="password_changed",
        user_id=current_user.id,
        email=current_user.email,
        ip_address=request.client.host if request.client else None,
    )

    return {"message": "Password changed successfully"}


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
    """Revoke all active password reset tokens for a user (admin only)."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")

    count = await reset_service.revoke_user_tokens(user_id)

    # Log admin action
    await audit_service.log_event(
        event_type="admin_revoked_password_resets",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"target_user_id": user_id, "revoked_count": count},
    )

    return {"message": f"Revoked {count} password reset tokens"}


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
