"""MFA API endpoints."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from authglow.api.auth import _set_auth_cookies, get_current_user
from authglow.core.config import get_settings
from authglow.core.crypto import decrypt_totp_secret, encrypt_totp_secret
from authglow.core.datetime import utcnow
from authglow.core.rate_limit import limiter
from authglow.models.mfa import (
    MFAEnrollResponse,
    MFAStatus,
    MFAVerifyRequest,
    TrustedDevice,
)
from authglow.models.user import User, UserResponse
from authglow.services.audit import AuditService
from authglow.services.jwt import JWTService
from authglow.services.mfa import BackupCodeLockedException, MFAService
from authglow.services.storage import UserStorage

router = APIRouter()


def get_mfa_service():
    """Get MFA service instance."""
    return MFAService()


def get_user_storage():
    """Get user storage instance."""
    return UserStorage()


def get_audit_service():
    """Get audit service instance."""
    return AuditService()


def get_jwt_service():
    """Get JWT service instance."""
    return JWTService()


@router.post("/api/mfa/enroll", response_model=MFAEnrollResponse)
async def enroll_mfa(
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
    storage: UserStorage = Depends(get_user_storage),
):
    """
    Start MFA enrollment process.
    Generates TOTP secret, QR code, and backup codes.
    """
    if current_user.mfa_enabled and current_user.mfa_verified:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled. Disable it first to re-enroll.",
        )

    # Generate TOTP secret
    secret = mfa_service.generate_totp_secret()

    # Generate QR code
    uri = mfa_service.get_totp_uri(secret, current_user.email)
    qr_code = mfa_service.generate_qr_code(uri)

    # Generate backup codes
    backup_codes = mfa_service.generate_backup_codes(10)

    # Save encrypted secret to user (not verified yet)
    current_user.mfa_secret = encrypt_totp_secret(secret)
    current_user.mfa_enabled = True
    current_user.mfa_verified = False
    await storage.update_user(current_user)

    # Save backup codes
    await mfa_service.save_backup_codes(current_user.id, backup_codes)

    return MFAEnrollResponse(secret=secret, qr_code=qr_code, backup_codes=backup_codes)


@router.post("/api/mfa/verify", response_model=UserResponse)
async def verify_mfa_enrollment(
    verify_request: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """
    Verify MFA enrollment with first TOTP code.
    This completes the MFA setup.
    """
    if not current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    if current_user.mfa_verified:
        raise HTTPException(status_code=400, detail="MFA is already verified")

    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="No MFA secret found")

    # Verify TOTP code (decrypt stored secret first)
    if not mfa_service.verify_totp(
        decrypt_totp_secret(current_user.mfa_secret), verify_request.code
    ):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    # Mark as verified
    current_user.mfa_verified = True
    await storage.update_user(current_user)

    # Log MFA enabled
    await audit_service.log_event(
        event_type="mfa_enabled", user_id=current_user.id, email=current_user.email
    )

    return UserResponse(**current_user.model_dump())


@router.delete("/api/mfa/disable")
async def disable_mfa(
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
    storage: UserStorage = Depends(get_user_storage),
):
    """Disable MFA for current user."""
    if not current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    # Remove MFA settings
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.mfa_verified = False
    await storage.update_user(current_user)

    # Delete backup codes
    await mfa_service.delete_backup_codes(current_user.id)

    return {"message": "MFA disabled successfully"}


@router.get("/api/mfa/status", response_model=MFAStatus)
async def get_mfa_status(
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
):
    """Get MFA status for current user."""
    backup_codes = await mfa_service.get_backup_codes(current_user.id)
    trusted_devices = await mfa_service.list_trusted_devices(current_user.id)

    return MFAStatus(
        enabled=current_user.mfa_enabled,
        verified=current_user.mfa_verified,
        backup_codes_remaining=len(backup_codes.codes) if backup_codes else 0,
        trusted_devices_count=len(trusted_devices),
    )


@router.get("/api/mfa/trusted-devices", response_model=List[TrustedDevice])
async def list_trusted_devices(
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
):
    """List all trusted devices for current user."""
    return await mfa_service.list_trusted_devices(current_user.id)


@router.delete("/api/mfa/trusted-devices/{device_id}")
async def remove_trusted_device(
    device_id: str,
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
):
    """Remove a trusted device."""
    # Verify device belongs to current user
    devices = await mfa_service.list_trusted_devices(current_user.id)
    device_ids = [d.id for d in devices]

    if device_id not in device_ids:
        raise HTTPException(status_code=404, detail="Device not found")

    success = await mfa_service.remove_trusted_device(device_id)
    if not success:
        raise HTTPException(status_code=404, detail="Device not found")

    return {"message": "Device removed successfully"}


@router.post("/api/mfa/regenerate-backup-codes", response_model=dict)
async def regenerate_backup_codes(
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
):
    """Regenerate backup codes (requires MFA to be enabled)."""
    if not current_user.mfa_enabled or not current_user.mfa_verified:
        raise HTTPException(
            status_code=400,
            detail="MFA must be enabled and verified to regenerate backup codes",
        )

    # Generate new backup codes
    backup_codes = mfa_service.generate_backup_codes(10)

    # Save new backup codes (replaces old ones)
    await mfa_service.save_backup_codes(current_user.id, backup_codes)

    return {
        "message": "Backup codes regenerated successfully",
        "backup_codes": backup_codes,
    }


@router.post("/api/mfa/verify-login")
@limiter.limit("3/minute")
async def verify_mfa_login(
    response: Response,
    verify_request: MFAVerifyRequest,
    storage: UserStorage = Depends(get_user_storage),
    mfa_service: MFAService = Depends(get_mfa_service),
    jwt_service: JWTService = Depends(get_jwt_service),
    audit_service: AuditService = Depends(get_audit_service),
    request: Request = None,  # type: ignore[assignment]
):
    """Verify MFA code during login and return access token. Sets httpOnly auth cookies."""
    settings = get_settings()
    # Decode session token (should be in Authorization header or in body)

    # Try to get session token from request
    session_token = (
        request.headers.get("Authorization", "").replace("Bearer ", "") if request else None
    )
    if not session_token:
        raise HTTPException(status_code=401, detail="Session token required")

    # Decode session token
    token_data = jwt_service.decode_token(session_token)
    if not token_data or token_data.token_type != "mfa_session":
        raise HTTPException(status_code=401, detail="Invalid session token")

    # Get user
    user = await storage.get_user(token_data.sub)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if not user.mfa_enabled or not user.mfa_verified:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    # Check if account is suspended
    if user.suspended_until and utcnow() < user.suspended_until:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account suspended until {user.suspended_until.isoformat()}",
        )

    # Verify TOTP code or backup code
    is_valid = False
    is_backup_code = False

    if len(verify_request.code) == 6 and verify_request.code.isdigit():
        # Try TOTP
        if not user.mfa_secret:
            raise HTTPException(status_code=500, detail="MFA secret not configured")

        is_valid = mfa_service.verify_totp(
            decrypt_totp_secret(user.mfa_secret), verify_request.code
        )
    else:
        # Try backup code
        try:
            if await mfa_service.verify_user_backup_code(user.id, verify_request.code):
                is_valid = True
                is_backup_code = True
        except BackupCodeLockedException as e:
            raise HTTPException(
                status_code=429,
                detail=f"Too many backup code attempts. Retry after {e.retry_after_seconds} seconds.",
                headers={"Retry-After": str(e.retry_after_seconds)},
            )

    if not is_valid:
        await audit_service.log_event(
            event_type="mfa_verification_failed",
            user_id=user.id,
            email=user.email,
            ip_address=request.client.host if request and request.client else None,
            severity="warning",
        )
        from authglow.services.login_history import LoginHistoryService

        login_svc = LoginHistoryService()
        await login_svc.record_login(
            user_id=user.id,
            email=user.email,
            success=False,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            failure_reason="invalid_mfa_code",
        )
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    # Update last login
    await storage.update_last_login(user.id)

    # Log successful login with MFA
    await audit_service.log_event(
        event_type="login_success_with_mfa",
        user_id=user.id,
        email=user.email,
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get("user-agent") if request else None,
        metadata={"backup_code_used": is_backup_code},
    )

    from authglow.services.login_history import LoginHistoryService

    login_svc = LoginHistoryService()
    await login_svc.record_login(
        user_id=user.id,
        email=user.email,
        success=True,
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get("user-agent") if request else None,
    )

    # Blacklist the MFA session token so it cannot be replayed (VAPT-013)
    if token_data.jti:
        from authglow.core.token_blacklist import token_blacklist as get_blacklist

        await get_blacklist().revoke(token_data.jti, token_data.exp.timestamp())

    # Create refresh token and set httpOnly auth cookies
    from authglow.services.refresh_token import RefreshTokenService

    rt_service = RefreshTokenService()
    rt = await rt_service.create_refresh_token(
        user_id=user.id,
        client_id="password_grant",
        scopes=user.scopes,
        issued_ip=request.client.host if request and request.client else None,
        expires_in_days=settings.refresh_token_expire_days,
    )

    token_response = jwt_service.create_token_response(user.id, user.email, user.scopes)
    token_response.refresh_token = rt.token
    _set_auth_cookies(response, token_response.access_token, rt.token, settings)

    return token_response
