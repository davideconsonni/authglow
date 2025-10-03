"""MFA API endpoints."""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status, Request

from authglow.models.user import User, UserResponse
from authglow.models.mfa import (
    MFAEnrollResponse,
    MFAVerifyRequest,
    MFAStatus,
    TrustedDevice
)
from authglow.services.storage import UserStorage
from authglow.services.mfa import MFAService
from authglow.services.audit import AuditService
from authglow.api.auth import get_current_user


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


@router.post("/api/mfa/enroll", response_model=MFAEnrollResponse)
async def enroll_mfa(
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
    storage: UserStorage = Depends(get_user_storage)
):
    """
    Start MFA enrollment process.
    Generates TOTP secret, QR code, and backup codes.
    """
    if current_user.mfa_enabled:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled. Disable it first to re-enroll."
        )

    # Generate TOTP secret
    secret = mfa_service.generate_totp_secret()

    # Generate QR code
    uri = mfa_service.get_totp_uri(secret, current_user.email)
    qr_code = mfa_service.generate_qr_code(uri)

    # Generate backup codes
    backup_codes = mfa_service.generate_backup_codes(10)

    # Save secret to user (not verified yet)
    current_user.mfa_secret = secret
    current_user.mfa_enabled = True
    current_user.mfa_verified = False
    await storage.update_user(current_user)

    # Save backup codes
    await mfa_service.save_backup_codes(current_user.id, backup_codes)

    return MFAEnrollResponse(
        secret=secret,
        qr_code=qr_code,
        backup_codes=backup_codes
    )


@router.post("/api/mfa/verify", response_model=UserResponse)
async def verify_mfa_enrollment(
    verify_request: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service)
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

    # Verify TOTP code
    if not mfa_service.verify_totp(current_user.mfa_secret, verify_request.code):
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    # Mark as verified
    current_user.mfa_verified = True
    await storage.update_user(current_user)

    # Log MFA enabled
    await audit_service.log_event(
        event_type="mfa_enabled",
        user_id=current_user.id,
        email=current_user.email
    )

    return UserResponse(**current_user.model_dump())


@router.delete("/api/mfa/disable")
async def disable_mfa(
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
    storage: UserStorage = Depends(get_user_storage)
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
    mfa_service: MFAService = Depends(get_mfa_service)
):
    """Get MFA status for current user."""
    backup_codes = await mfa_service.get_backup_codes(current_user.id)
    trusted_devices = await mfa_service.list_trusted_devices(current_user.id)

    return MFAStatus(
        enabled=current_user.mfa_enabled,
        verified=current_user.mfa_verified,
        backup_codes_remaining=len(backup_codes.codes) if backup_codes else 0,
        trusted_devices_count=len(trusted_devices)
    )


@router.get("/api/mfa/trusted-devices", response_model=List[TrustedDevice])
async def list_trusted_devices(
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service)
):
    """List all trusted devices for current user."""
    return await mfa_service.list_trusted_devices(current_user.id)


@router.delete("/api/mfa/trusted-devices/{device_id}")
async def remove_trusted_device(
    device_id: str,
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service)
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
    mfa_service: MFAService = Depends(get_mfa_service)
):
    """Regenerate backup codes (requires MFA to be enabled)."""
    if not current_user.mfa_enabled or not current_user.mfa_verified:
        raise HTTPException(
            status_code=400,
            detail="MFA must be enabled and verified to regenerate backup codes"
        )

    # Generate new backup codes
    backup_codes = mfa_service.generate_backup_codes(10)

    # Save new backup codes (replaces old ones)
    await mfa_service.save_backup_codes(current_user.id, backup_codes)

    return {
        "message": "Backup codes regenerated successfully",
        "backup_codes": backup_codes
    }
