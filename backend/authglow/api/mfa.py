"""MFA API endpoints."""

import asyncio
from typing import List

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from authglow.api.auth import _build_oauth_redirect, _set_auth_cookies, get_current_user
from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.core.crypto import decrypt_totp_secret, encrypt_totp_secret
from authglow.core.datetime import utcnow
from authglow.core.jwt_singleton import get_jwt_service
from authglow.core.rate_limit import limiter
from authglow.models.audit_events import AuditEventType
from authglow.models.audit_metadata import (
    BackupCodeMetadata,
    MFAEnabledMetadata,
    MFAFailedMetadata,
    MFAVerifiedMetadata,
    TrustedDeviceMetadata,
)
from authglow.models.mfa import (
    MFAEnrollResponse,
    MFALoginRequest,
    MFAStatus,
    MFAVerifyRequest,
    TrustedDevice,
)
from authglow.models.user import User, UserResponse
from authglow.services.audit import AuditService
from authglow.services.jwt import JWTService
from authglow.services.mfa import BackupCodeLockedException, MFAService
from authglow.services.oauth2 import OAuth2Service
from authglow.services.oauth_client import OAuth2ClientStorage
from authglow.services.oauth_consent import OAuth2ConsentService
from authglow.services.security_notifications import SecurityNotificationService
from authglow.services.session import SessionService
from authglow.services.user import UserService

# Back-compat alias for Fase 21 transition window
UserStorage = UserService

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
    storage: UserStorage = Depends(get_user_storage),
):
    """
    Start MFA enrollment process.

    Generates a fresh TOTP secret, QR code and backup codes, then stores
    the encrypted secret on the user record. ``mfa_enabled`` and
    ``mfa_verified`` are **not** flipped to ``True`` here — that only
    happens after a successful TOTP code submission in
    ``/api/mfa/verify``. Persisting the flag too early leaves users
    in an unrecoverable state where the login flow asks for a code
    the user never had a chance to enroll against.
    """
    lock = named_lock()
    async with lock(f"mfa_enroll:{current_user.id}"):
        fresh_user = await storage.get_user(current_user.id)
        if not fresh_user:
            raise HTTPException(status_code=404, detail="User not found")

        if fresh_user.mfa_enabled and fresh_user.mfa_verified:
            raise HTTPException(
                status_code=400,
                detail="MFA is already enabled. Disable it first to re-enroll.",
            )

        # Generate TOTP secret
        secret = mfa_service.generate_totp_secret()

        # Generate QR code
        uri = mfa_service.get_totp_uri(secret, fresh_user.email)
        qr_code = mfa_service.generate_qr_code(uri)

        # Generate backup codes
        backup_codes = mfa_service.generate_backup_codes(10)

        # Auto-heal orphaned state: if a previous enroll left a secret
        # behind but the user never verified, treat this as a fresh
        # enroll. We never reuse a stale secret because the user may
        # have lost the QR/backup codes from that attempt.
        fresh_user.mfa_secret = encrypt_totp_secret(secret)
        fresh_user.mfa_enabled = False
        fresh_user.mfa_verified = False
        await storage.update_user(fresh_user)

        # Save backup codes (overwrites any prior set for this user)
        await mfa_service.save_backup_codes(fresh_user.id, backup_codes)

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

    Completes the MFA setup: flips ``mfa_enabled`` and ``mfa_verified``
    to ``True`` only after the user proves they can produce a valid
    TOTP code from the secret returned by ``/api/mfa/enroll``.
    """
    if not current_user.mfa_secret:
        raise HTTPException(status_code=400, detail="No MFA secret found")

    if current_user.mfa_enabled and current_user.mfa_verified:
        raise HTTPException(status_code=400, detail="MFA is already verified")

    # Verify TOTP code (decrypt stored secret first)
    if not mfa_service.verify_totp(
        decrypt_totp_secret(current_user.mfa_secret), verify_request.code
    ):
        raise HTTPException(status_code=400, detail="Invalid MFA code")

    # Mark as enabled AND verified atomically — both flags are required
    # for the login flow to demand a TOTP code, so flipping only one
    # would leave the account in a half-protected state.
    current_user.mfa_enabled = True
    current_user.mfa_verified = True
    await storage.update_user(current_user)

    # Get backup codes count for audit log
    backup_codes_obj = await mfa_service.get_backup_codes(current_user.id)
    backup_codes_count = len(backup_codes_obj.codes) if backup_codes_obj else 0

    from authglow.models.webhook_events import MFA_ENROLLED
    from authglow.services.webhook_dispatcher import emit_webhook_event

    emit_webhook_event(MFA_ENROLLED, {"user_id": current_user.id})

    # Log MFA enabled
    await audit_service.log_event(
        event_type=AuditEventType.MFA_ENABLED,
        user_id=current_user.id,
        email=current_user.email,
        metadata=MFAEnabledMetadata(
            method="totp",
            backup_codes_generated=backup_codes_count,
        ),
    )

    return UserResponse(**current_user.model_dump())


@router.delete("/api/mfa/disable")
async def disable_mfa(
    request: Request,
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Disable MFA for current user.

    Accepts both fully-enrolled (``mfa_enabled=True``) and orphaned
    half-states (e.g. ``mfa_secret`` set but never verified) so users
    stuck after a failed enroll can self-recover without an admin
    call.

    VAPT-056: the disable event is one of the highest-signal
    compromise indicators — it always leaves a warning-severity audit
    trail and triggers the user-facing security email (fire-and-forget,
    send failures are swallowed by the notification service).
    """
    has_any_mfa_state = current_user.mfa_enabled or bool(current_user.mfa_secret)
    if not has_any_mfa_state:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    # Remove MFA settings
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    current_user.mfa_verified = False
    await storage.update_user(current_user)

    # Delete backup codes
    await mfa_service.delete_backup_codes(current_user.id)

    client_ip = request.client.host if request.client else None

    await audit_service.log_event(
        event_type=AuditEventType.MFA_DISABLED,
        user_id=current_user.id,
        email=current_user.email,
        ip_address=client_ip,
        metadata=MFAEnabledMetadata(method="totp"),
        severity="warning",
    )

    asyncio.create_task(
        SecurityNotificationService().send_mfa_disabled_alert(current_user, ip_address=client_ip)
    )

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
    audit_service: AuditService = Depends(get_audit_service),
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

    # Audit: trusted device removed
    await audit_service.log_event(
        event_type=AuditEventType.TRUSTED_DEVICE_REMOVED,
        user_id=current_user.id,
        email=current_user.email,
        metadata=TrustedDeviceMetadata(
            device_fingerprint=device_id,
        ),
    )

    return {"message": "Device removed successfully"}


@router.post("/api/mfa/regenerate-backup-codes", response_model=dict)
async def regenerate_backup_codes(
    current_user: User = Depends(get_current_user),
    mfa_service: MFAService = Depends(get_mfa_service),
    audit_service: AuditService = Depends(get_audit_service),
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

    # Audit: backup codes regenerated
    await audit_service.log_event(
        event_type=AuditEventType.BACKUP_CODES_GENERATED,
        user_id=current_user.id,
        email=current_user.email,
        metadata=BackupCodeMetadata(
            method="backup_code",
            codes_remaining=len(backup_codes),
        ),
    )

    return {
        "message": "Backup codes regenerated successfully",
        "backup_codes": backup_codes,
    }


@router.post("/api/mfa/verify-login")
@limiter.limit("3/minute")
async def verify_mfa_login(
    response: Response,
    login_request: MFALoginRequest,
    storage: UserStorage = Depends(get_user_storage),
    mfa_service: MFAService = Depends(get_mfa_service),
    jwt_service: JWTService = Depends(get_jwt_service),
    audit_service: AuditService = Depends(get_audit_service),
    request: Request = None,  # type: ignore[assignment]
):
    """Verify MFA code during login and return access token. Sets httpOnly auth cookies."""
    settings = get_settings()

    session_token = login_request.session_token
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

    if len(login_request.code) == 6 and login_request.code.isdigit():
        # Try TOTP
        if not user.mfa_secret:
            raise HTTPException(status_code=500, detail="MFA secret not configured")

        is_valid = mfa_service.verify_totp(decrypt_totp_secret(user.mfa_secret), login_request.code)
    else:
        # Try backup code
        try:
            if await mfa_service.verify_user_backup_code(user.id, login_request.code):
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
            event_type=AuditEventType.MFA_FAILED,
            user_id=user.id,
            email=user.email,
            ip_address=request.client.host if request and request.client else None,
            user_agent=request.headers.get("user-agent") if request else None,
            metadata=MFAFailedMetadata(
                method="backup_code" if is_backup_code else "totp",
                failure_reason="invalid_code",
            ),
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
        event_type=AuditEventType.MFA_VERIFIED,
        user_id=user.id,
        email=user.email,
        ip_address=request.client.host if request and request.client else None,
        user_agent=request.headers.get("user-agent") if request else None,
        metadata=MFAVerifiedMetadata(
            method="backup_code" if is_backup_code else "totp",
        ),
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
        from authglow.services.auth.token_blacklist import token_blacklist as get_blacklist

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

    # Issue the access token with the claim policy applied —
    # first-party MFA completion uses the default rule set
    # (namespaced RBAC roles + permissions).
    from authglow.models.claim_policy import ClaimTarget
    from authglow.services.claim_policy import ClaimPolicyService

    claim_policy_service = ClaimPolicyService()
    extra_claims = await claim_policy_service.build_claims(
        user,
        client_id=None,
        scopes=list(user.scopes),
        target=ClaimTarget.ACCESS_TOKEN,
    )

    token_response = jwt_service.create_token_response(
        user.id,
        user.email,
        user.scopes,
        extra_claims=extra_claims,
    )
    token_response.refresh_token = rt.token
    _set_auth_cookies(response, token_response.access_token, rt.token, settings)

    return token_response


@router.post("/api/mfa/verify-oauth-login")
@limiter.limit("3/minute")
async def verify_oauth_mfa_login(
    request: Request,
    login_request: MFALoginRequest,
    storage: UserStorage = Depends(get_user_storage),
    mfa_service: MFAService = Depends(get_mfa_service),
    session_service: SessionService = Depends(lambda: SessionService()),
    oauth2_service: OAuth2Service = Depends(lambda: OAuth2Service()),
    consent_service: OAuth2ConsentService = Depends(lambda: OAuth2ConsentService()),
    client_storage: OAuth2ClientStorage = Depends(lambda: OAuth2ClientStorage()),
):
    """Complete MFA for an OAuth authorization transaction."""
    session = await session_service.get_mfa_session(login_request.session_token)
    if not session:
        raise HTTPException(status_code=401, detail="Invalid or expired OAuth MFA session")

    user = await storage.get_user(session.user_id)
    if not user or not user.is_active or not user.mfa_enabled or not user.mfa_verified:
        raise HTTPException(status_code=401, detail="Invalid OAuth MFA session")

    is_valid = False
    if len(login_request.code) == 6 and login_request.code.isdigit():
        if not user.mfa_secret:
            raise HTTPException(status_code=500, detail="MFA secret not configured")
        is_valid = mfa_service.verify_totp(decrypt_totp_secret(user.mfa_secret), login_request.code)
    else:
        try:
            is_valid = await mfa_service.verify_user_backup_code(user.id, login_request.code)
        except BackupCodeLockedException as exc:
            raise HTTPException(
                status_code=429,
                detail=f"Too many backup code attempts. Retry after {exc.retry_after_seconds} seconds.",
                headers={"Retry-After": str(exc.retry_after_seconds)},
            ) from exc

    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    await storage.update_last_login(user.id)
    await session_service.delete_mfa_session(login_request.session_token)

    client = await client_storage.get_client(session.client_id)
    if not client or not client.is_active:
        raise HTTPException(status_code=400, detail="Invalid or inactive OAuth client")

    requested_scopes = session.scope.split() if session.scope else ["read"]
    has_consent, _ = await consent_service.check_consent(
        user_id=user.id,
        client_id=session.client_id,
        required_scopes=requested_scopes,
    )

    if client.require_consent and not has_consent:
        consent_session = await session_service.create_consent_session(
            user_id=user.id,
            client_id=session.client_id,
            redirect_uri=session.redirect_uri,
            scope=session.scope,
            state=session.state,
            code_challenge=session.code_challenge,
            code_challenge_method=session.code_challenge_method,
            nonce=session.nonce,
        )
        return {"consent_session_token": consent_session["session_token"]}

    auth_code = await oauth2_service.create_authorization_code(
        client_id=session.client_id,
        user_id=user.id,
        redirect_uri=session.redirect_uri,
        scope=session.scope,
        code_challenge=session.code_challenge,
        code_challenge_method=session.code_challenge_method,
        nonce=session.nonce,
        acr="2",
        amr=["pwd", "otp"],
        state=session.state,
    )
    return {
        "redirect_url": _build_oauth_redirect(
            session.redirect_uri,
            code=auth_code.code,
            state=session.state,
            # RFC 9207 §2: mix-up mitigation — every authorization
            # response carries the issuer identifier.
            iss=get_settings().issuer,
        )
    }
