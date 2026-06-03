"""Admin portal API endpoints."""

import os
from datetime import datetime
from typing import Optional, TypedDict

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from authglow.api.auth import get_current_user
from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.models.admin import (
    AdminUserDetail,
    BulkUserOperation,
    DashboardStats,
    PaginatedResponse,
    SetPasswordRequest,
    UserUpdate,
)
from authglow.models.user import User, UserResponse
from authglow.services.audit import AuditService
from authglow.services.jwt import JWTService
from authglow.services.mfa import MFAService
from authglow.services.oauth_client import OAuth2ClientStorage
from authglow.services.oauth_consent import OAuth2ConsentService
from authglow.services.passkey import PasskeyService
from authglow.services.password import PasswordValidator, hash_password
from authglow.services.password_reset import PasswordResetService
from authglow.services.refresh_token import RefreshTokenService
from authglow.services.storage import UserStorage

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
        storage_path=settings.storage_path,
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
@limiter.limit("30/minute")  # Max 30 user updates per minute per IP
async def update_user(
    request: Request,
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

    # Update fields
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

    user = await storage.update_user(user)

    # Log action
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

    return {"message": "MFA reset successfully"}


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

    reset_service = PasswordResetService()
    token, plaintext = await reset_service.create_reset_token(
        user_id=user.id,
        email=user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    from authglow.services.email.factory import get_email_service

    email_service = get_email_service()
    reset_url = f"{get_settings().base_url}/reset-password?token={plaintext}"
    await email_service.send_template(
        to=[user.email],
        subject="Password Reset Request - AuthGlow",
        template_name="password_reset",
        context={
            "user": user,
            "reset_url": reset_url,
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

    user.password_expired = True
    await storage.update_user(user)

    await audit_service.log_event(
        event_type="password_expired_by_admin",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"target_user_id": user_id, "target_user_email": user.email},
        severity="warning",
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
                "client_id": rt.client_id,
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

    success = await refresh_token_service.revoke_token(rt.token, reason="Revoked by admin")

    if success:
        await audit_service.log_event(
            event_type="refresh_token_revoked_by_admin",
            user_id=current_user.id,
            email=current_user.email,
            metadata={"token_id": token_id, "target_user_id": rt.user_id},
            severity="warning",
        )

    return {"message": "Token revoked successfully"}


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
    client_storage = OAuth2ClientStorage()
    user_storage = UserStorage()

    consents_list = []

    try:
        import fsspec as _fsspec

        from authglow.core.async_io import AsyncFileSystem
        from authglow.core.config import get_settings as _get_settings

        _settings = _get_settings()
        _storage_path = f"{_settings.storage_path}/oauth_consents"

        if _settings.storage_backend == "file":
            _fs = _fsspec.filesystem("file")
        else:
            _fs = _fsspec.filesystem(_settings.storage_backend, **_settings.get_storage_options())
        _afs = AsyncFileSystem(_fs)

        pattern = f"{_storage_path}/**/*.json"
        files = await _afs.glob(pattern)

        for file_path in files:
            try:
                data = await _afs.read_json(file_path)
                from authglow.models.oauth_consent import OAuth2Consent

                consent = OAuth2Consent(**data)

                user = await user_storage.get_user(consent.user_id)
                if not user:
                    continue

                if email and email.lower() not in user.email.lower():
                    continue

                client = await client_storage.get_client(consent.client_id)
                client_name = client.client_name if client else consent.client_id

                consents_list.append(
                    {
                        "consent_id": consent.consent_id,
                        "user_email": user.email,
                        "client_id": consent.client_id,
                        "client_name": client_name,
                        "scopes": consent.scopes,
                        "granted_at": consent.granted_at.isoformat(),
                        "expires_at": consent.expires_at.isoformat()
                        if consent.expires_at
                        else None,
                        "revoked": consent.revoked,
                        "revoked_at": consent.revoked_at.isoformat()
                        if consent.revoked_at
                        else None,
                    }
                )

            except Exception:
                continue

    except Exception:
        pass

    consents_list.sort(key=lambda x: str(x.get("granted_at", "")), reverse=True)
    total = len(consents_list)
    paginated = consents_list[offset : offset + limit]

    return PaginatedResponse(items=paginated, total=total, limit=limit, offset=offset)


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
