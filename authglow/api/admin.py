"""Admin portal API endpoints."""

from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from authglow.core.rate_limit import limiter
from authglow.core.datetime import utcnow

from authglow.models.user import User, UserResponse
from authglow.models.admin import (
    DashboardStats,
    UserStatsTimeSeries,
    AdminUserDetail,
    UserFilter,
    UserUpdate,
    BulkUserOperation,
    AuditLogEntry,
    AuditLogFilter,
    SecurityEvent,
)
from authglow.services.storage import UserStorage
from authglow.services.audit import AuditService
from authglow.services.mfa import MFAService
from authglow.services.passkey import PasskeyService
from authglow.services.refresh_token import RefreshTokenService
from authglow.services.oauth_consent import OAuth2ConsentService
from authglow.services.oauth_client import OAuth2ClientStorage
from authglow.api.auth import get_current_user
from authglow.core.config import get_settings

router = APIRouter()
templates = Jinja2Templates(directory="authglow/templates")


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


# Dashboard Pages


@router.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    """Admin dashboard page (auth handled by JS)."""
    settings = get_settings()
    ui_context = settings.get_ui_context()

    return templates.TemplateResponse(
        "admin_dashboard.html", {"request": request, **ui_context}
    )


@router.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(request: Request):
    """User management page (auth handled by JS)."""
    settings = get_settings()
    ui_context = settings.get_ui_context()

    return templates.TemplateResponse(
        "admin_users.html", {"request": request, **ui_context}
    )


@router.get("/admin/audit", response_class=HTMLResponse)
async def admin_audit_page(request: Request):
    """Audit logs page (auth handled by JS)."""
    settings = get_settings()
    ui_context = settings.get_ui_context()

    return templates.TemplateResponse(
        "admin_audit.html",
        {
            "request": request,
            **ui_context,
            "current_user": {"email": "Loading..."},  # Will be loaded by JS
        },
    )


@router.get("/admin/oauth-clients", response_class=HTMLResponse)
async def admin_oauth_clients_page(request: Request):
    """OAuth2 clients management page (auth handled by JS)."""
    settings = get_settings()
    ui_context = settings.get_ui_context()

    return templates.TemplateResponse(
        "admin_oauth_clients.html", {"request": request, **ui_context}
    )


@router.get("/admin/api-keys", response_class=HTMLResponse)
async def admin_api_keys_page(request: Request):
    """API keys management page (auth handled by JS)."""
    settings = get_settings()
    ui_context = settings.get_ui_context()

    return templates.TemplateResponse(
        "admin_api_keys.html", {"request": request, **ui_context}
    )


@router.get("/admin/password-resets", response_class=HTMLResponse)
async def admin_password_resets_page(request: Request):
    """Password resets management page (auth handled by JS)."""
    settings = get_settings()
    ui_context = settings.get_ui_context()

    return templates.TemplateResponse(
        "admin_password_resets.html", {"request": request, **ui_context}
    )


# API Endpoints


@router.get("/api/admin/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Get dashboard statistics."""
    # Get all users
    users = await storage.list_users(limit=10000)

    total_users = len(users)
    active_users = sum(1 for u in users if u.is_active)
    inactive_users = total_users - active_users
    users_with_mfa = sum(1 for u in users if u.mfa_enabled and u.mfa_verified)
    mfa_percentage = (users_with_mfa / total_users * 100) if total_users > 0 else 0

    # Get new users
    now = utcnow()
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    week_start = today_start - timedelta(days=7)
    month_start = today_start - timedelta(days=30)

    new_users_today = sum(1 for u in users if u.created_at >= today_start)
    new_users_this_week = sum(1 for u in users if u.created_at >= week_start)
    new_users_this_month = sum(1 for u in users if u.created_at >= month_start)

    # Get login stats from audit logs
    event_counts_today = await audit_service.get_event_counts_by_type(
        start_date=today_start
    )
    event_counts_week = await audit_service.get_event_counts_by_type(
        start_date=week_start
    )
    event_counts_month = await audit_service.get_event_counts_by_type(
        start_date=month_start
    )

    total_logins_today = event_counts_today.get("login_success", 0)
    total_logins_this_week = event_counts_week.get("login_success", 0)
    total_logins_this_month = event_counts_month.get("login_success", 0)
    failed_logins_today = event_counts_today.get("login_failed", 0)

    return DashboardStats(
        total_users=total_users,
        active_users=active_users,
        inactive_users=inactive_users,
        users_with_mfa=users_with_mfa,
        mfa_percentage=round(mfa_percentage, 2),
        new_users_today=new_users_today,
        new_users_this_week=new_users_this_week,
        new_users_this_month=new_users_this_month,
        total_logins_today=total_logins_today,
        total_logins_this_week=total_logins_this_week,
        total_logins_this_month=total_logins_this_month,
        failed_logins_today=failed_logins_today,
    )


@router.get("/api/admin/stats/timeseries", response_model=List[dict])
async def get_stats_timeseries(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Get time series statistics for charts."""
    return await audit_service.get_logs_by_date(days=days)


@router.get("/api/admin/users/search", response_model=List[AdminUserDetail])
async def search_users(
    search: Optional[str] = Query(None),
    is_active: Optional[bool] = Query(None),
    mfa_enabled: Optional[bool] = Query(None),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Search and filter users."""
    # Get all users (in production, implement database-level filtering)
    all_users = await storage.list_users(limit=10000)

    # Apply filters
    filtered_users = []
    for user in all_users:
        # Search filter
        if search:
            search_lower = search.lower()
            if not (
                search_lower in user.email.lower()
                or (user.first_name and search_lower in user.first_name.lower())
                or (user.last_name and search_lower in user.last_name.lower())
            ):
                continue

        # Active filter
        if is_active is not None and user.is_active != is_active:
            continue

        # MFA filter
        if mfa_enabled is not None and user.mfa_enabled != mfa_enabled:
            continue

        # Get login counts from audit logs
        user_logs = await audit_service.get_logs(
            filters=AuditLogFilter(user_id=user.id), limit=10000
        )

        login_count = sum(1 for log in user_logs if log.event_type == "login_success")
        failed_login_count = sum(
            1 for log in user_logs if log.event_type == "login_failed"
        )

        filtered_users.append(
            AdminUserDetail(
                **user.model_dump(),
                login_count=login_count,
                failed_login_count=failed_login_count,
            )
        )

    # Apply pagination
    return filtered_users[offset : offset + limit]


@router.get("/api/admin/users/{user_id}", response_model=AdminUserDetail)
async def get_user_detail(
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Get detailed user information."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get login counts
    user_logs = await audit_service.get_logs(
        filters=AuditLogFilter(user_id=user_id), limit=10000
    )

    login_count = sum(1 for log in user_logs if log.event_type == "login_success")
    failed_login_count = sum(1 for log in user_logs if log.event_type == "login_failed")

    return AdminUserDetail(
        **user.model_dump(),
        login_count=login_count,
        failed_login_count=failed_login_count,
    )


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
    results = {"success": 0, "failed": 0, "errors": []}

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


@router.get("/api/admin/audit/logs", response_model=List[AuditLogEntry])
async def get_audit_logs(
    user_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(require_admin),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Get audit logs with filtering."""
    filters = AuditLogFilter(
        user_id=user_id, event_type=event_type, severity=severity, search=search
    )

    return await audit_service.get_logs(filters=filters, limit=limit, offset=offset)


@router.get("/api/admin/security/events", response_model=List[SecurityEvent])
async def get_security_events(
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(require_admin),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Get recent security events."""
    # Get logs with warning/error/critical severity
    logs = await audit_service.get_logs(
        filters=AuditLogFilter(severity="warning"), limit=limit
    )

    # Convert to security events
    events = []
    for log in logs:
        events.append(
            SecurityEvent(
                id=log.id,
                event_type=log.event_type,
                user_email=log.email,
                timestamp=log.timestamp,
                severity=log.severity,
                description=log.event_type.replace("_", " ").title(),
                ip_address=log.ip_address,
            )
        )

    return events


# New admin endpoints for OAuth2 features


@router.get("/admin/sessions", response_class=HTMLResponse)
async def admin_sessions_page(request: Request):
    """Active sessions management page (auth handled by JS)."""
    settings = get_settings()
    return templates.TemplateResponse(
        "admin_sessions.html", {"request": request, **settings.get_ui_context()}
    )


@router.get("/admin/oauth-consents", response_class=HTMLResponse)
async def admin_oauth_consents_page(request: Request):
    """OAuth2 consents management page (auth handled by JS)."""
    settings = get_settings()
    return templates.TemplateResponse(
        "admin_oauth_consents.html", {"request": request, **settings.get_ui_context()}
    )


@router.get("/admin/rbac", response_class=HTMLResponse)
async def admin_rbac_page(request: Request):
    """RBAC management page (auth handled by JS)."""
    settings = get_settings()
    return templates.TemplateResponse(
        "admin_rbac.html", {"request": request, **settings.get_ui_context()}
    )


@router.get("/admin/playground", response_class=HTMLResponse)
async def admin_playground_page(request: Request):
    """API Playground page for testing OAuth2/OIDC flows (auth handled by JS)."""
    settings = get_settings()
    return templates.TemplateResponse(
        "admin_playground.html", {"request": request, **settings.get_ui_context()}
    )


@router.get("/api/admin/sessions")
async def get_active_sessions(
    email: Optional[str] = Query(None),
    type: str = Query("all"),
    current_user: User = Depends(require_admin),
):
    """Get all active sessions and refresh tokens."""
    refresh_token_service = RefreshTokenService()
    user_storage = UserStorage()

    sessions_list = []
    total_sessions = 0
    total_refresh_tokens = 0
    unique_users = set()

    # Get all refresh tokens
    try:
        import fsspec

        settings = get_settings()
        storage_path = f"{settings.storage_path}/refresh_tokens"

        if settings.storage_backend == "file":
            import os

            os.makedirs(storage_path, exist_ok=True)
            fs = fsspec.filesystem("file")
        else:
            fs = fsspec.filesystem(
                settings.storage_backend, **settings.get_storage_options()
            )

        pattern = f"{storage_path}/*.json"
        files = fs.glob(pattern)

        for file_path in files:
            try:
                import json

                with fs.open(file_path, "r") as f:
                    data = json.load(f)
                    from authglow.models.refresh_token import RefreshToken

                    rt = RefreshToken(**data)

                    # Skip revoked or expired
                    if rt.revoked or utcnow() > rt.expires_at:
                        continue

                    # Get user
                    user = await user_storage.get_user(rt.user_id)
                    if not user:
                        continue

                    # Filter by email if specified
                    if email and email.lower() not in user.email.lower():
                        continue

                    # Filter by type
                    if type != "all" and type != "refresh":
                        continue

                    unique_users.add(rt.user_id)
                    total_refresh_tokens += 1

                    sessions_list.append(
                        {
                            "id": rt.token_id,
                            "type": "refresh",
                            "user_email": user.email,
                            "client_id": rt.client_id,
                            "created_at": rt.created_at.isoformat(),
                            "expires_at": rt.expires_at.isoformat()
                            if rt.expires_at
                            else None,
                            "last_used_at": rt.used_at.isoformat()
                            if rt.used_at
                            else None,
                            "ip_address": rt.issued_ip,
                            "scopes": rt.scopes,
                        }
                    )

            except Exception:
                continue

    except Exception:
        pass

    total_sessions = len(sessions_list)

    return {
        "sessions": sessions_list,
        "total_sessions": total_sessions,
        "total_refresh_tokens": total_refresh_tokens,
        "unique_users": len(unique_users),
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

    success = await refresh_token_service.revoke_token(
        rt.token, reason="Revoked by admin"
    )

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
    email: Optional[str] = Query(None), current_user: User = Depends(require_admin)
):
    """Get all OAuth2 consents."""
    consent_service = OAuth2ConsentService()
    client_storage = OAuth2ClientStorage()
    user_storage = UserStorage()

    consents_list = []

    # Get all consents
    try:
        import fsspec

        settings = get_settings()
        storage_path = f"{settings.storage_path}/oauth_consents"

        if settings.storage_backend == "file":
            import os

            os.makedirs(storage_path, exist_ok=True)
            fs = fsspec.filesystem("file")
        else:
            fs = fsspec.filesystem(
                settings.storage_backend, **settings.get_storage_options()
            )

        pattern = f"{storage_path}/*.json"
        files = fs.glob(pattern)

        for file_path in files:
            try:
                import json

                with fs.open(file_path, "r") as f:
                    data = json.load(f)
                    from authglow.models.oauth_consent import OAuth2Consent

                    consent = OAuth2Consent(**data)

                    # Get user
                    user = await user_storage.get_user(consent.user_id)
                    if not user:
                        continue

                    # Filter by email if specified
                    if email and email.lower() not in user.email.lower():
                        continue

                    # Get client info
                    client = await client_storage.get_client(consent.client_id)
                    client_name = client.name if client else consent.client_id

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

    # Sort by granted_at descending
    consents_list.sort(key=lambda x: x["granted_at"], reverse=True)

    return consents_list


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
