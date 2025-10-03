"""Admin portal API endpoints."""

from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

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
    SecurityEvent
)
from authglow.services.storage import UserStorage
from authglow.services.audit import AuditService
from authglow.services.mfa import MFAService
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


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin scope."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user


# Dashboard Pages

@router.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request):
    """Admin login page."""
    settings = get_settings()
    ui_context = settings.get_ui_context()

    return templates.TemplateResponse(
        "admin_login.html",
        {
            "request": request,
            **ui_context
        }
    )


@router.get("/admin", response_class=HTMLResponse)
async def admin_dashboard(request: Request):
    """Admin dashboard page (auth handled by JS)."""
    settings = get_settings()
    ui_context = settings.get_ui_context()

    return templates.TemplateResponse(
        "admin_dashboard.html",
        {
            "request": request,
            **ui_context
        }
    )


@router.get("/admin/users", response_class=HTMLResponse)
async def admin_users_page(request: Request):
    """User management page (auth handled by JS)."""
    settings = get_settings()
    ui_context = settings.get_ui_context()

    return templates.TemplateResponse(
        "admin_users.html",
        {
            "request": request,
            **ui_context
        }
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
            "current_user": {"email": "Loading..."}  # Will be loaded by JS
        }
    )


# API Endpoints

@router.get("/api/admin/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service)
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
    now = datetime.utcnow()
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
        failed_logins_today=failed_logins_today
    )


@router.get("/api/admin/stats/timeseries", response_model=List[dict])
async def get_stats_timeseries(
    days: int = Query(30, ge=1, le=365),
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service)
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
    audit_service: AuditService = Depends(get_audit_service)
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
                search_lower in user.email.lower() or
                (user.first_name and search_lower in user.first_name.lower()) or
                (user.last_name and search_lower in user.last_name.lower())
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
            filters=AuditLogFilter(user_id=user.id),
            limit=10000
        )

        login_count = sum(1 for log in user_logs if log.event_type == "login_success")
        failed_login_count = sum(1 for log in user_logs if log.event_type == "login_failed")

        filtered_users.append(AdminUserDetail(
            **user.model_dump(),
            login_count=login_count,
            failed_login_count=failed_login_count
        ))

    # Apply pagination
    return filtered_users[offset:offset + limit]


@router.get("/api/admin/users/{user_id}", response_model=AdminUserDetail)
async def get_user_detail(
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service)
):
    """Get detailed user information."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Get login counts
    user_logs = await audit_service.get_logs(
        filters=AuditLogFilter(user_id=user_id),
        limit=10000
    )

    login_count = sum(1 for log in user_logs if log.event_type == "login_success")
    failed_login_count = sum(1 for log in user_logs if log.event_type == "login_failed")

    return AdminUserDetail(
        **user.model_dump(),
        login_count=login_count,
        failed_login_count=failed_login_count
    )


@router.put("/api/admin/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: str,
    update_data: UserUpdate,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service)
):
    """Update user details."""
    user = await storage.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Update fields
    if update_data.is_active is not None:
        user.is_active = update_data.is_active
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
            "changes": update_data.model_dump(exclude_none=True)
        }
    )

    return UserResponse(**user.model_dump())


@router.delete("/api/admin/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
    mfa_service: MFAService = Depends(get_mfa_service)
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
        metadata={
            "target_user_id": user_id,
            "target_user_email": user.email
        },
        severity="warning"
    )

    return {"message": "User deleted successfully"}


@router.post("/api/admin/users/{user_id}/reset-mfa")
async def reset_user_mfa(
    user_id: str,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service),
    mfa_service: MFAService = Depends(get_mfa_service)
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
        metadata={
            "target_user_id": user_id,
            "target_user_email": user.email
        },
        severity="warning"
    )

    return {"message": "MFA reset successfully"}


@router.post("/api/admin/users/bulk", response_model=dict)
async def bulk_user_operation(
    operation: BulkUserOperation,
    current_user: User = Depends(require_admin),
    storage: UserStorage = Depends(get_user_storage),
    audit_service: AuditService = Depends(get_audit_service)
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
            "results": results
        }
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
    audit_service: AuditService = Depends(get_audit_service)
):
    """Get audit logs with filtering."""
    filters = AuditLogFilter(
        user_id=user_id,
        event_type=event_type,
        severity=severity,
        search=search
    )

    return await audit_service.get_logs(filters=filters, limit=limit, offset=offset)


@router.get("/api/admin/security/events", response_model=List[SecurityEvent])
async def get_security_events(
    limit: int = Query(50, ge=1, le=500),
    current_user: User = Depends(require_admin),
    audit_service: AuditService = Depends(get_audit_service)
):
    """Get recent security events."""
    # Get logs with warning/error/critical severity
    logs = await audit_service.get_logs(
        filters=AuditLogFilter(severity="warning"),
        limit=limit
    )

    # Convert to security events
    events = []
    for log in logs:
        events.append(SecurityEvent(
            id=log.id,
            event_type=log.event_type,
            user_email=log.email,
            timestamp=log.timestamp,
            severity=log.severity,
            description=log.event_type.replace("_", " ").title(),
            ip_address=log.ip_address
        ))

    return events
