"""Admin portal data models."""

from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, EmailStr, Field

from authglow.core.datetime import utcnow

if TYPE_CHECKING:
    from authglow.models.user import User

T = TypeVar("T")


class DashboardStats(BaseModel):
    """Dashboard statistics."""

    total_users: int
    active_users: int
    inactive_users: int
    users_with_mfa: int
    mfa_percentage: float
    new_users_today: int
    new_users_this_week: int
    new_users_this_month: int
    total_logins_today: int
    total_logins_this_week: int
    total_logins_this_month: int
    failed_logins_today: int


class UserStatsTimeSeries(BaseModel):
    """Time series data for user statistics."""

    date: str
    new_users: int
    total_logins: int
    failed_logins: int


class AdminUserDetail(BaseModel):
    """Detailed user information for admin."""

    id: str
    email: EmailStr
    is_active: bool
    is_invited: bool
    email_verified: bool
    created_at: datetime
    updated_at: datetime
    last_login: Optional[datetime]
    first_name: Optional[str]
    last_name: Optional[str]
    scopes: List[str]
    mfa_enabled: bool
    mfa_verified: bool
    login_count: int = 0
    failed_login_count: int = 0

    @classmethod
    def from_user(cls, user: "User") -> "AdminUserDetail":
        return cls(
            id=user.id,
            email=user.email,
            is_active=user.is_active,
            is_invited=user.is_invited,
            email_verified=user.email_verified,
            created_at=user.created_at,
            updated_at=user.updated_at,
            last_login=user.last_login,
            first_name=user.first_name,
            last_name=user.last_name,
            scopes=user.scopes,
            mfa_enabled=user.mfa_enabled,
            mfa_verified=user.mfa_verified,
            login_count=user.login_count,
            failed_login_count=user.failed_login_count,
        )


class UserFilter(BaseModel):
    """User filtering parameters."""

    search: Optional[str] = None  # Search email, name
    is_active: Optional[bool] = None
    mfa_enabled: Optional[bool] = None
    scopes: Optional[List[str]] = None
    created_after: Optional[datetime] = None
    created_before: Optional[datetime] = None
    last_login_after: Optional[datetime] = None
    last_login_before: Optional[datetime] = None


class UserUpdate(BaseModel):
    """Update user details (admin)."""

    is_active: Optional[bool] = None
    email_verified: Optional[bool] = None
    scopes: Optional[List[str]] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None


class BulkUserOperation(BaseModel):
    """Bulk operation on users."""

    user_ids: List[str]
    operation: str  # activate, deactivate, delete, assign_scope, remove_scope
    scope: Optional[str] = None  # For assign_scope/remove_scope operations


class AuditLogEntry(BaseModel):
    """Audit log entry."""

    id: str = Field(default_factory=lambda: str(__import__("uuid").uuid4()))
    user_id: Optional[str] = None
    email: Optional[str] = None
    event_type: str  # login_success, login_failed, mfa_enabled, mfa_disabled, etc.
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    timestamp: datetime = Field(default_factory=utcnow)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    severity: str = "info"  # info, warning, error, critical


class AuditLogFilter(BaseModel):
    """Audit log filtering parameters."""

    user_id: Optional[str] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    search: Optional[str] = None  # Search in email or metadata


class SecurityEvent(BaseModel):
    """Security event for dashboard."""

    id: str
    event_type: str
    user_email: Optional[str]
    timestamp: datetime
    severity: str
    description: str
    ip_address: Optional[str]


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic paginated response wrapper."""

    items: List[Any]
    total: int
    limit: int
    offset: int
