"""Admin portal data models."""

from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, EmailStr, Field, field_validator

from authglow.core.datetime import utcnow
from authglow.core.password import check_password_byte_length
from authglow.core.scopes import validate_scope_tokens

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
    phone: Optional[str] = None
    avatar_url: Optional[str] = None
    scopes: List[str]
    mfa_enabled: bool
    mfa_verified: bool
    login_count: int = 0
    failed_login_count: int = 0
    password_expired: bool = False
    locked_until: Optional[datetime] = None
    suspended_until: Optional[datetime] = None
    is_federated: bool = False
    is_bootstrap: bool = False

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
            phone=user.phone,
            avatar_url=user.avatar_url,
            scopes=user.scopes,
            mfa_enabled=user.mfa_enabled,
            mfa_verified=user.mfa_verified,
            login_count=user.login_count,
            failed_login_count=user.failed_login_count,
            password_expired=user.password_expired,
            locked_until=user.locked_until,
            suspended_until=user.suspended_until,
            is_federated=user.is_federated,
            is_bootstrap=user.is_bootstrap,
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
    email: Optional[EmailStr] = None
    email_verified: Optional[bool] = None
    scopes: Optional[List[str]] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone: Optional[str] = None
    avatar_url: Optional[str] = None

    @field_validator("scopes")
    @classmethod
    def _scopes_rfc6749_charset(cls, v):
        return validate_scope_tokens(v) if v is not None else v


class SetPasswordRequest(BaseModel):
    """Set password for a user (admin)."""

    password: str = Field(..., min_length=8)
    require_change: bool = False

    @field_validator("password")
    @classmethod
    def _vapt039_password_byte_cap(cls, v: str) -> str:
        return check_password_byte_length(v)


class SuspendRequest(BaseModel):
    """Temporary user suspension request."""

    duration_hours: int = Field(..., ge=1, le=8760)


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
    request_id: Optional[str] = None  # correlation ID propagated by middleware (VAPT-042)
    # Extended fields for enhanced audit logging
    session_id: Optional[str] = None
    client_id: Optional[str] = None
    correlation_id: Optional[str] = None
    event_category: str = "auth"


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
