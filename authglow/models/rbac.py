"""RBAC (Role-Based Access Control) models."""

from datetime import datetime
from typing import List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from authglow.core.datetime import utcnow


class Permission(BaseModel):
    """Permission model.

    Permissions are fine-grained access controls.
    Examples: users.read, users.write, users.delete, api_keys.create
    """

    permission_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str  # e.g., "users.read", "api_keys.create"
    description: Optional[str] = None
    resource: str  # e.g., "users", "api_keys", "oauth_clients"
    action: str  # e.g., "read", "write", "delete", "create"
    created_at: datetime = Field(default_factory=utcnow)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}


class Role(BaseModel):
    """Role model.

    Roles are collections of permissions.
    Examples: admin, user, developer, auditor
    """

    role_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str  # e.g., "admin", "developer", "user"
    description: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)  # List of permission names
    is_system: bool = False  # System roles cannot be deleted
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}


class UserRole(BaseModel):
    """User-Role assignment model."""

    assignment_id: str = Field(default_factory=lambda: str(uuid4()))
    user_id: str
    role_id: str
    assigned_by: str  # user_id of admin who assigned
    assigned_at: datetime = Field(default_factory=utcnow)
    expires_at: Optional[datetime] = None  # Optional expiration

    class Config:
        json_encoders = {datetime: lambda v: v.isoformat() if v else None}


# Request/Response models


class PermissionCreate(BaseModel):
    """Create permission request."""

    name: str
    description: Optional[str] = None
    resource: str
    action: str


class PermissionResponse(BaseModel):
    """Permission response."""

    permission_id: str
    name: str
    description: Optional[str]
    resource: str
    action: str
    created_at: datetime


class RoleCreate(BaseModel):
    """Create role request."""

    name: str
    description: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)


class RoleUpdate(BaseModel):
    """Update role request."""

    name: Optional[str] = None
    description: Optional[str] = None
    permissions: Optional[List[str]] = None


class RoleResponse(BaseModel):
    """Role response."""

    role_id: str
    name: str
    description: Optional[str]
    permissions: List[str]
    is_system: bool
    created_at: datetime
    updated_at: datetime


class RoleWithPermissions(RoleResponse):
    """Role response with full permission details."""

    permission_details: List[PermissionResponse] = Field(default_factory=list)


class AssignRoleRequest(BaseModel):
    """Assign role to user request."""

    user_id: str
    role_id: str
    expires_at: Optional[datetime] = None


class UserRoleResponse(BaseModel):
    """User role assignment response."""

    assignment_id: str
    user_id: str
    user_email: Optional[str] = None
    role_id: str
    role_name: Optional[str] = None
    assigned_by: str
    assigned_at: datetime
    expires_at: Optional[datetime]


class UserPermissions(BaseModel):
    """User's aggregated permissions."""

    user_id: str
    user_email: str
    roles: List[str]  # Role names
    permissions: List[str]  # Aggregated permission names
    is_admin: bool  # Has admin role or admin scope
