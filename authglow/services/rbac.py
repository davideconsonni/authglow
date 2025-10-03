"""RBAC service for managing roles and permissions."""

import json
import os
from datetime import datetime
from typing import List, Optional, Set
import fsspec

from authglow.core.config import get_settings
from authglow.models.rbac import Role, Permission, UserRole


class RBACService:
    """Service for Role-Based Access Control."""

    def __init__(self):
        """Initialize RBAC service."""
        self.settings = get_settings()
        self.roles_path = f"{self.settings.storage_path}/rbac/roles"
        self.permissions_path = f"{self.settings.storage_path}/rbac/permissions"
        self.user_roles_path = f"{self.settings.storage_path}/rbac/user_roles"
        self.storage_options = self.settings.get_storage_options()

        # Initialize filesystem
        if self.settings.storage_backend == "file":
            os.makedirs(self.roles_path, exist_ok=True)
            os.makedirs(self.permissions_path, exist_ok=True)
            os.makedirs(self.user_roles_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(
                self.settings.storage_backend,
                **self.storage_options
            )

    # Permission Management

    async def create_permission(self, permission: Permission) -> Permission:
        """Create a new permission."""
        file_path = f"{self.permissions_path}/{permission.permission_id}.json"
        with self.fs.open(file_path, "w") as f:
            json.dump(permission.model_dump(), f, default=str)
        return permission

    async def get_permission(self, permission_id: str) -> Optional[Permission]:
        """Get permission by ID."""
        try:
            file_path = f"{self.permissions_path}/{permission_id}.json"
            with self.fs.open(file_path, "r") as f:
                data = json.load(f)
                return Permission(**data)
        except Exception:
            return None

    async def get_permission_by_name(self, name: str) -> Optional[Permission]:
        """Get permission by name."""
        try:
            pattern = f"{self.permissions_path}/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        perm = Permission(**data)
                        if perm.name == name:
                            return perm
                except Exception:
                    continue
            return None
        except Exception:
            return None

    async def list_permissions(self) -> List[Permission]:
        """List all permissions."""
        permissions = []
        try:
            pattern = f"{self.permissions_path}/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        permissions.append(Permission(**data))
                except Exception:
                    continue
        except Exception:
            pass

        return sorted(permissions, key=lambda p: p.name)

    async def delete_permission(self, permission_id: str) -> bool:
        """Delete a permission."""
        try:
            file_path = f"{self.permissions_path}/{permission_id}.json"
            self.fs.rm(file_path)
            return True
        except Exception:
            return False

    # Role Management

    async def create_role(self, role: Role) -> Role:
        """Create a new role."""
        file_path = f"{self.roles_path}/{role.role_id}.json"
        with self.fs.open(file_path, "w") as f:
            json.dump(role.model_dump(), f, default=str)
        return role

    async def get_role(self, role_id: str) -> Optional[Role]:
        """Get role by ID."""
        try:
            file_path = f"{self.roles_path}/{role_id}.json"
            with self.fs.open(file_path, "r") as f:
                data = json.load(f)
                return Role(**data)
        except Exception:
            return None

    async def get_role_by_name(self, name: str) -> Optional[Role]:
        """Get role by name."""
        try:
            pattern = f"{self.roles_path}/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        role = Role(**data)
                        if role.name == name:
                            return role
                except Exception:
                    continue
            return None
        except Exception:
            return None

    async def list_roles(self) -> List[Role]:
        """List all roles."""
        roles = []
        try:
            pattern = f"{self.roles_path}/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        roles.append(Role(**data))
                except Exception:
                    continue
        except Exception:
            pass

        return sorted(roles, key=lambda r: r.name)

    async def update_role(self, role: Role) -> Role:
        """Update a role."""
        role.updated_at = datetime.utcnow()
        file_path = f"{self.roles_path}/{role.role_id}.json"
        with self.fs.open(file_path, "w") as f:
            json.dump(role.model_dump(), f, default=str)
        return role

    async def delete_role(self, role_id: str) -> bool:
        """Delete a role (cannot delete system roles)."""
        role = await self.get_role(role_id)
        if not role or role.is_system:
            return False

        try:
            file_path = f"{self.roles_path}/{role_id}.json"
            self.fs.rm(file_path)
            return True
        except Exception:
            return False

    # User-Role Assignment

    async def assign_role_to_user(self, user_role: UserRole) -> UserRole:
        """Assign a role to a user."""
        file_path = f"{self.user_roles_path}/{user_role.assignment_id}.json"
        with self.fs.open(file_path, "w") as f:
            json.dump(user_role.model_dump(), f, default=str)
        return user_role

    async def remove_role_from_user(self, user_id: str, role_id: str) -> bool:
        """Remove a role from a user."""
        try:
            pattern = f"{self.user_roles_path}/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        ur = UserRole(**data)
                        if ur.user_id == user_id and ur.role_id == role_id:
                            self.fs.rm(file_path)
                            return True
                except Exception:
                    continue
            return False
        except Exception:
            return False

    async def get_user_roles(self, user_id: str) -> List[UserRole]:
        """Get all roles assigned to a user."""
        user_roles = []
        try:
            pattern = f"{self.user_roles_path}/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                try:
                    with self.fs.open(file_path, "r") as f:
                        data = json.load(f)
                        ur = UserRole(**data)
                        if ur.user_id == user_id:
                            # Check if expired
                            if ur.expires_at and datetime.utcnow() > ur.expires_at:
                                self.fs.rm(file_path)
                                continue
                            user_roles.append(ur)
                except Exception:
                    continue
        except Exception:
            pass

        return user_roles

    async def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get all permissions for a user (aggregated from roles)."""
        permissions: Set[str] = set()

        # Get user's roles
        user_roles = await self.get_user_roles(user_id)

        for user_role in user_roles:
            role = await self.get_role(user_role.role_id)
            if role:
                permissions.update(role.permissions)

        return permissions

    async def user_has_permission(self, user_id: str, permission_name: str) -> bool:
        """Check if user has a specific permission."""
        user_permissions = await self.get_user_permissions(user_id)
        return permission_name in user_permissions

    async def user_has_role(self, user_id: str, role_name: str) -> bool:
        """Check if user has a specific role."""
        user_roles = await self.get_user_roles(user_id)
        for ur in user_roles:
            role = await self.get_role(ur.role_id)
            if role and role.name == role_name:
                return True
        return False

    # Initialize default roles and permissions

    async def initialize_defaults(self):
        """Initialize default roles and permissions."""
        # Default permissions
        default_permissions = [
            Permission(name="users.read", resource="users", action="read", description="View users"),
            Permission(name="users.write", resource="users", action="write", description="Create/update users"),
            Permission(name="users.delete", resource="users", action="delete", description="Delete users"),
            Permission(name="api_keys.read", resource="api_keys", action="read", description="View API keys"),
            Permission(name="api_keys.write", resource="api_keys", action="write", description="Create/update API keys"),
            Permission(name="api_keys.delete", resource="api_keys", action="delete", description="Delete API keys"),
            Permission(name="oauth_clients.read", resource="oauth_clients", action="read", description="View OAuth clients"),
            Permission(name="oauth_clients.write", resource="oauth_clients", action="write", description="Create/update OAuth clients"),
            Permission(name="audit.read", resource="audit", action="read", description="View audit logs"),
            Permission(name="roles.read", resource="roles", action="read", description="View roles"),
            Permission(name="roles.write", resource="roles", action="write", description="Create/update roles"),
        ]

        for perm in default_permissions:
            existing = await self.get_permission_by_name(perm.name)
            if not existing:
                await self.create_permission(perm)

        # Default roles
        admin_role = await self.get_role_by_name("admin")
        if not admin_role:
            admin_role = Role(
                name="admin",
                description="Full system access",
                permissions=[p.name for p in default_permissions],
                is_system=True
            )
            await self.create_role(admin_role)

        user_role = await self.get_role_by_name("user")
        if not user_role:
            user_role = Role(
                name="user",
                description="Standard user access",
                permissions=["users.read", "api_keys.read"],
                is_system=True
            )
            await self.create_role(user_role)

        developer_role = await self.get_role_by_name("developer")
        if not developer_role:
            developer_role = Role(
                name="developer",
                description="Developer access",
                permissions=[
                    "users.read",
                    "api_keys.read", "api_keys.write", "api_keys.delete",
                    "oauth_clients.read", "oauth_clients.write"
                ],
                is_system=False
            )
            await self.create_role(developer_role)
