"""RBAC service for managing roles and permissions.

Persistence is delegated to three repositories:

* ``self._perm_repo`` — :class:`PermissionRepository`
* ``self._role_repo`` — :class:`RoleRepository`
* ``self._user_role_repo`` — :class:`UserRoleRepository`

The pre-refactor service built its own fsspec/AsyncFileSystem
plumbing in ``__init__`` and would have crashed on any non-``file``
backend (``s3`` / ``gcs`` / ``abfs``) with a confusing
``ValueError`` from fsspec. The refactored service routes through
the standard ``BaseFileRepository._init_filesystem`` via the
factories, which honour ``Settings.storage_backend``.

Business logic that aggregates across repositories
(``initialize_defaults``, ``user_has_permission``,
``user_has_role``, ``get_user_permissions``, the
``is_system`` delete guard, the in-process ``named_lock`` around
``update_role``) stays in the service.
"""

from typing import List, Optional, Set

from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.rbac import Permission, Role, UserRole
from authglow.repositories.protocols import (
    PermissionRepository,
    RoleRepository,
    UserRoleRepository,
)


class RBACService:
    """Service for Role-Based Access Control."""

    def __init__(
        self,
        permission_repository: Optional[PermissionRepository] = None,
        role_repository: Optional[RoleRepository] = None,
        user_role_repository: Optional[UserRoleRepository] = None,
    ):
        """Initialize RBAC service with settings and repositories.

        All three repository arguments default to ``None`` and are
        resolved lazily via the corresponding ``get_*`` factories.
        Tests can pass a stub or an in-memory implementation
        directly.
        """
        from authglow.repositories.dependencies import (
            get_permission_repository,
            get_role_repository,
            get_user_role_repository,
        )

        self.settings = get_settings()
        self._perm_repo = permission_repository or get_permission_repository()
        self._role_repo = role_repository or get_role_repository()
        self._user_role_repo = user_role_repository or get_user_role_repository()
        self._lock = named_lock()

    # ------------------------------------------------------------------
    # Permission Management
    # ------------------------------------------------------------------

    async def create_permission(self, permission: Permission) -> Permission:
        """Create a new permission."""
        await self._perm_repo.create(permission)
        return permission

    async def get_permission(self, permission_id: str) -> Optional[Permission]:
        """Get permission by ID."""
        return await self._perm_repo.get_by_id(permission_id)

    async def get_permission_by_name(self, name: str) -> Optional[Permission]:
        """Get permission by name."""
        return await self._perm_repo.get_by_name(name)

    async def list_permissions(self) -> List[Permission]:
        """List all permissions."""
        return await self._perm_repo.list()

    async def delete_permission(self, permission_id: str) -> bool:
        """Delete a permission."""
        return await self._perm_repo.delete(permission_id)

    # ------------------------------------------------------------------
    # Role Management
    # ------------------------------------------------------------------

    async def create_role(self, role: Role) -> Role:
        """Create a new role."""
        await self._role_repo.create(role)
        return role

    async def get_role(self, role_id: str) -> Optional[Role]:
        """Get role by ID."""
        return await self._role_repo.get_by_id(role_id)

    async def get_role_by_name(self, name: str) -> Optional[Role]:
        """Get role by name."""
        return await self._role_repo.get_by_name(name)

    async def list_roles(self) -> List[Role]:
        """List all roles."""
        return await self._role_repo.list()

    async def update_role(self, role: Role) -> Role:
        """Update a role.

        Protected by a named lock on ``role.role_id`` to prevent
        concurrent updates from clobbering each other. The
        ``updated_at`` timestamp is refreshed here (business rule,
        not a storage concern).
        """
        async with self._lock(f"role:{role.role_id}"):
            role.updated_at = utcnow()
            await self._role_repo.update(role)
        return role

    async def delete_role(self, role_id: str) -> bool:
        """Delete a role (cannot delete system roles)."""
        role = await self._role_repo.get_by_id(role_id)
        if not role or role.is_system:
            return False
        return await self._role_repo.delete(role_id)

    # ------------------------------------------------------------------
    # User-Role Assignment
    # ------------------------------------------------------------------

    async def assign_role_to_user(self, user_role: UserRole) -> UserRole:
        """Assign a role to a user."""
        await self._user_role_repo.assign(user_role)
        return user_role

    async def remove_role_from_user(self, user_id: str, role_id: str) -> bool:
        """Remove a role from a user."""
        assignment = await self._user_role_repo.find_assignment(user_id, role_id)
        if assignment is None:
            return False
        return await self._user_role_repo.remove(assignment.assignment_id)

    async def get_user_roles(self, user_id: str) -> List[UserRole]:
        """Get all roles assigned to a user.

        ``expires_at`` filtering is enforced by the repository
        (expired assignments are auto-deleted on read). The
        service-layer wrapper simply returns the active set.
        """
        return await self._user_role_repo.list_for_user(user_id)

    async def get_user_permissions(self, user_id: str) -> Set[str]:
        """Get all permissions for a user (aggregated from roles)."""
        permissions: Set[str] = set()

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

    # ------------------------------------------------------------------
    # Initialize default roles and permissions
    # ------------------------------------------------------------------

    async def initialize_defaults(self):
        """Initialize default roles and permissions."""
        default_permissions = [
            Permission(
                name="users.read",
                resource="users",
                action="read",
                description="View users",
            ),
            Permission(
                name="users.write",
                resource="users",
                action="write",
                description="Create/update users",
            ),
            Permission(
                name="users.delete",
                resource="users",
                action="delete",
                description="Delete users",
            ),
            Permission(
                name="api_keys.read",
                resource="api_keys",
                action="read",
                description="View API keys",
            ),
            Permission(
                name="api_keys.write",
                resource="api_keys",
                action="write",
                description="Create/update API keys",
            ),
            Permission(
                name="api_keys.delete",
                resource="api_keys",
                action="delete",
                description="Delete API keys",
            ),
            Permission(
                name="oauth_clients.read",
                resource="oauth_clients",
                action="read",
                description="View OAuth clients",
            ),
            Permission(
                name="oauth_clients.write",
                resource="oauth_clients",
                action="write",
                description="Create/update OAuth clients",
            ),
            Permission(
                name="audit.read",
                resource="audit",
                action="read",
                description="View audit logs",
            ),
            Permission(
                name="roles.read",
                resource="roles",
                action="read",
                description="View roles",
            ),
            Permission(
                name="roles.write",
                resource="roles",
                action="write",
                description="Create/update roles",
            ),
        ]

        for perm in default_permissions:
            existing = await self.get_permission_by_name(perm.name)
            if not existing:
                await self.create_permission(perm)

        admin_role = await self.get_role_by_name("admin")
        if not admin_role:
            admin_role = Role(
                name="admin",
                description="Full system access",
                permissions=[p.name for p in default_permissions],
                is_system=True,
            )
            await self.create_role(admin_role)

        user_role = await self.get_role_by_name("user")
        if not user_role:
            user_role = Role(
                name="user",
                description="Standard user access",
                permissions=["users.read", "api_keys.read"],
                is_system=True,
            )
            await self.create_role(user_role)

        developer_role = await self.get_role_by_name("developer")
        if not developer_role:
            developer_role = Role(
                name="developer",
                description="Developer access",
                permissions=[
                    "users.read",
                    "api_keys.read",
                    "api_keys.write",
                    "api_keys.delete",
                    "oauth_clients.read",
                    "oauth_clients.write",
                ],
                is_system=False,
            )
            await self.create_role(developer_role)
