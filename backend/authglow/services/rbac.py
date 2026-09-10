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
from authglow.models.rbac import ADMIN_ROLE_NAME, Permission, Role, UserRole
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

    async def user_has_any_permission(
        self, user_id: str, permission_names: List[str]
    ) -> bool:
        """Check if user has at least one of the given permissions."""
        user_permissions = await self.get_user_permissions(user_id)
        return any(name in user_permissions for name in permission_names)

    async def user_has_role(self, user_id: str, role_name: str) -> bool:
        """Check if user has a specific role."""
        user_roles = await self.get_user_roles(user_id)
        for ur in user_roles:
            role = await self.get_role(ur.role_id)
            if role and role.name == role_name:
                return True
        return False

    async def list_role_holders(self, role_id: str) -> List[str]:
        """Return the user ids currently holding *role_id*.

        Backed by the concrete File repository's ``list_all`` (not part
        of the ``UserRoleRepository`` Protocol). Injected test doubles
        that do not implement ``list_all`` yield an empty scan — the
        anti-lockout caller treats that as "no other holders", i.e. the
        conservative outcome (refuse the removal).
        """
        list_all = getattr(self._user_role_repo, "list_all", None)
        if list_all is None:
            return []
        holders: List[str] = []
        for ur in await list_all():
            if ur.role_id == role_id and ur.user_id not in holders:
                holders.append(ur.user_id)
        return holders

    # ------------------------------------------------------------------
    # Bootstrap helpers (idempotent)
    # ------------------------------------------------------------------

    async def ensure_admin_role(self) -> str:
        """Return the ``Authglow Administrator`` role id, creating the
        role if missing.

        Calls :meth:`initialize_defaults` first so the role is
        guaranteed to carry the full permission catalog. Idempotent.
        """
        await self.initialize_defaults()
        role = await self.get_role_by_name(ADMIN_ROLE_NAME)
        if role is None:
            role = Role(
                name=ADMIN_ROLE_NAME,
                description="Full system access (platform administrators)",
                permissions=[],
                is_system=True,
            )
            await self.create_role(role)
        return role.role_id

    async def assign_role_to_user_idempotent(
        self, user_id: str, role_id: str, actor_id: str
    ) -> bool:
        """Assign *role_id* to *user_id* if not already assigned.

        Returns ``True`` if a new assignment was created, ``False`` if
        the user already held the role. The expiration is left as
        ``None`` (permanent).
        """
        existing = await self._user_role_repo.list_for_user(user_id)
        for ur in existing:
            if ur.role_id == role_id:
                return False
        await self.assign_role_to_user(
            UserRole(
                user_id=user_id,
                role_id=role_id,
                assigned_by=actor_id,
            )
        )
        return True

    async def assign_role_names_to_user(
        self,
        user_id: str,
        role_names: List[str],
        actor_id: str,
    ) -> List[str]:
        """Assign each *named* role to *user_id* (idempotent per role).

        Returns the names of the roles that were NEWLY assigned (a
        role the user already held is skipped, not an error). Raises
        ``ValueError`` for a role name that does not exist — the API
        layer translates it into a 400.
        """
        newly_assigned: List[str] = []
        for name in role_names or []:
            role = await self.get_role_by_name(name)
            if role is None:
                raise ValueError(f"Role '{name}' does not exist")
            created = await self.assign_role_to_user_idempotent(
                user_id=user_id, role_id=role.role_id, actor_id=actor_id
            )
            if created:
                newly_assigned.append(name)
        return newly_assigned

    # ------------------------------------------------------------------
    # Initialize default roles and permissions
    # ------------------------------------------------------------------

    async def initialize_defaults(self):
        """Initialize the default permission vocabulary and the
        ``Authglow Administrator`` system role.

        The vocabulary is UX-driven: one ``*.manage`` permission per
        admin section (matching the sidebar), plus ``admin.read`` for
        view-only access everywhere and the legacy ``roles.read`` for
        the RBAC read endpoints. Every permission is actually
        enforced, route by route (see ``core.permissions``).
        """
        default_permissions = [
            Permission(
                name="users.manage",
                resource="users",
                action="manage",
                description="User lifecycle: CRUD, MFA, passwords, suspend, bulk, invite",
            ),
            Permission(
                name="sessions.manage",
                resource="sessions",
                action="manage",
                description="Operational hygiene: sessions, consents, device authorizations, password resets",
            ),
            Permission(
                name="clients.manage",
                resource="oauth_clients",
                action="manage",
                description="Integration surface: OAuth clients, claim policies, playground, federation, webhooks",
            ),
            Permission(
                name="keys.manage",
                resource="api_keys",
                action="manage",
                description="Key material: API keys admin, JWK rotation and revocation",
            ),
            Permission(
                name="system.manage",
                resource="system",
                action="manage",
                description="Platform settings and rate limits",
            ),
            Permission(
                name="roles.manage",
                resource="roles",
                action="manage",
                description="RBAC roles, permissions and assignments",
            ),
            Permission(
                name="admin.read",
                resource="admin",
                action="read",
                description="View-only access to all admin sections",
            ),
            Permission(
                name="roles.read",
                resource="roles",
                action="read",
                description="View roles",
            ),
        ]

        for perm in default_permissions:
            existing = await self.get_permission_by_name(perm.name)
            if not existing:
                await self.create_permission(perm)

        administrator_role = await self.get_role_by_name(ADMIN_ROLE_NAME)
        if not administrator_role:
            administrator_role = Role(
                name=ADMIN_ROLE_NAME,
                description="Full system access (platform administrators)",
                permissions=[p.name for p in default_permissions],
                is_system=True,
            )
            await self.create_role(administrator_role)
        else:
            # Backfill: an Administrator seeded before a vocabulary
            # change keeps working — merge any missing default
            # permissions in (never remove: operators may have trimmed
            # the role on purpose... in practice nobody trims the
            # admin role, but removal stays an explicit API action).
            missing = [
                p.name
                for p in default_permissions
                if p.name not in (administrator_role.permissions or [])
            ]
            if missing:
                administrator_role.permissions = [
                    *(administrator_role.permissions or []),
                    *missing,
                ]
                await self.update_role(administrator_role)
