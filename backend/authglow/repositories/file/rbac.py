"""File-system-backed repositories for the RBAC domain.

Three repositories share the same ``rbac/`` on-disk subdirectory but
each owns its own sub-subdirectory so the File path layout mirrors
the historical on-disk structure of the pre-refactor service:

* ``rbac/permissions/<permission_id>.json`` —
  :class:`FilePermissionRepository`
* ``rbac/roles/<role_id>.json`` — :class:`FileRoleRepository`
* ``rbac/user_roles/<assignment_id>.json`` —
  :class:`FileUserRoleRepository`

The pre-refactor ``RBACService`` built its own fsspec/AsyncFileSystem
plumbing in ``__init__``; the refactored repositories inherit the
standard ``BaseFileRepository._init_filesystem`` and therefore honour
``Settings.storage_backend`` (the historical code would have crashed
on any non-``file`` backend with a confusing ``ValueError`` from
fsspec).

Business logic (``initialize_defaults``, ``user_has_permission``,
``user_has_role``, ``get_user_permissions``, the
``is_system`` delete guard, the in-process ``named_lock`` around
``update_role``) stays in the service.
"""

from typing import List, Optional

from authglow.core.datetime import utcnow
from authglow.models.rbac import Permission, Role, UserRole
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import (
    PermissionRepository,
    RoleRepository,
    UserRoleRepository,
)


class FilePermissionRepository(BaseFileRepository, PermissionRepository):
    """File-backed implementation of :class:`PermissionRepository`.

    Stores one ``Permission`` document per ``permission_id`` at
    ``<storage>/rbac/permissions/<permission_id>.json``. ``list`` and
    ``get_by_name`` scan the directory; the alternative backends
    (SQL) would use a unique index on ``name``.
    """

    _subdir = "rbac/permissions"

    def _path_for(self, permission_id: str) -> str:
        """Return the on-disk path for the *permission_id*'s document."""
        return self._path(f"{permission_id}.json")

    async def create(self, permission: Permission) -> None:
        """Persist a new permission."""
        path = self._path_for(permission.permission_id)
        await self._write_json(path, permission.model_dump(mode="json"))

    async def get_by_id(self, permission_id: str) -> Optional[Permission]:
        """Return the permission, or ``None``."""
        path = self._path_for(permission_id)
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return Permission(**data)
        except (ValueError, TypeError):
            return None

    async def get_by_name(self, name: str) -> Optional[Permission]:
        """Return the permission with the given name, or ``None``."""
        files = await self._glob(f"{self._storage_path}/*.json")
        for file_path in files:
            data = await self._read_json(file_path)
            if data is None:
                continue
            try:
                perm = Permission(**data)
            except (ValueError, TypeError):
                continue
            if perm.name == name:
                return perm
        return None

    async def delete(self, permission_id: str) -> bool:
        """Remove the permission. Returns ``True`` if it existed."""
        path = self._path_for(permission_id)
        return await self._delete(path)

    async def list(self) -> List[Permission]:
        """Return every permission, sorted by name."""
        files = await self._glob(f"{self._storage_path}/*.json")
        permissions: List[Permission] = []
        for file_path in files:
            data = await self._read_json(file_path)
            if data is None:
                continue
            try:
                permissions.append(Permission(**data))
            except (ValueError, TypeError):
                continue
        permissions.sort(key=lambda p: p.name)
        return permissions


class FileRoleRepository(BaseFileRepository, RoleRepository):
    """File-backed implementation of :class:`RoleRepository`.

    Stores one ``Role`` document per ``role_id`` at
    ``<storage>/rbac/roles/<role_id>.json``. ``list`` and
    ``get_by_name`` scan the directory.

    The ``is_system`` delete guard is enforced by the service layer
    (it is business logic, not a storage concern); the repository
    will happily delete a system role if asked.
    """

    _subdir = "rbac/roles"

    def _path_for(self, role_id: str) -> str:
        """Return the on-disk path for the *role_id*'s document."""
        return self._path(f"{role_id}.json")

    async def create(self, role: Role) -> None:
        """Persist a new role."""
        path = self._path_for(role.role_id)
        await self._write_json(path, role.model_dump(mode="json"))

    async def get_by_id(self, role_id: str) -> Optional[Role]:
        """Return the role, or ``None``."""
        path = self._path_for(role_id)
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return Role(**data)
        except (ValueError, TypeError):
            return None

    async def get_by_name(self, name: str) -> Optional[Role]:
        """Return the role with the given name, or ``None``."""
        files = await self._glob(f"{self._storage_path}/*.json")
        for file_path in files:
            data = await self._read_json(file_path)
            if data is None:
                continue
            try:
                role = Role(**data)
            except (ValueError, TypeError):
                continue
            if role.name == name:
                return role
        return None

    async def update(self, role: Role) -> None:
        """Persist changes to an existing role (no CAS — the
        in-process ``named_lock`` in the service is sufficient for
        role updates)."""
        path = self._path_for(role.role_id)
        await self._write_json(path, role.model_dump(mode="json"))

    async def delete(self, role_id: str) -> bool:
        """Remove the role. Returns ``True`` if it existed. The
        ``is_system`` guard is the service layer's responsibility."""
        path = self._path_for(role_id)
        return await self._delete(path)

    async def list(self) -> List[Role]:
        """Return every role, sorted by name."""
        files = await self._glob(f"{self._storage_path}/*.json")
        roles: List[Role] = []
        for file_path in files:
            data = await self._read_json(file_path)
            if data is None:
                continue
            try:
                roles.append(Role(**data))
            except (ValueError, TypeError):
                continue
        roles.sort(key=lambda r: r.name)
        return roles


class FileUserRoleRepository(BaseFileRepository, UserRoleRepository):
    """File-backed implementation of :class:`UserRoleRepository`.

    Stores one ``UserRole`` document per ``assignment_id`` at
    ``<storage>/rbac/user_roles/<assignment_id>.json``. ``list_for_user``
    auto-deletes expired assignments on read (consistent with the
    pre-refactor behaviour) so the service layer can treat the
    return value as "currently active".
    """

    _subdir = "rbac/user_roles"

    def _path_for(self, assignment_id: str) -> str:
        """Return the on-disk path for the *assignment_id*'s document."""
        return self._path(f"{assignment_id}.json")

    async def assign(self, user_role: UserRole) -> None:
        """Persist a new user-role assignment."""
        path = self._path_for(user_role.assignment_id)
        await self._write_json(path, user_role.model_dump(mode="json"))

    async def get_by_id(self, assignment_id: str) -> Optional[UserRole]:
        """Return the assignment, or ``None``."""
        path = self._path_for(assignment_id)
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return UserRole(**data)
        except (ValueError, TypeError):
            return None

    async def remove(self, assignment_id: str) -> bool:
        """Remove the assignment. Returns ``True`` if it existed."""
        path = self._path_for(assignment_id)
        return await self._delete(path)

    async def list_for_user(self, user_id: str) -> List[UserRole]:
        """Return every non-expired assignment for a user.

        ``expires_at`` filtering is enforced here (and expired
        assignments are auto-deleted) so the service layer can
        treat the return value as "currently active".
        """
        files = await self._glob(f"{self._storage_path}/*.json")
        assignments: List[UserRole] = []
        now = utcnow()
        for file_path in files:
            data = await self._read_json(file_path)
            if data is None:
                continue
            try:
                ur = UserRole(**data)
            except (ValueError, TypeError):
                continue
            if ur.user_id != user_id:
                continue
            if ur.expires_at and ur.expires_at < now:
                # Auto-delete expired assignment
                await self._delete(file_path)
                continue
            assignments.append(ur)
        return assignments

    async def find_assignment(self, user_id: str, role_id: str) -> Optional[UserRole]:
        """Return the first assignment matching ``(user_id, role_id)``,
        or ``None``. Used by ``remove_role_from_user`` to find the
        assignment_id to delete."""
        files = await self._glob(f"{self._storage_path}/*.json")
        for file_path in files:
            data = await self._read_json(file_path)
            if data is None:
                continue
            try:
                ur = UserRole(**data)
            except (ValueError, TypeError):
                continue
            if ur.user_id == user_id and ur.role_id == role_id:
                return ur
        return None
