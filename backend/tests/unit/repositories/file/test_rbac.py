"""Unit tests for the three File-backed RBAC repositories.

Covers ``FilePermissionRepository``, ``FileRoleRepository`` and
``FileUserRoleRepository``. The service-level behaviour
(``initialize_defaults``, ``user_has_permission``, ``user_has_role``,
``get_user_permissions``, the ``is_system`` delete guard, the
in-process ``named_lock`` around ``update_role``) is exercised by
``tests/unit/test_rbac.py``.

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method;
* validates Protocol conformance via ``isinstance(repo, <Protocol>)``.
"""

from datetime import timedelta
from pathlib import Path
from unittest.mock import patch

from authglow.core.datetime import utcnow
from authglow.models.rbac import Permission, Role, UserRole
from authglow.repositories.file.rbac import (
    FilePermissionRepository,
    FileRoleRepository,
    FileUserRoleRepository,
)
from authglow.repositories.protocols import (
    PermissionRepository,
    RoleRepository,
    UserRoleRepository,
)


def _make_perm(
    name: str = "test.read",
    resource: str = "test",
    action: str = "read",
) -> Permission:
    return Permission(name=name, resource=resource, action=action)


def _make_role(
    name: str = "test-role",
    permissions: list[str] | None = None,
    is_system: bool = False,
) -> Role:
    return Role(name=name, permissions=permissions or [], is_system=is_system)


def _make_user_role(
    user_id: str = "user-1",
    role_id: str = "role-1",
    *,
    expires_in_days: int | None = 30,
) -> UserRole:
    return UserRole(
        user_id=user_id,
        role_id=role_id,
        assigned_by="admin-1",
        expires_at=(
            utcnow() + timedelta(days=expires_in_days) if expires_in_days is not None else None
        ),
    )


# ---------------------------------------------------------------------------
# FilePermissionRepository
# ---------------------------------------------------------------------------


class TestFilePermissionRepository:
    def _make_repo(self, test_settings) -> FilePermissionRepository:
        return FilePermissionRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "rbac/permissions"
        assert Path(repo._storage_path).name == "permissions"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, PermissionRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in ("create", "get_by_id", "get_by_name", "delete", "list"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    async def test_create_and_get_by_id_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        perm = _make_perm(name="p-rt")
        await repo.create(perm)
        loaded = await repo.get_by_id(perm.permission_id)
        assert loaded is not None
        assert loaded.name == "p-rt"

    async def test_get_by_id_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_id("nope") is None

    async def test_get_by_name_finds_match(self, test_settings):
        repo = self._make_repo(test_settings)
        perm = _make_perm(name="p-byname")
        await repo.create(perm)
        found = await repo.get_by_name("p-byname")
        assert found is not None
        assert found.permission_id == perm.permission_id

    async def test_get_by_name_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_name("nope") is None

    async def test_list_returns_all_sorted_by_name(self, test_settings):
        repo = self._make_repo(test_settings)
        for n in ("z.list", "a.list", "m.list"):
            await repo.create(_make_perm(name=n))
        result = await repo.list()
        assert [p.name for p in result] == ["a.list", "m.list", "z.list"]

    async def test_list_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.list() == []

    async def test_delete_removes(self, test_settings):
        repo = self._make_repo(test_settings)
        perm = _make_perm(name="p-del")
        await repo.create(perm)
        result = await repo.delete(perm.permission_id)
        assert result is True
        assert await repo.get_by_id(perm.permission_id) is None

    async def test_delete_returns_false_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.delete("nope") is False


# ---------------------------------------------------------------------------
# FileRoleRepository
# ---------------------------------------------------------------------------


class TestFileRoleRepository:
    def _make_repo(self, test_settings) -> FileRoleRepository:
        return FileRoleRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "rbac/roles"
        assert Path(repo._storage_path).name == "roles"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, RoleRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in (
            "create",
            "get_by_id",
            "get_by_name",
            "update",
            "delete",
            "list",
        ):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    async def test_create_and_get_by_id_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        role = _make_role(name="r-rt", permissions=["users.read"])
        await repo.create(role)
        loaded = await repo.get_by_id(role.role_id)
        assert loaded is not None
        assert loaded.name == "r-rt"
        assert loaded.permissions == ["users.read"]

    async def test_get_by_id_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_id("nope") is None

    async def test_get_by_name_finds_match(self, test_settings):
        repo = self._make_repo(test_settings)
        role = _make_role(name="r-byname")
        await repo.create(role)
        found = await repo.get_by_name("r-byname")
        assert found is not None
        assert found.role_id == role.role_id

    async def test_update_persists_changes(self, test_settings):
        repo = self._make_repo(test_settings)
        role = _make_role(name="r-upd", permissions=["p1"])
        await repo.create(role)
        role.permissions = ["p1", "p2"]
        await repo.update(role)
        loaded = await repo.get_by_id(role.role_id)
        assert loaded is not None
        assert loaded.permissions == ["p1", "p2"]

    async def test_delete_removes(self, test_settings):
        repo = self._make_repo(test_settings)
        role = _make_role(name="r-del")
        await repo.create(role)
        result = await repo.delete(role.role_id)
        assert result is True
        assert await repo.get_by_id(role.role_id) is None

    async def test_delete_returns_false_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.delete("nope") is False

    async def test_list_returns_all_sorted_by_name(self, test_settings):
        repo = self._make_repo(test_settings)
        for n in ("z.role", "a.role", "m.role"):
            await repo.create(_make_role(name=n))
        result = await repo.list()
        assert [r.name for r in result] == ["a.role", "m.role", "z.role"]


# ---------------------------------------------------------------------------
# FileUserRoleRepository
# ---------------------------------------------------------------------------


class TestFileUserRoleRepository:
    def _make_repo(self, test_settings) -> FileUserRoleRepository:
        return FileUserRoleRepository(settings=test_settings)

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "rbac/user_roles"
        assert Path(repo._storage_path).name == "user_roles"

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, UserRoleRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in (
            "assign",
            "get_by_id",
            "find_assignment",
            "remove",
            "list_for_user",
        ):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    async def test_assign_and_get_by_id_roundtrip(self, test_settings):
        repo = self._make_repo(test_settings)
        ur = _make_user_role(user_id="u-rt", role_id="r-rt")
        await repo.assign(ur)
        loaded = await repo.get_by_id(ur.assignment_id)
        assert loaded is not None
        assert loaded.user_id == "u-rt"
        assert loaded.role_id == "r-rt"

    async def test_get_by_id_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_id("nope") is None

    async def test_remove_removes(self, test_settings):
        repo = self._make_repo(test_settings)
        ur = _make_user_role()
        await repo.assign(ur)
        result = await repo.remove(ur.assignment_id)
        assert result is True
        assert await repo.get_by_id(ur.assignment_id) is None

    async def test_remove_returns_false_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.remove("nope") is False

    async def test_find_assignment_finds_match(self, test_settings):
        repo = self._make_repo(test_settings)
        ur = _make_user_role(user_id="u-find", role_id="r-find")
        await repo.assign(ur)
        found = await repo.find_assignment("u-find", "r-find")
        assert found is not None
        assert found.assignment_id == ur.assignment_id

    async def test_find_assignment_returns_none_for_mismatch(self, test_settings):
        repo = self._make_repo(test_settings)
        ur = _make_user_role(user_id="u-other", role_id="r-other")
        await repo.assign(ur)
        assert await repo.find_assignment("u-me", "r-other") is None
        assert await repo.find_assignment("u-other", "r-me") is None

    async def test_find_assignment_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.find_assignment("nobody", "norole") is None

    async def test_list_for_user_filters_by_user(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.assign(_make_user_role(user_id="u-a", role_id="r-1"))
        await repo.assign(_make_user_role(user_id="u-a", role_id="r-2"))
        await repo.assign(_make_user_role(user_id="u-b", role_id="r-1"))
        result = await repo.list_for_user("u-a")
        assert len(result) == 2
        assert all(ur.user_id == "u-a" for ur in result)

    async def test_list_for_user_filters_expired(self, test_settings):
        repo = self._make_repo(test_settings)
        valid = _make_user_role(user_id="u-list", role_id="r-v", expires_in_days=30)
        expired = _make_user_role(user_id="u-list", role_id="r-e", expires_in_days=-1)
        await repo.assign(valid)
        await repo.assign(expired)
        expired_path = Path(repo._path_for(expired.assignment_id))
        assert expired_path.exists()
        result = await repo.list_for_user("u-list")
        assert len(result) == 1
        assert result[0].assignment_id == valid.assignment_id
        # Expired assignment was auto-deleted on read
        assert not expired_path.exists()

    async def test_list_for_user_returns_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.list_for_user("nobody") == []

    async def test_list_for_user_no_expiry_keeps(self, test_settings):
        repo = self._make_repo(test_settings)
        ur = _make_user_role(user_id="u-noex", role_id="r-noex", expires_in_days=None)
        await repo.assign(ur)
        result = await repo.list_for_user("u-noex")
        assert len(result) == 1


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFileRBACRepositoriesWithPatchedSettings:
    def test_all_three_construct_via_get_settings(self, tmp_path):
        """Smoke test: the file-based constructors resolve
        ``get_settings()`` via ``BaseFileRepository``'s binding."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from authglow.core.config import Settings
        from authglow.core.crypto import encrypt_private_key

        storage_path = str(tmp_path / "data" / "users")
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        priv_path = str(keys_dir / "private_key.pem")

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encrypted_priv = encrypt_private_key(
            priv_bytes, secret_key="test-secret-key-for-authglow-testing-32chars!"
        )
        with open(priv_path, "wb") as f:
            f.write(encrypted_priv)

        settings = Settings(
            secret_key="test-secret-key-for-authglow-testing-32chars!",
            storage_path=storage_path,
            storage_backend="file",
            keys_dir=str(keys_dir),
            private_key_path=priv_path,
            public_key_path=str(keys_dir / "public_key.pem"),
        )

        with patch("authglow.repositories.file.base.get_settings", return_value=settings):
            perm_repo = FilePermissionRepository()
            role_repo = FileRoleRepository()
            ur_repo = FileUserRoleRepository()
            assert Path(perm_repo._storage_path).exists()
            assert Path(role_repo._storage_path).exists()
            assert Path(ur_repo._storage_path).exists()
