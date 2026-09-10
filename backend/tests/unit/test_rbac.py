import pytest
import asyncio
from datetime import timedelta
from authglow.core.datetime import utcnow
from authglow.models.rbac import ADMIN_ROLE_NAME, Permission, Role, UserRole


def asyncio_run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


class TestPermissionCRUD:
    def test_create_permission(self, rbac_service):
        perm = Permission(
            name="test.read",
            resource="test",
            action="read",
            description="Read test resource",
        )
        created = asyncio_run(rbac_service.create_permission(perm))
        assert created is not None
        assert created.name == "test.read"

    def test_get_permission(self, rbac_service):
        perm = Permission(
            name="test.get",
            resource="test",
            action="read",
            description="Get test",
        )
        created = asyncio_run(rbac_service.create_permission(perm))
        retrieved = asyncio_run(rbac_service.get_permission(created.permission_id))
        assert retrieved is not None
        assert retrieved.name == "test.get"

    def test_get_permission_not_found(self, rbac_service):
        result = asyncio_run(rbac_service.get_permission("nonexistent"))
        assert result is None

    def test_get_permission_by_name(self, rbac_service):
        perm = Permission(
            name="test.byname",
            resource="test",
            action="read",
            description="ByName test",
        )
        asyncio_run(rbac_service.create_permission(perm))
        retrieved = asyncio_run(rbac_service.get_permission_by_name("test.byname"))
        assert retrieved is not None
        assert retrieved.name == "test.byname"

    def test_list_permissions(self, rbac_service):
        for i in range(3):
            perm = Permission(
                name=f"test.list{i}",
                resource="test",
                action="read",
            )
            asyncio_run(rbac_service.create_permission(perm))
        perms = asyncio_run(rbac_service.list_permissions())
        assert len(perms) >= 3

    def test_delete_permission(self, rbac_service):
        perm = Permission(
            name="test.delete",
            resource="test",
            action="delete",
        )
        created = asyncio_run(rbac_service.create_permission(perm))
        result = asyncio_run(rbac_service.delete_permission(created.permission_id))
        assert result is True
        assert asyncio_run(rbac_service.get_permission(created.permission_id)) is None

    def test_delete_nonexistent_permission(self, rbac_service):
        result = asyncio_run(rbac_service.delete_permission("nonexistent"))
        assert result is False


class TestRoleCRUD:
    def test_create_role(self, rbac_service):
        role = Role(
            name="test-role",
            description="Test role",
            permissions=["test.read"],
        )
        created = asyncio_run(rbac_service.create_role(role))
        assert created is not None
        assert created.name == "test-role"

    def test_get_role(self, rbac_service):
        role = Role(
            name="test-role-get",
            description="Get test",
            permissions=["test.read"],
        )
        created = asyncio_run(rbac_service.create_role(role))
        retrieved = asyncio_run(rbac_service.get_role(created.role_id))
        assert retrieved is not None
        assert retrieved.name == "test-role-get"

    def test_get_role_not_found(self, rbac_service):
        result = asyncio_run(rbac_service.get_role("nonexistent"))
        assert result is None

    def test_get_role_by_name(self, rbac_service):
        role = Role(
            name="test-role-byname",
            description="ByName",
            permissions=["test.read"],
        )
        asyncio_run(rbac_service.create_role(role))
        retrieved = asyncio_run(rbac_service.get_role_by_name("test-role-byname"))
        assert retrieved is not None
        assert retrieved.name == "test-role-byname"

    def test_list_roles(self, rbac_service):
        for i in range(3):
            role = Role(name=f"test-list-{i}", permissions=[])
            asyncio_run(rbac_service.create_role(role))
        roles = asyncio_run(rbac_service.list_roles())
        assert len(roles) >= 3

    def test_update_role(self, rbac_service):
        role = Role(
            name="test-role-update",
            permissions=["test.read"],
        )
        created = asyncio_run(rbac_service.create_role(role))
        created.description = "Updated description"
        updated = asyncio_run(rbac_service.update_role(created))
        assert updated.description == "Updated description"

    def test_delete_role(self, rbac_service):
        role = Role(
            name="test-role-delete",
            permissions=[],
        )
        created = asyncio_run(rbac_service.create_role(role))
        result = asyncio_run(rbac_service.delete_role(created.role_id))
        assert result is True

    def test_delete_system_role_fails(self, rbac_service):
        role = Role(
            name="system-role",
            permissions=[],
            is_system=True,
        )
        created = asyncio_run(rbac_service.create_role(role))
        result = asyncio_run(rbac_service.delete_role(created.role_id))
        assert result is False


class TestUserRoleAssignment:
    def test_assign_role_to_user(self, rbac_service):
        role = Role(name="test-assign-role", permissions=["test.read"])
        created_role = asyncio_run(rbac_service.create_role(role))
        assignment = UserRole(
            user_id="user-1",
            role_id=created_role.role_id,
            assigned_by="admin-1",
        )
        result = asyncio_run(rbac_service.assign_role_to_user(assignment))
        assert result is not None
        assert result.user_id == "user-1"

    def test_remove_role_from_user(self, rbac_service):
        role = Role(name="test-remove-role", permissions=["test.read"])
        created_role = asyncio_run(rbac_service.create_role(role))
        assignment = UserRole(
            user_id="user-2",
            role_id=created_role.role_id,
            assigned_by="admin-1",
        )
        asyncio_run(rbac_service.assign_role_to_user(assignment))
        result = asyncio_run(rbac_service.remove_role_from_user("user-2", created_role.role_id))
        assert result is True

    def test_remove_nonexistent_role(self, rbac_service):
        result = asyncio_run(rbac_service.remove_role_from_user("nouser", "norole"))
        assert result is False

    def test_get_user_roles(self, rbac_service):
        role = Role(name="test-urole", permissions=["test.read"])
        created_role = asyncio_run(rbac_service.create_role(role))
        assignment = UserRole(
            user_id="user-3",
            role_id=created_role.role_id,
            assigned_by="admin-1",
        )
        asyncio_run(rbac_service.assign_role_to_user(assignment))
        roles = asyncio_run(rbac_service.get_user_roles("user-3"))
        assert len(roles) >= 1
        assert any(r.role_id == created_role.role_id for r in roles)


class TestGetUserPermissions:
    def test_get_user_permissions(self, rbac_service):
        perm = Permission(name="test.perm.get", resource="test", action="read")
        asyncio_run(rbac_service.create_permission(perm))
        role = Role(name="test-perm-role", permissions=["test.perm.get"])
        created_role = asyncio_run(rbac_service.create_role(role))
        assignment = UserRole(
            user_id="user-perm-1",
            role_id=created_role.role_id,
            assigned_by="admin-1",
        )
        asyncio_run(rbac_service.assign_role_to_user(assignment))
        perms = asyncio_run(rbac_service.get_user_permissions("user-perm-1"))
        assert "test.perm.get" in perms

    def test_user_has_permission(self, rbac_service):
        perm = Permission(name="test.perm.has", resource="test", action="read")
        asyncio_run(rbac_service.create_permission(perm))
        role = Role(name="test-has-role", permissions=["test.perm.has"])
        created_role = asyncio_run(rbac_service.create_role(role))
        assignment = UserRole(
            user_id="user-has-1",
            role_id=created_role.role_id,
            assigned_by="admin-1",
        )
        asyncio_run(rbac_service.assign_role_to_user(assignment))
        assert asyncio_run(rbac_service.user_has_permission("user-has-1", "test.perm.has"))
        assert not asyncio_run(rbac_service.user_has_permission("user-has-1", "nonexistent"))

    def test_user_has_role(self, rbac_service):
        role = Role(name="test-has-role-check", permissions=[])
        created_role = asyncio_run(rbac_service.create_role(role))
        assignment = UserRole(
            user_id="user-role-1",
            role_id=created_role.role_id,
            assigned_by="admin-1",
        )
        asyncio_run(rbac_service.assign_role_to_user(assignment))
        assert asyncio_run(rbac_service.user_has_role("user-role-1", "test-has-role-check"))
        assert not asyncio_run(rbac_service.user_has_role("user-role-1", "nonexistent"))


class TestInitializeDefaults:
    def test_initialize_defaults(self, rbac_service):
        asyncio_run(rbac_service.initialize_defaults())
        administrator_role = asyncio_run(
            rbac_service.get_role_by_name(ADMIN_ROLE_NAME)
        )
        assert administrator_role is not None
        assert administrator_role.is_system is True

        # Only the Administrator role is seeded — no example roles.
        assert asyncio_run(rbac_service.get_role_by_name("user")) is None
        assert asyncio_run(rbac_service.get_role_by_name("developer")) is None

        # The UX-driven vocabulary: 6 manage + admin.read + roles.read.
        perms = asyncio_run(rbac_service.list_permissions())
        assert {p.name for p in perms} == {
            "users.manage",
            "sessions.manage",
            "clients.manage",
            "keys.manage",
            "system.manage",
            "roles.manage",
            "admin.read",
            "roles.read",
        }
        assert set(administrator_role.permissions) == {p.name for p in perms}

    def test_initialize_defaults_idempotent(self, rbac_service):
        asyncio_run(rbac_service.initialize_defaults())
        asyncio_run(rbac_service.initialize_defaults())
        administrator_role = asyncio_run(
            rbac_service.get_role_by_name(ADMIN_ROLE_NAME)
        )
        assert administrator_role is not None

    def test_initialize_defaults_backfills_admin_permissions(self, rbac_service):
        """An Administrator seeded with a stale catalog gets the
        missing defaults merged in (upgrade path, no lockout)."""
        from authglow.models.rbac import Role

        stale = Role(name=ADMIN_ROLE_NAME, permissions=["users.manage"], is_system=True)
        asyncio_run(rbac_service.create_role(stale))
        asyncio_run(rbac_service.initialize_defaults())
        refreshed = asyncio_run(rbac_service.get_role_by_name(ADMIN_ROLE_NAME))
        assert refreshed is not None
        assert "users.manage" in refreshed.permissions
        assert "system.manage" in refreshed.permissions
        assert "admin.read" in refreshed.permissions


class TestBootstrapHelpers:
    """Idempotent helpers used by setup / demo seeding."""

    def test_ensure_admin_role_idempotent(self, rbac_service):
        role_id_1 = asyncio_run(rbac_service.ensure_admin_role())
        role_id_2 = asyncio_run(rbac_service.ensure_admin_role())
        assert role_id_1 == role_id_2
        role = asyncio_run(rbac_service.get_role_by_name(ADMIN_ROLE_NAME))
        assert role is not None
        assert role.is_system is True

    def test_ensure_admin_role_carries_permissions(self, rbac_service):
        asyncio_run(rbac_service.ensure_admin_role())
        role = asyncio_run(rbac_service.get_role_by_name(ADMIN_ROLE_NAME))
        perms = asyncio_run(rbac_service.list_permissions())
        assert set(p.name for p in perms).issubset(set(role.permissions))

    def test_assign_role_to_user_idempotent(self, rbac_service):
        role_id = asyncio_run(rbac_service.ensure_admin_role())
        created_first = asyncio_run(
            rbac_service.assign_role_to_user_idempotent(
                "user-assign-1", role_id, actor_id="admin-1"
            )
        )
        created_second = asyncio_run(
            rbac_service.assign_role_to_user_idempotent(
                "user-assign-1", role_id, actor_id="admin-1"
            )
        )
        assert created_first is True
        assert created_second is False
        assert asyncio_run(rbac_service.user_has_role("user-assign-1", ADMIN_ROLE_NAME))

    def test_assign_role_names_to_user_assigns_and_validates(self, rbac_service):
        asyncio_run(rbac_service.ensure_admin_role())
        asyncio_run(rbac_service.create_role(Role(name="auditor", permissions=[])))

        assigned = asyncio_run(
            rbac_service.assign_role_names_to_user(
                "user-roles-1",
                [ADMIN_ROLE_NAME, "auditor"],
                actor_id="actor-1",
            )
        )
        assert sorted(assigned) == sorted([ADMIN_ROLE_NAME, "auditor"])
        assert asyncio_run(rbac_service.user_has_role("user-roles-1", ADMIN_ROLE_NAME))
        assert asyncio_run(rbac_service.user_has_role("user-roles-1", "auditor"))

        # Idempotent: second run assigns nothing new.
        assigned_again = asyncio_run(
            rbac_service.assign_role_names_to_user(
                "user-roles-1", [ADMIN_ROLE_NAME], actor_id="actor-1"
            )
        )
        assert assigned_again == []

        # Unknown role name raises ValueError.
        import pytest as _pytest

        with _pytest.raises(ValueError, match="does not exist"):
            asyncio_run(
                rbac_service.assign_role_names_to_user(
                    "user-roles-1", ["nonexistent-role"], actor_id="actor-1"
                )
            )


class TestUsersMeRBACFields:
    """``GET /api/users/me`` exposes RBAC role names + is_admin."""

    @staticmethod
    def _user():
        from authglow.models.user import User

        return User(
            id="users-me-1",
            email="usersme@example.com",
            hashed_password="x",
            is_active=True,
            scopes=["read", "write"],
        )

    def test_admin_user_gets_roles_and_is_admin(self, rbac_service):
        from authglow.api.auth import read_users_me

        user = self._user()
        asyncio_run(rbac_service.ensure_admin_role())
        asyncio_run(
            rbac_service.assign_role_names_to_user(
                user.id, [ADMIN_ROLE_NAME], actor_id=user.id
            )
        )
        resp = asyncio_run(read_users_me(user))
        assert resp.is_admin is True
        assert ADMIN_ROLE_NAME in resp.roles

    def test_plain_user_has_no_roles(self, rbac_service):
        from authglow.api.auth import read_users_me

        user = self._user()
        asyncio_run(rbac_service.ensure_admin_role())
        resp = asyncio_run(read_users_me(user))
        assert resp.is_admin is False
        assert resp.roles == []


class TestAdminRoleAntiLockout:
    """D6: the Administrator role cannot be self-demotioned nor
    stripped from the last holder."""

    @staticmethod
    def _mk_audit():
        from unittest.mock import AsyncMock, MagicMock

        audit = MagicMock()
        audit.log_event = AsyncMock()
        return audit

    def test_self_demotion_refused(self, rbac_service):
        from fastapi import HTTPException

        from authglow.api.rbac import remove_role_from_user

        role_id = asyncio_run(rbac_service.ensure_admin_role())
        asyncio_run(
            rbac_service.assign_role_to_user_idempotent(
                "admin-self", role_id, actor_id="admin-self"
            )
        )
        with pytest.raises(HTTPException) as exc_info:
            asyncio_run(
                remove_role_from_user(
                    user_id="admin-self",
                    role_id=role_id,
                    current_user_id="admin-self",
                    audit_service=self._mk_audit(),
                )
            )
        assert exc_info.value.status_code == 409
        assert "yourself" in exc_info.value.detail

    def test_last_admin_removal_refused(self, rbac_service):
        from fastapi import HTTPException

        from authglow.api.rbac import remove_role_from_user

        role_id = asyncio_run(rbac_service.ensure_admin_role())
        asyncio_run(
            rbac_service.assign_role_to_user_idempotent(
                "admin-last", role_id, actor_id="actor-1"
            )
        )
        with pytest.raises(HTTPException) as exc_info:
            asyncio_run(
                remove_role_from_user(
                    user_id="admin-last",
                    role_id=role_id,
                    current_user_id="actor-1",
                    audit_service=self._mk_audit(),
                )
            )
        assert exc_info.value.status_code == 409
        assert "last" in exc_info.value.detail
        # The assignment is still there.
        assert asyncio_run(rbac_service.user_has_role("admin-last", ADMIN_ROLE_NAME))

    def test_demotion_allowed_with_second_admin(self, rbac_service):
        from authglow.api.rbac import remove_role_from_user

        role_id = asyncio_run(rbac_service.ensure_admin_role())
        asyncio_run(
            rbac_service.assign_role_to_user_idempotent(
                "admin-a", role_id, actor_id="actor-1"
            )
        )
        asyncio_run(
            rbac_service.assign_role_to_user_idempotent(
                "admin-b", role_id, actor_id="actor-1"
            )
        )
        asyncio_run(
            remove_role_from_user(
                user_id="admin-a",
                role_id=role_id,
                current_user_id="admin-b",
                audit_service=self._mk_audit(),
            )
        )
        assert not asyncio_run(rbac_service.user_has_role("admin-a", ADMIN_ROLE_NAME))
        assert asyncio_run(rbac_service.user_has_role("admin-b", ADMIN_ROLE_NAME))

    def test_non_admin_role_removal_unaffected(self, rbac_service):
        from authglow.api.rbac import remove_role_from_user

        asyncio_run(rbac_service.create_role(Role(name="viewer", permissions=[])))
        viewer = asyncio_run(rbac_service.get_role_by_name("viewer"))
        asyncio_run(
            rbac_service.assign_role_to_user_idempotent(
                "viewer-user", viewer.role_id, actor_id="actor-1"
            )
        )
        asyncio_run(
            remove_role_from_user(
                user_id="viewer-user",
                role_id=viewer.role_id,
                current_user_id="actor-1",
                audit_service=self._mk_audit(),
            )
        )
        assert not asyncio_run(rbac_service.user_has_role("viewer-user", "viewer"))


class TestPrivilegeEscalationPrevention:
    """VAPT-006/007/008: RBAC management endpoints must require the
    ``roles.manage`` permission, not just ``roles.read``."""

    def test_create_role_requires_roles_manage(self):
        import inspect
        from authglow.api.rbac import create_role

        source = inspect.getsource(create_role)
        assert 'require_permission("roles.manage")' in source
        assert "require_administrator" not in source

    def test_update_role_requires_roles_manage(self):
        import inspect
        from authglow.api.rbac import update_role

        source = inspect.getsource(update_role)
        assert 'require_permission("roles.manage")' in source
        assert "require_administrator" not in source

    def test_delete_role_requires_roles_manage(self):
        import inspect
        from authglow.api.rbac import delete_role

        source = inspect.getsource(delete_role)
        assert 'require_permission("roles.manage")' in source
        assert "require_administrator" not in source

    def test_assign_role_to_user_requires_roles_manage(self):
        import inspect
        from authglow.api.rbac import assign_role_to_user

        source = inspect.getsource(assign_role_to_user)
        assert 'require_permission("roles.manage")' in source
        assert "require_administrator" not in source

    def test_remove_role_from_user_requires_roles_manage(self):
        import inspect
        from authglow.api.rbac import remove_role_from_user

        source = inspect.getsource(remove_role_from_user)
        assert 'require_permission("roles.manage")' in source
        assert "require_administrator" not in source

    def test_list_roles_allows_roles_read(self):
        import inspect
        from authglow.api.rbac import list_roles

        source = inspect.getsource(list_roles)
        assert "require_permission" in source

    def test_get_role_allows_roles_read(self):
        import inspect
        from authglow.api.rbac import get_role

        source = inspect.getsource(get_role)
        assert "require_permission" in source
