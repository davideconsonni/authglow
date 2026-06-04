import pytest
import asyncio
from datetime import timedelta
from authglow.core.datetime import utcnow
from authglow.models.rbac import Permission, Role, UserRole


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
        admin_role = asyncio_run(rbac_service.get_role_by_name("admin"))
        assert admin_role is not None
        assert admin_role.is_system is True

        user_role = asyncio_run(rbac_service.get_role_by_name("user"))
        assert user_role is not None
        assert user_role.is_system is True

        perms = asyncio_run(rbac_service.list_permissions())
        assert len(perms) >= 11

    def test_initialize_defaults_idempotent(self, rbac_service):
        asyncio_run(rbac_service.initialize_defaults())
        asyncio_run(rbac_service.initialize_defaults())
        admin_role = asyncio_run(rbac_service.get_role_by_name("admin"))
        assert admin_role is not None


class TestPrivilegeEscalationPrevention:
    """VAPT-006/007/008: RBAC endpoints must require admin, not just roles.write."""

    def test_create_role_requires_admin(self):
        import inspect
        from authglow.api.rbac import create_role

        source = inspect.getsource(create_role)
        assert "require_admin" in source
        assert "require_permission" not in source

    def test_update_role_requires_admin(self):
        import inspect
        from authglow.api.rbac import update_role

        source = inspect.getsource(update_role)
        assert "require_admin" in source
        assert "require_permission" not in source

    def test_delete_role_requires_admin(self):
        import inspect
        from authglow.api.rbac import delete_role

        source = inspect.getsource(delete_role)
        assert "require_admin" in source
        assert "require_permission" not in source

    def test_assign_role_to_user_requires_admin(self):
        import inspect
        from authglow.api.rbac import assign_role_to_user

        source = inspect.getsource(assign_role_to_user)
        assert "require_admin" in source
        assert "require_permission" not in source

    def test_remove_role_from_user_requires_admin(self):
        import inspect
        from authglow.api.rbac import remove_role_from_user

        source = inspect.getsource(remove_role_from_user)
        assert "require_admin" in source
        assert "require_permission" not in source

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
