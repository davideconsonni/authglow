"""HTTP-level tests for ``authglow.api.rbac``.

The service layer is covered in ``test_rbac.py``; this module pins the
API layer: status codes, conflict/not-found paths, the system-role
guard, the admin anti-lockout refusals, and the audit calls on
assignment/removal. Handlers are invoked directly with the permission
dependency satisfied by the caller (``_`` / ``current_user_id``), and
``RBACService`` / ``UserStorage`` are patched at the API-module
boundary so no disk is touched.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from authglow.models.rbac import (
    ADMIN_ROLE_NAME,
    AssignRoleRequest,
    Permission,
    PermissionCreate,
    Role,
    RoleCreate,
    RoleUpdate,
    UserRole,
)


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _mock_rbac():
    svc = MagicMock()
    svc.get_permission_by_name = AsyncMock(return_value=None)
    svc.get_permission = AsyncMock(return_value=None)
    svc.list_permissions = AsyncMock(return_value=[])
    svc.create_permission = AsyncMock()
    svc.delete_permission = AsyncMock(return_value=True)
    svc.get_role_by_name = AsyncMock(return_value=None)
    svc.get_role = AsyncMock(return_value=None)
    svc.list_roles = AsyncMock(return_value=[])
    svc.create_role = AsyncMock()
    svc.update_role = AsyncMock()
    svc.delete_role = AsyncMock(return_value=True)
    svc.get_user_roles = AsyncMock(return_value=[])
    svc.assign_role_to_user = AsyncMock()
    svc.remove_role_from_user = AsyncMock(return_value=True)
    svc.get_user_permissions = AsyncMock(return_value=set())
    svc.user_has_role = AsyncMock(return_value=False)
    svc.user_has_any_permission = AsyncMock(return_value=False)
    svc.list_role_holders = AsyncMock(return_value=[])
    return svc


def _mock_storage(user=None):
    storage = MagicMock()
    storage.get_user = AsyncMock(return_value=user)
    return storage


def _user(email="user@example.com"):
    from authglow.models.user import User

    return User(id="u-1", email=email, hashed_password="x", scopes=["read"])


class TestModuleFactories:
    def test_get_audit_service(self):
        from authglow.api import rbac as rbac_api
        from authglow.services.audit import AuditService

        assert isinstance(rbac_api.get_audit_service(), AuditService)


class TestPermissionEndpoints:
    def test_create_permission(self):
        from authglow.api import rbac as rbac_api

        perm = Permission(name="users.read", description="d", resource="users", action="read")
        svc = _mock_rbac()
        svc.create_permission = AsyncMock(return_value=perm)
        with patch.object(rbac_api, "RBACService", return_value=svc):
            out = _run(rbac_api.create_permission(PermissionCreate(name="users.read"), _="admin"))
        assert out.name == "users.read"
        assert out.resource == "users"
        assert out.action == "read"

    def test_create_permission_conflict(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_permission_by_name = AsyncMock(
            return_value=Permission(name="users.read", resource="users", action="read")
        )
        with patch.object(rbac_api, "RBACService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.create_permission(PermissionCreate(name="users.read"), _="admin"))
        assert exc.value.status_code == 409

    def test_create_permission_without_dot(self):
        from authglow.api import rbac as rbac_api

        perm = Permission(name="read", resource="", action="read")
        svc = _mock_rbac()
        svc.create_permission = AsyncMock(return_value=perm)
        with patch.object(rbac_api, "RBACService", return_value=svc):
            out = _run(rbac_api.create_permission(PermissionCreate(name="read"), _="admin"))
        assert out.resource == ""
        assert out.action == "read"

    def test_list_permissions(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.list_permissions = AsyncMock(
            return_value=[Permission(name="a.b", resource="a", action="b")]
        )
        with patch.object(rbac_api, "RBACService", return_value=svc):
            out = _run(rbac_api.list_permissions(_="admin"))
        assert len(out) == 1 and out[0].name == "a.b"

    def test_get_permission(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_permission = AsyncMock(
            return_value=Permission(name="a.b", resource="a", action="b")
        )
        with patch.object(rbac_api, "RBACService", return_value=svc):
            out = _run(rbac_api.get_permission("pid-1", _="admin"))
        assert out.name == "a.b"

    def test_get_permission_not_found(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        with patch.object(rbac_api, "RBACService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.get_permission("nope", _="admin"))
        assert exc.value.status_code == 404

    def test_delete_permission(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        with patch.object(rbac_api, "RBACService", return_value=svc):
            out = _run(rbac_api.delete_permission("pid-1", _="admin"))
        assert out is None
        svc.delete_permission.assert_awaited_once_with("pid-1")

    def test_delete_permission_not_found(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.delete_permission = AsyncMock(return_value=False)
        with patch.object(rbac_api, "RBACService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.delete_permission("nope", _="admin"))
        assert exc.value.status_code == 404


class TestRoleEndpoints:
    def _role(self, **kw):
        base = {"name": "support", "permissions": ["users.read"]}
        base.update(kw)
        return Role(**base)

    def test_create_role(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_permission_by_name = AsyncMock(
            return_value=Permission(name="users.read", resource="users", action="read")
        )
        created = self._role()
        svc.create_role = AsyncMock(return_value=created)
        with patch.object(rbac_api, "RBACService", return_value=svc):
            out = _run(
                rbac_api.create_role(RoleCreate(name="support", permissions=["users.read"]), _="a")
            )
        assert out.name == "support"

    def test_create_role_conflict(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_role_by_name = AsyncMock(return_value=self._role())
        with patch.object(rbac_api, "RBACService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.create_role(RoleCreate(name="support"), _="a"))
        assert exc.value.status_code == 409

    def test_create_role_unknown_permission(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        with patch.object(rbac_api, "RBACService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.create_role(RoleCreate(name="x", permissions=["nope.perm"]), _="a"))
        assert exc.value.status_code == 400

    def test_list_roles(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.list_roles = AsyncMock(return_value=[self._role(), self._role(name="dev")])
        with patch.object(rbac_api, "RBACService", return_value=svc):
            out = _run(rbac_api.list_roles(_="a"))
        assert [r.name for r in out] == ["support", "dev"]

    def test_get_role_with_details(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_role = AsyncMock(return_value=self._role())
        svc.get_permission_by_name = AsyncMock(
            return_value=Permission(name="users.read", resource="users", action="read")
        )
        with patch.object(rbac_api, "RBACService", return_value=svc):
            out = _run(rbac_api.get_role("rid-1", _="a"))
        assert out.name == "support"
        assert len(out.permission_details) == 1

    def test_get_role_not_found(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        with patch.object(rbac_api, "RBACService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.get_role("nope", _="a"))
        assert exc.value.status_code == 404

    def test_update_role(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_role = AsyncMock(return_value=self._role())
        updated = self._role(description="new")
        svc.update_role = AsyncMock(return_value=updated)
        with patch.object(rbac_api, "RBACService", return_value=svc):
            out = _run(rbac_api.update_role("rid-1", RoleUpdate(description="new"), _="a"))
        assert out.description == "new"

    def test_update_role_not_found(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        with patch.object(rbac_api, "RBACService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.update_role("nope", RoleUpdate(description="x"), _="a"))
        assert exc.value.status_code == 404

    def test_update_system_role_forbidden(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_role = AsyncMock(return_value=self._role(name=ADMIN_ROLE_NAME, is_system=True))
        with patch.object(rbac_api, "RBACService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.update_role("rid-1", RoleUpdate(description="x"), _="a"))
        assert exc.value.status_code == 403

    def test_update_role_name_conflict(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_role = AsyncMock(return_value=self._role())
        svc.get_role_by_name = AsyncMock(return_value=self._role(name="taken"))
        with patch.object(rbac_api, "RBACService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.update_role("rid-1", RoleUpdate(name="taken"), _="a"))
        assert exc.value.status_code == 409

    def test_update_role_unknown_permission(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_role = AsyncMock(return_value=self._role())
        with patch.object(rbac_api, "RBACService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.update_role("rid-1", RoleUpdate(permissions=["nope"]), _="a"))
        assert exc.value.status_code == 400

    def test_delete_role(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        with patch.object(rbac_api, "RBACService", return_value=svc):
            out = _run(rbac_api.delete_role("rid-1", _="a"))
        assert out is None

    def test_delete_role_not_found(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.delete_role = AsyncMock(return_value=False)
        with patch.object(rbac_api, "RBACService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.delete_role("nope", _="a"))
        assert exc.value.status_code == 404


class TestUserRoleEndpoints:
    def test_assign_role(self):
        from authglow.api import rbac as rbac_api

        user = _user()
        role = Role(name="support", permissions=[])
        assignment = UserRole(user_id="u-1", role_id="rid-1", assigned_by="admin")
        svc = _mock_rbac()
        svc.get_role = AsyncMock(return_value=role)
        svc.assign_role_to_user = AsyncMock(return_value=assignment)
        audit = AsyncMock()
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(user)),
        ):
            out = _run(
                rbac_api.assign_role_to_user(
                    AssignRoleRequest(user_id="u-1", role_id="rid-1"),
                    current_user_id="admin",
                    audit_service=audit,
                )
            )
        assert out.role_name == "support"
        assert out.user_email == "user@example.com"
        audit.log_event.assert_awaited_once()

    def test_assign_role_user_not_found(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        audit = AsyncMock()
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(None)),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(
                    rbac_api.assign_role_to_user(
                        AssignRoleRequest(user_id="nope", role_id="rid-1"),
                        current_user_id="admin",
                        audit_service=audit,
                    )
                )
        assert exc.value.status_code == 404

    def test_assign_role_not_found(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        audit = AsyncMock()
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(_user())),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(
                    rbac_api.assign_role_to_user(
                        AssignRoleRequest(user_id="u-1", role_id="nope"),
                        current_user_id="admin",
                        audit_service=audit,
                    )
                )
        assert exc.value.status_code == 404

    def test_assign_role_already_assigned(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_role = AsyncMock(return_value=Role(name="support", permissions=[]))
        svc.get_user_roles = AsyncMock(
            return_value=[UserRole(user_id="u-1", role_id="rid-1", assigned_by="admin")]
        )
        audit = AsyncMock()
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(_user())),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(
                    rbac_api.assign_role_to_user(
                        AssignRoleRequest(user_id="u-1", role_id="rid-1"),
                        current_user_id="admin",
                        audit_service=audit,
                    )
                )
        assert exc.value.status_code == 409

    def test_remove_role(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_role = AsyncMock(return_value=Role(name="support", permissions=[]))
        audit = AsyncMock()
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(_user())),
        ):
            out = _run(
                rbac_api.remove_role_from_user(
                    "u-1", "rid-1", current_user_id="admin", audit_service=audit
                )
            )
        assert out is None
        audit.log_event.assert_awaited_once()

    def test_remove_role_not_found(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_role = AsyncMock(return_value=Role(name="support", permissions=[]))
        svc.remove_role_from_user = AsyncMock(return_value=False)
        audit = AsyncMock()
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(_user())),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(
                    rbac_api.remove_role_from_user(
                        "u-1", "rid-1", current_user_id="admin", audit_service=audit
                    )
                )
        assert exc.value.status_code == 404

    def test_remove_admin_role_from_self_refused(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_role = AsyncMock(return_value=Role(name=ADMIN_ROLE_NAME, permissions=[]))
        audit = AsyncMock()
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(_user())),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(
                    rbac_api.remove_role_from_user(
                        "admin", "rid-admin", current_user_id="admin", audit_service=audit
                    )
                )
        assert exc.value.status_code == 409

    def test_remove_last_admin_refused(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_role = AsyncMock(return_value=Role(name=ADMIN_ROLE_NAME, permissions=[]))
        svc.list_role_holders = AsyncMock(return_value=["u-1"])
        audit = AsyncMock()
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(_user())),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(
                    rbac_api.remove_role_from_user(
                        "u-1", "rid-admin", current_user_id="admin", audit_service=audit
                    )
                )
        assert exc.value.status_code == 409

    def test_get_own_roles(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_user_roles = AsyncMock(
            return_value=[UserRole(user_id="u-1", role_id="rid-1", assigned_by="admin")]
        )
        svc.get_role = AsyncMock(return_value=Role(name="support", permissions=[]))
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(_user())),
        ):
            out = _run(rbac_api.get_user_roles("u-1", current_user_id="u-1"))
        assert len(out) == 1 and out[0].role_name == "support"

    def test_get_other_roles_forbidden(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(_user())),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.get_user_roles("u-2", current_user_id="u-1"))
        assert exc.value.status_code == 403

    def test_get_roles_user_not_found(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.user_has_any_permission = AsyncMock(return_value=True)
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(None)),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.get_user_roles("nope", current_user_id="admin"))
        assert exc.value.status_code == 404

    def test_get_own_permissions(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.get_user_roles = AsyncMock(
            return_value=[UserRole(user_id="u-1", role_id="rid-1", assigned_by="admin")]
        )
        svc.get_role = AsyncMock(return_value=Role(name="support", permissions=[]))
        svc.get_user_permissions = AsyncMock(return_value={"users.read"})
        svc.user_has_role = AsyncMock(return_value=False)
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(_user())),
        ):
            out = _run(rbac_api.get_user_permissions("u-1", current_user_id="u-1"))
        assert out.permissions == ["users.read"]
        assert out.is_admin is False

    def test_get_other_permissions_forbidden(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(_user())),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.get_user_permissions("u-2", current_user_id="u-1"))
        assert exc.value.status_code == 403

    def test_get_permissions_user_not_found(self):
        from authglow.api import rbac as rbac_api

        svc = _mock_rbac()
        svc.user_has_any_permission = AsyncMock(return_value=True)
        with (
            patch.object(rbac_api, "RBACService", return_value=svc),
            patch.object(rbac_api, "UserStorage", return_value=_mock_storage(None)),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(rbac_api.get_user_permissions("nope", current_user_id="admin"))
        assert exc.value.status_code == 404
