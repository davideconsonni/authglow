"""Enforcement matrix for the UX-driven permission vocabulary.

Proves that permissions actually ALLOW and DENY, route by route, for
non-Administrator roles:

- ``support`` role (``users.manage`` only): may manage users, must be
  denied settings/stats/RBAC writes.
- ``auditor`` role (``admin.read`` only): may read admin surfaces,
  must be denied every mutation.
- plain user (no roles): denied everywhere on the admin surface.
"""

import asyncio

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api import admin as admin_module
from authglow.api import rbac as rbac_module
from authglow.api.admin_settings import router as admin_settings_router
from authglow.models.rbac import Role
from authglow.models.user import User
from authglow.services.password import hash_password


def _make_user(user_id: str, email: str) -> User:
    return User(
        id=user_id,
        email=email,
        hashed_password=hash_password("TestP@ss123!"),
        is_active=True,
        email_verified=True,
        scopes=["read", "write"],
    )


def _grant(user_id: str, role_name: str, permissions: list, rbac_service) -> None:
    async def _go():
        role = await rbac_service.get_role_by_name(role_name)
        if role is None:
            role = await rbac_service.create_role(
                Role(name=role_name, permissions=list(permissions), is_system=False)
            )
        await rbac_service.assign_role_to_user_idempotent(
            user_id=user_id, role_id=role.role_id, actor_id=user_id
        )

    asyncio.run(_go())


@pytest.fixture
def admin_test_app(test_settings, jwt_service, rbac_service, storage):
    """Build a TestClient factory bound to per-test stores.

    Returns a helper ``client_for(user_id, email, roles)`` that persists
    the user, assigns the named roles (creating them with the given
    permission sets), mints a real JWT and returns an authenticated
    TestClient over the admin surface (users + settings + RBAC).
    """
    asyncio.run(rbac_service.initialize_defaults())

    def _client_for(user_id: str, email: str, grants: dict) -> TestClient:
        user = _make_user(user_id, email)
        try:
            asyncio.run(storage.create_user(user))
        except ValueError:
            pass
        for role_name, permissions in grants.items():
            _grant(user_id, role_name, permissions, rbac_service)
        token = jwt_service.create_access_token(
            user_id=user.id, email=user.email, scopes=user.scopes
        )
        app = FastAPI()
        app.include_router(admin_module.router)
        app.include_router(admin_settings_router)
        app.include_router(rbac_module.router)
        return TestClient(app, headers={"Authorization": f"Bearer {token}"})

    return _client_for


class TestSupportRoleUsersManage:
    """Support = users.manage only: users yes, everything else no."""

    def test_support_can_search_users(self, admin_test_app):
        client = admin_test_app("support-1", "support@test.com", {"support": ["users.manage"]})
        resp = client.get("/api/admin/users/search?q=support")
        assert resp.status_code == 200, resp.text

    def test_support_can_create_user(self, admin_test_app):
        client = admin_test_app("support-1", "support@test.com", {"support": ["users.manage"]})
        resp = client.post(
            "/api/admin/users/create",
            json={
                "email": "newbie@test.com",
                "password": "StrongP@ss1!",
                "email_verified": True,
            },
        )
        assert resp.status_code == 201, resp.text

    def test_support_cannot_read_settings(self, admin_test_app):
        client = admin_test_app("support-1", "support@test.com", {"support": ["users.manage"]})
        resp = client.get("/api/admin/settings")
        assert resp.status_code == 403, resp.text

    def test_support_cannot_read_stats(self, admin_test_app):
        client = admin_test_app("support-1", "support@test.com", {"support": ["users.manage"]})
        resp = client.get("/api/admin/stats")
        assert resp.status_code == 403, resp.text

    def test_support_cannot_create_role(self, admin_test_app):
        client = admin_test_app("support-1", "support@test.com", {"support": ["users.manage"]})
        resp = client.post(
            "/api/rbac/roles",
            json={"name": "evil", "description": "", "permissions": []},
        )
        assert resp.status_code == 403, resp.text

    def test_support_cannot_assign_role(self, admin_test_app):
        client = admin_test_app("support-1", "support@test.com", {"support": ["users.manage"]})
        resp = client.post(
            "/api/rbac/user-roles",
            json={"user_id": "support-1", "role_id": "whatever"},
        )
        assert resp.status_code == 403, resp.text


class TestAuditorRoleAdminRead:
    """Auditor = admin.read only: reads yes, every mutation no."""

    def test_auditor_can_read_settings(self, admin_test_app):
        client = admin_test_app("audit-1", "audit@test.com", {"auditor": ["admin.read"]})
        resp = client.get("/api/admin/settings")
        assert resp.status_code == 200, resp.text

    def test_auditor_can_list_users(self, admin_test_app):
        client = admin_test_app("audit-1", "audit@test.com", {"auditor": ["admin.read"]})
        resp = client.get("/api/admin/users/search?q=audit")
        assert resp.status_code == 200, resp.text

    def test_auditor_cannot_patch_settings(self, admin_test_app):
        client = admin_test_app("audit-1", "audit@test.com", {"auditor": ["admin.read"]})
        resp = client.patch("/api/admin/settings", json={})
        assert resp.status_code == 403, resp.text

    def test_auditor_cannot_create_user(self, admin_test_app):
        client = admin_test_app("audit-1", "audit@test.com", {"auditor": ["admin.read"]})
        resp = client.post(
            "/api/admin/users/create",
            json={
                "email": "newbie2@test.com",
                "password": "StrongP@ss1!",
                "email_verified": True,
            },
        )
        assert resp.status_code == 403, resp.text


class TestPlainUserDenied:
    """No roles at all: denied everywhere on the admin surface."""

    def test_plain_user_cannot_search_users(self, admin_test_app):
        client = admin_test_app("plain-1", "plain@test.com", {})
        resp = client.get("/api/admin/users/search?q=plain")
        assert resp.status_code == 403, resp.text

    def test_plain_user_cannot_read_settings(self, admin_test_app):
        client = admin_test_app("plain-1", "plain@test.com", {})
        resp = client.get("/api/admin/settings")
        assert resp.status_code == 403, resp.text


class TestAdministratorKeepsFullAccess:
    """The Administrator role holds every permission in the vocabulary."""

    def test_administrator_passes_area_gates(
        self, test_settings, jwt_service, rbac_service, storage
    ):
        import asyncio

        from authglow.services.password import hash_password as _hash

        user = User(
            id="boss-1",
            email="boss@test.com",
            hashed_password=_hash("TestP@ss123!"),
            is_active=True,
            email_verified=True,
            scopes=["read", "write"],
        )
        try:
            asyncio.run(storage.create_user(user))
        except ValueError:
            pass
        role_id = asyncio.run(rbac_service.ensure_admin_role())
        asyncio.run(
            rbac_service.assign_role_to_user_idempotent(
                user_id=user.id, role_id=role_id, actor_id=user.id
            )
        )
        token = jwt_service.create_access_token(
            user_id=user.id, email=user.email, scopes=user.scopes
        )
        app = FastAPI()
        app.include_router(admin_module.router)
        app.include_router(admin_settings_router)
        app.include_router(rbac_module.router)
        client = TestClient(app, headers={"Authorization": f"Bearer {token}"})
        assert client.get("/api/admin/users/search?q=boss").status_code == 200
        assert client.get("/api/admin/settings").status_code == 200
        assert client.get("/api/rbac/roles").status_code == 200
