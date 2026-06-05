"""Integration tests for RBAC permissions/roles injection in JWT tokens."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.models.oauth_client import OAuth2Client
from authglow.models.user import User
from authglow.services.password import hash_password


@pytest.fixture
def rbac_test_app():
    app = FastAPI()
    from authglow.api.auth import router

    app.include_router(router)
    return TestClient(app)


class TestPermissionsInJwt:
    def test_access_token_contains_permissions_and_roles(self, test_settings, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u1",
            email="u1@test.com",
            scopes=["openid", "read"],
            permissions=["users.read", "users.write"],
            roles=["developer"],
        )

        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        assert decoded.permissions == ["users.read", "users.write"]
        assert decoded.roles == ["developer"]

    def test_access_token_without_rbac_has_none_fields(self, test_settings, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u1",
            email="u1@test.com",
            scopes=["openid"],
        )

        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        assert decoded.permissions is None
        assert decoded.roles is None

    def test_create_token_response_passes_permissions(self, test_settings, jwt_service):
        response = jwt_service.create_token_response(
            user_id="u1",
            email="u1@test.com",
            scopes=["openid"],
            permissions=["users.read"],
            roles=["admin"],
        )

        decoded = jwt_service.decode_token(response.access_token)
        assert decoded is not None
        assert decoded.permissions == ["users.read"]
        assert decoded.roles == ["admin"]

    def test_resolve_rbac_permissions_returns_empty_for_no_roles(self, test_settings):
        from authglow.services.jwt import resolve_rbac_permissions

        async def _run():
            perms, roles = await resolve_rbac_permissions("nonexistent")
            return perms, roles

        perms, roles = asyncio.run(_run())
        assert len(list(perms)) == 0
        assert len(list(roles)) == 0

    def test_resolve_rbac_permissions_resolves_real_rbac(self, test_settings):
        from authglow.services.jwt import resolve_rbac_permissions
        from authglow.services.rbac import RBACService
        from authglow.models.rbac import Role, UserRole

        async def _run():
            rbac = RBACService()
            role = await rbac.create_role(
                Role(
                    name="developer-rbac",
                    description="Test developer role",
                    permissions=["users.read", "users.write"],
                    is_system=False,
                )
            )
            await rbac.assign_role_to_user(
                UserRole(
                    user_id="test-user-rbac",
                    role_id=role.role_id,
                    assigned_by="test-runner",
                )
            )
            perms, roles = await resolve_rbac_permissions("test-user-rbac")
            return perms, roles, role.role_id

        perms, roles, role_id = asyncio.run(_run())
        assert "users.read" in perms
        assert "users.write" in perms
        assert role_id in roles

    def test_rbac_permissions_are_json_serializable(self, test_settings, jwt_service):
        token = jwt_service.create_access_token(
            user_id="u1",
            email="u1@test.com",
            scopes=["openid"],
            permissions=["users.read", "users.write"],
            roles=["developer"],
        )

        import json

        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        assert isinstance(decoded.permissions, list)
        assert isinstance(decoded.roles, list)
        json.dumps({"permissions": decoded.permissions, "roles": decoded.roles})

    def test_full_login_flow_rbac_serializable(self, test_settings, jwt_service):
        from authglow.services.jwt import resolve_rbac_permissions
        from authglow.services.rbac import RBACService
        from authglow.models.rbac import Role, UserRole

        async def _run():
            rbac = RBACService()
            role = await rbac.create_role(
                Role(
                    name="flow-test",
                    permissions=["users.read"],
                    is_system=False,
                )
            )
            await rbac.assign_role_to_user(
                UserRole(user_id="u-flow", role_id=role.role_id, assigned_by="test")
            )
            perms, roles = await resolve_rbac_permissions("u-flow")
            token = jwt_service.create_access_token(
                user_id="u-flow",
                email="u-flow@test.com",
                scopes=["openid"],
                permissions=list(perms),
                roles=roles,
            )
            return token

        import json

        token = asyncio.run(_run())
        decoded = jwt_service.decode_token(token)
        assert decoded is not None
        assert "users.read" in decoded.permissions
        json.dumps({"permissions": decoded.permissions, "roles": decoded.roles})
