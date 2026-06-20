from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials


class TestLazyJWTServiceInit:
    def test_import_does_not_instantiate_jwt_service(self):
        import importlib

        import authglow.core.jwt_singleton as jwt_singleton_mod
        from authglow.services.jwt import JWTService

        with patch.object(
            JWTService, "__init__", side_effect=RuntimeError("should not init")
        ) as mock_init:
            importlib.reload(jwt_singleton_mod)
            mock_init.assert_not_called()

    def test_lazy_init_creates_instance_on_first_call(self, test_settings):
        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            import authglow.core.jwt_singleton as jwt_singleton_mod
            from authglow.core.jwt_singleton import get_jwt_service

            jwt_singleton_mod._singleton = None

            svc = asyncio_run(get_jwt_service())
            assert svc is not None
            assert jwt_singleton_mod._singleton is svc

    def test_lazy_init_caches_instance(self, test_settings):
        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            import authglow.core.jwt_singleton as jwt_singleton_mod
            from authglow.core.jwt_singleton import get_jwt_service

            jwt_singleton_mod._singleton = None

            svc1 = asyncio_run(get_jwt_service())
            svc2 = asyncio_run(get_jwt_service())
            assert svc1 is svc2

    def test_reset_lazy_singleton(self, test_settings):
        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            import authglow.core.jwt_singleton as jwt_singleton_mod
            from authglow.core.jwt_singleton import (
                get_jwt_service,
                reset_jwt_singleton,
            )

            jwt_singleton_mod._singleton = None
            svc1 = asyncio_run(get_jwt_service())
            asyncio_run(reset_jwt_singleton())
            svc2 = asyncio_run(get_jwt_service())
            assert svc1 is not svc2


class TestPermissionChecker:
    def _make_token_data(self, sub="user-1", email="test@example.com", scopes=None):
        from datetime import datetime, timedelta, timezone

        from authglow.models.token import TokenData

        return TokenData(
            sub=sub,
            email=email,
            scopes=scopes or ["read"],
            token_type="access",
            exp=datetime.now(timezone.utc) + timedelta(hours=1),
            iat=datetime.now(timezone.utc),
        )

    def test_admin_scope_bypasses_permissions(self, test_settings):
        from authglow.core.permissions import PermissionChecker

        with patch(
            "authglow.core.permissions.get_jwt_service", new_callable=AsyncMock
        ) as mock_jwt:
            token_data = self._make_token_data(scopes=["read", "admin"])
            fake_svc = MagicMock()
            fake_svc.decode_token = MagicMock(return_value=token_data)
            mock_jwt.return_value = fake_svc

            checker = PermissionChecker(required_permissions=["users.delete"])
            mock_request = MagicMock(spec=Request)
            mock_request.cookies = {}
            creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="valid-token")
            result = asyncio_run(checker.__call__(mock_request, creds))
            assert result == "user-1"

    def test_any_permission_sufficient(self, test_settings):
        from authglow.core.permissions import PermissionChecker
        from authglow.services.rbac import RBACService

        with patch(
            "authglow.core.permissions.get_jwt_service", new_callable=AsyncMock
        ) as mock_jwt:
            token_data = self._make_token_data(scopes=["read"])
            fake_svc = MagicMock()
            fake_svc.decode_token = MagicMock(return_value=token_data)
            mock_jwt.return_value = fake_svc

            with patch.object(
                RBACService, "get_user_permissions", new_callable=AsyncMock
            ) as mock_perms:
                mock_perms.return_value = {"users.read"}

                checker = PermissionChecker(
                    required_permissions=["users.read", "users.delete"],
                    require_all_permissions=False,
                )
                mock_request = MagicMock(spec=Request)
                mock_request.cookies = {}
                creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="valid-token")
                result = asyncio_run(checker(mock_request, creds))
                assert result == "user-1"

    def test_all_permissions_required(self, test_settings):
        from authglow.core.permissions import PermissionChecker
        from authglow.services.rbac import RBACService

        with patch(
            "authglow.core.permissions.get_jwt_service", new_callable=AsyncMock
        ) as mock_jwt:
            token_data = self._make_token_data(scopes=["read"])
            fake_svc = MagicMock()
            fake_svc.decode_token = MagicMock(return_value=token_data)
            mock_jwt.return_value = fake_svc

            with patch.object(
                RBACService, "get_user_permissions", new_callable=AsyncMock
            ) as mock_perms:
                mock_perms.return_value = {"users.read"}

                checker = PermissionChecker(
                    required_permissions=["users.read", "users.delete"],
                    require_all_permissions=True,
                )
                mock_request = MagicMock(spec=Request)
                mock_request.cookies = {}
                creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="valid-token")
                with pytest.raises(HTTPException) as exc_info:
                    asyncio_run(checker(mock_request, creds))
                assert exc_info.value.status_code == 403

    def test_invalid_token_returns_401(self, test_settings):
        from authglow.core.permissions import PermissionChecker

        with patch(
            "authglow.core.permissions.get_jwt_service", new_callable=AsyncMock
        ) as mock_jwt:
            fake_svc = MagicMock()
            fake_svc.decode_token = MagicMock(return_value=None)
            mock_jwt.return_value = fake_svc

            checker = PermissionChecker(required_permissions=["users.read"])
            mock_request = MagicMock(spec=Request)
            mock_request.cookies = {}
            creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid-token")
            with pytest.raises(HTTPException) as exc_info:
                asyncio_run(checker(mock_request, creds))
            assert exc_info.value.status_code == 401


class TestGetCurrentUser:
    def test_get_current_user_valid_token(self, test_settings):
        from datetime import datetime, timedelta, timezone

        from authglow.core.permissions import get_current_user
        from authglow.models.token import TokenData

        with patch(
            "authglow.core.permissions.get_jwt_service", new_callable=AsyncMock
        ) as mock_jwt:
            token_data = TokenData(
                sub="user-42",
                email="test@example.com",
                scopes=["read"],
                token_type="access",
                exp=datetime.now(timezone.utc) + timedelta(hours=1),
                iat=datetime.now(timezone.utc),
            )
            fake_svc = MagicMock()
            fake_svc.decode_token = MagicMock(return_value=token_data)
            mock_jwt.return_value = fake_svc

            mock_request = MagicMock(spec=Request)
            mock_request.cookies = {}
            creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="valid-token")
            result = asyncio_run(get_current_user(mock_request, creds))
            assert result == "user-42"

    def test_get_current_user_invalid_token(self, test_settings):
        from authglow.core.permissions import get_current_user

        with patch(
            "authglow.core.permissions.get_jwt_service", new_callable=AsyncMock
        ) as mock_jwt:
            fake_svc = MagicMock()
            fake_svc.decode_token = MagicMock(return_value=None)
            mock_jwt.return_value = fake_svc

            mock_request = MagicMock(spec=Request)
            mock_request.cookies = {}
            creds = HTTPAuthorizationCredentials(scheme="Bearer", credentials="invalid")
            with pytest.raises(HTTPException) as exc_info:
                asyncio_run(get_current_user(mock_request, creds))
            assert exc_info.value.status_code == 401


def asyncio_run(coro):
    import asyncio

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _make_jwt_service(test_settings):
    """Build a fully-loaded ``JWTService`` for tests that
    mock ``get_jwt_service`` (sync-returning) and need
    ``decode_token`` to work."""
    from authglow.services.jwt import JWTService

    with patch("authglow.services.jwt.get_settings", return_value=test_settings):
        return asyncio_run(JWTService.new())
