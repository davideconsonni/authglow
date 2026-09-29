"""Extra execution tests for ``authglow.core.permissions`` (COV-BE-015).

``tests/unit/test_permissions.py`` covers the permission/role decision
paths and OA-504 audience checks. This module fills the remainder:
cookie-based token extraction, role-only checks (all/any), the
missing-``sub`` guard, and the public ``require_*`` dependency factories.
Kept in its own file because the original module predates
``ruff format`` and reformatting it would touch unrelated lines.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _access_token_data(sub="user-1", aud="authglow-internal"):
    from authglow.models.token import TokenData

    return TokenData(
        sub=sub,
        email="t@example.com",
        scopes=["read"],
        token_type="access",
        exp=datetime.now(timezone.utc) + timedelta(hours=1),
        iat=datetime.now(timezone.utc),
        aud=aud,
    )


def _bearer(token="tok"):
    return HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)


def _run_checker(checker, token_data):
    """Invoke a ``PermissionChecker`` with the JWT service patched."""
    with patch("authglow.core.permissions.get_jwt_service", new_callable=AsyncMock) as mock_jwt:
        fake_svc = MagicMock()
        fake_svc.decode_token = MagicMock(return_value=token_data)
        mock_jwt.return_value = fake_svc
        mock_request = MagicMock(spec=Request)
        mock_request.cookies = {}
        return _run(checker(mock_request, _bearer()))


class TestExtractTokenFromCookie:
    def test_cookie_token_used_when_no_bearer(self, test_settings):
        from authglow.core.permissions import _extract_token

        mock_request = MagicMock(spec=Request)
        mock_request.cookies = {test_settings.auth_cookie_access_name: "cookie-token"}
        with patch("authglow.core.permissions.get_settings", return_value=test_settings):
            assert _extract_token(mock_request, None) == "cookie-token"

    def test_no_bearer_no_cookie_401(self, test_settings):
        from authglow.core.permissions import _extract_token

        mock_request = MagicMock(spec=Request)
        mock_request.cookies = {}
        with patch("authglow.core.permissions.get_settings", return_value=test_settings):
            with pytest.raises(HTTPException) as exc_info:
                _extract_token(mock_request, None)
        assert exc_info.value.status_code == 401


class TestRoleAndAllPermissionChecks:
    def test_all_permissions_present_passes(self):
        from authglow.core.permissions import PermissionChecker
        from authglow.services.rbac import RBACService

        checker = PermissionChecker(required_permissions=["a", "b"], require_all_permissions=True)
        with patch.object(
            RBACService, "get_user_permissions", new_callable=AsyncMock
        ) as mock_perms:
            mock_perms.return_value = {"a", "b"}
            assert _run_checker(checker, _access_token_data()) == "user-1"

    def test_roles_only_require_all_passes(self):
        from authglow.core.permissions import PermissionChecker
        from authglow.services.rbac import RBACService

        checker = PermissionChecker(required_roles=["support", "auditor"], require_all_roles=True)
        with patch.object(RBACService, "user_has_role", new_callable=AsyncMock) as mock_has_role:
            mock_has_role.return_value = True
            assert _run_checker(checker, _access_token_data()) == "user-1"

    def test_roles_only_require_all_missing_403(self):
        from authglow.core.permissions import PermissionChecker
        from authglow.services.rbac import RBACService

        checker = PermissionChecker(required_roles=["support", "auditor"], require_all_roles=True)
        with patch.object(RBACService, "user_has_role", new_callable=AsyncMock) as mock_has_role:
            mock_has_role.side_effect = lambda _uid, role: role == "support"
            with pytest.raises(HTTPException) as exc_info:
                _run_checker(checker, _access_token_data())
            assert exc_info.value.status_code == 403

    def test_roles_any_second_matches(self):
        from authglow.core.permissions import PermissionChecker
        from authglow.services.rbac import RBACService

        checker = PermissionChecker(required_roles=["support", "auditor"], require_all_roles=False)
        with patch.object(RBACService, "user_has_role", new_callable=AsyncMock) as mock_has_role:
            mock_has_role.side_effect = lambda _uid, role: role == "auditor"
            assert _run_checker(checker, _access_token_data()) == "user-1"

    def test_roles_any_none_403(self):
        from authglow.core.permissions import PermissionChecker
        from authglow.services.rbac import RBACService

        checker = PermissionChecker(required_roles=["support", "auditor"], require_all_roles=False)
        with patch.object(RBACService, "user_has_role", new_callable=AsyncMock) as mock_has_role:
            mock_has_role.return_value = False
            with pytest.raises(HTTPException) as exc_info:
                _run_checker(checker, _access_token_data())
            assert exc_info.value.status_code == 403


class TestMissingUserId:
    def test_checker_missing_sub_401(self):
        from authglow.core.permissions import PermissionChecker

        checker = PermissionChecker(required_permissions=["users.read"])
        with pytest.raises(HTTPException) as exc_info:
            _run_checker(checker, _access_token_data(sub=""))
        assert exc_info.value.status_code == 401

    def test_get_current_user_missing_sub_401(self):
        from authglow.core.permissions import get_current_user

        with patch("authglow.core.permissions.get_jwt_service", new_callable=AsyncMock) as mock_jwt:
            fake_svc = MagicMock()
            fake_svc.decode_token = MagicMock(return_value=_access_token_data(sub=""))
            mock_jwt.return_value = fake_svc
            mock_request = MagicMock(spec=Request)
            mock_request.cookies = {}
            with pytest.raises(HTTPException) as exc_info:
                _run(get_current_user(mock_request, _bearer()))
        assert exc_info.value.status_code == 401


class TestDependencyFactories:
    def test_require_permission_single(self):
        from authglow.core.permissions import PermissionChecker, require_permission

        checker = require_permission("users.read").dependency
        assert isinstance(checker, PermissionChecker)
        assert checker.required_permissions == ["users.read"]
        assert checker.require_all_permissions is False

    def test_require_permission_list_require_all(self):
        from authglow.core.permissions import require_permission

        checker = require_permission(["a", "b"], require_all=True).dependency
        assert checker.required_permissions == ["a", "b"]
        assert checker.require_all_permissions is True

    def test_require_role_single(self):
        from authglow.core.permissions import require_role

        checker = require_role("support").dependency
        assert checker.required_roles == ["support"]
        assert checker.require_all_roles is False

    def test_require_role_list_require_all(self):
        from authglow.core.permissions import require_role

        checker = require_role(["a", "b"], require_all=True).dependency
        assert checker.required_roles == ["a", "b"]
        assert checker.require_all_roles is True

    def test_require_administrator_targets_admin_role(self):
        from authglow.core.permissions import require_administrator
        from authglow.models.rbac import ADMIN_ROLE_NAME

        checker = require_administrator().dependency
        assert checker.required_roles == [ADMIN_ROLE_NAME]
