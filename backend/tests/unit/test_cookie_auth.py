"""Tests for cookie-based auth flow (VAPT-001 remediation)."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from authglow.core.config import Settings
from authglow.api.auth import _cookie_kwargs, _set_auth_cookies, _clear_auth_cookies


class TestCookieHelpers:
    def test_cookie_kwargs_dev_no_secure(self, test_settings):
        """In dev mode, Secure is False (HTTP allowed)."""
        test_settings.app_env = "development"
        kw = _cookie_kwargs(test_settings)
        assert kw["httponly"] is True
        assert kw["secure"] is False
        assert kw["samesite"] == "lax"
        assert kw["path"] == "/api"

    def test_cookie_kwargs_prod_secure(self, test_settings):
        """In production mode, Secure is True (HTTPS required)."""
        test_settings.app_env = "production"
        kw = _cookie_kwargs(test_settings)
        assert kw["secure"] is True

    def test_cookie_kwargs_with_domain(self, test_settings):
        """When domain is set, it's included in kwargs."""
        test_settings.auth_cookie_domain = "example.com"
        kw = _cookie_kwargs(test_settings)
        assert kw["domain"] == "example.com"

    def test_set_auth_cookies_sets_both(self, test_settings):
        """_set_auth_cookies sets access_token and refresh_token cookies."""
        from fastapi import Response

        response = Response()
        _set_auth_cookies(response, "access-jwt", "refresh-opaque", test_settings)

        all_cookies = response.headers.getlist("set-cookie") or [
            response.headers.get("set-cookie", "")
        ]
        combined = " ".join(all_cookies)
        assert "access_token=access-jwt" in combined
        assert "refresh_token=refresh-opaque" in combined
        assert "HttpOnly" in combined
        assert "SameSite=lax" in combined
        assert "Path=/api" in combined

    def test_set_auth_cookies_no_refresh(self, test_settings):
        """When refresh_token is None, only access_token cookie is set."""
        from fastapi import Response

        response = Response()
        _set_auth_cookies(response, "access-jwt", None, test_settings)

        all_cookies = response.headers.getlist("set-cookie") or [
            response.headers.get("set-cookie", "")
        ]
        combined = " ".join(all_cookies)
        assert "access_token=access-jwt" in combined
        assert "refresh_token" not in combined

    def test_clear_auth_cookies_clears_both(self, test_settings):
        """_clear_auth_cookies emits delete for both cookies."""
        from fastapi import Response

        response = Response()
        _clear_auth_cookies(response, test_settings)

        all_cookies = response.headers.getlist("set-cookie") or [
            response.headers.get("set-cookie", "")
        ]
        combined = " ".join(all_cookies)
        assert "access_token=" in combined
        assert "refresh_token=" in combined
        assert "Max-Age=0" in combined or "max-age=0" in combined


class TestCookiesSetOnLogin:
    def test_login_sets_auth_cookies(self, test_settings):
        """POST /api/token response includes Set-Cookie headers with httpOnly tokens."""
        from fastapi import Response
        from authglow.api.auth import _set_auth_cookies
        from authglow.models.token import Token

        response = Response()
        token_resp = Token(access_token="test-access", token_type="bearer", expires_in=1800)
        token_resp.refresh_token = "test-refresh"

        _set_auth_cookies(
            response, token_resp.access_token, token_resp.refresh_token, test_settings
        )

        all_cookies = response.headers.getlist("set-cookie") or [
            response.headers.get("set-cookie", "")
        ]
        combined = " ".join(all_cookies)
        assert "access_token=test-access" in combined
        assert "refresh_token=test-refresh" in combined


class TestGetCurrentUserReadsCookie:
    async def test_reads_token_from_cookie_when_no_auth_header(self, test_settings):
        """get_current_user falls back to access_token cookie."""
        from authglow.api.auth import get_current_user

        request = MagicMock()
        request.headers.get.return_value = ""  # No auth header
        request.cookies.get.return_value = "valid-access-token"

        jwt_service = MagicMock()
        token_data = MagicMock()
        token_data.token_type = "access"
        token_data.sub = "user-1"
        token_data.scopes = ["read"]
        jwt_service.decode_token.return_value = token_data

        storage = MagicMock()
        user_mock = MagicMock()
        user_mock.is_active = True
        user_mock.scopes = ["read"]
        storage.get_user = AsyncMock(return_value=user_mock)

        api_key_service = MagicMock()
        audit_service = MagicMock()
        audit_service.log_event = AsyncMock()
        oauth2_service = MagicMock()

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            result = await get_current_user(
                request=request,
                token=None,
                storage=storage,
                jwt_service=jwt_service,
                api_key_service=api_key_service,
                audit_service=audit_service,
                oauth2_service=oauth2_service,
            )

        assert result is user_mock
        jwt_service.decode_token.assert_called_once_with("valid-access-token")

    async def test_raises_401_when_no_header_and_no_cookie(self, test_settings):
        """get_current_user raises 401 when both header and cookie are missing."""
        from authglow.api.auth import get_current_user
        from fastapi import HTTPException

        request = MagicMock()
        request.headers.get.return_value = ""  # No auth header
        request.cookies.get.return_value = None  # No cookie

        jwt_service = MagicMock()
        storage = MagicMock()
        api_key_service = MagicMock()
        audit_service = MagicMock()
        oauth2_service = MagicMock()

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            with pytest.raises(HTTPException) as exc:
                await get_current_user(
                    request=request,
                    token=None,
                    storage=storage,
                    jwt_service=jwt_service,
                    api_key_service=api_key_service,
                    audit_service=audit_service,
                    oauth2_service=oauth2_service,
                )

        assert exc.value.status_code == 401


class TestAuthCookieEndpointsRegistered:
    def test_refresh_endpoint_registered(self):
        """POST /api/auth/refresh is registered on the auth router."""
        from authglow.api.auth import router

        paths = set()
        for r in router.routes:
            if hasattr(r, "path"):
                paths.add(r.path)
        assert "/api/auth/refresh" in paths

    def test_logout_endpoint_registered(self):
        """POST /api/auth/logout is registered on the auth router."""
        from authglow.api.auth import router

        paths = set()
        for r in router.routes:
            if hasattr(r, "path"):
                paths.add(r.path)
        assert "/api/auth/logout" in paths

    def test_refresh_endpoint_requires_cookie(self):
        """cookie_refresh returns 401 when no refresh_token cookie present."""
        from fastapi.testclient import TestClient
        from unittest.mock import patch

        from authglow.api.auth import router

        with patch("authglow.api.auth.get_settings") as mock_get_settings:
            mock_settings = MagicMock()
            mock_settings.auth_cookie_refresh_name = "refresh_token"
            mock_get_settings.return_value = mock_settings

            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)

            client = TestClient(app)
            response = client.post("/api/auth/refresh")
            assert response.status_code == 401

    def test_logout_clears_cookies(self):
        """cookie_logout returns {"ok": true} and clears cookies."""
        from fastapi.testclient import TestClient
        from unittest.mock import patch

        from authglow.api.auth import router

        with patch("authglow.api.auth.get_settings") as mock_get_settings:
            mock_settings = MagicMock()
            mock_settings.auth_cookie_refresh_name = "refresh_token"
            mock_settings.auth_cookie_access_name = "access_token"
            mock_settings.auth_cookie_secure = False
            mock_settings.auth_cookie_samesite = "lax"
            mock_settings.auth_cookie_path = "/api"
            mock_settings.auth_cookie_domain = None
            mock_get_settings.return_value = mock_settings

            from fastapi import FastAPI

            app = FastAPI()
            app.include_router(router)

            client = TestClient(app)
            response = client.post("/api/auth/logout")
            assert response.status_code == 200
            assert response.json() == {"ok": True}


class TestConfigCookieSettings:
    def test_auth_cookie_secure_false_in_dev(self):
        """Cookie Secure flag is False in development."""
        settings = Settings(
            secret_key="a" * 32,
            app_env="development",
        )
        assert settings.auth_cookie_secure is False

    def test_auth_cookie_secure_true_in_prod(self):
        """Cookie Secure flag is True in production."""
        settings = Settings(
            secret_key="a" * 32,
            app_env="production",
        )
        assert settings.auth_cookie_secure is True

    def test_default_cookie_names(self):
        """Default cookie names are access_token and refresh_token."""
        settings = Settings(secret_key="a" * 32)
        assert settings.auth_cookie_access_name == "access_token"
        assert settings.auth_cookie_refresh_name == "refresh_token"

    def test_default_cookie_path(self):
        """Default cookie path is /api."""
        settings = Settings(secret_key="a" * 32)
        assert settings.auth_cookie_path == "/api"

    def test_default_cookie_samesite(self):
        """Default SameSite is lax."""
        settings = Settings(secret_key="a" * 32)
        assert settings.auth_cookie_samesite == "lax"
