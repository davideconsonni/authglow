"""Integration tests for OIDC API endpoints via TestClient."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from authglow.api.oidc import router


def _make_test_token(jwt_service, sub, scopes=None, audience="test-client"):
    """Helper to create a valid, aud-bound access token JWT (OIDC Core §3.1.3.7)."""

    if scopes is None:
        scopes = ["openid", "profile", "email"]
    return jwt_service.create_access_token(
        user_id=sub,
        email=f"{sub}@example.com",
        scopes=scopes,
        audience=audience,
    )


@pytest.fixture
def _userinfo_app():
    """Create a fresh FastAPI app with the OIDC router for each test."""
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestUserInfoEndpoint:
    def test_userinfo_success(self, jwt_service, _userinfo_app, test_settings):
        token = _make_test_token(jwt_service, sub="userinfo-test-001")

        from authglow.models.user import User
        from authglow.services.password import hash_password

        mock_user = User(
            id="userinfo-test-001",
            email="userinfo-test-001@example.com",
            hashed_password=hash_password("TestP@ss123!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            first_name="Test",
            last_name="User",
        )

        with patch("authglow.services.oidc.UserStorage") as MockStorage:
            mock_storage = MagicMock()
            mock_storage.get_user = AsyncMock(return_value=mock_user)
            MockStorage.return_value = mock_storage

            response = _userinfo_app.get(
                "/oauth2/userinfo",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert response.status_code == 200
        data = response.json()
        assert data["sub"] == "userinfo-test-001"
        assert data["email"] == "userinfo-test-001@example.com"
        assert data["name"] == "Test User"

    def test_userinfo_missing_openid_scope(self, jwt_service, _userinfo_app):
        token = _make_test_token(jwt_service, sub="userinfo-test-002", scopes=["email"])

        response = _userinfo_app.get(
            "/oauth2/userinfo",
            headers={"Authorization": f"Bearer {token}"},
        )

        assert response.status_code == 403
        assert "openid" in response.json()["detail"].lower()

    def test_userinfo_invalid_token(self, _userinfo_app):
        response = _userinfo_app.get(
            "/oauth2/userinfo",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert response.status_code == 401

    def test_userinfo_no_auth_header(self, _userinfo_app):
        response = _userinfo_app.get("/oauth2/userinfo")
        assert response.status_code in (401, 403)

    def test_userinfo_user_not_found(self, jwt_service, _userinfo_app):
        token = _make_test_token(jwt_service, sub="nonexistent-user")

        with patch("authglow.services.oidc.UserStorage") as MockStorage:
            mock_storage = MagicMock()
            mock_storage.get_user = AsyncMock(return_value=None)
            MockStorage.return_value = mock_storage

            response = _userinfo_app.get(
                "/oauth2/userinfo",
                headers={"Authorization": f"Bearer {token}"},
            )

        assert response.status_code == 404
