"""Integration tests for the Token Revocation endpoint (RFC 7009)."""

import pytest
from unittest.mock import AsyncMock, MagicMock
from fastapi.testclient import TestClient


@pytest.fixture
def _revoke_app():
    """Create a fresh FastAPI app with dependency overrides for each test."""
    from fastapi import FastAPI
    from authglow.api.oauth2_advanced import router, get_refresh_token_service
    from authglow.api.oauth2_advanced import get_jwt_service, get_oauth2_service, get_audit_service

    app = FastAPI()
    app.include_router(router)

    mock_rt_svc = MagicMock()
    mock_rt_svc.get_refresh_token = AsyncMock(return_value=None)
    mock_rt_svc.revoke_token = AsyncMock(return_value=True)

    mock_jwt_svc = MagicMock()
    mock_jwt_svc.decode_token = MagicMock(return_value=None)

    mock_oauth2_svc = MagicMock()
    mock_oauth2_svc.verify_client = AsyncMock(return_value=True)

    mock_audit = MagicMock()
    mock_audit.log_event = AsyncMock()

    app.dependency_overrides[get_refresh_token_service] = lambda: mock_rt_svc
    app.dependency_overrides[get_jwt_service] = lambda: mock_jwt_svc
    app.dependency_overrides[get_oauth2_service] = lambda: mock_oauth2_svc
    app.dependency_overrides[get_audit_service] = lambda: mock_audit

    client = TestClient(app)

    # Attach mocks to the client for assertions in tests
    client._mock_rt_svc = mock_rt_svc
    client._mock_jwt_svc = mock_jwt_svc
    client._mock_oauth2_svc = mock_oauth2_svc
    client._mock_audit = mock_audit

    return client


def _make_refresh_token(token_id="rt-revoke-001", user_id="user-1", client_id="test-client"):
    from authglow.models.refresh_token import RefreshToken
    from authglow.core.datetime import utcnow
    from datetime import timedelta

    return RefreshToken(
        token_id=token_id,
        user_id=user_id,
        client_id=client_id,
        scopes=["openid", "profile"],
        expires_at=utcnow() + timedelta(days=30),
    )


class TestRevokeEndpoint:
    """POST /oauth2/revoke per RFC 7009."""

    def test_revoke_refresh_token_success(self, _revoke_app):
        mock_rt = _make_refresh_token()
        _revoke_app._mock_rt_svc.get_refresh_token = AsyncMock(return_value=mock_rt)
        _revoke_app._mock_rt_svc.revoke_token = AsyncMock(return_value=True)

        response = _revoke_app.post(
            "/oauth2/revoke",
            data={"token": "refresh-token-value", "token_type_hint": "refresh_token"},
        )

        assert response.status_code == 200
        assert response.json() == {}
        _revoke_app._mock_rt_svc.get_refresh_token.assert_awaited_once_with("refresh-token-value")
        _revoke_app._mock_rt_svc.revoke_token.assert_awaited_once()
        _revoke_app._mock_audit.log_event.assert_awaited_once()

    def test_revoke_refresh_token_auto_detect(self, _revoke_app):
        mock_rt = _make_refresh_token()
        _revoke_app._mock_rt_svc.get_refresh_token = AsyncMock(return_value=mock_rt)
        _revoke_app._mock_rt_svc.revoke_token = AsyncMock(return_value=True)

        response = _revoke_app.post(
            "/oauth2/revoke",
            data={"token": "refresh-token-value"},
        )

        assert response.status_code == 200
        assert response.json() == {}
        _revoke_app._mock_rt_svc.get_refresh_token.assert_awaited_once_with("refresh-token-value")
        _revoke_app._mock_rt_svc.revoke_token.assert_awaited_once()
        _revoke_app._mock_audit.log_event.assert_awaited_once()

    def test_revoke_access_token(self, _revoke_app):
        from authglow.models.token import TokenData
        from authglow.core.datetime import utcnow

        mock_token_data = TokenData(
            sub="user-1",
            email="user-1@example.com",
            scopes=["openid", "profile"],
            exp=utcnow(),
            iat=utcnow(),
        )
        _revoke_app._mock_jwt_svc.decode_token = MagicMock(return_value=mock_token_data)

        response = _revoke_app.post(
            "/oauth2/revoke",
            data={"token": "access-token-value", "token_type_hint": "access_token"},
        )

        assert response.status_code == 200
        assert response.json() == {}
        _revoke_app._mock_jwt_svc.decode_token.assert_called_once_with("access-token-value")
        _revoke_app._mock_audit.log_event.assert_awaited_once()

    def test_revoke_with_client_credentials(self, _revoke_app):
        mock_rt = _make_refresh_token()
        _revoke_app._mock_rt_svc.get_refresh_token = AsyncMock(return_value=mock_rt)
        _revoke_app._mock_rt_svc.revoke_token = AsyncMock(return_value=True)

        response = _revoke_app.post(
            "/oauth2/revoke",
            data={
                "token": "refresh-token-value",
                "client_id": "valid-client",
                "client_secret": "valid-secret",
            },
        )

        assert response.status_code == 200
        _revoke_app._mock_oauth2_svc.verify_client.assert_awaited_once_with(
            "valid-client", "valid-secret"
        )
        _revoke_app._mock_rt_svc.get_refresh_token.assert_awaited_once()

    def test_revoke_with_invalid_client_returns_200(self, _revoke_app):
        _revoke_app._mock_oauth2_svc.verify_client = AsyncMock(return_value=False)

        response = _revoke_app.post(
            "/oauth2/revoke",
            data={
                "token": "some-token",
                "client_id": "invalid-client",
                "client_secret": "invalid-secret",
            },
        )

        assert response.status_code == 200
        assert response.json() == {}
        _revoke_app._mock_oauth2_svc.verify_client.assert_awaited_once_with(
            "invalid-client", "invalid-secret"
        )

    def test_revoke_unknown_token_returns_200(self, _revoke_app):
        response = _revoke_app.post(
            "/oauth2/revoke",
            data={"token": "nonexistent-token"},
        )

        assert response.status_code == 200
        assert response.json() == {}

    def test_revoke_missing_token_returns_422(self, _revoke_app):
        response = _revoke_app.post("/oauth2/revoke", data={})
        assert response.status_code == 422
