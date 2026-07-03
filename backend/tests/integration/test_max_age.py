"""OIDC max_age parameter integration tests — Workstream H.

Validates that ``max_age`` forces re-authentication when the user's
``last_login`` is older than the threshold (OIDC Core §3.1.2.1).
"""

import asyncio
import secrets
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_authorize_app(test_settings):
    from authglow.api.auth import (
        get_audit_service,
        get_mfa_service,
        get_oauth2_service,
        get_session_service,
        get_user_storage,
        router,
    )
    from authglow.models.oauth_client import OAuth2Client

    client = OAuth2Client(
        client_id="client-abc",
        client_secret="fake-hash",
        client_name="Test Client",
        redirect_uris=["https://example.com/callback"],
    )

    oauth2_client_storage = MagicMock()
    oauth2_client_storage.get_client = AsyncMock(return_value=client)
    oauth2_client_storage.verify_redirect_uri = AsyncMock(return_value=True)

    oauth2_svc = MagicMock()
    oauth2_svc.client_storage = oauth2_client_storage
    oauth2_svc.verify_redirect_uri = AsyncMock(return_value=True)
    oauth2_svc.process_scopes = AsyncMock(return_value=["read"])

    mfa_svc = MagicMock()
    mfa_svc.is_device_trusted = AsyncMock(return_value=True)

    session_svc = MagicMock()
    session_svc.create_consent_session = AsyncMock()

    audit_svc = AsyncMock()
    audit_svc.log_event = AsyncMock()

    storage = MagicMock()
    storage.get_user = AsyncMock()
    storage.get_user_by_email = AsyncMock()
    storage.is_account_locked = AsyncMock(return_value=False)
    storage.reset_failed_login_attempts = AsyncMock()
    storage.record_failed_login = AsyncMock()
    storage.update_last_login = AsyncMock()

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[get_user_storage] = lambda: storage
    app.dependency_overrides[get_oauth2_service] = lambda: oauth2_svc
    app.dependency_overrides[get_mfa_service] = lambda: mfa_svc
    app.dependency_overrides[get_session_service] = lambda: session_svc
    app.dependency_overrides[get_audit_service] = lambda: audit_svc

    return app, storage


class TestMaxAge:
    """H.3: max_age checks user.last_login age."""

    def test_max_age_zero_forces_re_auth(self, test_settings):
        """max_age=0 always forces re-login, even with valid cookie."""
        from authglow.models.user import User
        from authglow.services.jwt import JWTService
        from authglow.services.password import hash_password

        app, storage = _build_authorize_app(test_settings)

        user = User(
            id="user-1",
            email="test@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            last_login=datetime.now(timezone.utc) - timedelta(minutes=1),
        )
        storage.get_user.return_value = user

        jwt_svc = asyncio.run(JWTService.new())
        access_token = jwt_svc.create_access_token("user-1", "test@example.com", ["read"])

        http_client = TestClient(app, follow_redirects=False)
        http_client.cookies.set(
            test_settings.auth_cookie_access_name, access_token, domain="testserver.local"
        )

        response = http_client.post(
            "/api/oauth2/authorize",
            data={
                "client_id": "client-abc",
                "redirect_uri": "https://example.com/callback",
                "scope": "read",
                "code_challenge": "challenge123",
                "code_challenge_method": "S256",
                "max_age": "0",
                "state": secrets.token_urlsafe(32),
            },
        )

        # max_age=0 forces re-auth → removes user → falls to credentials-required error
        assert response.status_code == 400, response.text
        assert "Credentials required" in response.json().get("detail", "")

    def test_max_age_expired_forces_re_auth(self, test_settings):
        """last_login is 2h ago, max_age=3600 → forces re-login."""
        from authglow.models.user import User
        from authglow.services.jwt import JWTService
        from authglow.services.password import hash_password

        app, storage = _build_authorize_app(test_settings)

        user = User(
            id="user-1",
            email="test@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            last_login=datetime.now(timezone.utc) - timedelta(hours=2),
        )
        storage.get_user.return_value = user

        jwt_svc = asyncio.run(JWTService.new())
        access_token = jwt_svc.create_access_token("user-1", "test@example.com", ["read"])

        http_client = TestClient(app, follow_redirects=False)
        http_client.cookies.set(
            test_settings.auth_cookie_access_name, access_token, domain="testserver.local"
        )

        response = http_client.post(
            "/api/oauth2/authorize",
            data={
                "client_id": "client-abc",
                "redirect_uri": "https://example.com/callback",
                "scope": "read",
                "code_challenge": "challenge123",
                "code_challenge_method": "S256",
                "max_age": "3600",
                "state": secrets.token_urlsafe(32),
            },
        )

        assert response.status_code == 400, response.text
        assert "Credentials required" in response.json().get("detail", "")

    def test_max_age_not_expired_allows_cookie(self, test_settings):
        """last_login is 30 min ago, max_age=3600 → cookie auth proceeds."""
        from authglow.models.user import User
        from authglow.services.jwt import JWTService
        from authglow.services.password import hash_password

        app, storage = _build_authorize_app(test_settings)

        user = User(
            id="user-1",
            email="test@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            last_login=datetime.now(timezone.utc) - timedelta(minutes=30),
        )
        storage.get_user.return_value = user

        jwt_svc = asyncio.run(JWTService.new())
        access_token = jwt_svc.create_access_token("user-1", "test@example.com", ["read"])

        http_client = TestClient(app, follow_redirects=False)
        http_client.cookies.set(
            test_settings.auth_cookie_access_name, access_token, domain="testserver.local"
        )

        response = http_client.post(
            "/api/oauth2/authorize",
            data={
                "client_id": "client-abc",
                "redirect_uri": "https://example.com/callback",
                "scope": "read",
                "code_challenge": "challenge123",
                "code_challenge_method": "S256",
                "max_age": "3600",
                "state": secrets.token_urlsafe(32),
            },
        )

        # Should NOT be 400 "Credentials required" — cookie auth allowed
        # Will be 403 because CSRF token is missing, which proves the cookie path is taken
        assert response.status_code == 403, response.text
        assert "CSRF" in response.json().get("detail", "")
