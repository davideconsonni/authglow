"""OIDC prompt parameter integration tests — Workstream G.

Validates that the ``prompt`` parameter (OIDC Core §3.1.2) is correctly
handled in ``/api/oauth2/authorize``.

Tested prompt values:
- ``none`` — silent re-auth with cookie; redirect error without
- ``login`` — forces re-authentication even with valid cookie
- ``consent`` — skips prior-consent check, shows consent screen
"""

from unittest.mock import AsyncMock, MagicMock

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_authorize_app_with_mocks(test_settings):
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
    oauth2_client_storage.is_scope_allowed = AsyncMock(return_value=True)

    oauth2_svc = MagicMock()
    oauth2_svc.client_storage = oauth2_client_storage
    oauth2_svc.verify_redirect_uri = AsyncMock(return_value=True)
    oauth2_svc.process_scopes = AsyncMock(return_value=["read"])
    oauth2_svc.create_authorization_code = AsyncMock()
    oauth2_svc.is_grant_type_allowed = AsyncMock(return_value=True)

    mfa_svc = MagicMock()
    mfa_svc.is_device_trusted = AsyncMock(return_value=True)

    session_svc = MagicMock()
    session_svc.create_consent_session = AsyncMock()
    session_svc.create_mfa_session = AsyncMock()

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

    return app, storage, audit_svc, oauth2_svc


# ---------------------------------------------------------------------------


class TestPromptNone:
    """G.3 + G.7: ``prompt=none`` — silent re-auth or OIDC redirect error."""

    def test_none_with_cookie_redirects_with_code(self, test_settings):
        """User is authenticated via cookie → redirect with auth code."""
        from authglow.models.user import User
        from authglow.services.jwt import JWTService
        from authglow.services.password import hash_password

        app, storage, audit_svc, oauth2_svc = _build_authorize_app_with_mocks(test_settings)

        user = User(
            id="user-1",
            email="test@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        storage.get_user.return_value = user

        jwt_svc = JWTService()
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
                "prompt": "none",
            },
        )

        assert response.status_code == 302, response.text
        location = response.headers["location"]
        assert "code=" in location

    def test_none_without_cookie_redirects_with_error(self, test_settings):
        """No session cookie → redirect with error=login_required."""
        app, storage, audit_svc, oauth2_svc = _build_authorize_app_with_mocks(test_settings)

        http_client = TestClient(app, follow_redirects=False)

        response = http_client.post(
            "/api/oauth2/authorize",
            data={
                "client_id": "client-abc",
                "redirect_uri": "https://example.com/callback",
                "scope": "read",
                "code_challenge": "challenge123",
                "code_challenge_method": "S256",
                "prompt": "none",
            },
        )

        assert response.status_code == 302, response.text
        location = response.headers["location"]
        assert "error=login_required" in location


class TestPromptLogin:
    """G.4: ``prompt=login`` forces re-authentication even with cookie."""

    def test_login_ignores_cookie_requires_password(self, test_settings):
        """Cookie present → ignored, email+password required."""
        from authglow.models.user import User
        from authglow.services.jwt import JWTService
        from authglow.services.password import hash_password

        app, storage, audit_svc, oauth2_svc = _build_authorize_app_with_mocks(test_settings)

        user = User(
            id="user-1",
            email="test@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        storage.get_user_by_email.return_value = user

        jwt_svc = JWTService()
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
                "prompt": "login",
                "email": "test@example.com",
                "password": "GoodP@ss1!",
            },
        )

        # Should succeed via password auth (not 403 CSRF)
        assert response.status_code != 403, f"Got CSRF rejection when prompt=login: {response.text}"


class TestPromptConsent:
    """G.5: ``prompt=consent`` forces consent screen."""

    def test_consent_shows_screen_when_prior_consent_exists(self, test_settings):
        """Even with existing consent, prompt=consent shows the screen."""
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app, storage, audit_svc, oauth2_svc = _build_authorize_app_with_mocks(test_settings)

        user = User(
            id="user-1",
            email="test@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        storage.get_user_by_email.return_value = user

        http_client = TestClient(app, follow_redirects=False)

        response = http_client.post(
            "/api/oauth2/authorize",
            data={
                "client_id": "client-abc",
                "redirect_uri": "https://example.com/callback",
                "scope": "read",
                "code_challenge": "challenge123",
                "code_challenge_method": "S256",
                "prompt": "consent",
                "email": "test@example.com",
                "password": "GoodP@ss1!",
            },
        )

        # Should return consent_required, not generate auth code
        assert response.status_code == 200, response.text
        body = response.json()
        assert body.get("consent_required") is True
