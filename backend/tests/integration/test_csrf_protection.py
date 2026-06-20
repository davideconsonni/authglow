"""Integration tests for CSRF protection on /api/oauth2/authorize — Workstream C.

Validates that:
- ``GET /api/oauth2/csrf-token`` returns a valid token and sets the cookie.
- ``POST /api/oauth2/authorize`` with a session cookie but no CSRF token → 403.
- ``POST /api/oauth2/authorize`` with a valid CSRF token → proceeds past CSRF.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.services.csrf import SESSION_ID_COOKIE

# ---------------------------------------------------------------------------
# csrf-token endpoint
# ---------------------------------------------------------------------------


class TestCsrfTokenEndpoint:
    def test_get_csrf_token_returns_token_and_cookie(self, test_settings):
        from authglow.api.auth import router

        app = FastAPI()
        app.include_router(router)
        http_client = TestClient(app)

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            response = http_client.get("/api/oauth2/csrf-token")

        assert response.status_code == 200, response.text
        body = response.json()
        assert "csrf_token" in body
        assert len(body["csrf_token"]) >= 32

        cookies = response.cookies
        assert SESSION_ID_COOKIE in cookies
        assert cookies[SESSION_ID_COOKIE]

    def test_get_csrf_token_returns_different_tokens(self, test_settings):
        from authglow.api.auth import router

        app = FastAPI()
        app.include_router(router)
        http_client = TestClient(app)

        with patch("authglow.services.csrf.get_settings", return_value=test_settings):
            r1 = http_client.get("/api/oauth2/csrf-token")
            r2 = http_client.get("/api/oauth2/csrf-token")

        t1 = r1.json()["csrf_token"]
        t2 = r2.json()["csrf_token"]
        assert t1 != t2, "Two consecutive requests should return different tokens"


# ---------------------------------------------------------------------------
# authorize_post — CSRF enforcement for cookie-authenticated users
# ---------------------------------------------------------------------------


def _build_authorize_app_with_mocks(test_settings):
    """Build a FastAPI app with mocked dependencies for authorize_post."""
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

    return app, storage, audit_svc


class TestAuthorizePostCsrfEnforcement:
    """C.2 + C.5: CSRF token required when user is authenticated via cookie."""

    def test_no_session_cookie_no_csrf_required(self, test_settings):
        """Without an active session cookie the user provides credentials — CSRF is skipped."""
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app, storage, audit_svc = _build_authorize_app_with_mocks(test_settings)

        # No cookie → no user found → falls through to email+password
        storage.get_user.return_value = None
        user = User(
            id="user-1",
            email="test@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        storage.get_user_by_email.return_value = user
        storage.is_account_locked.return_value = False
        storage.reset_failed_login_attempts = AsyncMock()
        storage.record_failed_login = AsyncMock()

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "client-abc",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "read",
                    "code_challenge": "test-challenge-abc",
                    "code_challenge_method": "S256",
                    "email": "test@example.com",
                    "password": "GoodP@ss1!",
                },
            )

        # The CSRF gate is only triggered when user is found via cookie.
        # Here the user authenticates via email+password — no CSRF needed.
        # But without rbac data, the response might be a 200 or other.
        # We just assert it's NOT a 403 CSRF rejection.
        assert response.status_code != 403, (
            f"Email+password auth should not trigger CSRF, got {response.status_code}"
        )

    def test_session_cookie_without_csrf_token_returns_403(self, test_settings):
        """User authenticated via session cookie but no CSRF token → 403."""
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app, storage, audit_svc = _build_authorize_app_with_mocks(test_settings)

        user = User(
            id="user-1",
            email="test@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        storage.get_user.return_value = user

        # Produce a valid JWT access token in the cookie
        from authglow.services.jwt import JWTService

        jwt_svc = asyncio.run(JWTService.new())
        access_token = jwt_svc.create_access_token("user-1", "test@example.com", ["read"])

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            http_client = TestClient(app)
            http_client.cookies.set(
                test_settings.auth_cookie_access_name, access_token, domain="testserver.local"
            )
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "client-abc",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "read",
                    "code_challenge": "test-challenge-abc",
                    "code_challenge_method": "S256",
                },
            )

        assert response.status_code == 403, response.text
        detail = response.json().get("detail", "")
        assert "CSRF" in detail

    def test_session_cookie_with_valid_csrf_token_proceeds(self, test_settings):
        """User authenticated via cookie + valid CSRF token → not rejected by CSRF."""
        from authglow.models.user import User
        from authglow.services.jwt import JWTService
        from authglow.services.password import hash_password

        app, storage, audit_svc = _build_authorize_app_with_mocks(test_settings)

        user = User(
            id="user-1",
            email="test@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
            mfa_enabled=False,
        )
        storage.get_user.return_value = user

        # Generate a real CSRF token
        import asyncio

        from authglow.services.csrf import CSRFTokenService

        async def _gen_token():
            svc = CSRFTokenService(settings=test_settings)
            return await svc.generate_token("test-csrf-session")

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        token = loop.run_until_complete(_gen_token())

        # Produce a valid JWT access token in the cookie
        jwt_svc = asyncio.run(JWTService.new())
        access_token = jwt_svc.create_access_token("user-1", "test@example.com", ["read"])

        with (
            patch("authglow.api.auth.get_settings", return_value=test_settings),
            patch("authglow.services.csrf.get_settings", return_value=test_settings),
        ):
            http_client = TestClient(app)
            http_client.cookies.set(
                test_settings.auth_cookie_access_name, access_token, domain="testserver.local"
            )
            http_client.cookies.set(
                SESSION_ID_COOKIE, "test-csrf-session", domain="testserver.local"
            )
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "client-abc",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "read",
                    "code_challenge": "test-challenge-abc",
                    "code_challenge_method": "S256",
                    "csrf_token": token,
                },
            )

        # Should NOT be 403 from CSRF. Will be something else (e.g., error from code auth flow).
        assert response.status_code != 403, (
            f"Valid CSRF token should pass CSRF gate, got {response.status_code}: {response.text}"
        )
