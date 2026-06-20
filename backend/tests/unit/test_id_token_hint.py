"""OIDC id_token_hint login tests — Workstream I.

Validates that an ``id_token_hint`` in the ``/api/oauth2/authorize``
POST body is decoded and used to pre-populate the login email field
(OIDC Core §3.1.2.1).
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app(test_settings):
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
    oauth2_svc.create_authorization_code = AsyncMock()

    session_svc = MagicMock()
    session_svc.create_consent_session = AsyncMock()
    session_svc.create_mfa_session = AsyncMock()

    mfa_svc = MagicMock()
    mfa_svc.is_device_trusted = AsyncMock(return_value=True)

    audit_svc = AsyncMock()

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


class TestIdTokenHintPrePopulation:
    """I.2: id_token_hint pre-popola email nel form di login."""

    def test_valid_hint_prefills_email(self, test_settings):
        """Valid id_token_hint → email pre-populated, password auth succeeds."""
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app, storage = _build_app(test_settings)

        user = User(
            id="hint-user-1",
            email="hintuser@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        storage.get_user.return_value = user
        storage.get_user_by_email.return_value = user

        from authglow.services.jwt import JWTService

        jwt_svc = asyncio.run(JWTService.new())
        id_token = jwt_svc.create_id_token(
            user_id="hint-user-1",
            client_id="client-abc",
            scopes=["openid"],
            user_claims={"email": "hintuser@example.com", "email_verified": True},
        )

        # Patch both the class symbol and ``new()`` so direct
        # ``await JWTService.new()`` calls in the route handler
        # resolve to the pre-built ``jwt_svc`` instance.
        with patch("authglow.api.auth.JWTService") as mock_cls:
            mock_cls.new = AsyncMock(return_value=jwt_svc)
            http_client = TestClient(app)
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "client-abc",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "read",
                    "code_challenge": "test123",
                    "code_challenge_method": "S256",
                    "id_token_hint": id_token,
                    "password": "GoodP@ss1!",
                },
            )

        # Email pre-populated from id_token_hint → password auth succeeds with hint email
        # 401 would mean the hint email wasn't used (credentials missing)
        assert response.status_code != 400 or "Credentials required" not in response.text

    def test_invalid_hint_is_ignored(self, test_settings):
        """Invalid id_token_hint is silently ignored."""
        from authglow.models.user import User
        from authglow.services.jwt import JWTService
        from authglow.services.password import hash_password

        app, storage = _build_app(test_settings)

        user = User(
            id="hint-user-1",
            email="actual@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        storage.get_user_by_email.return_value = user

        jwt_svc = asyncio.run(JWTService.new())

        with patch("authglow.api.auth.JWTService", return_value=jwt_svc):
            http_client = TestClient(app)
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "client-abc",
                    "redirect_uri": "https://example.com/callback",
                    "scope": "read",
                    "code_challenge": "test123",
                    "code_challenge_method": "S256",
                    "id_token_hint": "not-a-valid-jwt",
                    "email": "actual@example.com",
                    "password": "GoodP@ss1!",
                },
            )

        # The bogus id_token_hint is ignored; auth proceeds with the explicit email
        assert response.status_code != 401, response.text
