"""Integration tests for federation callback with OAuth2 context."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.models.user import User
from authglow.services.federation_state import FederationStateToken
from authglow.services.password import hash_password


@pytest.fixture
def _fed_app(test_settings, jwt_service):
    app = FastAPI()

    from authglow.api.federation import router as fed_router

    app.include_router(fed_router)

    from authglow.api.federation import (
        FederationStorage,
        FederationService,
        FederationStateToken,
        FederationStateError,
    )

    return TestClient(app)


class TestFederatedConsentSessionEndpoint:
    def test_federated_consent_without_cookie_returns_false(self, _fed_app, test_settings):
        response = _fed_app.post("/api/oauth2/federated-consent")

        assert response.status_code == 200
        data = response.json()
        assert data["consent_required"] is False

    def test_federated_consent_with_invalid_token_returns_false(self, _fed_app, test_settings):
        _fed_app.cookies.set("__Host-authglow-consent-session", "garbage-token")
        response = _fed_app.post("/api/oauth2/federated-consent")

        assert response.status_code == 200
        data = response.json()
        assert data["consent_required"] is False

    def test_federated_consent_with_valid_session_returns_consent_data(
        self, _fed_app, test_settings
    ):
        import asyncio
        from authglow.models.oauth_client import OAuth2Client
        from authglow.services.oauth_client import OAuth2ClientStorage
        from authglow.services.session import SessionService

        client = OAuth2Client(
            client_id="fed-test-client",
            client_secret="fed-test-secret",
            client_name="Federated Test App",
            description="A test OAuth2 client",
            redirect_uris=["https://app.example.com/cb"],
            allowed_scopes=["openid", "profile", "email"],
            grant_types=["authorization_code"],
            is_active=True,
        )

        async def _run():
            session_svc = SessionService()
            session = await session_svc.create_consent_session(
                user_id="fed-user-1",
                client_id="fed-test-client",
                redirect_uri="https://app.example.com/cb",
                scope="openid profile email",
            )
            return session["session_token"]

        session_token = asyncio.run(_run())

        mock_storage = MagicMock()
        mock_storage.get_client = AsyncMock(return_value=client)

        with patch.object(OAuth2ClientStorage, "get_client", return_value=client):
            _fed_app.cookies.set(
                "__Host-authglow-consent-session",
                session_token,
            )
            response = _fed_app.post("/api/oauth2/federated-consent")

        assert response.status_code == 200
        data = response.json()
        assert data["consent_required"] is True
        assert data["client_name"] == "Federated Test App"
        assert "session_token" in data
        assert len(data["scopes"]) >= 1

    def test_login_url_works_without_oauth2_params(self, _fed_app, test_settings):
        from authglow.models.federation import ExternalIdpConfig

        provider = ExternalIdpConfig(
            id="google",
            label="Google",
            issuer="https://accounts.google.com",
            client_id="test-google-client-id",
            client_secret="test-google-client-secret",
            scopes=["openid", "profile", "email"],
            enabled=True,
        )

        with patch(
            "authglow.api.federation.FederationStorage.get_provider",
            return_value=provider,
        ):
            response = _fed_app.get(
                "/api/federation/login/google",
                params={"redirect_uri": "https://app.example.com/cb"},
                follow_redirects=False,
            )

        assert response.status_code == 302
        location = response.headers["location"]
        assert "accounts.google.com" in location


class TestFederationStateOAuth2Context:
    def test_state_token_with_oauth2_context_roundtrip(self, test_settings):
        state_token = FederationStateToken()

        oauth2_ctx = {
            "client_id": "my-client",
            "oauth_redirect_uri": "https://app.example.com/cb",
            "scope": "openid email",
            "app_state": "xyz",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
            "response_type": "code",
            "oidc_nonce": "n123",
        }

        signed = state_token.sign(
            "google",
            "https://idp.example.com/cb",
            oauth2_context=oauth2_ctx,
        )

        claims = state_token.verify(signed["state"])
        ctx = FederationStateToken.get_oauth2_context(claims)
        assert ctx is not None
        assert ctx["client_id"] == "my-client"
        assert ctx["oauth_redirect_uri"] == "https://app.example.com/cb"
        assert ctx["scope"] == "openid email"
        assert ctx["app_state"] == "xyz"

    def test_state_token_without_oauth2_context_returns_none(self, test_settings):
        state_token = FederationStateToken()

        signed = state_token.sign("google", "https://idp.example.com/cb")
        claims = state_token.verify(signed["state"])
        assert FederationStateToken.get_oauth2_context(claims) is None

    def test_state_token_direct_login_no_regression(self, test_settings):
        state_token = FederationStateToken()

        signed = state_token.sign(
            provider_id="google",
            redirect_uri="https://idp.example.com/cb",
        )

        claims = state_token.verify(signed["state"])
        assert claims["provider_id"] == "google"
        assert claims["redirect_uri"] == "https://idp.example.com/cb"
        assert claims["nonce"] == signed["nonce"]
