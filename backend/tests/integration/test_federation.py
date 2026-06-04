"""Integration tests for the federation login/callback CSRF protection."""

from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.federation import router as federation_router


@pytest.fixture
def federation_app():
    app = FastAPI()
    app.include_router(federation_router)
    return TestClient(app)


def _sign_state(test_settings, provider_id="google", redirect_uri=None, **overrides):
    """Build a valid state JWT for callback tests."""
    import time

    redirect_uri = redirect_uri or f"{test_settings.base_url.rstrip('/')}/api/federation/callback"
    now = int(time.time())
    claims = {
        "iss": "authglow",
        "aud": "federation",
        "sub": provider_id,
        "provider_id": provider_id,
        "redirect_uri": redirect_uri,
        "nonce": overrides.get("nonce", "fixed-nonce-for-tests"),
        "jti": overrides.get("jti", "test-jti"),
        "iat": now,
        "exp": now + 600,
    }
    claims.update(overrides)
    return pyjwt.encode(claims, test_settings.secret_key, algorithm="HS256")


def _make_provider(provider_id="google", label="Google"):
    provider = MagicMock()
    provider.id = provider_id
    provider.label = label
    provider.enabled = True
    provider.issuer = "https://accounts.google.com"
    provider.client_id = "test-client"
    provider.client_secret = "test-secret"
    provider.scopes = ["openid", "email", "profile"]
    provider.claims_mapping = {"sub": "external_id", "email": "email", "name": "name"}
    return provider


class TestFederationLoginGeneratesState:
    def test_login_redirects_with_signed_state(self, test_settings, federation_app):
        provider = _make_provider()

        async def fake_get_auth_url(_provider, redirect_uri, state, nonce, acr_values=None):
            # The endpoint should hand us a signed JWT and a bound nonce.
            assert state and state.count(".") == 2, "state must be a signed JWT"
            from urllib.parse import urlencode

            qs = urlencode({"state": state, "nonce": nonce, "redirect_uri": redirect_uri})
            return f"https://idp.example.com/auth?{qs}", state, nonce

        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=provider)
            with patch("authglow.api.federation.FederationService") as MockService:
                service = MockService.return_value
                service.get_authorization_url = AsyncMock(side_effect=fake_get_auth_url)

                resp = federation_app.get(
                    "/api/federation/login/google",
                    follow_redirects=False,
                )

        assert resp.status_code == 302
        location = resp.headers["location"]
        from urllib.parse import parse_qs, urlparse

        qs = parse_qs(urlparse(location).query)
        state_value = qs["state"][0]
        assert state_value.count(".") == 2
        claims = pyjwt.decode(
            state_value,
            test_settings.secret_key,
            algorithms=["HS256"],
            audience="federation",
            issuer="authglow",
        )
        assert claims["provider_id"] == "google"
        assert claims["nonce"] == qs["nonce"][0]
        # The bound redirect_uri should point back to our callback endpoint
        assert "callback" in qs["redirect_uri"][0]


class TestFederationCallbackRejectsBadState:
    def test_callback_rejects_missing_state(self, test_settings, federation_app):
        resp = federation_app.get(
            "/api/federation/callback",
            params={"code": "abc", "state": "", "provider_id": "google"},
        )
        assert resp.status_code == 400
        assert "state" in resp.json()["detail"].lower()

    def test_callback_rejects_garbage_state(self, test_settings, federation_app):
        resp = federation_app.get(
            "/api/federation/callback",
            params={"code": "abc", "state": "not-a-jwt", "provider_id": "google"},
        )
        assert resp.status_code == 400

    def test_callback_rejects_state_signed_with_wrong_key(self, test_settings, federation_app):
        # Sign a state with a different secret
        import time

        now = int(time.time())
        claims = {
            "iss": "authglow",
            "aud": "federation",
            "sub": "google",
            "provider_id": "google",
            "redirect_uri": "https://app.example.com/cb",
            "nonce": "n",
            "jti": "x",
            "iat": now,
            "exp": now + 600,
        }
        forged = pyjwt.encode(claims, "different-secret-of-at-least-32-chars-!!", algorithm="HS256")
        resp = federation_app.get(
            "/api/federation/callback",
            params={"code": "abc", "state": forged, "provider_id": "google"},
        )
        assert resp.status_code == 400

    def test_callback_rejects_expired_state(self, test_settings, federation_app):
        import time

        from authglow.services.federation_state import EXPIRY_SECONDS

        now = int(time.time()) - (EXPIRY_SECONDS + 60)
        claims = {
            "iss": "authglow",
            "aud": "federation",
            "sub": "google",
            "provider_id": "google",
            "redirect_uri": f"{test_settings.base_url}/api/federation/callback",
            "nonce": "n",
            "jti": "x",
            "iat": now,
            "exp": now + EXPIRY_SECONDS,
        }
        token = pyjwt.encode(claims, test_settings.secret_key, algorithm="HS256")
        resp = federation_app.get(
            "/api/federation/callback",
            params={"code": "abc", "state": token, "provider_id": "google"},
        )
        assert resp.status_code == 400
        assert "expired" in resp.json()["detail"].lower()

    def test_callback_rejects_provider_mismatch(self, test_settings, federation_app):
        token = _sign_state(test_settings, provider_id="google")
        resp = federation_app.get(
            "/api/federation/callback",
            params={"code": "abc", "state": token, "provider_id": "facebook"},
        )
        assert resp.status_code == 400
        assert "provider" in resp.json()["detail"].lower()


class TestFederationCallbackIdTokenNonce:
    def test_callback_accepts_matching_nonce(self, test_settings, federation_app):
        from unittest.mock import AsyncMock

        token = _sign_state(test_settings, provider_id="google")
        provider = _make_provider()
        # Build an id_token whose nonce matches the state
        id_token_claims = {
            "iss": "https://accounts.google.com",
            "sub": "user-123",
            "aud": "test-client",
            "nonce": "fixed-nonce-for-tests",
        }
        id_token = pyjwt.encode(id_token_claims, "whatever", algorithm="HS256")

        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=provider)
            with patch("authglow.api.federation.FederationService") as MockService:
                service = MockService.return_value
                service.exchange_code = AsyncMock(
                    return_value={"access_token": "at-123", "id_token": id_token}
                )
                service.fetch_userinfo = AsyncMock(
                    return_value={"sub": "user-123", "email": "u@x.com", "name": "U"}
                )
                service.map_claims_to_user = AsyncMock(
                    return_value={"external_id": "user-123", "email": "u@x.com", "name": "U"}
                )
                with patch("authglow.api.federation.UserStorage") as MockUserStorage:
                    user = MagicMock()
                    user.id = "u-1"
                    user.email = "u@x.com"
                    user.name = "U"
                    user.suspended_until = None
                    MockUserStorage.return_value.get_by_external_id = AsyncMock(return_value=user)
                    with patch("authglow.api.federation.JWTService") as MockJWT:
                        MockJWT.return_value.create_user_tokens = AsyncMock(
                            return_value={"access_token": "issued-at", "refresh_token": "issued-rt"}
                        )
                        with patch("authglow.api.federation.AuditService") as MockAudit:
                            MockAudit.return_value.log_event = AsyncMock()
                            with patch("authglow.api.federation.LoginHistoryService") as MockLHS:
                                MockLHS.return_value.record_login = AsyncMock()
                                resp = federation_app.get(
                                    "/api/federation/callback",
                                    params={"code": "abc", "state": token, "provider_id": "google"},
                                )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["access_token"] == "issued-at"

    def test_callback_rejects_mismatched_nonce(self, test_settings, federation_app):
        from unittest.mock import AsyncMock

        token = _sign_state(test_settings, provider_id="google")  # nonce="fixed-nonce-for-tests"
        provider = _make_provider()
        id_token_claims = {
            "iss": "https://accounts.google.com",
            "sub": "user-123",
            "aud": "test-client",
            "nonce": "WRONG-NONCE",
        }
        id_token = pyjwt.encode(id_token_claims, "whatever", algorithm="HS256")

        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=provider)
            with patch("authglow.api.federation.FederationService") as MockService:
                service = MockService.return_value
                service.exchange_code = AsyncMock(
                    return_value={"access_token": "at-123", "id_token": id_token}
                )
                with patch("authglow.api.federation.AuditService") as MockAudit:
                    MockAudit.return_value.log_event = AsyncMock()
                    resp = federation_app.get(
                        "/api/federation/callback",
                        params={"code": "abc", "state": token, "provider_id": "google"},
                    )

        assert resp.status_code == 400
        assert "nonce" in resp.json()["detail"].lower()
