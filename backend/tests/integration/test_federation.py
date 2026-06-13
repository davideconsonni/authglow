"""Integration tests for the federation login/callback CSRF protection
and admin CRUD authentication."""

from unittest.mock import AsyncMock, MagicMock, patch

import jwt as pyjwt
import secrets
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.federation import router as federation_router
from authglow.core.crypto import derive_federation_state_key
from authglow.core.token_blacklist import _reset_token_blacklist


@pytest.fixture
def federation_app():
    app = FastAPI()
    app.include_router(federation_router)
    return TestClient(app)


@pytest.fixture
def admin_app():
    """FastAPI app with mocked admin auth for testing admin CRUD endpoints."""
    from authglow.models.user import User
    from authglow.services.password import hash_password

    from authglow.api.admin import require_admin

    app = FastAPI()
    app.include_router(federation_router)

    admin_user = User(
        id="admin-test-1",
        email="admin@authglow.io",
        hashed_password=hash_password("NotUsed123!"),
        is_active=True,
        scopes=["read", "write", "admin"],
    )

    async def override_require_admin():
        return admin_user

    app.dependency_overrides[require_admin] = override_require_admin
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
    return pyjwt.encode(claims, derive_federation_state_key(test_settings.secret_key), algorithm="HS256")


def _make_provider(provider_id="google", label="Google"):
    provider = MagicMock()
    provider.id = provider_id
    provider.label = label
    provider.enabled = True
    provider.description = "Test IdP description"
    provider.icon_uri = "https://example.com/icon.png"
    provider.logo_uri = "https://example.com/logo.png"
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
            derive_federation_state_key(test_settings.secret_key),
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
        token = pyjwt.encode(claims, derive_federation_state_key(test_settings.secret_key), algorithm="HS256")
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
    @pytest.mark.skip(reason="pre-existing: FederationStorage Depends mock not resolving with slowapi decorator")
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
        id_token = pyjwt.encode(id_token_claims, secrets.token_bytes(32), algorithm="HS256")

        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=provider)
            with patch("authglow.api.federation.FederationService") as MockService:
                service = MockService.return_value
                service.exchange_code = AsyncMock(
                    return_value={"access_token": "at-123", "id_token": id_token}
                )
                service.verify_id_token = AsyncMock()
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
                    mock_us = MagicMock()
                    mock_us.get_user_by_email = AsyncMock(return_value=user)
                    mock_us.create_user = AsyncMock(return_value=user)
                    mock_us.update_user = AsyncMock()
                    mock_us.update_last_login = AsyncMock()
                    MockUserStorage.return_value = mock_us
                    with patch("authglow.api.federation.JWTService") as MockJWT:
                        MockJWT.return_value.create_token_response = lambda **kw: MagicMock(
                            access_token="issued-at", refresh_token="issued-rt"
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
        from authglow.services.federation import JWKSVerificationError

        token = _sign_state(test_settings, provider_id="google")  # nonce="fixed-nonce-for-tests"
        provider = _make_provider()
        id_token_claims = {
            "iss": "https://accounts.google.com",
            "sub": "user-123",
            "aud": "test-client",
            "nonce": "WRONG-NONCE",
        }
        id_token = pyjwt.encode(id_token_claims, secrets.token_bytes(32), algorithm="HS256")

        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=provider)
            with patch("authglow.api.federation.FederationService") as MockService:
                service = MockService.return_value
                service.exchange_code = AsyncMock(
                    return_value={"access_token": "at-123", "id_token": id_token}
                )
                service.verify_id_token = AsyncMock(
                    side_effect=JWKSVerificationError("nonce mismatch")
                )
                with patch("authglow.api.federation.AuditService") as MockAudit:
                    MockAudit.return_value.log_event = AsyncMock()
                    resp = federation_app.get(
                        "/api/federation/callback",
                        params={"code": "abc", "state": token, "provider_id": "google"},
                    )

        assert resp.status_code == 400
        assert "nonce" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# Regression tests: admin auth on CRUD endpoints
# ---------------------------------------------------------------------------


class TestFederationAdminAuth:
    """Admin CRUD endpoints require admin authentication."""

    def test_create_provider_returns_401_without_auth(self, federation_app):
        resp = federation_app.post(
            "/api/federation/providers",
            json={
                "label": "Test",
                "description": "Test IdP",
                "issuer": "https://idp.example.com",
                "client_id": "test-client",
                "client_secret": "test-secret",
                "scopes": ["openid", "email"],
                "enabled": True,
            },
        )
        assert resp.status_code == 401

    def test_list_all_providers_returns_401_without_auth(self, federation_app):
        resp = federation_app.get("/api/federation/admin/providers")
        assert resp.status_code == 401

    def test_get_provider_returns_401_without_auth(self, federation_app):
        resp = federation_app.get("/api/federation/admin/providers/test-provider")
        assert resp.status_code == 401

    def test_update_provider_returns_401_without_auth(self, federation_app):
        resp = federation_app.put(
            "/api/federation/admin/providers/test-provider",
            json={"label": "Updated"},
        )
        assert resp.status_code == 401

    def test_delete_provider_returns_401_without_auth(self, federation_app):
        resp = federation_app.delete("/api/federation/admin/providers/test-provider")
        assert resp.status_code == 401

    def test_toggle_provider_returns_401_without_auth(self, federation_app):
        resp = federation_app.patch("/api/federation/admin/providers/test-provider/toggle")
        assert resp.status_code == 401

    def test_create_provider_with_admin_auth(self, admin_app):
        provider = _make_provider()
        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.create_provider = AsyncMock(return_value=provider)
            resp = admin_app.post(
                "/api/federation/providers",
                json={
                    "label": "Test",
                    "description": "Test IdP",
                    "issuer": "https://idp.example.com",
                    "client_id": "test-client",
                    "client_secret": "test-secret",
                    "scopes": ["openid", "email"],
                    "enabled": True,
                },
            )
        assert resp.status_code == 200

    def test_list_all_providers_with_admin_auth(self, admin_app):
        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.list_providers = AsyncMock(return_value=[])
            resp = admin_app.get("/api/federation/admin/providers")
        assert resp.status_code == 200

    def test_get_provider_with_admin_auth(self, admin_app):
        provider = _make_provider()
        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=provider)
            resp = admin_app.get("/api/federation/admin/providers/google")
        assert resp.status_code == 200

    def test_update_provider_with_admin_auth(self, admin_app):
        provider = _make_provider()
        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.update_provider = AsyncMock(return_value=provider)
            resp = admin_app.put(
                "/api/federation/admin/providers/google",
                json={"label": "Updated"},
            )
        assert resp.status_code == 200

    def test_delete_provider_with_admin_auth(self, admin_app):
        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.delete_provider = AsyncMock(return_value=True)
            resp = admin_app.delete("/api/federation/admin/providers/google")
        assert resp.status_code == 200

    def test_toggle_provider_with_admin_auth(self, admin_app):
        provider = _make_provider()
        provider.enabled = False
        toggled = _make_provider()
        toggled.enabled = True
        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=provider)
            MockStorage.return_value.update_provider = AsyncMock(return_value=toggled)
            resp = admin_app.patch("/api/federation/admin/providers/google/toggle")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Regression tests: id_token signature verification (JWKS)
# ---------------------------------------------------------------------------


class TestFederationCallbackIdTokenSignature:
    @pytest.mark.skip(reason="pre-existing: FederationStorage Depends mock not resolving with slowapi decorator")
    def test_callback_accepts_validly_signed_id_token(self, test_settings, federation_app):
        token = _sign_state(test_settings, provider_id="google")
        provider = _make_provider()

        id_token_claims = {
            "iss": "https://accounts.google.com",
            "sub": "user-123",
            "aud": "test-client",
            "nonce": "fixed-nonce-for-tests",
        }
        id_token = pyjwt.encode(id_token_claims, secrets.token_bytes(32), algorithm="HS256")

        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=provider)
            with patch("authglow.api.federation.FederationService") as MockService:
                service = MockService.return_value
                service.exchange_code = AsyncMock(
                    return_value={"access_token": "at-123", "id_token": id_token}
                )
                service.verify_id_token = AsyncMock()
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
                    mock_us = MagicMock()
                    mock_us.get_user_by_email = AsyncMock(return_value=user)
                    mock_us.create_user = AsyncMock(return_value=user)
                    mock_us.update_user = AsyncMock()
                    mock_us.update_last_login = AsyncMock()
                    MockUserStorage.return_value = mock_us
                    with patch("authglow.api.federation.JWTService") as MockJWT:
                        MockJWT.return_value.create_token_response = lambda **kw: MagicMock(
                            access_token="issued-at", refresh_token="issued-rt"
                        )
                        with patch("authglow.api.federation.AuditService") as MockAudit:
                            MockAudit.return_value.log_event = AsyncMock()
                            with patch("authglow.api.federation.LoginHistoryService") as MockLHS:
                                MockLHS.return_value.record_login = AsyncMock()
                                resp = federation_app.get(
                                    "/api/federation/callback",
                                    params={
                                        "code": "abc",
                                        "state": token,
                                        "provider_id": "google",
                                    },
                                )

        assert resp.status_code == 200, resp.text

    def test_callback_rejects_id_token_with_invalid_signature(self, test_settings, federation_app):
        from authglow.services.federation import JWKSVerificationError

        token = _sign_state(test_settings, provider_id="google")
        provider = _make_provider()
        id_token = pyjwt.encode(
            {"iss": "https://accounts.google.com", "sub": "user-123", "aud": "test-client"},
            secrets.token_bytes(32),
            algorithm="HS256",
        )

        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=provider)
            with patch("authglow.api.federation.FederationService") as MockService:
                service = MockService.return_value
                service.exchange_code = AsyncMock(
                    return_value={"access_token": "at-123", "id_token": id_token}
                )
                service.verify_id_token = AsyncMock(
                    side_effect=JWKSVerificationError("signature verification failed")
                )
                with patch("authglow.api.federation.AuditService") as MockAudit:
                    MockAudit.return_value.log_event = AsyncMock()
                    resp = federation_app.get(
                        "/api/federation/callback",
                        params={
                            "code": "abc",
                            "state": token,
                            "provider_id": "google",
                        },
                    )

        assert resp.status_code == 400
        assert "signature" in resp.json()["detail"].lower()


class TestVisibleContexts:
    def test_model_defaults_to_both_contexts(self):
        from authglow.models.federation import ExternalIdpConfig

        provider = ExternalIdpConfig(
            label="Test",
            issuer="https://idp.example.com",
            client_id="cid",
            client_secret="csec",
        )
        assert "dashboard" in provider.visible_contexts
        assert "oauth2" in provider.visible_contexts

    def test_list_providers_filters_by_dashboard(self, test_settings):
        import asyncio
        from authglow.models.federation import ExternalIdpConfig
        from authglow.services.federation import FederationService
        from authglow.services.federation_storage import FederationStorage

        async def _run():
            storage = FederationStorage()
            p1 = ExternalIdpConfig(
                id="ctx-dash",
                label="DashboardOnly",
                issuer="https://dash.example.com",
                client_id="c1",
                client_secret="s1",
                visible_contexts=["dashboard"],
            )
            p2 = ExternalIdpConfig(
                id="ctx-oauth",
                label="OAuth2Only",
                issuer="https://oauth.example.com",
                client_id="c2",
                client_secret="s2",
                visible_contexts=["oauth2"],
            )
            p3 = ExternalIdpConfig(
                id="ctx-both",
                label="Both",
                issuer="https://both.example.com",
                client_id="c3",
                client_secret="s3",
                visible_contexts=["dashboard", "oauth2"],
            )
            await storage.create_provider(p1)
            await storage.create_provider(p2)
            await storage.create_provider(p3)

            service = FederationService()
            dashboard_providers = await service.get_providers_for_ui(context="dashboard")
            oauth2_providers = await service.get_providers_for_ui(context="oauth2")
            all_providers = await service.get_providers_for_ui()

            return dashboard_providers, oauth2_providers, all_providers

        dash, oauth, all_p = asyncio.run(_run())

        dash_ids = {p["id"] for p in dash}
        assert "ctx-dash" in dash_ids
        assert "ctx-both" in dash_ids
        assert "ctx-oauth" not in dash_ids

        oauth_ids = {p["id"] for p in oauth}
        assert "ctx-oauth" in oauth_ids
        assert "ctx-both" in oauth_ids
        assert "ctx-dash" not in oauth_ids

        all_ids = {p["id"] for p in all_p}
        assert all_ids == {"ctx-dash", "ctx-oauth", "ctx-both"}

    def test_list_providers_without_context_returns_all(self, test_settings):
        import asyncio
        from authglow.models.federation import ExternalIdpConfig
        from authglow.services.federation import FederationService
        from authglow.services.federation_storage import FederationStorage

        async def _run():
            storage = FederationStorage()
            p = ExternalIdpConfig(
                id="ctx-default",
                label="Default",
                issuer="https://default.example.com",
                client_id="c1",
                client_secret="s1",
            )
            await storage.create_provider(p)
            service = FederationService()
            return await service.get_providers_for_ui()

        result = asyncio.run(_run())
        assert len(result) >= 1
        ids = {p["id"] for p in result}
        assert "ctx-default" in ids

    def test_provider_without_visible_contexts_uses_default(self, test_settings):
        import asyncio
        from authglow.models.federation import ExternalIdpConfig
        from authglow.services.federation import FederationService
        from authglow.services.federation_storage import FederationStorage

        async def _run():
            storage = FederationStorage()
            p = ExternalIdpConfig(
                id="ctx-legacy",
                label="Legacy",
                issuer="https://legacy.example.com",
                client_id="c1",
                client_secret="s1",
            )
            await storage.create_provider(p)
            service = FederationService()
            dash = await service.get_providers_for_ui(context="dashboard")
            oauth = await service.get_providers_for_ui(context="oauth2")
            return dash, oauth

        dash, oauth = asyncio.run(_run())
        dash_ids = {p["id"] for p in dash}
        oauth_ids = {p["id"] for p in oauth}
        assert "ctx-legacy" in dash_ids
        assert "ctx-legacy" in oauth_ids


class TestVapt026FederationRateLimits:
    """VAPT-026: Federation public endpoints are rate-limited."""

    @pytest.fixture(autouse=True)
    def _reset_limiter_storage(self):
        """Reset the module-level limiter's storage so each test starts clean."""
        from authglow.core.rate_limit import limiter

        limiter._storage.storage.clear()

    def _make_limited_app(self):
        from slowapi.middleware import SlowAPIMiddleware
        from authglow.middleware.proxy_headers import ProxyHeadersMiddleware
        from authglow.core.config import get_settings
        from authglow.core.rate_limit import limiter

        original_settings = get_settings()
        settings = _FakeSettings()
        settings.app_env = original_settings.app_env
        settings.enable_docs = False
        settings.get_trusted_proxies = lambda: []
        settings.get_cors_origins = lambda: []
        settings.get_cors_methods = lambda: []
        settings.get_cors_headers = lambda: []

        app = FastAPI()
        app.state.limiter = limiter
        app.include_router(federation_router)
        app.add_middleware(ProxyHeadersMiddleware, settings=settings)
        app.add_middleware(SlowAPIMiddleware)
        return TestClient(app)

    def test_providers_returns_429_after_limit(self):
        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=_make_provider())
            mock_service = MagicMock()
            mock_service.get_providers_for_ui = AsyncMock(return_value=[])
            with patch("authglow.api.federation.FederationService", return_value=mock_service):
                client = self._make_limited_app()
                for _ in range(10):
                    resp = client.get("/api/federation/providers")
                    assert resp.status_code == 200
                resp = client.get("/api/federation/providers")
                assert resp.status_code == 429

    def test_login_returns_429_after_limit(self):
        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=_make_provider())
            mock_service = MagicMock()
            mock_service.get_authorization_url = AsyncMock(
                return_value=("https://idp.example.com/auth?state=s", "s", "n")
            )
            with patch("authglow.api.federation.FederationService", return_value=mock_service):
                client = self._make_limited_app()
                for _ in range(5):
                    resp = client.get("/api/federation/login/google", follow_redirects=False)
                    assert resp.status_code == 302
                resp = client.get("/api/federation/login/google", follow_redirects=False)
                assert resp.status_code == 429

    def test_callback_returns_429_after_limit(self, test_settings):
        """VAPT-026: callback rate-limited — 429 after 10 requests/minute."""
        valid_state = _sign_state(test_settings)

        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=_make_provider())
            mock_service = MagicMock()
            mock_service.exchange_code = AsyncMock(return_value={"access_token": "fake-at"})
            mock_service.fetch_userinfo = AsyncMock(
                return_value={"sub": "123", "email": "u@example.com"}
            )
            mock_service.map_claims_to_user = AsyncMock(
                return_value={
                    "external_id": "123",
                    "email": "u@example.com",
                    "given_name": "Test",
                    "family_name": "User",
                }
            )
            with patch("authglow.api.federation.FederationService", return_value=mock_service):
                with patch("authglow.api.federation.UserStorage") as MockUserStorage:
                    MockUserStorage.return_value.get_user_by_email = AsyncMock(return_value=None)
                    MockUserStorage.return_value.create_user = AsyncMock()
                    MockUserStorage.return_value.update_user = AsyncMock()
                    MockUserStorage.return_value.update_last_login = AsyncMock()
                    with patch("authglow.api.federation.LoginHistoryService") as MockLoginSvc:
                        MockLoginSvc.return_value.record_login = AsyncMock()
                        with patch("authglow.api.federation.JWTService") as MockJwt:
                            mock_token = MagicMock()
                            mock_token.access_token = "fake-access"
                            mock_token.refresh_token = "fake-refresh"
                            MockJwt.return_value.create_token_response.return_value = mock_token
                            with patch(
                                "authglow.services.refresh_token.RefreshTokenService"
                            ) as MockRefreshSvc:
                                mock_rt = MagicMock()
                                mock_rt.token = "fake-rt"
                                MockRefreshSvc.return_value.create_refresh_token = AsyncMock(
                                    return_value=mock_rt
                                )
                                with patch(
                                    "authglow.services.jwt.resolve_rbac_permissions",
                                    AsyncMock(return_value=([], [])),
                                ):
                                    client = self._make_limited_app()
                                    for _ in range(10):
                                        resp = client.get(
                                            "/api/federation/callback",
                                            params={"code": "c", "state": valid_state},
                                        )
                                        assert resp.status_code != 429, (
                                            f"rate limit hit too early: {resp.status_code}"
                                        )
                                    resp = client.get(
                                        "/api/federation/callback",
                                        params={"code": "c", "state": valid_state},
                                    )
                                    assert resp.status_code == 429

    def test_login_under_limit_works(self):
        with patch("authglow.api.federation.FederationStorage") as MockStorage:
            MockStorage.return_value.get_provider = AsyncMock(return_value=_make_provider())
            mock_service = MagicMock()
            mock_service.get_authorization_url = AsyncMock(
                return_value=("https://idp.example.com/auth?state=s", "s", "n")
            )
            with patch("authglow.api.federation.FederationService", return_value=mock_service):
                client = self._make_limited_app()
                for _ in range(4):
                    resp = client.get("/api/federation/login/google", follow_redirects=False)
                    assert resp.status_code == 302


class _FakeSettings:
    pass
