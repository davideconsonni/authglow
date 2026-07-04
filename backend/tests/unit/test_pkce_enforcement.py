"""PKCE enforcement conformance tests — Workstream B.

Validates that ``Settings.enforce_pkce=True`` (global gate) forces every
authorisation request and token exchange to include PKCE, regardless of
per-client ``require_pkce``.

See ``docs/plans/CONFORMANCE_REMEDIATION_PLAN.md`` for context
(OAuth 2.0 Security BCP §4.8.1, RFC 7636).
"""

import secrets
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.core.config import Settings

# ---------------------------------------------------------------------------
# Global Settings flag
# ---------------------------------------------------------------------------


class TestSettingsEnforcePkce:
    """B.1: ``Settings.enforce_pkce`` defaults to ``True``."""

    def test_enforce_pkce_defaults_true(self):
        settings = Settings(
            secret_key="test-secret-key-for-authglow-testing-32chars!",
            storage_path="/tmp/doesnotexist",
            oauth2_client_id="test-client",
            oauth2_client_secret="test-secret",
        )
        assert settings.enforce_pkce is True


# ---------------------------------------------------------------------------
# Model default
# ---------------------------------------------------------------------------


class TestOAuth2ClientRequirePkceDefault:
    """B.2: ``require_pkce`` defaults to ``True`` on new models."""

    def test_oauth2client_defaults_require_pkce_true(self):
        from authglow.models.oauth_client import OAuth2Client

        client = OAuth2Client(
            client_secret="fake",
            client_name="Default PKCE Client",
        )
        assert client.require_pkce is True

    def test_oauth2clientcreate_defaults_require_pkce_true(self):
        from authglow.models.oauth_client import OAuth2ClientCreate

        create = OAuth2ClientCreate(
            client_name="Default PKCE Client",
            redirect_uris=["https://example.com/callback"],
        )
        assert create.require_pkce is True


# ---------------------------------------------------------------------------
# authorize_post — global PKCE gate
# ---------------------------------------------------------------------------


def _build_authorize_app(
    storage_mock,
    oauth2_service_mock,
    mfa_service_mock,
    session_service_mock,
    audit_service_mock,
) -> FastAPI:
    from authglow.api.auth import (
        get_audit_service,
        get_mfa_service,
        get_oauth2_service,
        get_session_service,
        get_user_storage,
        router,
    )

    app = FastAPI()
    app.include_router(router)

    async def _storage():
        return storage_mock

    async def _oauth2():
        return oauth2_service_mock

    async def _mfa():
        return mfa_service_mock

    async def _session():
        return session_service_mock

    async def _audit():
        return audit_service_mock

    app.dependency_overrides[get_user_storage] = _storage
    app.dependency_overrides[get_oauth2_service] = _oauth2
    app.dependency_overrides[get_mfa_service] = _mfa
    app.dependency_overrides[get_session_service] = _session
    app.dependency_overrides[get_audit_service] = _audit

    return app


class TestAuthorizePostGlobalPkceGate:
    """B.3: No ``code_challenge`` → 400 when ``enforce_pkce=True``."""

    def _setup_mocks(self):
        storage = MagicMock()
        storage.get_user = AsyncMock()
        storage.get_user_by_email = AsyncMock(return_value=None)
        storage.is_account_locked = AsyncMock(return_value=False)
        storage.record_failed_login = AsyncMock()

        oauth2_client_storage = MagicMock()
        oauth2_client_storage.get_client = AsyncMock()
        oauth2_client_storage.verify_redirect_uri = AsyncMock(return_value=True)
        oauth2_client_storage.is_scope_allowed = AsyncMock(return_value=True)

        oauth2_svc = MagicMock()
        oauth2_svc.client_storage = oauth2_client_storage
        oauth2_svc.verify_redirect_uri = AsyncMock(return_value=True)
        oauth2_svc.process_scopes = AsyncMock(return_value=["read"])

        mfa_svc = MagicMock()
        mfa_svc.is_device_trusted = AsyncMock(return_value=True)

        session_svc = MagicMock()

        audit_svc = AsyncMock()
        audit_svc.log_event = AsyncMock()

        return storage, oauth2_svc, mfa_svc, session_svc, audit_svc

    def test_authorize_post_rejects_missing_code_challenge(self, test_settings):
        from authglow.models.oauth_client import OAuth2Client

        storage, oauth2_svc, mfa_svc, sess_svc, audit_svc = self._setup_mocks()
        client = OAuth2Client(
            client_id="client-abc",
            client_secret="fake-hash",
            client_name="Test PKCE Client",
            require_pkce=True,
        )
        oauth2_svc.client_storage.get_client.return_value = client

        app = _build_authorize_app(storage, oauth2_svc, mfa_svc, sess_svc, audit_svc)
        http_client = TestClient(app)

        response = http_client.post(
            "/api/oauth2/authorize",
            data={
                "client_id": "client-abc",
                "redirect_uri": "https://example.com/callback",
                "scope": "read",
                "email": "test@example.com",
                "password": "GoodP@ss1!",
            },
        )

        assert response.status_code == 400, response.text
        detail = response.json().get("detail", "")
        assert "PKCE" in detail or "code_challenge" in detail.lower()

    def test_authorize_post_accepts_with_code_challenge(self, test_settings):
        from authglow.models.oauth_client import OAuth2Client

        storage, oauth2_svc, mfa_svc, sess_svc, audit_svc = self._setup_mocks()
        client = OAuth2Client(
            client_id="client-abc",
            client_secret="fake-hash",
            client_name="Test PKCE Client",
            require_pkce=True,
        )
        oauth2_svc.client_storage.get_client.return_value = client

        app = _build_authorize_app(storage, oauth2_svc, mfa_svc, sess_svc, audit_svc)
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
                "password": "BadP@ss1!",
                "state": secrets.token_urlsafe(32),
            },
        )

        assert response.status_code == 401, response.text
        detail = response.json().get("detail", "")
        assert "invalid credentials" in detail.lower()


# ---------------------------------------------------------------------------
# DCR — require_pkce always True
# ---------------------------------------------------------------------------


class TestDcrRequiresPkce:
    """B.4: DCR sets ``require_pkce=True`` for every client."""

    def test_dcr_creates_client_with_require_pkce_true(self, test_settings):
        from authglow.api import oidc as oidc_module
        from authglow.api.oidc import router

        storage = MagicMock()
        storage.generate_client_secret.return_value = "fake-secret"
        storage.create_client = AsyncMock()
        audit = MagicMock()
        audit.log_event = AsyncMock()

        app = FastAPI()
        app.include_router(router)
        http_client = TestClient(app)

        with (
            patch.object(oidc_module, "OAuth2ClientStorage", return_value=storage),
            patch.object(oidc_module, "AuditService", return_value=audit),
        ):
            response = http_client.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/callback"],
                    "client_name": "PKCE DCR Client",
                    "grant_types": ["authorization_code"],
                    "token_endpoint_auth_method": "client_secret_basic",
                },
            )

        assert response.status_code == 201, response.text
        storage.create_client.assert_awaited_once()
        created_client = storage.create_client.call_args[0][0]
        assert created_client.require_pkce is True
