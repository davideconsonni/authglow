"""Integration tests for the Dynamic Client Registration endpoint (RFC 7591)."""

import asyncio
import importlib.util
import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from authglow.services.password import hash_password


def _load_authglow_app(test_settings):
    """Load backend/main.py as the 'authglow.main' module so that
    `from authglow.main import app` works inside the endpoint code.
    """
    backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main_path = os.path.join(backend_dir, "main.py")

    spec = importlib.util.spec_from_file_location("authglow.main", main_path)
    mod = importlib.util.module_from_spec(spec)
    with (
        patch("authglow.core.config.get_settings", return_value=test_settings),
        patch("authglow.core.config.Settings", return_value=test_settings),
    ):
        spec.loader.exec_module(mod)
    return mod.app


@pytest.fixture
def test_app(test_settings):
    return _load_authglow_app(test_settings)


@pytest.fixture
def client(test_app):
    return TestClient(test_app)


def _run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


class TestClientRegistrationEndpoint:
    """POST /oauth2/register per RFC 7591."""

    def test_endpoint_exists_in_oidc_router(self):
        from authglow.api.oidc import router

        paths = {r.path for r in router.routes if hasattr(r, "path")}
        assert "/oauth2/register" in paths

    def test_endpoint_is_post(self):
        from authglow.api.oidc import router

        for r in router.routes:
            if hasattr(r, "path") and r.path == "/oauth2/register":
                assert "POST" in r.methods
                break

    def test_successful_registration_with_https(self, client, test_settings):
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage") as mock_storage_cls,
            patch("authglow.api.oidc.AuditService") as mock_audit_cls,
        ):
            mock_storage = MagicMock()
            mock_storage.generate_client_secret.return_value = "test-secret-xyz"
            mock_storage.create_client = AsyncMock()
            mock_storage_cls.return_value = mock_storage

            mock_audit = MagicMock()
            mock_audit.log_event = AsyncMock()
            mock_audit_cls.return_value = mock_audit

            resp = client.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://app.example.com/cb"],
                    "client_name": "My App",
                },
            )

            assert resp.status_code == 201, resp.text
            data = resp.json()
            assert data["client_id"]
            assert data["client_secret"] == "test-secret-xyz"
            assert data["client_name"] == "My App"
            assert data["redirect_uris"] == ["https://app.example.com/cb"]
            assert data["token_endpoint_auth_method"] == "client_secret_basic"
            assert data["scope"] == "read"
            assert "client_id_issued_at" in data
            assert data["client_secret_expires_at"] == 0

    def test_successful_registration_with_localhost_http(self, client):
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage") as mock_storage_cls,
            patch("authglow.api.oidc.AuditService") as mock_audit_cls,
        ):
            mock_storage = MagicMock()
            mock_storage.generate_client_secret.return_value = "s"
            mock_storage.create_client = AsyncMock()
            mock_storage_cls.return_value = mock_storage

            mock_audit = MagicMock()
            mock_audit.log_event = AsyncMock()
            mock_audit_cls.return_value = mock_audit

            resp = client.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["http://localhost:3000/cb"],
                    "client_name": "Dev App",
                },
            )
            assert resp.status_code == 201, resp.text

    def test_rejects_non_https_non_localhost_http(self, client):
        resp = client.post(
            "/oauth2/register",
            json={
                "redirect_uris": ["http://app.example.com/cb"],
            },
        )
        assert resp.status_code == 400
        assert "https" in resp.json()["detail"].lower()

    def test_rejects_javascript_scheme(self, client):
        resp = client.post(
            "/oauth2/register",
            json={
                "redirect_uris": ["javascript:alert(1)"],
            },
        )
        assert resp.status_code == 400

    def test_rejects_missing_redirect_uris(self, client):
        resp = client.post(
            "/oauth2/register",
            json={"client_name": "Bad App"},
        )
        assert resp.status_code == 422

    def test_rejects_empty_redirect_uris(self, client):
        resp = client.post(
            "/oauth2/register",
            json={"redirect_uris": []},
        )
        assert resp.status_code == 422

    def test_rejects_invalid_grant_type(self, client):
        resp = client.post(
            "/oauth2/register",
            json={
                "redirect_uris": ["https://app.example.com/cb"],
                "grant_types": ["password"],
            },
        )
        assert resp.status_code == 400
        assert "grant_type" in resp.json()["detail"].lower()

    def test_public_client_sets_require_pkce(self, client):
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage") as mock_storage_cls,
            patch("authglow.api.oidc.AuditService") as mock_audit_cls,
        ):
            mock_storage = MagicMock()
            mock_storage.generate_client_secret.return_value = "s"
            captured = {}

            async def _capture(client_obj, plaintext):
                captured["is_confidential"] = client_obj.is_confidential
                captured["require_pkce"] = client_obj.require_pkce
                return client_obj

            mock_storage.create_client = AsyncMock(side_effect=_capture)
            mock_storage_cls.return_value = mock_storage

            mock_audit = MagicMock()
            mock_audit.log_event = AsyncMock()
            mock_audit_cls.return_value = mock_audit

            resp = client.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://app.example.com/cb"],
                    "token_endpoint_auth_method": "none",
                },
            )
            assert resp.status_code == 201, resp.text
            assert captured["is_confidential"] is False
            assert captured["require_pkce"] is True

    def test_scope_parsed_from_space_separated_string(self, client):
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage") as mock_storage_cls,
            patch("authglow.api.oidc.AuditService") as mock_audit_cls,
        ):
            mock_storage = MagicMock()
            mock_storage.generate_client_secret.return_value = "s"
            mock_storage.create_client = AsyncMock()
            mock_storage_cls.return_value = mock_storage

            mock_audit = MagicMock()
            mock_audit.log_event = AsyncMock()
            mock_audit_cls.return_value = mock_audit

            resp = client.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://app.example.com/cb"],
                    "scope": "openid profile email",
                },
            )
            assert resp.status_code == 201, resp.text
            assert resp.json()["scope"] == "openid profile email"

    def test_default_grant_types_when_not_provided(self, client):
        with (
            patch("authglow.api.oidc.OAuth2ClientStorage") as mock_storage_cls,
            patch("authglow.api.oidc.AuditService") as mock_audit_cls,
        ):
            mock_storage = MagicMock()
            mock_storage.generate_client_secret.return_value = "s"
            mock_storage.create_client = AsyncMock()
            mock_storage_cls.return_value = mock_storage

            mock_audit = MagicMock()
            mock_audit.log_event = AsyncMock()
            mock_audit_cls.return_value = mock_audit

            resp = client.post(
                "/oauth2/register",
                json={"redirect_uris": ["https://app.example.com/cb"]},
            )
            assert resp.status_code == 201
            assert set(resp.json()["grant_types"]) == {
                "authorization_code",
                "refresh_token",
            }

    def test_openid_discovery_advertises_register_endpoint(self, client, test_settings):
        resp = client.get("/.well-known/openid-configuration")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert data["registration_endpoint"].endswith("/oauth2/register")
