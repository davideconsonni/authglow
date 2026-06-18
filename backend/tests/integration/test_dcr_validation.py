"""DCR validation hardening tests — Workstream P.

Validates that:
- ``token_endpoint_auth_method=none`` is rejected with ``client_credentials``
- Metadata URIs must be HTTPS (or http localhost)
- ``software_statement`` must be a valid JWT
"""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_app():
    from authglow.api.oidc import router

    app = FastAPI()
    app.include_router(router)
    return app


def _mock_storage():
    storage = MagicMock()
    storage.generate_client_secret.return_value = "fake-secret"
    storage.create_client = AsyncMock()
    return storage


def _mock_audit():
    audit = MagicMock()
    audit.log_event = AsyncMock()
    return audit


class TestDcrValidation:
    """P.1, P.2, P.3: input validation on DCR requests."""

    def test_none_auth_with_client_credentials_is_rejected(self):
        app = _build_app()
        client_http = TestClient(app)

        from authglow.api import oidc as oidc_mod

        with (
            patch.object(oidc_mod, "OAuth2ClientStorage", return_value=_mock_storage()),
            patch.object(oidc_mod, "AuditService", return_value=_mock_audit()),
        ):
            response = client_http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/callback"],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["client_credentials"],
                },
            )

        assert response.status_code == 400, response.text
        detail = response.json()["detail"]
        assert "client_credentials" in detail.lower()

    def test_none_auth_with_authorization_code_is_allowed(self):
        """Public client with PKCE can use authorization_code."""
        app = _build_app()
        client_http = TestClient(app)

        from authglow.api import oidc as oidc_mod

        with (
            patch.object(oidc_mod, "OAuth2ClientStorage", return_value=_mock_storage()),
            patch.object(oidc_mod, "AuditService", return_value=_mock_audit()),
        ):
            response = client_http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/callback"],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code"],
                },
            )

        assert response.status_code == 201, response.text

    def test_http_client_uri_is_rejected(self):
        app = _build_app()
        client_http = TestClient(app)

        from authglow.api import oidc as oidc_mod

        with (
            patch.object(oidc_mod, "OAuth2ClientStorage", return_value=_mock_storage()),
            patch.object(oidc_mod, "AuditService", return_value=_mock_audit()),
        ):
            response = client_http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/callback"],
                    "client_uri": "http://evil.com",
                },
            )

        assert response.status_code == 400, response.text

    def test_localhost_client_uri_is_allowed(self):
        app = _build_app()
        client_http = TestClient(app)

        from authglow.api import oidc as oidc_mod

        with (
            patch.object(oidc_mod, "OAuth2ClientStorage", return_value=_mock_storage()),
            patch.object(oidc_mod, "AuditService", return_value=_mock_audit()),
        ):
            response = client_http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/callback"],
                    "client_uri": "http://localhost:3000",
                },
            )

        assert response.status_code == 201, response.text

    def test_invalid_software_statement_is_rejected(self):
        app = _build_app()
        client_http = TestClient(app)

        from authglow.api import oidc as oidc_mod

        with (
            patch.object(oidc_mod, "OAuth2ClientStorage", return_value=_mock_storage()),
            patch.object(oidc_mod, "AuditService", return_value=_mock_audit()),
        ):
            response = client_http.post(
                "/oauth2/register",
                json={
                    "redirect_uris": ["https://example.com/callback"],
                    "software_statement": "not-a-valid-jwt",
                },
            )

        assert response.status_code == 400, response.text
        assert "software_statement" in response.json()["detail"].lower()
