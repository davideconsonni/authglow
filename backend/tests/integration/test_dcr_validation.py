"""DCR validation hardening tests — Workstream P.

Validates that:
- ``token_endpoint_auth_method=none`` is rejected with ``client_credentials``
- Metadata URIs must be HTTPS (or http localhost)
- ``software_statement`` is rejected (no trust anchor, OA-205)
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


class TestOA503DcrDpop:
    """OA-503: DPoP opt-in via DCR (parity with the admin UI toggle)."""

    def _register(self, payload) -> tuple:
        from authglow.api import oidc as oidc_mod

        storage = _mock_storage()
        app = _build_app()
        client_http = TestClient(app)
        with (
            patch.object(oidc_mod, "OAuth2ClientStorage", return_value=storage),
            patch.object(oidc_mod, "AuditService", return_value=_mock_audit()),
        ):
            response = client_http.post("/oauth2/register", json=payload)
        assert response.status_code == 201, response.text
        created = storage.create_client.call_args[0][0]
        return response, created

    def test_dpop_bound_opt_in(self):
        """OA-503: DCR with dpop_bound=true creates a DPoP-bound client."""
        _response, created = self._register(
            {
                "redirect_uris": ["https://example.com/callback"],
                "dpop_bound": True,
            }
        )
        assert created.dpop_bound is True

    def test_dpop_bound_defaults_off(self):
        """OA-503: DCR without the field keeps the off default (no flip yet)."""
        _response, created = self._register({"redirect_uris": ["https://example.com/callback"]})
        assert created.dpop_bound is False

    def test_discovery_has_no_tls_client_auth(self):
        """OA-503: mTLS waived — discovery must not advertise tls_client_auth."""
        client_http = TestClient(_build_app())
        response = client_http.get("/.well-known/openid-configuration")
        assert response.status_code == 200, response.text
        assert "tls_client_auth" not in response.json()["token_endpoint_auth_methods_supported"]
