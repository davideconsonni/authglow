"""Integration tests for CONFORMANCE A1: the OAuth2 protocol endpoints
must answer errors with the RFC 6749 §5.2 top-level envelope::

    {"error": "...", "error_description": "..."}

instead of FastAPI's default ``{"detail": ...}`` wrapper. Covers
``/oauth2/token``, ``/oauth2/introspect`` and ``/oauth2/revoke``.
"""

import importlib.util
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


def _load_authglow_app(test_settings):
    """Load backend/main.py as the 'authglow.main' module."""
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
def client(test_settings):
    return TestClient(_load_authglow_app(test_settings))


class TestTokenEndpointErrorEnvelope:
    """RFC 6749 §5.2 wire shape on /oauth2/token."""

    def test_unsupported_grant_type(self, client):
        resp = client.post("/oauth2/token", data={"grant_type": "nope"})
        assert resp.status_code == 400
        body = resp.json()
        assert body["error"] == "unsupported_grant_type"
        assert "detail" not in body
        assert isinstance(body.get("error_description"), str)

    def test_authorization_code_missing_params_invalid_request(self, client):
        resp = client.post(
            "/oauth2/token",
            data={"grant_type": "authorization_code"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"

    def test_refresh_token_missing_grant_is_invalid_request(self, client):
        resp = client.post(
            "/oauth2/token",
            data={"grant_type": "refresh_token"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "invalid_request"


class TestIntrospectionErrorEnvelope:
    """RFC 7662 client-auth failures reuse the RFC 6749 §5.2 envelope."""

    def test_missing_credentials_invalid_client_401(self, client):
        resp = client.post("/oauth2/introspect", data={"token": "anything"})
        assert resp.status_code == 401
        body = resp.json()
        assert body["error"] == "invalid_client"
        assert "www-authenticate" in {k.lower() for k in resp.headers}

    def test_bad_credentials_invalid_client_401(self, client):
        resp = client.post(
            "/oauth2/introspect",
            data={
                "token": "anything",
                "client_id": "ghost-client",
                "client_secret": "wrong",
            },
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"


class TestRevocationErrorEnvelope:
    """RFC 7009 §2.1 client-auth failures reuse the RFC 6749 §5.2 envelope."""

    def test_missing_credentials_invalid_client_401(self, client):
        resp = client.post("/oauth2/revoke", data={"token": "anything"})
        assert resp.status_code == 401
        body = resp.json()
        assert body["error"] == "invalid_client"

    def test_bad_credentials_invalid_client_401(self, client):
        resp = client.post(
            "/oauth2/revoke",
            data={
                "token": "anything",
                "client_id": "ghost-client",
                "client_secret": "wrong",
            },
        )
        assert resp.status_code == 401
        assert resp.json()["error"] == "invalid_client"
