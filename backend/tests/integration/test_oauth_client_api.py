"""Integration tests for the OAuth2 client admin API.

Regression tests for the ``POST /api/oauth-clients`` happy
path on every ``token_endpoint_auth_method`` — the previous
regression (duplicate ``client_secret_jwt_key`` keyword) was
only caught by running the server manually. These tests
exercise the create endpoint via ``TestClient`` for every
auth method so the response assembly is always validated.
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from unittest.mock import patch

from authglow.api.oauth_client import require_admin, router
from authglow.models.user import User
from authglow.services.password import hash_password


def _admin() -> User:
    return User(
        id="admin-1",
        email="admin@test.com",
        hashed_password=hash_password("TestP@ss123!"),
        is_active=True,
        scopes=["admin"],
    )


@pytest.fixture
def admin_client(test_settings) -> TestClient:
    """``TestClient`` with ``require_admin`` bypassed."""
    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[require_admin] = _admin
    return TestClient(app)


class TestCreateOAuthClient:
    def test_create_client_secret_basic(self, admin_client, test_settings):
        resp = admin_client.post(
            "/api/oauth-clients",
            json={
                "client_name": "Basic Client",
                "redirect_uris": ["https://example.com/cb"],
                "allowed_scopes": ["read"],
                "grant_types": ["authorization_code"],
                "is_confidential": True,
                "token_endpoint_auth_method": "client_secret_basic",
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert "client_id" in body
        assert "client_secret" in body
        # No JWT key for this method
        assert body.get("client_secret_jwt_key") is None

    def test_create_client_secret_jwt(self, admin_client, test_settings):
        """Regression: ``OAuth2ClientWithSecret`` was being
        constructed with two values for
        ``client_secret_jwt_key`` (once from the model_dump,
        once from the explicit kwarg). The fix excludes
        ``client_secret_jwt_key`` from the dump and only
        passes the PLAINTEXT key to the response."""
        resp = admin_client.post(
            "/api/oauth-clients",
            json={
                "client_name": "JWT Secret Client",
                "redirect_uris": ["https://example.com/cb"],
                "allowed_scopes": ["read"],
                "grant_types": ["authorization_code"],
                "is_confidential": True,
                "token_endpoint_auth_method": "client_secret_jwt",
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert "client_id" in body
        assert "client_secret" in body
        # The plaintext JWT key is returned once
        assert body.get("client_secret_jwt_key")
        # The response must not contain the ENCRYPTED server-side
        # copy (it would leak the storage envelope).
        # (No direct way to assert this from the wire — the dump
        # excluded the field. We rely on the absence of
        # an "agcj1:" prefix in the value, which is the
        # encryption envelope.)
        jwt_key = body["client_secret_jwt_key"]
        assert not jwt_key.startswith("agcj1:")

    def test_create_private_key_jwt(self, admin_client, test_settings):
        resp = admin_client.post(
            "/api/oauth-clients",
            json={
                "client_name": "PKJ Client",
                "redirect_uris": ["https://example.com/cb"],
                "allowed_scopes": ["read"],
                "grant_types": ["authorization_code"],
                "is_confidential": True,
                "token_endpoint_auth_method": "private_key_jwt",
                "public_jwk": {
                    "kty": "RSA",
                    "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86z",
                    "e": "AQAB",
                },
            },
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        assert "client_id" in body
        # No JWT key for PKJ — the client owns its key
        assert body.get("client_secret_jwt_key") is None
        # The public_jwk round-trips in the response
        assert body["public_jwk"]["kty"] == "RSA"

    def test_create_none(self, admin_client, test_settings):
        """Public client, no secret — for SPA / mobile flows."""
        resp = admin_client.post(
            "/api/oauth-clients",
            json={
                "client_name": "Public SPA",
                "redirect_uris": ["https://app.example.com/cb"],
                "allowed_scopes": ["read"],
                "grant_types": ["authorization_code"],
                "is_confidential": False,
                "token_endpoint_auth_method": "none",
            },
        )
        assert resp.status_code == 201, resp.text
