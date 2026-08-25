"""Integration tests for CONFORMANCE T.1: ROPC (Resource Owner Password
Credentials) must be rejected on the standard OAuth2 token endpoint.

ROPC (RFC 6749 §4.3) is deprecated in OAuth 2.0 Security BCP and removed in
OAuth 2.1. OIDC Core 1.0 does not support it. AuthGlow must reject
``grant_type=password`` on ``/oauth2/token`` with HTTP 400.
"""

import importlib.util
import os
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


def _load_authglow_app(test_settings):
    """Load backend/main.py as the 'authglow.main' module so that
    ``from authglow.main import app`` works inside the endpoint code.
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


class TestROPCRejection:
    """Verify that ``/oauth2/token`` does not implement ROPC."""

    def test_password_grant_rejected(self, client):
        """CONFORMANCE T.1: ``grant_type=password`` on /oauth2/token must 400.

        Even with valid-looking credentials, the standard OAuth2 token
        endpoint must not accept ROPC. The error message must be
        ``Unsupported grant_type``.
        """
        resp = client.post(
            "/oauth2/token",
            data={
                "grant_type": "password",
                "username": "user@example.com",
                "password": "any-password-here",
            },
        )
        assert resp.status_code == 400, (
            f"ROPC must be rejected with 400, got {resp.status_code}: {resp.text}"
        )
        assert resp.json()["error"] == "unsupported_grant_type"

    def test_unknown_grant_type_rejected(self, client):
        """Sanity check: a totally unknown grant_type is also rejected.

        This guarantees the rejection logic in the ``else`` branch of
        ``token_endpoint`` (api/auth.py) covers all non-allowlisted grants,
        not just ROPC.
        """
        resp = client.post(
            "/oauth2/token",
            data={"grant_type": "totally-not-a-real-grant"},
        )
        assert resp.status_code == 400
        assert resp.json()["error"] == "unsupported_grant_type"

    def test_password_grant_no_token_leaked(self, client):
        """CONFORMANCE T.1: an ROPC attempt must NOT return a token.

        Regression guard: if someone in the future re-enables ROPC by
        accident, this test fails before the attacker receives an access
        token.
        """
        resp = client.post(
            "/oauth2/token",
            data={
                "grant_type": "password",
                "username": "user@example.com",
                "password": "any-password",
            },
        )
        body = resp.json()
        assert "access_token" not in body, f"ROPC must not issue an access_token, got body: {body}"
        assert "token_type" not in body
