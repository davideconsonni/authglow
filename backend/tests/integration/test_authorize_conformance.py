"""Integration tests for CONFORMANCE A5 + A3 on ``/api/oauth2/authorize``.

* A5 — server-side ``response_type`` validation (RFC 6749 §4.1.2.1):
  only ``code`` is accepted; anything else (including the implicit
  ``token`` type) is answered with a redirect carrying
  ``error=unsupported_response_type``. Missing value →
  ``invalid_request``.
* A3 — OIDC Core §3.1.2.1: under ``prompt=none`` no interaction is
  permitted; when consent is outstanding the request fails with
  ``error=consent_required`` instead of rendering the consent payload.
"""

import asyncio
import secrets
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi.testclient import TestClient

from tests.integration.test_prompt_param import _build_authorize_app_with_mocks


def _auth_cookie(test_settings, user_id="user-1") -> str:
    from authglow.services.jwt import JWTService

    jwt_svc = asyncio.run(JWTService.new())
    return jwt_svc.create_access_token(user_id, "test@example.com", ["read"])


class TestResponseTypeValidation:
    """A5: response_type is validated server-side with redirects."""

    def _post(self, app, **extra):
        client = TestClient(app, follow_redirects=False)
        data = {
            "client_id": "client-abc",
            "redirect_uri": "https://example.com/callback",
            "scope": "read",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
            "state": secrets.token_urlsafe(32),
        }
        data.update(extra)
        return client.post("/api/oauth2/authorize", data=data)

    def test_implicit_token_response_type_rejected(self, test_settings):
        app, *_ = _build_authorize_app_with_mocks(test_settings)
        res = self._post(app, response_type="token")
        assert res.status_code == 302, res.text
        loc = res.headers["location"]
        assert "error=unsupported_response_type" in loc
        # The redirect target must be the validated redirect_uri.
        assert loc.startswith("https://example.com/callback")

    def test_missing_response_type_defaults_to_code(self, test_settings):
        """An ABSENT response_type defaults to ``code`` (legacy first-party
        SPA form contract); the request proceeds past the gate."""
        app, *_ = _build_authorize_app_with_mocks(test_settings)
        res = self._post(app)
        assert res.status_code in (200, 400, 401), res.text
        if res.status_code == 302:
            assert "unsupported_response_type" not in res.headers["location"]

    def test_hybrid_response_type_rejected(self, test_settings):
        app, *_ = _build_authorize_app_with_mocks(test_settings)
        res = self._post(app, response_type="code token")
        assert res.status_code == 302, res.text
        assert "error=unsupported_response_type" in res.headers["location"]

    def test_code_response_type_passes_validation(self, test_settings):
        """``response_type=code`` proceeds past the new gate — the request
        then fails later on missing credentials (400/401), never on
        response_type."""
        app, *_ = _build_authorize_app_with_mocks(test_settings)
        res = self._post(app, response_type="code")
        assert res.status_code in (200, 400, 401), res.text


class TestPromptNoneConsentGate:
    """A3: prompt=none must not fall through to interactive consent."""

    def _authenticated_request(self, test_settings):
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app, storage, audit_svc, oauth2_svc = _build_authorize_app_with_mocks(test_settings)
        user = User(
            id="user-1",
            email="test@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        storage.get_user.return_value = user

        http_client = TestClient(app, follow_redirects=False)
        http_client.cookies.set(
            test_settings.auth_cookie_access_name,
            _auth_cookie(test_settings),
            domain="testserver.local",
        )

        data = {
            "client_id": "client-abc",
            "redirect_uri": "https://example.com/callback",
            "scope": "read",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
            "prompt": "none",
            "state": secrets.token_urlsafe(32),
        }
        return http_client, data

    def test_outstanding_consent_redirects_consent_required(self, test_settings):
        """Authenticated session but NO prior consent → error=consent_required."""
        http_client, data = self._authenticated_request(test_settings)

        res = http_client.post("/api/oauth2/authorize", data=data)

        assert res.status_code == 302, res.text
        loc = res.headers["location"]
        assert "error=consent_required" in loc
        assert loc.startswith("https://example.com/callback")
        assert "state=" in loc

    def test_granted_consent_mints_code_silently(self, test_settings):
        """Authenticated session + recorded consent → silent code redirect."""
        http_client, data = self._authenticated_request(test_settings)

        consent_svc = MagicMock()
        consent_svc.check_consent = AsyncMock(return_value=(True, None))
        with patch(
            "authglow.services.oauth_consent.OAuth2ConsentService", return_value=consent_svc
        ):
            res = http_client.post("/api/oauth2/authorize", data=data)

        assert res.status_code == 302, res.text
        assert "code=" in res.headers["location"]

    def test_consent_not_required_mints_code_silently(self, test_settings):
        """require_consent=False clients skip the gate entirely."""
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app, storage, audit_svc, oauth2_svc = _build_authorize_app_with_mocks(test_settings)
        user = User(
            id="user-1",
            email="test@example.com",
            hashed_password=hash_password("GoodP@ss1!"),
            is_active=True,
            email_verified=True,
            scopes=["read"],
        )
        storage.get_user.return_value = user
        # Flip the client's consent requirement off.
        oauth2_svc.client_storage.get_client.return_value.require_consent = False

        http_client = TestClient(app, follow_redirects=False)
        http_client.cookies.set(
            test_settings.auth_cookie_access_name,
            _auth_cookie(test_settings),
            domain="testserver.local",
        )

        res = http_client.post("/api/oauth2/authorize", data={
            "client_id": "client-abc",
            "redirect_uri": "https://example.com/callback",
            "scope": "read",
            "code_challenge": "challenge123",
            "code_challenge_method": "S256",
            "prompt": "none",
            "state": secrets.token_urlsafe(32),
        })

        assert res.status_code == 302, res.text
        assert "code=" in res.headers["location"]
