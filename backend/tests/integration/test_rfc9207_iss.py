"""Integration tests for RFC 9207 (Authorization Server Issuer
Identification) on ``/api/oauth2/authorize``.

RFC 9207 §2: every authorization response — success (``code=...``)
and error (``error=...``) — MUST carry ``iss=<issuer>`` so a client
that talks to multiple authorization servers can attribute the
response and mitigate mix-up attacks. The discovery document
advertises the capability via
``authorization_response_iss_parameter_supported``.
"""

import asyncio
import secrets
from unittest.mock import AsyncMock, MagicMock, patch
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.api.auth import get_settings as auth_get_settings
from tests.integration.test_prompt_param import _build_authorize_app_with_mocks


def _auth_cookie() -> str:
    from authglow.services.jwt import JWTService

    jwt_svc = asyncio.run(JWTService.new())
    return jwt_svc.create_access_token("user-1", "test@example.com", ["read"])


def _query(url: str) -> dict:
    """Parse the query string of an authorization response redirect."""
    return parse_qs(urlsplit(url).query)


def _post_authorize(http_client, **extra):
    data = {
        "client_id": "client-abc",
        "redirect_uri": "https://example.com/callback",
        "scope": "read",
        "code_challenge": "challenge123",
        "code_challenge_method": "S256",
        "state": secrets.token_urlsafe(32),
    }
    data.update(extra)
    return http_client.post("/api/oauth2/authorize", data=data)


class TestIssOnAuthorizeResponses:
    """RFC 9207 §2: ``iss`` is present on every authorization response."""

    def test_error_redirect_carries_iss(self, test_settings):
        """Invalid response_type → error redirect carries ``iss``."""
        app, *_ = _build_authorize_app_with_mocks(test_settings)
        client = TestClient(app, follow_redirects=False)

        res = _post_authorize(client, response_type="token")

        assert res.status_code == 302, res.text
        query = _query(res.headers["location"])
        assert query["error"] == ["unsupported_response_type"]
        assert query["iss"] == [auth_get_settings().issuer]

    def test_login_required_error_carries_iss(self, test_settings):
        """prompt=none without a session → error=login_required + ``iss``."""
        app, *_ = _build_authorize_app_with_mocks(test_settings)
        client = TestClient(app, follow_redirects=False)

        res = _post_authorize(client, prompt="none")

        assert res.status_code == 302, res.text
        query = _query(res.headers["location"])
        assert query["error"] == ["login_required"]
        assert query["iss"] == [auth_get_settings().issuer]

    def _authenticated_client(self, test_settings):
        from authglow.models.user import User
        from authglow.services.password import hash_password

        app, storage, *_ = _build_authorize_app_with_mocks(test_settings)
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
            _auth_cookie(),
            domain="testserver.local",
        )
        return http_client

    def test_consent_required_error_carries_iss(self, test_settings):
        """prompt=none with outstanding consent → consent_required + ``iss``."""
        http_client = self._authenticated_client(test_settings)

        res = _post_authorize(http_client, prompt="none")

        assert res.status_code == 302, res.text
        query = _query(res.headers["location"])
        assert query["error"] == ["consent_required"]
        assert query["iss"] == [auth_get_settings().issuer]

    def test_silent_code_redirect_carries_iss(self, test_settings):
        """prompt=none with recorded consent → silent code redirect + ``iss``."""
        http_client = self._authenticated_client(test_settings)

        consent_svc = MagicMock()
        consent_svc.check_consent = AsyncMock(return_value=(True, None))
        with patch(
            "authglow.services.oauth_consent.OAuth2ConsentService", return_value=consent_svc
        ):
            res = _post_authorize(http_client, prompt="none")

        assert res.status_code == 302, res.text
        query = _query(res.headers["location"])
        assert "code" in query
        assert query["iss"] == [auth_get_settings().issuer]


class TestDiscoveryAdvertisesIssParameter:
    """RFC 9207 §3: the AS advertises support in its discovery metadata."""

    def test_authorization_response_iss_parameter_supported(self):
        from authglow.api.oidc import router

        app = FastAPI()
        app.include_router(router)
        client = TestClient(app)

        res = client.get("/.well-known/openid-configuration")

        assert res.status_code == 200, res.text
        body = res.json()
        assert body["authorization_response_iss_parameter_supported"] is True
