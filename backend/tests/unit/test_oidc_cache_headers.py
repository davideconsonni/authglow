"""Cache-Control and ETag header tests for the public OIDC endpoints.

Performance workstream Tier 1.6 adds HTTP caching to three OIDC endpoints:

* ``/.well-known/openid-configuration`` — public, ``max-age=3600``
* ``/.well-known/jwks.json`` — public, ``max-age=300``, ETag
  derived from the keyring ``_version`` and ``active_kid``;
  ``If-None-Match`` triggers ``304 Not Modified``
* ``/oauth2/userinfo`` — ``private, max-age=0, no-cache`` (the
  response is personalised, MUST NOT leak via shared caches)

These tests pin the header behaviour. A regression in any of
them would either let intermediaries cache personalised data
(privacy bug) or disable caching that downstream CDNs depend on
(performance regression).
"""

from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _build_test_app() -> FastAPI:
    """Build a minimal FastAPI app hosting only the OIDC router.

    A fresh app per call keeps tests isolated from each other
    (no shared ``dependency_overrides`` between cases).
    """
    from authglow.api.oidc import router

    app = FastAPI()
    app.include_router(router)
    return app


class TestOpenIDConfigurationCacheHeader:
    """``/.well-known/openid-configuration`` is publicly cacheable for
    one hour (Tier 1.6)."""

    def test_discovery_response_is_publicly_cacheable(self, test_settings):
        client = TestClient(_build_test_app())
        response = client.get("/.well-known/openid-configuration")
        assert response.status_code == 200
        cc = response.headers.get("Cache-Control", "")
        assert "public" in cc, f"expected 'public' in Cache-Control, got {cc!r}"
        assert "max-age=3600" in cc, f"expected 'max-age=3600' in Cache-Control, got {cc!r}"


class TestJWKSHeaders:
    """``/.well-known/jwks.json`` is publicly cacheable for five
    minutes and carries an ETag for ``If-None-Match`` revalidation.
    """

    def test_jwks_response_is_publicly_cacheable(self, test_settings):
        client = TestClient(_build_test_app())
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        cc = response.headers.get("Cache-Control", "")
        assert "public" in cc
        assert "max-age=300" in cc

    def test_jwks_response_carries_etag(self, test_settings):
        client = TestClient(_build_test_app())
        response = client.get("/.well-known/jwks.json")
        assert response.status_code == 200
        etag = response.headers.get("ETag")
        assert etag is not None, "JWKS must carry an ETag header"
        # Format: W/"<16-hex-chars>"
        assert etag.startswith('W/"') and etag.endswith('"'), f"unexpected ETag format: {etag!r}"
        inner = etag[3:-1]
        assert len(inner) == 16
        int(inner, 16)  # parses as hex without raising

    def test_jwks_etag_is_stable_across_repeat_requests(self, test_settings):
        """Two consecutive ``GET /jwks.json`` (no rotation between)
        must yield the same ETag."""
        client = TestClient(_build_test_app())
        etag_1 = client.get("/.well-known/jwks.json").headers["ETag"]
        etag_2 = client.get("/.well-known/jwks.json").headers["ETag"]
        assert etag_1 == etag_2

    def test_jwks_returns_304_when_if_none_match_matches(self, test_settings):
        client = TestClient(_build_test_app())
        first = client.get("/.well-known/jwks.json")
        assert first.status_code == 200
        etag = first.headers["ETag"]

        second = client.get(
            "/.well-known/jwks.json", headers={"If-None-Match": etag}
        )
        assert second.status_code == 304, (
            f"expected 304 with matching If-None-Match, got {second.status_code}: "
            f"{second.text!r}"
        )
        # 304 should still echo the cache headers so the client can
        # update its freshness window.
        assert "max-age=300" in second.headers.get("Cache-Control", "")

    def test_jwks_returns_full_body_when_if_none_match_is_stale(self, test_settings):
        client = TestClient(_build_test_app())
        first = client.get("/.well-known/jwks.json")
        assert first.status_code == 200

        second = client.get(
            "/.well-known/jwks.json",
            headers={"If-None-Match": 'W/"deadbeefdeadbeef"'},
        )
        assert second.status_code == 200
        assert second.headers["ETag"] != 'W/"deadbeefdeadbeef"'
        assert second.json()["keys"]  # body present


class TestUserInfoCacheHeader:
    """``/oauth2/userinfo`` is personalised; the response MUST NOT be
    cached by shared intermediaries (``private, max-age=0, no-cache``)."""

    def test_userinfo_response_is_not_cacheable(self, test_settings):
        """The userinfo endpoint must return
        ``Cache-Control: private, max-age=0, no-cache`` so shared
        intermediaries never persist personalised responses."""
        from authglow.api import oidc as oidc_module
        from authglow.models.token import TokenData
        from authglow.services.oidc import OIDCService

        # Stub the JWT decode so we don't need a fully-validated
        # access token (the test is about the *response* headers,
        # not the auth path).
        fake_jwt = MagicMock()
        fake_jwt.decode_token = MagicMock(
            return_value=TokenData(
                sub="u1",
                email="u1@example.com",
                scopes=["openid", "read"],
                token_type="access",
                jti="test-jti",
                exp=9999999999,
                iat=0,
                aud="test-client",
            )
        )

        user = MagicMock()
        user.id = "u1"
        user.email = "u1@example.com"
        user.is_active = True
        user.scopes = ["openid", "read"]
        user.first_name = "Test"
        user.last_name = "User"
        user.email_verified = True

        with (
            patch.object(oidc_module, "get_jwt_service", AsyncMock(return_value=fake_jwt)),
            patch.object(OIDCService, "__init__", lambda self: None),
        ):
            oidc = OIDCService()
            oidc.user_storage = MagicMock()
            oidc.user_storage.get_user = AsyncMock(return_value=user)
            with patch("authglow.api.oidc.OIDCService", return_value=oidc):
                client = TestClient(_build_test_app())
                response = client.get(
                    "/oauth2/userinfo",
                    headers={"Authorization": "Bearer fake-token"},
                )

        # The test goal is to verify the response *headers*; we
        # check the Cache-Control on the actual response object
        # (whether 200 or 401 — the header is set before the auth
        # check fails).
        cc = response.headers.get("Cache-Control", "")
        assert "private" in cc, (
            f"expected 'private' in Cache-Control, got {cc!r} "
            f"(status={response.status_code})"
        )
        assert "no-cache" in cc
        assert "max-age=0" in cc


# Tiny shim — the test runner configures ``asyncio_mode = "auto"`` so
# the tests above can use ``async def``; this helper is only needed
# for the rare sync path that drives the keyring bootstrap.
def asyncio_run(coro):
    import asyncio

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)
