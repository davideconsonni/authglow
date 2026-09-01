"""OIDC RP-Initiated Logout redirect validation — Workstream D.

Validates that ``post_logout_redirect_uri`` is strictly checked against
the client's ``allowed_post_logout_redirect_uris`` (RP-Initiated Logout §4).
No dev-mode bypass, no open redirector.
"""

from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.models.oauth_client import OAuth2Client


def _make_client(
    client_id: str = "test-client-abc",
    allowed_post_logout_redirect_uris=None,
    is_active: bool = True,
) -> OAuth2Client:
    """Factory: a minimal OAuth2Client for logout tests."""
    return OAuth2Client(
        client_id=client_id,
        client_secret="fake-hash",
        client_name="Test Client",
        redirect_uris=["https://example.com/callback"],
        allowed_post_logout_redirect_uris=allowed_post_logout_redirect_uris
        or ["https://example.com/logout"],
        is_active=is_active,
    )


def _build_app(router) -> FastAPI:
    app = FastAPI()
    app.include_router(router)
    return app


# ---------------------------------------------------------------------------
# Strict post_logout_redirect_uri validation
# ---------------------------------------------------------------------------


class TestLogoutRedirectStrictValidation:
    """Production-only strict validation: no bypass, no dev-mode exceptions."""

    def _patch_services(
        self,
        *,
        id_token_valid: bool = True,
        client=None,
        frontchannel_uris=None,
    ):
        """Return an ``ExitStack`` that mocks JWT / OAuth2 / Audit services.

        ``logout_get`` imports ``OAuth2Service`` and ``AuditService``
        locally, so the patching target is each service's definition
        module (``services.{jwt,oauth2,audit}``).
        ``frontchannel_uris`` is the list returned by
        ``client_storage.list_clients`` (drives the front-channel
        logout HTML branch; default empty → plain 303 redirect).
        """
        from authglow.models.oidc import IDTokenClaims

        if id_token_valid:
            token = IDTokenClaims(
                iss="https://authglow.example.com",
                sub="user-1",
                aud="test-client-abc",
                exp=9999999999,
                iat=1,
            )
        else:
            token = None

        jwt_mock = MagicMock()
        jwt_mock.decode_id_token.return_value = token

        storage_mock = MagicMock()
        storage_mock.get_client = AsyncMock(return_value=client)
        storage_mock.list_clients = AsyncMock(return_value=frontchannel_uris or [])

        oauth2_service_mock = MagicMock()
        oauth2_service_mock.client_storage = storage_mock

        audit_mock = AsyncMock()
        audit_mock.log_event = AsyncMock()

        stack = ExitStack()
        # Patch the singleton ``get_jwt_service`` so the route handler
        # resolves to the pre-built ``jwt_mock`` instead of constructing
        # a real ``JWTService.new()`` against the keyring.
        stack.enter_context(
            patch(
                "authglow.api.oidc.get_jwt_service",
                new_callable=AsyncMock,
                return_value=jwt_mock,
            )
        )
        stack.enter_context(
            patch("authglow.services.oauth2.OAuth2Service", return_value=oauth2_service_mock)
        )
        stack.enter_context(patch("authglow.services.audit.AuditService", return_value=audit_mock))
        stack.enter_context(
            patch(
                "jwt.decode",
                return_value={
                    "aud": "test-client-abc",
                    "sub": "user-1",
                    "iss": "https://a.example",
                },
            )
        )
        return stack, storage_mock, audit_mock

    # --- Happy path -------------------------------------------------------

    def test_redirect_allowed_match_returns_303(self, test_settings):
        """Redirect URI in allowed_post_logout_redirect_uris → 303 redirect."""
        from authglow.api.oidc import router

        client = _make_client(allowed_post_logout_redirect_uris=["https://example.com/logout"])
        patches, _, _ = self._patch_services(client=client)

        app = _build_app(router)
        client_http = TestClient(app, follow_redirects=False)

        with patches:
            response = client_http.get(
                "/oauth2/logout",
                params={
                    "id_token_hint": "valid-hint",
                    "post_logout_redirect_uri": "https://example.com/logout",
                },
            )

        assert response.status_code == 303, response.text
        assert response.headers["location"] == "https://example.com/logout"

    def test_redirect_with_state_preserves_state(self, test_settings):
        """state is URL-encoded and appended to the redirect."""
        from authglow.api.oidc import router

        client = _make_client(allowed_post_logout_redirect_uris=["https://example.com/logout"])
        patches, _, _ = self._patch_services(client=client)

        app = _build_app(router)
        client_http = TestClient(app, follow_redirects=False)

        with patches:
            response = client_http.get(
                "/oauth2/logout",
                params={
                    "id_token_hint": "valid-hint",
                    "post_logout_redirect_uri": "https://example.com/logout",
                    "state": "abc/123",
                },
            )

        assert response.status_code == 303
        location = response.headers["location"]
        assert "https://example.com/logout?" in location
        assert "state=abc%2F123" in location or "state=abc/123" in location

    # --- Rejection paths --------------------------------------------------

    def test_redirect_not_in_allowed_list_returns_400(self, test_settings):
        """Redirect URI NOT in allowed_post_logout_redirect_uris → 400."""
        from authglow.api.oidc import router

        client = _make_client(allowed_post_logout_redirect_uris=["https://example.com/logout"])
        patches, _, _ = self._patch_services(client=client)

        app = _build_app(router)
        client_http = TestClient(app, follow_redirects=False)

        with patches:
            response = client_http.get(
                "/oauth2/logout",
                params={
                    "id_token_hint": "valid-hint",
                    "post_logout_redirect_uri": "https://evil.com/steal",
                },
            )

        assert response.status_code == 400, response.text
        detail = response.json().get("detail", "")
        assert "not allowed" in detail.lower()

    def test_missing_id_token_hint_returns_400(self, test_settings):
        """post_logout_redirect_uri without id_token_hint → 400."""
        from authglow.api.oidc import router

        app = _build_app(router)
        client_http = TestClient(app, follow_redirects=False)

        response = client_http.get(
            "/oauth2/logout",
            params={"post_logout_redirect_uri": "https://example.com/logout"},
        )

        assert response.status_code == 400, response.text
        detail = response.json().get("detail", "")
        assert "id_token_hint" in detail.lower()

    def test_client_not_found_returns_400(self, test_settings):
        """id_token_hint refers to a deleted/inactive client → 400."""
        from authglow.api.oidc import router

        patches, _, _ = self._patch_services(client=None)

        app = _build_app(router)
        client_http = TestClient(app, follow_redirects=False)

        with patches:
            response = client_http.get(
                "/oauth2/logout",
                params={
                    "id_token_hint": "valid-hint",
                    "post_logout_redirect_uri": "https://example.com/logout",
                },
            )

        assert response.status_code == 400, response.text
        detail = response.json().get("detail", "")
        assert "not found" in detail.lower() or "inactive" in detail.lower()

    def test_invalid_id_token_hint_returns_400(self, test_settings):
        """id_token_hint fails signature/audience validation → 400."""
        from authglow.api.oidc import router

        patches, _, _ = self._patch_services(id_token_valid=False)

        app = _build_app(router)
        client_http = TestClient(app, follow_redirects=False)

        with patches:
            response = client_http.get(
                "/oauth2/logout",
                params={
                    "id_token_hint": "tampered-token",
                    "post_logout_redirect_uri": "https://example.com/logout",
                },
            )

        assert response.status_code == 400, response.text
        detail = response.json().get("detail", "")
        assert "invalid" in detail.lower()


# ---------------------------------------------------------------------------
# Front-Channel Logout HTML — JS/HTML-safe interpolation (F6)
# ---------------------------------------------------------------------------


class TestFrontChannelLogoutHtmlEscaping:
    """F6 / defence in depth: the front-channel logout HTML must never
    interpolate the redirect URI or the registered front-channel URIs
    raw into their JS/HTML contexts. The redirect URI is serialized
    with ``json.dumps`` inside the script; the iframe attributes are
    HTML-escaped; the iframe query is URL-encoded."""

    def _logout_html(self, *, allowed_uri: str, frontchannel_uri: str, state=None) -> str:
        from authglow.api.oidc import router

        client = _make_client(allowed_post_logout_redirect_uris=[allowed_uri])
        client.frontchannel_logout_uri = frontchannel_uri

        patches, _, _ = TestLogoutRedirectStrictValidation()._patch_services(
            client=client,
            frontchannel_uris=[client],
        )

        app = _build_app(router)
        http = TestClient(app, follow_redirects=False)

        params = {
            "id_token_hint": "valid-hint",
            "post_logout_redirect_uri": allowed_uri,
        }
        if state:
            params["state"] = state
        with patches:
            response = http.get("/oauth2/logout", params=params)

        assert response.status_code == 200, response.text
        assert response.headers["content-type"].startswith("text/html")
        return response.text

    def test_redirect_uri_is_json_serialized_in_script(self, test_settings):
        """The script assigns the URI through ``json.dumps`` — exactly
        one pair of surrounding quotes; the old raw-replacement pattern
        (``location="..."``) is gone."""
        html = self._logout_html(
            allowed_uri="https://example.com/logout",
            frontchannel_uri="https://rp.example/frontchannel",
        )
        assert 'location = "https://example.com/logout";' in html
        assert 'location="' not in html

    def test_hostile_redirect_uri_cannot_break_out_of_the_script(self, test_settings):
        """A registered URI carrying JS metacharacters stays a string
        literal: json.dumps escapes the embedded quotes, so no code
        can execute out of the assignment."""
        hostile = 'https://example.com/logout?x=",alert(1),("'
        html = self._logout_html(
            allowed_uri=hostile,
            frontchannel_uri="https://rp.example/frontchannel",
        )
        assert "location = " in html
        # The hostile payload never appears raw inside the script…
        assert '",alert(1),("' not in html
        # …it is JSON-escaped instead.
        assert '\\"' in html

    def test_iframe_attributes_are_html_escaped(self, test_settings):
        """A front-channel URI containing a double quote cannot break
        out of the ``src`` attribute — html.escape(quote=True) turns
        it into &quot; and any injected markup is neutralized as text."""
        html = self._logout_html(
            allowed_uri="https://example.com/logout",
            frontchannel_uri='https://rp.example/fc?x="><script>alert(1)</script>',
        )
        assert 'src="https://rp.example/fc?x=">' not in html
        assert "&quot;&gt;&lt;script&gt;" in html

    def test_iframe_query_components_are_url_encoded(self, test_settings):
        """iss/sid in the iframe query go through urlencode."""
        html = self._logout_html(
            allowed_uri="https://example.com/logout",
            frontchannel_uri="https://rp.example/frontchannel",
            state="abc/123",
        )
        assert "src=" in html
        # The state appended to the redirect URL stays URL-encoded too.
        assert "state=abc%2F123" in html
