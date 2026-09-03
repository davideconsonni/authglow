"""Integration tests for the global ``CSRFMiddleware`` (T0-1 / VAPT-066).

Covers the gate matrix on a minimal app that mounts the middleware
exactly like ``main.py`` does:

- access cookie + no token header            → 403
- access cookie + valid token header         → 200
- refresh cookie only (expired access)       → 403 / 200 (G1)
- csrf_session_id only (login POST case, G5) → 403 / 200
- explicit ``Authorization`` credentials      → bypass (CSRF-immune)
- cross-site ``Origin``                       → 403 untrusted origin
- safe methods and the issuing endpoint       → always pass through
"""

import asyncio
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from authglow.middleware.csrf import CSRFMiddleware
from authglow.services.csrf import SESSION_ID_COOKIE, CSRFTokenService


@pytest.fixture
def _csrf_app(test_settings):
    from fastapi.responses import JSONResponse

    from authglow.core import config as config_mod

    app = FastAPI()
    app.add_middleware(CSRFMiddleware)

    @app.post("/api/echo")
    async def echo():
        return JSONResponse({"ok": True})

    with (
        patch.object(config_mod, "get_settings", return_value=test_settings),
        patch("authglow.middleware.csrf.get_settings", return_value=test_settings),
        patch("authglow.services.csrf.get_settings", return_value=test_settings),
    ):
        yield app


def _issue_token(test_settings, session_id: str) -> str:
    async def _gen():
        svc = CSRFTokenService(settings=test_settings)
        return await svc.generate_token(session_id)

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(_gen())


def _post(client: TestClient, **kwargs):
    return client.post("/api/echo", **kwargs)


class TestCsrfMiddlewareGate:
    def test_access_cookie_without_header_rejected(self, _csrf_app, test_settings):
        client = TestClient(_csrf_app)
        client.cookies.set(test_settings.auth_cookie_access_name, "jwt", domain="testserver.local")
        response = _post(client)
        assert response.status_code == 403
        assert "CSRF" in response.json()["detail"]

    def test_access_cookie_with_valid_header_passes(self, _csrf_app, test_settings):
        token = _issue_token(test_settings, "mw-session-1")
        client = TestClient(_csrf_app)
        client.cookies.set(test_settings.auth_cookie_access_name, "jwt", domain="testserver.local")
        client.cookies.set(SESSION_ID_COOKIE, "mw-session-1", domain="testserver.local")
        response = _post(client, headers={"X-CSRF-Token": token})
        assert response.status_code == 200
        assert response.json() == {"ok": True}

    def test_refresh_cookie_only_is_gated(self, _csrf_app, test_settings):
        """G1: the refresh endpoint runs when the access cookie has
        already expired — the gate must cover refresh-cookie requests."""
        client = TestClient(_csrf_app)
        client.cookies.set(test_settings.auth_cookie_refresh_name, "rt", domain="testserver.local")
        response = _post(client)
        assert response.status_code == 403

    def test_refresh_cookie_only_with_valid_header_passes(self, _csrf_app, test_settings):
        token = _issue_token(test_settings, "mw-session-2")
        client = TestClient(_csrf_app)
        client.cookies.set(test_settings.auth_cookie_refresh_name, "rt", domain="testserver.local")
        client.cookies.set(SESSION_ID_COOKIE, "mw-session-2", domain="testserver.local")
        response = _post(client, headers={"X-CSRF-Token": token})
        assert response.status_code == 200

    def test_csrf_session_cookie_only_is_gated(self, _csrf_app, test_settings):
        """G5: the first-party login POST carries only the CSRF session
        cookie (no access cookie yet) — it must be gated too."""
        client = TestClient(_csrf_app)
        client.cookies.set(SESSION_ID_COOKIE, "mw-session-3", domain="testserver.local")
        response = _post(client)
        assert response.status_code == 403

    def test_csrf_session_cookie_only_with_valid_header_passes(self, _csrf_app, test_settings):
        token = _issue_token(test_settings, "mw-session-4")
        client = TestClient(_csrf_app)
        client.cookies.set(SESSION_ID_COOKIE, "mw-session-4", domain="testserver.local")
        response = _post(client, headers={"X-CSRF-Token": token})
        assert response.status_code == 200

    def test_no_cookies_at_all_passes(self, _csrf_app):
        """Server-to-server callers (client credentials) send no
        ambient cookies — never gated."""
        client = TestClient(_csrf_app)
        assert _post(client).status_code == 200

    def test_authorization_header_bypasses_gate(self, _csrf_app, test_settings):
        """Explicit credentials cannot be attached by a cross-site
        request (non-simple header → preflight) — CSRF-immune."""
        client = TestClient(_csrf_app)
        client.cookies.set(test_settings.auth_cookie_access_name, "jwt", domain="testserver.local")
        response = _post(client, headers={"Authorization": "Bearer some-token"})
        assert response.status_code == 200

    def test_untrusted_origin_rejected_even_with_valid_token(self, _csrf_app, test_settings):
        token = _issue_token(test_settings, "mw-session-5")
        client = TestClient(_csrf_app)
        client.cookies.set(test_settings.auth_cookie_access_name, "jwt", domain="testserver.local")
        client.cookies.set(SESSION_ID_COOKIE, "mw-session-5", domain="testserver.local")
        response = _post(
            client, headers={"X-CSRF-Token": token, "Origin": "https://evil.example.net"}
        )
        assert response.status_code == 403
        assert "Untrusted request origin" in response.json()["detail"]

    def test_allowed_origin_with_valid_token_passes(self, _csrf_app, test_settings):
        token = _issue_token(test_settings, "mw-session-6")
        client = TestClient(_csrf_app)
        client.cookies.set(test_settings.auth_cookie_access_name, "jwt", domain="testserver.local")
        client.cookies.set(SESSION_ID_COOKIE, "mw-session-6", domain="testserver.local")
        allowed = test_settings.get_cors_origins()[0]
        response = _post(client, headers={"X-CSRF-Token": token, "Origin": allowed})
        assert response.status_code == 200

    def test_safe_method_passes_without_token(self, _csrf_app, test_settings):
        client = TestClient(_csrf_app)
        client.cookies.set(test_settings.auth_cookie_access_name, "jwt", domain="testserver.local")

        @client.app.get("/api/echo")
        async def echo_get():
            return {"ok": True}

        assert client.get("/api/echo").status_code == 200
