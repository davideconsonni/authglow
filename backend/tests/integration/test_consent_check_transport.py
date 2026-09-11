"""Transport-level tests for the consent auto-check endpoint.

ZAP-006: the consent ``session_token`` is a bearer credential and must
never travel in the URL (browser history, server access logs, Referer).
It is accepted only in the POST body; the legacy GET query transport is
gone (405).
"""

from contextlib import ExitStack
from unittest.mock import AsyncMock, MagicMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient


def _session():
    return {
        "session_token": "consent-token",
        "user_id": "user-1",
        "client_id": "client-1",
        "redirect_uri": "https://client.example/callback",
        "scope": "openid profile",
        "state": "state-value",
    }


def _build_app():
    from slowapi.middleware import SlowAPIMiddleware

    from authglow.api.oauth_consent_handler import router
    from authglow.core.rate_limit import limiter

    app = FastAPI()
    app.state.limiter = limiter
    app.add_middleware(SlowAPIMiddleware)
    app.include_router(router)
    return app


def _patched_services():
    """Stub the handler's service globals (resolved via lambdas at call time)."""
    session_service = MagicMock()
    session_service.get_consent_session = AsyncMock(
        side_effect=lambda token: _session() if token == "consent-token" else None
    )
    user = MagicMock()
    user.id = "user-1"
    user_storage = MagicMock()
    user_storage.get_user = AsyncMock(return_value=user)
    consent_service = MagicMock()
    consent_service.check_consent = AsyncMock(return_value=(False, None))
    client = MagicMock()
    client.client_name = "Test client"
    client.client_id = "client-1"
    client.description = None
    client.logo_uri = None
    client.homepage_uri = None
    client.terms_uri = None
    client.privacy_uri = None
    client.branding = None
    client_storage = MagicMock()
    client_storage.get_client = AsyncMock(return_value=client)
    stack = ExitStack()
    stack.enter_context(
        patch(
            "authglow.api.oauth_consent_handler.SessionService",
            return_value=session_service,
        )
    )
    stack.enter_context(
        patch(
            "authglow.api.oauth_consent_handler.UserStorage",
            return_value=user_storage,
        )
    )
    stack.enter_context(
        patch(
            "authglow.api.oauth_consent_handler.OAuth2ConsentService",
            return_value=consent_service,
        )
    )
    stack.enter_context(
        patch(
            "authglow.api.oauth_consent_handler.OAuth2ClientStorage",
            return_value=client_storage,
        )
    )
    return stack


def test_post_accepts_token_in_body():
    with _patched_services():
        client = TestClient(_build_app())
        response = client.post(
            "/api/oauth2/consent/check", data={"session_token": "consent-token"}
        )

    assert response.status_code == 200
    body = response.json()
    assert body["consent_required"] is True
    assert body["session_token"] == "consent-token"


def test_get_query_transport_is_gone():
    with _patched_services():
        client = TestClient(_build_app())
        response = client.get("/api/oauth2/consent/check?session_token=consent-token")

    assert response.status_code == 405


def test_post_invalid_token_returns_400_without_leak():
    with _patched_services():
        client = TestClient(_build_app())
        response = client.post(
            "/api/oauth2/consent/check", data={"session_token": "bogus-token"}
        )

    assert response.status_code == 400
    assert "bogus-token" not in response.text
