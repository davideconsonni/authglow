from unittest.mock import AsyncMock, MagicMock

import pytest
from starlette.requests import Request

from authglow.api.oauth_consent_handler import process_consent


def _request() -> Request:
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/oauth2/consent",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 8000),
            "server": ("testserver", 80),
            "scheme": "http",
        }
    )


def _session_service() -> tuple[AsyncMock, dict[str, str]]:
    session = {
        "session_token": "consent-token",
        "user_id": "user-1",
        "client_id": "client-1",
        "redirect_uri": "https://client.example/callback",
        "scope": "openid profile",
        "state": "state-value",
    }
    service = AsyncMock()
    service.get_consent_session.return_value = session
    return service, session


@pytest.mark.asyncio
async def test_consent_without_remember_does_not_persist_grant():
    session_service, _ = _session_service()
    consent_service = AsyncMock()
    oauth2_service = MagicMock()
    oauth2_service.create_authorization_code = AsyncMock(return_value=MagicMock(code="auth-code"))
    audit_service = AsyncMock()

    result = await process_consent(
        request=_request(),
        session_token="consent-token",
        approved="true",
        remember="false",
        session_service=session_service,
        consent_service=consent_service,
        oauth2_service=oauth2_service,
        audit_service=audit_service,
    )

    consent_service.create_consent.assert_not_awaited()
    assert result["approved"] is True
    assert result["redirect_url"].endswith("code=auth-code&state=state-value")


@pytest.mark.asyncio
async def test_consent_with_remember_persists_grant():
    session_service, _ = _session_service()
    consent_service = AsyncMock()
    oauth2_service = MagicMock()
    oauth2_service.create_authorization_code = AsyncMock(return_value=MagicMock(code="auth-code"))
    audit_service = AsyncMock()

    await process_consent(
        request=_request(),
        session_token="consent-token",
        approved="true",
        remember="true",
        session_service=session_service,
        consent_service=consent_service,
        oauth2_service=oauth2_service,
        audit_service=audit_service,
    )

    consent_service.create_consent.assert_awaited_once_with(
        user_id="user-1",
        client_id="client-1",
        scopes=["openid", "profile"],
        expires_at=None,
    )
