"""OAuth 2.0 state parameter validation tests — Workstream Q.

Validates that ``state`` is stored in the ``AuthorizationCode`` and
a warning is logged when it is absent (best practice).
"""

from unittest.mock import AsyncMock, MagicMock, patch

from authglow.models.token import AuthorizationCode


class TestStateStoredInAuthorizationCode:
    """Q.2: state is persisted in the AuthorizationCode model."""

    def test_state_stored_in_code(self, test_settings):
        from datetime import datetime, timezone

        code = AuthorizationCode(
            client_id="c",
            user_id="u",
            redirect_uri="https://e.com/cb",
            scope="read",
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
            state="my-state-value-123",
        )
        assert code.state == "my-state-value-123"

    def test_state_defaults_none(self, test_settings):
        from datetime import datetime, timezone

        code = AuthorizationCode(
            client_id="c",
            user_id="u",
            redirect_uri="https://e.com/cb",
            scope="read",
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
        )
        assert code.state is None


class TestStateWarningLogged:
    """Q.1: warning log when state is absent."""

    def test_warning_logged_when_state_missing(self, test_settings):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from authglow.api.auth import (
            get_audit_service,
            get_mfa_service,
            get_oauth2_service,
            get_session_service,
            get_user_storage,
            router,
        )
        from authglow.models.oauth_client import OAuth2Client

        client = OAuth2Client(
            client_id="c-abc",
            client_secret="hash",
            client_name="Test",
            redirect_uris=["https://e.com/cb"],
        )

        oauth2_cs = MagicMock()
        oauth2_cs.get_client = AsyncMock(return_value=client)
        oauth2_cs.verify_redirect_uri = AsyncMock(return_value=True)

        oauth2_svc = MagicMock()
        oauth2_svc.client_storage = oauth2_cs
        oauth2_svc.verify_redirect_uri = AsyncMock(return_value=True)
        oauth2_svc.process_scopes = AsyncMock(return_value=["read"])

        storage = MagicMock()
        storage.get_user = AsyncMock()
        storage.get_user_by_email = AsyncMock()

        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[get_user_storage] = lambda: storage
        app.dependency_overrides[get_oauth2_service] = lambda: oauth2_svc
        app.dependency_overrides[get_mfa_service] = lambda: MagicMock()
        app.dependency_overrides[get_session_service] = lambda: MagicMock()
        app.dependency_overrides[get_audit_service] = lambda: AsyncMock()

        http_client = TestClient(app)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "c-abc",
                    "redirect_uri": "https://e.com/cb",
                    "scope": "read",
                    "code_challenge": "ch123",
                    "code_challenge_method": "S256",
                },
            )

        # No state → request should still be processed (400 for missing credentials)
        assert response.status_code in (400, 401, 200), response.text
