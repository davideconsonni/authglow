"""OAuth 2.0 state parameter validation tests — VAPT-044.

RFC 6819 §4.4.1.8 and RFC 9700 (OAuth 2.0 Security BCP, July 2025)
require the server to validate ``state`` is a high-entropy opaque
nonce. The pre-VAPT-044 implementation only logged a warning when
state was absent and accepted any value. After the fix, the
endpoint rejects requests with missing / short / tainted ``state``
with HTTP 400 before any session is created.
"""

from unittest.mock import AsyncMock, MagicMock, patch

from authglow.models.token import AuthorizationCode


class TestStateStoredInAuthorizationCode:
    """state is persisted in the AuthorizationCode model."""

    def test_state_stored_in_code(self, test_settings):
        from datetime import datetime, timezone

        code = AuthorizationCode(
            client_id="c",
            user_id="u",
            redirect_uri="https://e.com/cb",
            scope="read",
            expires_at=datetime(2099, 1, 1, tzinfo=timezone.utc),
            state="my-state-value-1234567890",
        )
        assert code.state == "my-state-value-1234567890"

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


class TestVapt044StateValidation:
    """VAPT-044: state is mandatory and must be a high-entropy nonce."""

    def _build_client_app(self, test_settings):
        from fastapi import FastAPI

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

        return FastAPI, app

    def test_missing_state_is_rejected_with_400(self, test_settings):
        from fastapi.testclient import TestClient

        _, app = self._build_client_app(test_settings)
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

        # VAPT-044: a missing state is now a hard error,
        # not a warning.
        assert response.status_code == 400, response.text
        body = response.json()
        assert "state" in body["detail"].lower()
        assert "16" in body["detail"] or "at least" in body["detail"].lower()

    def test_short_state_is_rejected_with_400(self, test_settings):
        from fastapi.testclient import TestClient

        _, app = self._build_client_app(test_settings)
        http_client = TestClient(app)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "c-abc",
                    "redirect_uri": "https://e.com/cb",
                    "scope": "read",
                    "state": "short",  # 5 chars — well below the 16-char floor
                    "code_challenge": "ch123",
                    "code_challenge_method": "S256",
                },
            )

        assert response.status_code == 400, response.text
        assert "state" in response.json()["detail"].lower()

    def test_state_with_log_injection_chars_is_rejected(self, test_settings):
        """A state with a newline would let a malicious client
        inject extra redirect parameters or log entries. The
        validator must reject it."""
        from fastapi.testclient import TestClient

        _, app = self._build_client_app(test_settings)
        http_client = TestClient(app)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "c-abc",
                    "redirect_uri": "https://e.com/cb",
                    "scope": "read",
                    # 16 chars (passes the length check) but contains
                    # whitespace — a classic log-injection vector.
                    "state": "goodstate-good\nFAKE",
                    "code_challenge": "ch123",
                    "code_challenge_method": "S256",
                },
            )

        assert response.status_code == 400, response.text

    def test_state_with_shell_metachars_is_rejected(self, test_settings):
        from fastapi.testclient import TestClient

        _, app = self._build_client_app(test_settings)
        http_client = TestClient(app)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "c-abc",
                    "redirect_uri": "https://e.com/cb",
                    "scope": "read",
                    "state": "good|rm -rf /etc/",
                    "code_challenge": "ch123",
                    "code_challenge_method": "S256",
                },
            )

        assert response.status_code == 400, response.text

    def test_valid_uuid4_style_state_is_accepted(self, test_settings):
        """A 32-hex-char UUID4 (typical legitimate value) is
        accepted. We don't need a 200 (the request still needs
        credentials) — a 400/401 from the auth path is the
        right outcome, the key is that the state validator
        does NOT reject it upfront."""
        from fastapi.testclient import TestClient

        _, app = self._build_client_app(test_settings)
        http_client = TestClient(app)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "c-abc",
                    "redirect_uri": "https://e.com/cb",
                    "scope": "read",
                    "state": "abc123def456789012345678901234ab",  # 32 hex
                    "code_challenge": "ch123",
                    "code_challenge_method": "S256",
                },
            )

        # Not 400 from the state validator (the response may
        # still be 400/401 from the auth path because no
        # credentials were supplied — that's fine, the
        # validator did its job).
        if response.status_code == 400:
            assert "state" not in response.json()["detail"].lower(), (
                "valid 32-hex state was rejected by the state validator"
            )

    def test_valid_token_urlsafe_state_is_accepted(self, test_settings):
        """``secrets.token_urlsafe(32)`` produces a 43-char
        base64url nonce — the canonical recommendation in the
        OAuth 2.0 Security BCP."""
        from fastapi.testclient import TestClient

        _, app = self._build_client_app(test_settings)
        http_client = TestClient(app)

        # secrets.token_urlsafe(32) → 43 base64url chars
        import secrets

        valid_state = secrets.token_urlsafe(32)
        assert len(valid_state) == 43

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "c-abc",
                    "redirect_uri": "https://e.com/cb",
                    "scope": "read",
                    "state": valid_state,
                    "code_challenge": "ch123",
                    "code_challenge_method": "S256",
                },
            )

        if response.status_code == 400:
            assert "state" not in response.json()["detail"].lower()

    def test_oversized_state_is_rejected(self, test_settings):
        """Defensive cap: a 1 MB state would make the redirect
        URL huge. The 512-char cap keeps the response line
        within HTTP reasonable limits."""
        from fastapi.testclient import TestClient

        _, app = self._build_client_app(test_settings)
        http_client = TestClient(app)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = http_client.post(
                "/api/oauth2/authorize",
                data={
                    "client_id": "c-abc",
                    "redirect_uri": "https://e.com/cb",
                    "scope": "read",
                    "state": "a" * 513,  # 1 over the 512 cap
                    "code_challenge": "ch123",
                    "code_challenge_method": "S256",
                },
            )

        assert response.status_code == 400, response.text
        assert "state" in response.json()["detail"].lower()
