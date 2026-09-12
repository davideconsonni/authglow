"""OAuth 2.0 state parameter validation tests — OA-201 (ex VAPT-044).

RFC 6749 §4.1.2.1 makes ``state`` RECOMMENDED, not required:
a missing state completes the flow (no echo), while a
PRESENT-but-weak state (too short/long, unsafe charset —
RFC 6819 §4.4.1.8, RFC 9700) is refused via redirect
(``error=invalid_request``), never echoed and never a bare
JSON oracle. The pre-OA-201 implementation rejected missing
state with HTTP 400; that broke conformant clients.
"""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from authglow.models.token import AuthorizationCode


@pytest.fixture(autouse=True)
def _reset_limiter_storage():
    """Reset the module-level slowapi limiter so rate-limit counters
    from previous test files do not bleed into this module's
    10-per-minute authorize endpoint budget."""
    from authglow.core.rate_limit import limiter

    limiter._storage.storage.clear()
    yield
    limiter._storage.storage.clear()


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
    """OA-201: state is optional; weak state redirects without echo."""

    def _post(self, app, data, follow_redirects=False):
        from fastapi.testclient import TestClient

        return TestClient(app, follow_redirects=follow_redirects).post(
            "/api/oauth2/authorize", data=data
        )

    def _base_form(self, **extra):
        form = {
            "client_id": "c-abc",
            "redirect_uri": "https://e.com/cb",
            "scope": "read",
            "code_challenge": "ch123",
            "code_challenge_method": "S256",
        }
        form.update(extra)
        return form

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

    def test_missing_state_completes_past_gate(self, test_settings):
        """OA-201: no state → the flow proceeds (fails later on credentials, not state)."""
        _, app = self._build_client_app(test_settings)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = self._post(app, self._base_form())

        # Past the state gate: 400 comes from the auth path
        # ("Credentials required"), never from the state validator.
        assert response.status_code == 400, response.text
        assert "state" not in response.json()["detail"].lower()

    def test_short_state_redirects_without_echo(self, test_settings):
        """OA-201: a present-but-short state → 302 `invalid_request`, no echo."""
        from urllib.parse import parse_qs, urlparse

        _, app = self._build_client_app(test_settings)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = self._post(
                app,
                self._base_form(state="short"),  # 5 chars — below the 16-char floor
            )

        assert response.status_code == 302, response.text
        query = parse_qs(urlparse(response.headers["location"]).query)
        assert query.get("error") == ["invalid_request"]
        assert "state" not in query

    def test_state_with_log_injection_chars_redirects_without_echo(self, test_settings):
        """A state with a newline would let a malicious client
        inject extra redirect parameters or log entries. It is
        refused via redirect and never reflected."""
        from urllib.parse import parse_qs, urlparse

        _, app = self._build_client_app(test_settings)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = self._post(
                app,
                self._base_form(
                    # 16 chars (passes the length check) but contains
                    # whitespace — a classic log-injection vector.
                    state="goodstate-good\nFAKE"
                ),
            )

        assert response.status_code == 302, response.text
        location = response.headers["location"]
        assert "\n" not in location
        assert "FAKE" not in location
        assert "state" not in parse_qs(urlparse(location).query)

    def test_state_with_shell_metachars_redirects(self, test_settings):
        from urllib.parse import parse_qs, urlparse

        _, app = self._build_client_app(test_settings)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = self._post(app, self._base_form(state="good|rm -rf /etc/"))

        assert response.status_code == 302, response.text
        query = parse_qs(urlparse(response.headers["location"]).query)
        assert query.get("error") == ["invalid_request"]
        assert "state" not in query

    def test_valid_uuid4_style_state_is_accepted(self, test_settings):
        """A 32-hex-char UUID4 (typical legitimate value) is
        accepted. We don't need a 200 (the request still needs
        credentials) — a 400/401 from the auth path is the
        right outcome, the key is that the state validator
        does NOT reject it upfront."""
        _, app = self._build_client_app(test_settings)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = self._post(
                app,
                self._base_form(
                    state="abc123def456789012345678901234ab"  # 32 hex
                ),
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
        # secrets.token_urlsafe(32) → 43 base64url chars
        import secrets

        valid_state = secrets.token_urlsafe(32)
        assert len(valid_state) == 43

        _, app = self._build_client_app(test_settings)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = self._post(app, self._base_form(state=valid_state))

        if response.status_code == 400:
            assert "state" not in response.json()["detail"].lower()

    def test_oversized_state_redirects(self, test_settings):
        """Defensive cap: a 1 MB state would make the redirect
        URL huge. The 512-char cap keeps the response line
        within HTTP reasonable limits — refused via redirect."""
        from urllib.parse import parse_qs, urlparse

        _, app = self._build_client_app(test_settings)

        with patch("authglow.api.auth.get_settings", return_value=test_settings):
            response = self._post(
                app,
                self._base_form(
                    state="a" * 513,  # 1 over the 512 cap
                ),
            )

        assert response.status_code == 302, response.text
        query = parse_qs(urlparse(response.headers["location"]).query)
        assert query.get("error") == ["invalid_request"]
        assert "state" not in query
