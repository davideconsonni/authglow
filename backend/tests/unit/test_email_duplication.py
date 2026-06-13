"""Verify that admin email actions send exactly one email per invocation."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import Request


def _make_admin_user():
    from authglow.models.user import User

    return User(
        id="admin-test-1",
        email="admin@authglow.io",
        hashed_password="not-used-in-test",
        is_active=True,
        scopes=["admin"],
    )


def _make_test_user():
    from authglow.models.user import User

    return User(
        id="user-to-act-on",
        email="testuser@example.com",
        hashed_password="$2b$12$LJ3m4ys3LkHhzjjI/jxRtuH4XHqzpQhA6QF3VJ5Gj9N6S8gK2O3u",
        is_active=True,
        scopes=["read"],
        failed_login_attempts=0,
        locked_until=None,
        password_expired=False,
    )


def _make_request():
    request = Request({"type": "http", "method": "POST", "path": "", "headers": []})
    request.state.view_rate_limit = None
    return request


class TestEmailDuplication:
    """Verify that admin actions send exactly one email per call."""

    @patch("authglow.services.email.factory.get_email_service")
    def test_send_password_reset_calls_send_template_exactly_once(self, mock_get_email):
        """send_password_reset must call send_template exactly once."""
        from authglow.api.admin import send_password_reset

        existing = _make_test_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        mock_email = AsyncMock()
        mock_email.send_template.return_value = AsyncMock(success=True)
        mock_get_email.return_value = mock_email

        asyncio.get_event_loop().run_until_complete(
            send_password_reset(
                request=_make_request(),
                user_id="user-to-act-on",
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        call_count = mock_email.send_template.call_count
        assert call_count == 1, f"Expected exactly 1 email for password reset, got {call_count}"

    def test_confirmdialog_has_loading_prop(self):
        """ConfirmDialog frontend component must accept loading prop."""
        confirm_dialog_path = (
            Path(__file__).resolve().parents[3]
            / "frontend"
            / "src"
            / "components"
            / "shared"
            / "ConfirmDialog.tsx"
        )
        source = confirm_dialog_path.read_text()
        assert "loading" in source, "ConfirmDialog must accept loading prop"
        assert "disabled" in source, "Buttons must be disabled during loading"
        assert "Loader2" in source, "Must show spinner during loading"
