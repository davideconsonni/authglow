"""Tests for Phase 2 admin endpoints: password management, lockout, etc."""

import asyncio

import pytest
from unittest.mock import patch, AsyncMock
from fastapi import Request

asyncio.set_event_loop(asyncio.new_event_loop())


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


class TestSetPassword:
    def test_set_password_success(self):
        import asyncio
        from authglow.api.admin import set_user_password
        from authglow.models.admin import SetPasswordRequest

        existing = _make_test_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.set_password = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        body = SetPasswordRequest(password="NewStrongP@ss1", require_change=False)

        result = asyncio.get_event_loop().run_until_complete(
            set_user_password(
                request=_make_request(),
                user_id="user-to-act-on",
                body=body,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result["message"] == "Password set successfully"
        mock_storage.set_password.assert_called_once()

    def test_set_password_with_require_change(self):
        import asyncio
        from authglow.api.admin import set_user_password
        from authglow.models.admin import SetPasswordRequest

        existing = _make_test_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.set_password = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        body = SetPasswordRequest(password="NewStrongP@ss1", require_change=True)

        asyncio.get_event_loop().run_until_complete(
            set_user_password(
                request=_make_request(),
                user_id="user-to-act-on",
                body=body,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        mock_storage.set_password.assert_called_once()
        _, kwargs = mock_storage.set_password.call_args
        assert kwargs.get("require_change") is True

    def test_set_password_weak_password_rejected(self):
        import asyncio
        from fastapi import HTTPException
        from authglow.api.admin import set_user_password
        from authglow.models.admin import SetPasswordRequest

        existing = _make_test_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        body = SetPasswordRequest(password="alllowercase", require_change=False)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                set_user_password(
                    request=_make_request(),
                    user_id="user-to-act-on",
                    body=body,
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=mock_audit,
                )
            )

        assert exc_info.value.status_code == 400
        assert "Password" in exc_info.value.detail

    def test_set_password_nonexistent_user(self):
        import asyncio
        from fastapi import HTTPException
        from authglow.api.admin import set_user_password
        from authglow.models.admin import SetPasswordRequest

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=None)
        mock_audit = AsyncMock()

        body = SetPasswordRequest(password="NewStrongP@ss1", require_change=False)

        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                set_user_password(
                    request=_make_request(),
                    user_id="nonexistent",
                    body=body,
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=mock_audit,
                )
            )

        assert exc_info.value.status_code == 404

    def test_set_password_logs_audit_event(self):
        import asyncio
        from authglow.api.admin import set_user_password
        from authglow.models.admin import SetPasswordRequest

        existing = _make_test_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.set_password = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        body = SetPasswordRequest(password="NewStrongP@ss1", require_change=False)

        asyncio.get_event_loop().run_until_complete(
            set_user_password(
                request=_make_request(),
                user_id="user-to-act-on",
                body=body,
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        mock_audit.log_event.assert_called_once()
        call_kwargs = mock_audit.log_event.call_args[1]
        assert call_kwargs["event_type"] == "password_set_by_admin"
        assert call_kwargs["metadata"]["target_user_id"] == "user-to-act-on"


class TestSendPasswordReset:
    @patch("authglow.services.email.factory.get_email_service")
    def test_send_password_reset_success(self, mock_get_email):
        import asyncio
        from authglow.api.admin import send_password_reset

        existing = _make_test_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        mock_email = AsyncMock()
        mock_get_email.return_value = mock_email

        result = asyncio.get_event_loop().run_until_complete(
            send_password_reset(
                request=_make_request(),
                user_id="user-to-act-on",
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result["message"] == "Password reset email sent"
        mock_email.send_template.assert_called_once()

    def test_send_password_reset_nonexistent_user(self):
        import asyncio
        from fastapi import HTTPException
        from authglow.api.admin import send_password_reset

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=None)
        mock_audit = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                send_password_reset(
                    request=_make_request(),
                    user_id="nonexistent",
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=mock_audit,
                )
            )

        assert exc_info.value.status_code == 404

    @patch("authglow.services.email.factory.get_email_service")
    def test_send_password_reset_logs_audit(self, mock_get_email):
        import asyncio
        from authglow.api.admin import send_password_reset

        existing = _make_test_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        mock_email = AsyncMock()
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

        mock_audit.log_event.assert_called_once()
        call_kwargs = mock_audit.log_event.call_args[1]
        assert call_kwargs["event_type"] == "password_reset_sent_by_admin"


class TestExpirePassword:
    def test_expire_password_success(self):
        import asyncio
        from authglow.api.admin import expire_user_password

        existing = _make_test_user()
        existing.password_expired = False
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        result = asyncio.get_event_loop().run_until_complete(
            expire_user_password(
                request=_make_request(),
                user_id="user-to-act-on",
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result["message"] == "Password expired successfully"
        assert existing.password_expired is True

    def test_expire_password_nonexistent_user(self):
        import asyncio
        from fastapi import HTTPException
        from authglow.api.admin import expire_user_password

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=None)
        mock_audit = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                expire_user_password(
                    request=_make_request(),
                    user_id="nonexistent",
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=mock_audit,
                )
            )

        assert exc_info.value.status_code == 404

    def test_expire_password_logs_audit(self):
        import asyncio
        from authglow.api.admin import expire_user_password

        existing = _make_test_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.update_user = AsyncMock(return_value=existing)
        mock_audit = AsyncMock()

        asyncio.get_event_loop().run_until_complete(
            expire_user_password(
                request=_make_request(),
                user_id="user-to-act-on",
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        mock_audit.log_event.assert_called_once()
        call_kwargs = mock_audit.log_event.call_args[1]
        assert call_kwargs["event_type"] == "password_expired_by_admin"


class TestUnlockAccount:
    def test_unlock_success(self):
        import asyncio
        from authglow.api.admin import unlock_user_account

        existing = _make_test_user()
        existing.failed_login_attempts = 5
        from authglow.core.datetime import utcnow
        from datetime import timedelta

        existing.locked_until = utcnow() + timedelta(hours=1)

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.reset_failed_login_attempts = AsyncMock()
        mock_audit = AsyncMock()

        result = asyncio.get_event_loop().run_until_complete(
            unlock_user_account(
                request=_make_request(),
                user_id="user-to-act-on",
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result["message"] == "Account unlocked successfully"
        mock_storage.reset_failed_login_attempts.assert_called_once_with("user-to-act-on")

    def test_unlock_nonexistent_user(self):
        import asyncio
        from fastapi import HTTPException
        from authglow.api.admin import unlock_user_account

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=None)
        mock_audit = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                unlock_user_account(
                    request=_make_request(),
                    user_id="nonexistent",
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=mock_audit,
                )
            )

        assert exc_info.value.status_code == 404

    def test_unlock_logs_audit(self):
        import asyncio
        from authglow.api.admin import unlock_user_account

        existing = _make_test_user()
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.reset_failed_login_attempts = AsyncMock()
        mock_audit = AsyncMock()

        asyncio.get_event_loop().run_until_complete(
            unlock_user_account(
                request=_make_request(),
                user_id="user-to-act-on",
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        mock_audit.log_event.assert_called_once()
        call_kwargs = mock_audit.log_event.call_args[1]
        assert call_kwargs["event_type"] == "account_unlocked_by_admin"


class TestResetFailedAttempts:
    def test_reset_attempts_success(self):
        import asyncio
        from authglow.api.admin import reset_failed_attempts

        existing = _make_test_user()
        existing.failed_login_attempts = 3
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.clear_failed_login_attempts = AsyncMock()
        mock_audit = AsyncMock()

        result = asyncio.get_event_loop().run_until_complete(
            reset_failed_attempts(
                request=_make_request(),
                user_id="user-to-act-on",
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        assert result["message"] == "Failed attempts reset successfully"
        mock_storage.clear_failed_login_attempts.assert_called_once_with("user-to-act-on")

    def test_reset_attempts_nonexistent_user(self):
        import asyncio
        from fastapi import HTTPException
        from authglow.api.admin import reset_failed_attempts

        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=None)
        mock_audit = AsyncMock()

        with pytest.raises(HTTPException) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                reset_failed_attempts(
                    request=_make_request(),
                    user_id="nonexistent",
                    current_user=_make_admin_user(),
                    storage=mock_storage,
                    audit_service=mock_audit,
                )
            )

        assert exc_info.value.status_code == 404

    def test_reset_attempts_logs_audit(self):
        import asyncio
        from authglow.api.admin import reset_failed_attempts

        existing = _make_test_user()
        existing.failed_login_attempts = 3
        mock_storage = AsyncMock()
        mock_storage.get_user = AsyncMock(return_value=existing)
        mock_storage.clear_failed_login_attempts = AsyncMock()
        mock_audit = AsyncMock()

        asyncio.get_event_loop().run_until_complete(
            reset_failed_attempts(
                request=_make_request(),
                user_id="user-to-act-on",
                current_user=_make_admin_user(),
                storage=mock_storage,
                audit_service=mock_audit,
            )
        )

        mock_audit.log_event.assert_called_once()
        call_kwargs = mock_audit.log_event.call_args[1]
        assert call_kwargs["event_type"] == "failed_attempts_reset_by_admin"


class TestStorageSetPassword:
    def test_set_password_updates_fields(self):
        import asyncio
        from authglow.services.storage import UserStorage
        from authglow.services.password import hash_password

        existing = _make_test_user()
        existing.hashed_password = "oldhash"
        existing.password_expired = False
        existing.password_changed_at = None

        async def fake_write(user):
            return user

        storage = UserStorage()
        storage._write_user = fake_write
        storage.get_user = AsyncMock(return_value=existing)
        storage._lock = lambda x: AsyncMock().__aenter__

        new_hash = hash_password("NewStrongP@ss1")
        result = asyncio.get_event_loop().run_until_complete(
            storage.set_password("user-to-act-on", new_hash, require_change=True)
        )

        assert result is not None
        assert result.hashed_password == new_hash
        assert result.password_expired is True
        assert result.password_changed_at is not None

    def test_set_password_nonexistent_user_returns_none(self):
        import asyncio
        from authglow.services.storage import UserStorage

        storage = UserStorage()
        storage.get_user = AsyncMock(return_value=None)
        storage._lock = lambda x: AsyncMock().__aenter__

        result = asyncio.get_event_loop().run_until_complete(
            storage.set_password("nonexistent", "somehash")
        )

        assert result is None


class TestStorageClearFailedAttempts:
    def test_clear_failed_attempts_zeros_only_attempts(self):
        import asyncio
        from authglow.services.storage import UserStorage
        from authglow.core.datetime import utcnow
        from datetime import timedelta

        existing = _make_test_user()
        existing.failed_login_attempts = 3
        existing.locked_until = utcnow() + timedelta(hours=1)

        async def fake_write(user):
            return user

        storage = UserStorage()
        storage._write_user = fake_write
        storage.get_user = AsyncMock(return_value=existing)
        storage._lock = lambda x: AsyncMock().__aenter__

        asyncio.get_event_loop().run_until_complete(
            storage.clear_failed_login_attempts("user-to-act-on")
        )

        assert existing.failed_login_attempts == 0
        assert existing.locked_until is not None  # lockout preserved

    def test_clear_failed_attempts_nonexistent(self):
        import asyncio
        from authglow.services.storage import UserStorage

        storage = UserStorage()
        storage.get_user = AsyncMock(return_value=None)
        storage._lock = lambda x: AsyncMock().__aenter__

        asyncio.get_event_loop().run_until_complete(
            storage.clear_failed_login_attempts("nonexistent")
        )
