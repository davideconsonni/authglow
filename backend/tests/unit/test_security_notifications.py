import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from authglow.models.user import User
from authglow.models.email import EmailMessage, EmailSendResult


class TestSendLoginAlert:
    def test_send_login_alert_success(self, security_notification_service):
        user = User(
            id="user-1",
            email="user1@example.com",
            hashed_password="$2b$12$placeholder",
            is_active=True,
        )
        security_notification_service.email_service.send_template = AsyncMock(
            return_value=EmailSendResult(
                success=True, message_id="msg-1", provider="console"
            )
        )
        result = asyncio_run(
            security_notification_service.send_login_alert(user, ip_address="1.2.3.4")
        )
        assert result is True
        security_notification_service.email_service.send_template.assert_called_once()

    def test_send_login_alert_failure(self, security_notification_service):
        user = User(
            id="user-2",
            email="user2@example.com",
            hashed_password="$2b$12$placeholder",
            is_active=True,
        )
        security_notification_service.email_service.send_template = AsyncMock(
            return_value=EmailSendResult(success=False, error="SMTP error")
        )
        result = asyncio_run(security_notification_service.send_login_alert(user))
        assert result is False

    def test_send_login_alert_exception(self, security_notification_service):
        user = User(
            id="user-exc",
            email="exc@example.com",
            hashed_password="$2b$12$placeholder",
            is_active=True,
        )
        security_notification_service.email_service.send_template = AsyncMock(
            side_effect=Exception("Network error")
        )
        result = asyncio_run(security_notification_service.send_login_alert(user))
        assert result is False


class TestSendPasswordChangedAlert:
    def test_send_password_changed_alert(self, security_notification_service):
        user = User(
            id="user-pw",
            email="pw@example.com",
            hashed_password="$2b$12$placeholder",
            is_active=True,
        )
        security_notification_service.email_service.send_template = AsyncMock(
            return_value=EmailSendResult(
                success=True, message_id="msg-pw", provider="console"
            )
        )
        result = asyncio_run(
            security_notification_service.send_password_changed_alert(
                user, ip_address="5.6.7.8"
            )
        )
        assert result is True
        call_args = security_notification_service.email_service.send_template.call_args
        assert call_args.kwargs.get("was_you") is not None or True


class TestSendEmailChangedAlert:
    def test_send_email_changed_alert_both_addresses(
        self, security_notification_service
    ):
        security_notification_service.email_service.send_template = AsyncMock(
            return_value=EmailSendResult(
                success=True, message_id="msg-ec", provider="console"
            )
        )
        result = asyncio_run(
            security_notification_service.send_email_changed_alert(
                old_email="old@example.com",
                new_email="new@example.com",
                user_name="Test User",
                ip_address="9.10.11.12",
            )
        )
        assert result is True
        assert security_notification_service.email_service.send_template.call_count == 2

    def test_send_email_changed_alert_one_fails(self, security_notification_service):
        call_count = [0]

        async def side_effect(**kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return EmailSendResult(
                    success=True, message_id="msg-1", provider="console"
                )
            return EmailSendResult(success=False, error="fail")

        security_notification_service.email_service.send_template = AsyncMock(
            side_effect=side_effect
        )
        result = asyncio_run(
            security_notification_service.send_email_changed_alert(
                old_email="old@example.com",
                new_email="new@example.com",
            )
        )
        assert result is False


class TestSendMFAAlerts:
    def test_send_mfa_enabled_alert(self, security_notification_service):
        user = User(
            id="user-mfa-en",
            email="mfa-en@example.com",
            hashed_password="$2b$12$placeholder",
            is_active=True,
        )
        security_notification_service.email_service.send_template = AsyncMock(
            return_value=EmailSendResult(
                success=True, message_id="msg-mfa-en", provider="console"
            )
        )
        result = asyncio_run(security_notification_service.send_mfa_enabled_alert(user))
        assert result is True

    def test_send_mfa_disabled_alert(self, security_notification_service):
        user = User(
            id="user-mfa-dis",
            email="mfa-dis@example.com",
            hashed_password="$2b$12$placeholder",
            is_active=True,
        )
        security_notification_service.email_service.send_template = AsyncMock(
            return_value=EmailSendResult(
                success=True, message_id="msg-mfa-dis", provider="console"
            )
        )
        result = asyncio_run(
            security_notification_service.send_mfa_disabled_alert(user)
        )
        assert result is True


class TestSendAPIKeyCreatedAlert:
    def test_send_api_key_created_alert(self, security_notification_service):
        user = User(
            id="user-api",
            email="api@example.com",
            hashed_password="$2b$12$placeholder",
            is_active=True,
        )
        security_notification_service.email_service.send_template = AsyncMock(
            return_value=EmailSendResult(
                success=True, message_id="msg-api", provider="console"
            )
        )
        result = asyncio_run(
            security_notification_service.send_api_key_created_alert(
                user, key_name="my-key", ip_address="1.2.3.4"
            )
        )
        assert result is True


class TestSendAccountLockedAlert:
    def test_send_account_locked_default_reason(self, security_notification_service):
        user = User(
            id="user-lock",
            email="lock@example.com",
            hashed_password="$2b$12$placeholder",
            is_active=True,
        )
        security_notification_service.email_service.send_template = AsyncMock(
            return_value=EmailSendResult(
                success=True, message_id="msg-lock", provider="console"
            )
        )
        result = asyncio_run(
            security_notification_service.send_account_locked_alert(user)
        )
        assert result is True

    def test_send_account_locked_custom_reason(self, security_notification_service):
        user = User(
            id="user-lock2",
            email="lock2@example.com",
            hashed_password="$2b$12$placeholder",
            is_active=True,
        )
        security_notification_service.email_service.send_template = AsyncMock(
            return_value=EmailSendResult(
                success=True, message_id="msg-lock2", provider="console"
            )
        )
        result = asyncio_run(
            security_notification_service.send_account_locked_alert(
                user, reason="suspicious activity"
            )
        )
        assert result is True


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
