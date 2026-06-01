import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from authglow.models.user import User
from authglow.models.user_profile import UserProfileUpdate, UserPreferencesUpdate
from authglow.services.password import hash_password, verify_password


def asyncio_run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _make_user(user_id="profile-user-1", email="profile1@example.com"):
    return User(
        id=user_id,
        email=email,
        hashed_password=hash_password("TestP@ss123!"),
        is_active=True,
        email_verified=True,
        scopes=["read"],
    )


class TestGetUserProfile:
    def test_get_user_profile(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        result = asyncio_run(user_profile_service.get_user_profile("profile-user-1"))
        assert result is not None
        assert result.email == "profile1@example.com"

    def test_get_user_profile_not_found(self, user_profile_service):
        user_profile_service.user_storage.get_user = AsyncMock(return_value=None)
        result = asyncio_run(user_profile_service.get_user_profile("nonexistent"))
        assert result is None


class TestUpdateUserProfile:
    def test_update_user_profile(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage._write_user = AsyncMock()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        update = UserProfileUpdate(first_name="Updated")
        result = asyncio_run(
            user_profile_service.update_user_profile("profile-user-1", update)
        )
        assert result is not None


class TestChangePassword:
    def test_change_password_success(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage._write_user = AsyncMock()
        user_profile_service.security_service.send_password_changed_alert = AsyncMock(
            return_value=True
        )

        success, msg = asyncio_run(
            user_profile_service.change_password(
                "profile-user-1", "TestP@ss123!", "NewP@ss456!", ip_address="10.0.0.1"
            )
        )
        assert success is True
        assert "successfully" in msg.lower()
        # S7 regression: verify User object + ip passed, not destructured strings
        user_profile_service.security_service.send_password_changed_alert.assert_called_once()
        call_args = (
            user_profile_service.security_service.send_password_changed_alert.call_args
        )
        assert call_args[0][0] is user
        assert call_args[0][1] == "10.0.0.1"

    def test_change_password_wrong_current(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        success, msg = asyncio_run(
            user_profile_service.change_password(
                "profile-user-1", "WrongPass1!", "NewP@ss456!"
            )
        )
        assert success is False
        assert "incorrect" in msg.lower()

    def test_change_password_user_not_found(self, user_profile_service):
        user_profile_service.user_storage.get_user = AsyncMock(return_value=None)

        success, msg = asyncio_run(
            user_profile_service.change_password(
                "nonexistent", "OldPass1!", "NewP@ss456!"
            )
        )
        assert success is False
        assert "not found" in msg.lower()

    def test_change_password_alert_receives_user_object(self, user_profile_service):
        """S7 regression: send_password_changed_alert must receive User object, not strings."""
        from authglow.models.user import User as UserModel

        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage._write_user = AsyncMock()
        user_profile_service.security_service.send_password_changed_alert = AsyncMock()

        asyncio_run(
            user_profile_service.change_password(
                "profile-user-1", "TestP@ss123!", "NewP@ss456!"
            )
        )
        call_args = (
            user_profile_service.security_service.send_password_changed_alert.call_args
        )
        passed_user = call_args[0][0]
        assert isinstance(passed_user, UserModel)
        assert passed_user.email == "profile1@example.com"

    def test_change_password_alert_without_ip(self, user_profile_service):
        """S7 regression: ip_address defaults to None when not provided."""
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage._write_user = AsyncMock()
        user_profile_service.security_service.send_password_changed_alert = AsyncMock()

        asyncio_run(
            user_profile_service.change_password(
                "profile-user-1", "TestP@ss123!", "NewP@ss456!"
            )
        )
        user_profile_service.security_service.send_password_changed_alert.assert_called_once()
        call_args = (
            user_profile_service.security_service.send_password_changed_alert.call_args
        )
        assert call_args[0][1] is None


class TestChangeEmail:
    def test_change_email_success(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.get_user_by_email = AsyncMock(
            return_value=None
        )
        user_profile_service.user_storage._write_user = AsyncMock()
        user_profile_service.email_service.send_verification_email = AsyncMock(
            return_value=True
        )
        user_profile_service.security_service.send_email_changed_alert = AsyncMock(
            return_value=True
        )

        success, msg = asyncio_run(
            user_profile_service.change_email(
                "profile-user-1", "newemail@example.com", "TestP@ss123!"
            )
        )
        assert success is True

    def test_change_email_wrong_password(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        success, msg = asyncio_run(
            user_profile_service.change_email(
                "profile-user-1", "new@example.com", "WrongPass1!"
            )
        )
        assert success is False
        assert "incorrect" in msg.lower()

    def test_change_email_already_in_use(self, user_profile_service):
        user = _make_user()
        other_user = _make_user(user_id="other", email="taken@example.com")
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.get_user_by_email = AsyncMock(
            return_value=other_user
        )

        success, msg = asyncio_run(
            user_profile_service.change_email(
                "profile-user-1", "taken@example.com", "TestP@ss123!"
            )
        )
        assert success is False
        assert "in use" in msg.lower()


class TestDeleteAccount:
    def test_delete_account_success(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.delete_user = AsyncMock()

        success, msg = asyncio_run(
            user_profile_service.delete_account(
                "profile-user-1", "TestP@ss123!", "DELETE"
            )
        )
        assert success is True
        assert "deleted" in msg.lower()

    def test_delete_account_wrong_confirmation(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        success, msg = asyncio_run(
            user_profile_service.delete_account(
                "profile-user-1", "TestP@ss123!", "WRONG"
            )
        )
        assert success is False
        assert "DELETE" in msg

    def test_delete_account_wrong_password(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        success, msg = asyncio_run(
            user_profile_service.delete_account(
                "profile-user-1", "WrongPass1!", "DELETE"
            )
        )
        assert success is False
        assert "incorrect" in msg.lower()


class TestAccountStatus:
    def test_deactivate_account(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage._write_user = AsyncMock()

        success, msg = asyncio_run(
            user_profile_service.deactivate_account("profile-user-1")
        )
        assert success is True
        assert user.is_active is False

    def test_deactivate_account_not_found(self, user_profile_service):
        user_profile_service.user_storage.get_user = AsyncMock(return_value=None)

        success, msg = asyncio_run(
            user_profile_service.deactivate_account("nonexistent")
        )
        assert success is False

    def test_reactivate_account(self, user_profile_service):
        user = _make_user()
        user.is_active = False
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage._write_user = AsyncMock()

        success, msg = asyncio_run(
            user_profile_service.reactivate_account("profile-user-1")
        )
        assert success is True
        assert user.is_active is True


class TestUserPreferences:
    def test_get_default_preferences(self, user_profile_service):
        prefs = asyncio_run(
            user_profile_service.get_user_preferences("nonexistent-user")
        )
        assert prefs is not None
        assert prefs.user_id == "nonexistent-user"
        assert prefs.email_notifications is True
        assert prefs.theme == "auto"

    def test_update_preferences(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        update = UserPreferencesUpdate(theme="dark", language="it")
        prefs = asyncio_run(
            user_profile_service.update_user_preferences("profile-user-1", update)
        )
        assert prefs.theme == "dark"
        assert prefs.language == "it"
