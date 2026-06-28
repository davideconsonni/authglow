import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from authglow.models.user import User
from authglow.models.user_profile import UserPreferencesUpdate, UserProfileUpdate
from authglow.services.password import hash_password


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
        user_profile_service.user_storage.update_user = AsyncMock()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        update = UserProfileUpdate(first_name="Updated")
        result = asyncio_run(user_profile_service.update_user_profile("profile-user-1", update))
        assert result is not None


class TestChangePassword:
    def test_change_password_success(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.update_user = AsyncMock()
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
        call_args = user_profile_service.security_service.send_password_changed_alert.call_args
        assert call_args[0][0] is user
        assert call_args[0][1] == "10.0.0.1"

    def test_change_password_wrong_current(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        success, msg = asyncio_run(
            user_profile_service.change_password("profile-user-1", "WrongPass1!", "NewP@ss456!")
        )
        assert success is False
        assert "incorrect" in msg.lower()

    def test_change_password_user_not_found(self, user_profile_service):
        user_profile_service.user_storage.get_user = AsyncMock(return_value=None)

        success, msg = asyncio_run(
            user_profile_service.change_password("nonexistent", "OldPass1!", "NewP@ss456!")
        )
        assert success is False
        assert "not found" in msg.lower()

    def test_change_password_alert_receives_user_object(self, user_profile_service):
        """S7 regression: send_password_changed_alert must receive User object, not strings."""
        from authglow.models.user import User as UserModel

        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.update_user = AsyncMock()
        user_profile_service.security_service.send_password_changed_alert = AsyncMock()

        asyncio_run(
            user_profile_service.change_password("profile-user-1", "TestP@ss123!", "NewP@ss456!")
        )
        call_args = user_profile_service.security_service.send_password_changed_alert.call_args
        passed_user = call_args[0][0]
        assert isinstance(passed_user, UserModel)
        assert passed_user.email == "profile1@example.com"

    def test_change_password_alert_without_ip(self, user_profile_service):
        """S7 regression: ip_address defaults to None when not provided."""
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.update_user = AsyncMock()
        user_profile_service.security_service.send_password_changed_alert = AsyncMock()

        asyncio_run(
            user_profile_service.change_password("profile-user-1", "TestP@ss123!", "NewP@ss456!")
        )
        user_profile_service.security_service.send_password_changed_alert.assert_called_once()
        call_args = user_profile_service.security_service.send_password_changed_alert.call_args
        assert call_args[0][1] is None


class TestChangeEmail:
    def test_change_email_success(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.get_user_by_email = AsyncMock(return_value=None)
        user_profile_service.user_storage.update_user = AsyncMock()
        mock_token = MagicMock()
        mock_token.verification_code = "ABCD-EFGH-JKMN"
        user_profile_service.email_service.create_verification_token = AsyncMock(
            return_value=mock_token
        )
        user_profile_service.email_service.send_verification_email = AsyncMock(return_value=True)
        user_profile_service.security_service.send_email_changed_alert = AsyncMock(
            return_value=True
        )
        user_profile_service.audit_service.log_event = AsyncMock()

        success, msg = asyncio_run(
            user_profile_service.change_email(
                "profile-user-1", "newemail@example.com", "TestP@ss123!"
            )
        )
        assert success is True
        # VAPT-130: self-service change_email must call the audit
        # log with event_type="user_email_changed", severity
        # "warning", and both old + new email in metadata.
        user_profile_service.audit_service.log_event.assert_awaited_once()
        call_kwargs = user_profile_service.audit_service.log_event.call_args.kwargs
        assert call_kwargs["event_type"] == "user_email_changed"
        assert call_kwargs["severity"] == "warning"
        assert call_kwargs["user_id"] == "profile-user-1"
        # The user's existing email is "profile1@example.com"
        # (set in ``_make_user``); the new email is the one
        # passed to ``change_email``.
        assert call_kwargs["metadata"]["old_email"] == "profile1@example.com"
        assert call_kwargs["metadata"]["new_email"] == "newemail@example.com"

    def test_change_email_wrong_password(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        success, msg = asyncio_run(
            user_profile_service.change_email("profile-user-1", "new@example.com", "WrongPass1!")
        )
        assert success is False
        assert "incorrect" in msg.lower()

    def test_change_email_already_in_use(self, user_profile_service):
        user = _make_user()
        other_user = _make_user(user_id="other", email="taken@example.com")
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.get_user_by_email = AsyncMock(return_value=other_user)

        success, msg = asyncio_run(
            user_profile_service.change_email("profile-user-1", "taken@example.com", "TestP@ss123!")
        )
        assert success is False
        assert "in use" in msg.lower()


class TestDeleteAccount:
    def test_delete_account_success(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.delete_user = AsyncMock()
        # VAPT-087 + VAPT-082: ``delete_account`` must revoke
        # refresh tokens AND trigger the GDPR purge. We mock the
        # internal ``_purge_user_pii`` to keep the test focused
        # on the VAPT-087 behaviour; the dedicated purge tests
        # below exercise the multi-repo path in detail.
        with (
            patch("authglow.services.refresh_token.RefreshTokenService") as mock_rts,
            patch.object(user_profile_service, "_purge_user_pii", new=AsyncMock()),
        ):
            mock_rts.return_value.revoke_user_tokens = AsyncMock(return_value=0)

            success, msg = asyncio_run(
                user_profile_service.delete_account("profile-user-1", "TestP@ss123!", "DELETE")
            )
            assert success is True
            assert "deleted" in msg.lower()
            mock_rts.return_value.revoke_user_tokens.assert_awaited_once_with("profile-user-1")

    def test_delete_account_wrong_confirmation(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        success, msg = asyncio_run(
            user_profile_service.delete_account("profile-user-1", "TestP@ss123!", "WRONG")
        )
        assert success is False
        assert "DELETE" in msg

    def test_delete_account_wrong_password(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        success, msg = asyncio_run(
            user_profile_service.delete_account("profile-user-1", "WrongPass1!", "DELETE")
        )
        assert success is False
        assert "incorrect" in msg.lower()

    def test_delete_account_triggers_purge_pii(self, user_profile_service):
        """VAPT-082 — ``delete_account`` must trigger the
        ``_purge_user_pii`` GDPR right-to-erasure path after
        the user record is dropped.
        """
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.delete_user = AsyncMock()
        with patch("authglow.services.refresh_token.RefreshTokenService") as mock_rts:
            mock_rts.return_value.revoke_user_tokens = AsyncMock(return_value=0)
            with patch.object(
                user_profile_service, "_purge_user_pii", new=AsyncMock()
            ) as mock_purge:
                success, _ = asyncio_run(
                    user_profile_service.delete_account("profile-user-1", "TestP@ss123!", "DELETE")
                )
                assert success is True
                mock_purge.assert_awaited_once_with("profile-user-1")

    def test_purge_user_pii_calls_all_repositories(self, user_profile_service):
        """VAPT-082 — ``_purge_user_pii`` must drop login history,
        security events, admin actions, and OAuth2 consents
        for the user.
        """
        # All four delete_for_user calls are awaited in parallel;
        # patch them with AsyncMocks that return a count.
        with (
            patch("authglow.services.login_history.LoginHistoryService") as mock_login_cls,
            patch("authglow.services.security_event.SecurityEventService") as mock_sec_cls,
            patch("authglow.services.admin_action.AdminActionService") as mock_admin_cls,
            patch("authglow.services.oauth_consent.OAuth2ConsentService") as mock_consent_cls,
        ):
            mock_login_cls.return_value.delete_for_user = AsyncMock(return_value=3)
            mock_sec_cls.return_value.delete_for_user = AsyncMock(return_value=1)
            mock_admin_cls.return_value.delete_for_user = AsyncMock(return_value=2)
            mock_consent_cls.return_value.delete_for_user = AsyncMock(return_value=4)

            counts = asyncio_run(user_profile_service._purge_user_pii("user-x"))

            assert counts == {
                "login_history": 3,
                "security_event": 1,
                "admin_action": 2,
                "oauth_consent": 4,
            }
            mock_login_cls.return_value.delete_for_user.assert_awaited_once_with("user-x")
            mock_sec_cls.return_value.delete_for_user.assert_awaited_once_with("user-x")
            mock_admin_cls.return_value.delete_for_user.assert_awaited_once_with("user-x")
            mock_consent_cls.return_value.delete_for_user.assert_awaited_once_with("user-x")

    def test_purge_user_pii_continues_on_partial_failure(self, user_profile_service):
        """VAPT-082 — GDPR right-to-erasure should not abort the
        whole purge if one repo raises. Failures are recorded
        as -1 in the count dict.
        """
        with (
            patch("authglow.services.login_history.LoginHistoryService") as mock_login_cls,
            patch("authglow.services.security_event.SecurityEventService") as mock_sec_cls,
            patch("authglow.services.admin_action.AdminActionService") as mock_admin_cls,
            patch("authglow.services.oauth_consent.OAuth2ConsentService") as mock_consent_cls,
        ):
            mock_login_cls.return_value.delete_for_user = AsyncMock(
                side_effect=OSError("disk full")
            )
            mock_sec_cls.return_value.delete_for_user = AsyncMock(return_value=1)
            mock_admin_cls.return_value.delete_for_user = AsyncMock(return_value=0)
            mock_consent_cls.return_value.delete_for_user = AsyncMock(return_value=2)

            counts = asyncio_run(user_profile_service._purge_user_pii("user-x"))

            assert counts["login_history"] == -1
            assert counts["security_event"] == 1
            assert counts["admin_action"] == 0
            assert counts["oauth_consent"] == 2


class TestAccountStatus:
    def test_deactivate_account(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.update_user = AsyncMock()

        success, msg = asyncio_run(user_profile_service.deactivate_account("profile-user-1"))
        assert success is True
        assert user.is_active is False

    def test_deactivate_account_not_found(self, user_profile_service):
        user_profile_service.user_storage.get_user = AsyncMock(return_value=None)

        success, msg = asyncio_run(user_profile_service.deactivate_account("nonexistent"))
        assert success is False

    def test_reactivate_account(self, user_profile_service):
        user = _make_user()
        user.is_active = False
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)
        user_profile_service.user_storage.update_user = AsyncMock()

        success, msg = asyncio_run(user_profile_service.reactivate_account("profile-user-1"))
        assert success is True
        assert user.is_active is True


class TestUserPreferences:
    def test_get_default_preferences(self, user_profile_service):
        prefs = asyncio_run(user_profile_service.get_user_preferences("nonexistent-user"))
        assert prefs is not None
        assert prefs.user_id == "nonexistent-user"
        assert prefs.email_notifications is True
        assert prefs.theme == "light"

    def test_update_preferences(self, user_profile_service):
        user = _make_user()
        user_profile_service.user_storage.get_user = AsyncMock(return_value=user)

        update = UserPreferencesUpdate(theme="dark", language="it")
        prefs = asyncio_run(user_profile_service.update_user_preferences("profile-user-1", update))
        assert prefs.theme == "dark"
        assert prefs.language == "it"
