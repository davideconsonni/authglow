"""B3 regression: real code paths emit the right webhook events.

Every test patches ``emit_webhook_event`` at its source module (the hooks
lazy-import it at call time, so patching the dispatcher-module attribute
works) and asserts event_type + payload shape. Real services run against
per-test tmp storage.
"""

from unittest.mock import AsyncMock, MagicMock, patch

from authglow.models.user import User
from authglow.models.webhook_events import (
    LOGIN_FAILED,
    LOGIN_SUCCESS,
    PASSWORD_CHANGED,
    SESSION_REVOKED,
    USER_CREATED,
    USER_DELETED,
)
from authglow.services.password import hash_password


def _make_user(email="b3@example.com"):
    return User(
        id="user-b3-1",
        email=email,
        hashed_password=hash_password("TestP@ss123!"),
        is_active=True,
        email_verified=True,
        scopes=["read"],
    )


def _captured():
    """Patch emit_webhook_event and return the call-recording mock."""
    mock = MagicMock()
    p = patch("authglow.services.webhook_dispatcher.emit_webhook_event", mock)
    return mock, p


class TestUserLifecycleEmissions:
    async def test_create_user_emits_user_created(self, test_settings):
        from authglow.services.user import UserService

        svc = UserService()
        user = _make_user()
        mock, p = _captured()
        with p:
            await svc.create_user(user)

        mock.assert_called_once_with(
            USER_CREATED, {"user_id": user.id, "email": user.email}
        )

    async def test_delete_user_emits_user_deleted(self, test_settings):
        from authglow.services.user import UserService

        svc = UserService()
        user = _make_user("b3-del@example.com")
        user.id = "user-b3-del"
        await svc.create_user(user)

        mock, p = _captured()
        with p:
            deleted = await svc.delete_user(user.id)

        assert deleted is True
        mock.assert_called_once_with(USER_DELETED, {"user_id": user.id, "email": user.email})


class TestLoginEmissions:
    async def test_record_login_success_and_failed(self, test_settings):
        from authglow.services.login_history import LoginHistoryService

        svc = LoginHistoryService()
        mock, p = _captured()

        with p:
            await svc.record_login(
                user_id="u1", email="l@example.com", success=True, ip_address="10.0.0.9"
            )
        args = mock.call_args
        assert args.args[0] == LOGIN_SUCCESS
        assert args.args[1]["email"] == "l@example.com"

        with p:
            await svc.record_login(
                user_id="u1",
                email="l@example.com",
                success=False,
                failure_reason="bad_password",
            )
        args = mock.call_args
        assert args.args[0] == LOGIN_FAILED
        assert args.args[1]["failure_reason"] == "bad_password"


class TestPasswordChangedEmission:
    async def test_profile_change_password_emits(self, user_profile_service):

        user_profile_service.user_storage.get_user = AsyncMock(return_value=_make_user())
        user_profile_service.user_storage.update_user = AsyncMock()
        user_profile_service.security_service.send_password_changed_alert = AsyncMock()

        with patch(
            "authglow.services.refresh_token.RefreshTokenService"
        ) as rt_cls, patch(
            "authglow.services.webhook_dispatcher.emit_webhook_event"
        ) as emit:
            rt_cls.return_value.revoke_user_tokens = AsyncMock()
            await user_profile_service.change_password(
                "profile-user-1", "TestP@ss123!", "NewP@ss456!"
            )

        assert emit.call_count == 1
        call = emit.call_args
        assert call.args[0] == PASSWORD_CHANGED
        assert call.args[1] == {"user_id": "profile-user-1"}


class TestSessionRevokedEmission:
    async def test_revoke_user_tokens_emits_with_count(self, test_settings):
        from authglow.services.refresh_token import RefreshTokenService

        svc = RefreshTokenService()
        svc._repo = AsyncMock()
        svc._repo.revoke_user_tokens = AsyncMock(return_value=4)

        mock, p = _captured()
        with p:
            count = await svc.revoke_user_tokens("u-revoked")

        assert count == 4
        mock.assert_called_once_with(SESSION_REVOKED, {"user_id": "u-revoked", "revoked_count": 4})
