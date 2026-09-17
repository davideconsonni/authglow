"""Execution tests for ``authglow.api.user_profile`` (COV-BE-008).

The service layer is covered in ``test_user_profile.py``; this module
pins the API layer with ``UserProfileService`` mocked at the module
boundary. Handlers are invoked directly (a real starlette ``Request``
/ ``Response`` where the limiter or cookies are involved).
"""

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request, Response


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _request(cookies=None):
    headers = []
    if cookies:
        headers.append((b"cookie", "; ".join(f"{k}={v}" for k, v in cookies.items()).encode()))
    request = Request({"type": "http", "method": "POST", "path": "", "headers": headers})
    request.state.view_rate_limit = None
    return request


def _user(**kw):
    from authglow.models.user import User

    base = {"id": "u-1", "email": "u@example.com", "hashed_password": "x", "scopes": ["read"]}
    base.update(kw)
    return User(**base)


def _svc(**methods):
    svc = MagicMock()
    for name, value in methods.items():
        setattr(svc, name, AsyncMock(return_value=value))
    return svc


class TestGetUpdateProfile:
    def test_get_profile(self):
        from authglow.api import user_profile as up_api

        profile = SimpleNamespace(scopes=[])
        svc = _svc(get_user_profile=profile)
        with patch.object(up_api, "UserProfileService", return_value=svc):
            out = _run(up_api.get_my_profile(_user()))
        assert out.scopes == ["read"]

    def test_get_profile_not_found(self):
        from authglow.api import user_profile as up_api

        svc = _svc(get_user_profile=None)
        with patch.object(up_api, "UserProfileService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(up_api.get_my_profile(_user()))
        assert exc.value.status_code == 404

    def test_update_profile(self):
        from authglow.api import user_profile as up_api
        from authglow.models.user_profile import UserProfileUpdate

        profile = SimpleNamespace(first_name="New")
        svc = _svc(update_user_profile=profile)
        with patch.object(up_api, "UserProfileService", return_value=svc):
            out = _run(
                up_api.update_my_profile(UserProfileUpdate(first_name="New"), _user())
            )
        assert out.first_name == "New"

    def test_update_profile_not_found(self):
        from authglow.api import user_profile as up_api
        from authglow.models.user_profile import UserProfileUpdate

        svc = _svc(update_user_profile=None)
        with patch.object(up_api, "UserProfileService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(up_api.update_my_profile(UserProfileUpdate(), _user()))
        assert exc.value.status_code == 404


class TestChangePassword:
    def _call(self, service_result, *, cookies=None, token_data=None):
        from authglow.api import user_profile as up_api
        from authglow.models.user_profile import ChangePasswordRequest

        svc = _svc(change_password=service_result)
        jwt_svc = MagicMock()
        jwt_svc.decode_token = MagicMock(return_value=token_data)
        blacklist = MagicMock()
        blacklist.revoke = AsyncMock()
        with (
            patch.object(up_api, "UserProfileService", return_value=svc),
            patch.object(up_api, "get_jwt_service", return_value=jwt_svc),
            patch.object(up_api, "token_blacklist", return_value=blacklist),
        ):
            out = _run(
                up_api.change_my_password(
                    ChangePasswordRequest(
                        current_password="old-secret-value",
                        new_password="brand-new-secret-value",
                    ),
                    _request(cookies),
                    Response(),
                    _user(),
                )
            )
        return out, blacklist

    def test_failure_400(self):
        from authglow.api import user_profile as up_api
        from authglow.models.user_profile import ChangePasswordRequest

        svc = _svc(change_password=(False, "wrong current password"))
        with patch.object(up_api, "UserProfileService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(
                    up_api.change_my_password(
                        ChangePasswordRequest(
                            current_password="wrong-value",
                            new_password="brand-new-secret-value",
                        ),
                        _request(),
                        Response(),
                        _user(),
                    )
                )
        assert exc.value.status_code == 400

    def test_success_without_cookie(self):
        out, blacklist = self._call((True, "ok"))
        assert "sign in again" in out["message"]
        blacklist.revoke.assert_not_awaited()

    def test_success_blacklists_jti(self):
        token_data = SimpleNamespace(jti="jti-1", exp=datetime.now(timezone.utc))
        out, blacklist = self._call(
            (True, "ok"), cookies={"access_token": "tok"}, token_data=token_data
        )
        assert "sign in again" in out["message"]
        blacklist.revoke.assert_awaited_once()

    def test_success_token_without_jti(self):
        out, blacklist = self._call(
            (True, "ok"),
            cookies={"access_token": "tok"},
            token_data=SimpleNamespace(jti=None, exp=None),
        )
        assert "sign in again" in out["message"]
        blacklist.revoke.assert_not_awaited()


class TestChangeEmailDelete:
    def test_change_email_success(self):
        from authglow.api import user_profile as up_api
        from authglow.models.user_profile import ChangeEmailRequest

        svc = _svc(change_email=(True, "check your inbox"))
        with patch.object(up_api, "UserProfileService", return_value=svc):
            out = _run(
                up_api.change_my_email(
                    ChangeEmailRequest(new_email="n@example.com", password="current-value"),
                    _request(),
                    _user(),
                )
            )
        assert out == {"message": "check your inbox"}

    def test_change_email_failure(self):
        from authglow.api import user_profile as up_api
        from authglow.models.user_profile import ChangeEmailRequest

        svc = _svc(change_email=(False, "wrong password"))
        with patch.object(up_api, "UserProfileService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(
                    up_api.change_my_email(
                        ChangeEmailRequest(new_email="n@example.com", password="bad"),
                        _request(),
                        _user(),
                    )
                )
        assert exc.value.status_code == 400

    def test_delete_account_success(self):
        from authglow.api import user_profile as up_api
        from authglow.models.user_profile import DeleteAccountRequest

        svc = _svc(delete_account=(True, "bye"))
        with patch.object(up_api, "UserProfileService", return_value=svc):
            out = _run(
                up_api.delete_my_account(
                    DeleteAccountRequest(password="current-value", confirmation="DELETE"),
                    _user(),
                )
            )
        assert out == {"message": "bye"}

    def test_delete_account_failure(self):
        from authglow.api import user_profile as up_api
        from authglow.models.user_profile import DeleteAccountRequest

        svc = _svc(delete_account=(False, "wrong confirmation"))
        with patch.object(up_api, "UserProfileService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(
                    up_api.delete_my_account(
                        DeleteAccountRequest(password="current-value", confirmation="nope"),
                        _user(),
                    )
                )
        assert exc.value.status_code == 400


class TestDeactivateChallenge:
    def test_issue_challenge(self):
        from authglow.api import user_profile as up_api

        out = _run(up_api.request_deactivate_challenge(_request(), _user(id="u-9")))
        assert out.challenge_id
        assert out.word

    def test_deactivate_success(self):
        from authglow.api import user_profile as up_api
        from authglow.api.user_profile import DeactivateConfirm
        from authglow.core.safeword_store import SafewordPurpose, issue_challenge

        issued = issue_challenge("u-1", SafewordPurpose.ACCOUNT_DEACTIVATE)
        svc = _svc(deactivate_account=(True, "deactivated"))
        rt_svc = MagicMock()
        rt_svc.revoke_user_tokens = AsyncMock()
        with (
            patch.object(up_api, "UserProfileService", return_value=svc),
            patch.object(up_api, "RefreshTokenService", return_value=rt_svc),
        ):
            out = _run(
                up_api.deactivate_my_account(
                    DeactivateConfirm(challenge_id=issued["challenge_id"], word=issued["word"]),
                    _request(),
                    Response(),
                    _user(),
                )
            )
        assert out == {"message": "deactivated"}
        rt_svc.revoke_user_tokens.assert_awaited_once_with("u-1")

    def test_deactivate_bad_challenge(self):
        from authglow.api import user_profile as up_api
        from authglow.api.user_profile import DeactivateConfirm

        with pytest.raises(HTTPException):
            _run(
                up_api.deactivate_my_account(
                    DeactivateConfirm(challenge_id="nope", word="wrong horse"),
                    _request(),
                    Response(),
                    _user(),
                )
            )

    def test_deactivate_service_failure(self):
        from authglow.api import user_profile as up_api
        from authglow.api.user_profile import DeactivateConfirm
        from authglow.core.safeword_store import SafewordPurpose, issue_challenge

        issued = issue_challenge("u-1", SafewordPurpose.ACCOUNT_DEACTIVATE)
        svc = _svc(deactivate_account=(False, "already inactive"))
        with patch.object(up_api, "UserProfileService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(
                    up_api.deactivate_my_account(
                        DeactivateConfirm(
                            challenge_id=issued["challenge_id"], word=issued["word"]
                        ),
                        _request(),
                        Response(),
                        _user(),
                    )
                )
        assert exc.value.status_code == 400


class TestReactivatePreferences:
    def test_reactivate_success(self):
        from authglow.api import user_profile as up_api

        svc = _svc(reactivate_account=(True, "welcome back"))
        with patch.object(up_api, "UserProfileService", return_value=svc):
            out = _run(up_api.reactivate_my_account(_user()))
        assert out == {"message": "welcome back"}

    def test_reactivate_failure(self):
        from authglow.api import user_profile as up_api

        svc = _svc(reactivate_account=(False, "not deactivated"))
        with patch.object(up_api, "UserProfileService", return_value=svc):
            with pytest.raises(HTTPException) as exc:
                _run(up_api.reactivate_my_account(_user()))
        assert exc.value.status_code == 400

    def test_get_preferences(self):
        from authglow.api import user_profile as up_api

        prefs = SimpleNamespace(theme="dark")
        svc = _svc(get_user_preferences=prefs)
        with patch.object(up_api, "UserProfileService", return_value=svc):
            out = _run(up_api.get_my_preferences(_user()))
        assert out.theme == "dark"

    def test_update_preferences(self):
        from authglow.api import user_profile as up_api
        from authglow.models.user_profile import UserPreferencesUpdate

        prefs = SimpleNamespace(theme="dark")
        svc = _svc(update_user_preferences=prefs)
        with patch.object(up_api, "UserProfileService", return_value=svc):
            out = _run(
                up_api.update_my_preferences(UserPreferencesUpdate(theme="dark"), _user())
            )
        assert out.theme == "dark"
        svc.update_user_preferences.assert_awaited_once()
