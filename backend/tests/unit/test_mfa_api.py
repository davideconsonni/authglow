"""Execution tests for ``authglow.api.mfa`` (COV-BE-009).

The MFA service layer is covered by ``tests/unit/test_mfa.py`` and the
enroll/disable happy paths by ``tests/integration/test_mfa_api.py``.
This module pins the API layer at the handler boundary: the two
login-completion endpoints (TOTP + backup code + every guard), the
trusted-device / status / regenerate-backup-codes routes, and the error
branches the integration suite never reaches.

Handlers are invoked directly (a real starlette ``Request`` where the
limiter is involved); internal collaborators that do disk I/O
(``LoginHistoryService``, ``RefreshTokenService``, ``ClaimPolicyService``,
the token blacklist singleton) are patched at their source module so the
test exercises the handler logic, not the filesystem.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import BackgroundTasks, HTTPException, Request, Response

from authglow.core.datetime import utcnow


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _request():
    request = Request({"type": "http", "method": "POST", "path": "", "headers": []})
    request.state.view_rate_limit = None
    return request


def _user(**kw):
    from authglow.models.user import User

    base = {"id": "u-1", "email": "u@example.com", "hashed_password": "x", "scopes": ["read"]}
    base.update(kw)
    return User(**base)


def _token_data(**kw):
    base = {
        "sub": "u-1",
        "token_type": "mfa_session",
        "jti": "jti-1",
        "exp": datetime.now(timezone.utc),
    }
    base.update(kw)
    return SimpleNamespace(**base)


class _LoginHarness:
    """Wires the mocks ``verify_mfa_login`` reaches for internally."""

    def __init__(self, user, *, verify_totp=True, backup_result=False, backup_exc=None):
        self.user = user
        self.storage = MagicMock()
        self.storage.get_user = AsyncMock(return_value=user)
        self.storage.update_last_login = AsyncMock()
        self.storage.update_user = AsyncMock()

        self.mfa = MagicMock()
        self.mfa.verify_totp = MagicMock(return_value=verify_totp)
        if backup_exc is not None:
            self.mfa.verify_user_backup_code = AsyncMock(side_effect=backup_exc)
        else:
            self.mfa.verify_user_backup_code = AsyncMock(return_value=backup_result)

        self.jwt = MagicMock()
        self.jwt.decode_token = MagicMock(return_value=_token_data())
        self.token_response = SimpleNamespace(access_token="acc", refresh_token=None)
        self.jwt.create_token_response = MagicMock(return_value=self.token_response)

        self.audit = MagicMock()
        self.audit.log_event = AsyncMock()

        self.rt = MagicMock()
        self.rt.create_refresh_token = AsyncMock(return_value=SimpleNamespace(token="rt"))
        self.cp = MagicMock()
        self.cp.build_claims = AsyncMock(return_value={})
        self.blacklist = MagicMock()
        self.blacklist.revoke = AsyncMock()
        self.login = MagicMock()
        self.login.record_login = AsyncMock()

    def call(self, code="123456", *, token_data=None):
        from authglow.api import mfa as mfa_api
        from authglow.models.mfa import MFALoginRequest

        if token_data is not None:
            self.jwt.decode_token = MagicMock(return_value=token_data)
        with (
            patch.object(
                mfa_api,
                "get_settings",
                return_value=SimpleNamespace(refresh_token_expire_days=30, issuer="https://iss"),
            ),
            patch.object(mfa_api, "_set_auth_cookies") as set_cookies,
            patch("authglow.services.login_history.LoginHistoryService", return_value=self.login),
            patch("authglow.services.refresh_token.RefreshTokenService", return_value=self.rt),
            patch("authglow.services.claim_policy.ClaimPolicyService", return_value=self.cp),
            patch(
                "authglow.services.auth.token_blacklist.token_blacklist",
                return_value=self.blacklist,
            ),
        ):
            self.set_cookies = set_cookies
            return _run(
                mfa_api.verify_mfa_login(
                    Response(),
                    MFALoginRequest(session_token="sess", code=code),
                    self.storage,
                    self.mfa,
                    self.jwt,
                    self.audit,
                    _request(),
                )
            )


class TestDependencyFactories:
    def test_get_mfa_service_constructs_service(self):
        from authglow.api import mfa as mfa_api

        with patch.object(mfa_api, "MFAService") as cls:
            result = mfa_api.get_mfa_service()
        cls.assert_called_once_with()
        assert result is cls.return_value

    def test_get_user_storage_constructs_service(self):
        from authglow.api import mfa as mfa_api

        with patch.object(mfa_api, "UserStorage") as cls:
            result = mfa_api.get_user_storage()
        cls.assert_called_once_with()
        assert result is cls.return_value

    def test_get_audit_service_constructs_service(self):
        from authglow.api import mfa as mfa_api

        with patch.object(mfa_api, "AuditService") as cls:
            result = mfa_api.get_audit_service()
        cls.assert_called_once_with()
        assert result is cls.return_value


class TestSelfHealSecret:
    def test_noop_when_plain_secret_missing(self):
        from authglow.api import mfa as mfa_api

        storage = MagicMock()
        storage.update_user = AsyncMock()
        user = _user(mfa_secret="ag1:ciphertext")
        _run(mfa_api._self_heal_mfa_secret(user, storage, ""))
        storage.update_user.assert_not_awaited()

    def test_noop_when_user_has_no_secret(self):
        from authglow.api import mfa as mfa_api

        storage = MagicMock()
        storage.update_user = AsyncMock()
        user = _user(mfa_secret=None)
        _run(mfa_api._self_heal_mfa_secret(user, storage, "JBSWY3DPEHPK3PXP"))
        storage.update_user.assert_not_awaited()


class TestEnrollMfa:
    def test_unknown_user_404(self):
        from authglow.api import mfa as mfa_api

        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(mfa_api.enroll_mfa(_user(), MagicMock(), storage))
        assert exc.value.status_code == 404


class TestVerifyEnrollment:
    def test_missing_secret_400(self):
        from authglow.api import mfa as mfa_api
        from authglow.models.mfa import MFAVerifyRequest

        with pytest.raises(HTTPException) as exc:
            _run(
                mfa_api.verify_mfa_enrollment(
                    MFAVerifyRequest(code="123456"),
                    _user(mfa_secret=None),
                    MagicMock(),
                    MagicMock(),
                    MagicMock(),
                )
            )
        assert exc.value.status_code == 400

    def test_already_verified_400(self):
        from authglow.api import mfa as mfa_api
        from authglow.models.mfa import MFAVerifyRequest

        user = _user(mfa_secret="ag1:x", mfa_enabled=True, mfa_verified=True)
        with pytest.raises(HTTPException) as exc:
            _run(
                mfa_api.verify_mfa_enrollment(
                    MFAVerifyRequest(code="123456"), user, MagicMock(), MagicMock(), MagicMock()
                )
            )
        assert exc.value.status_code == 400


class TestDisableMfa:
    def test_without_mfa_state_400(self):
        from authglow.api import mfa as mfa_api

        with pytest.raises(HTTPException) as exc:
            _run(
                mfa_api.disable_mfa(
                    _request(), BackgroundTasks(), _user(), MagicMock(), MagicMock(), MagicMock()
                )
            )
        assert exc.value.status_code == 400


class TestMfaStatus:
    def test_status_reports_counts(self):
        from authglow.api import mfa as mfa_api

        mfa_svc = MagicMock()
        mfa_svc.get_backup_codes = AsyncMock(return_value=SimpleNamespace(codes=["a", "b", "c"]))
        mfa_svc.list_trusted_devices = AsyncMock(return_value=[MagicMock(), MagicMock()])
        user = _user(mfa_enabled=True, mfa_verified=True)
        out = _run(mfa_api.get_mfa_status(user, mfa_svc))
        assert out.enabled is True
        assert out.verified is True
        assert out.backup_codes_remaining == 3
        assert out.trusted_devices_count == 2


class TestTrustedDevices:
    def test_list_returns_service_result(self):
        from authglow.api import mfa as mfa_api

        device = SimpleNamespace(id="d-1")
        mfa_svc = MagicMock()
        mfa_svc.list_trusted_devices = AsyncMock(return_value=[device])
        out = _run(mfa_api.list_trusted_devices(_user(), mfa_svc))
        assert out == [device]

    def test_remove_success_audits(self):
        from authglow.api import mfa as mfa_api

        mfa_svc = MagicMock()
        mfa_svc.list_trusted_devices = AsyncMock(return_value=[SimpleNamespace(id="d-1")])
        mfa_svc.remove_trusted_device = AsyncMock(return_value=True)
        audit = MagicMock()
        audit.log_event = AsyncMock()
        out = _run(mfa_api.remove_trusted_device("d-1", _user(), mfa_svc, audit))
        assert out == {"message": "Device removed successfully"}
        audit.log_event.assert_awaited_once()

    def test_remove_device_not_owned_404(self):
        from authglow.api import mfa as mfa_api

        mfa_svc = MagicMock()
        mfa_svc.list_trusted_devices = AsyncMock(return_value=[SimpleNamespace(id="other")])
        with pytest.raises(HTTPException) as exc:
            _run(mfa_api.remove_trusted_device("d-1", _user(), mfa_svc, MagicMock()))
        assert exc.value.status_code == 404

    def test_remove_service_returns_false_404(self):
        from authglow.api import mfa as mfa_api

        mfa_svc = MagicMock()
        mfa_svc.list_trusted_devices = AsyncMock(return_value=[SimpleNamespace(id="d-1")])
        mfa_svc.remove_trusted_device = AsyncMock(return_value=False)
        with pytest.raises(HTTPException) as exc:
            _run(mfa_api.remove_trusted_device("d-1", _user(), mfa_svc, MagicMock()))
        assert exc.value.status_code == 404


class TestRegenerateBackupCodes:
    def test_requires_enabled_and_verified_400(self):
        from authglow.api import mfa as mfa_api

        with pytest.raises(HTTPException) as exc:
            _run(
                mfa_api.regenerate_backup_codes(
                    _user(mfa_enabled=True, mfa_verified=False), MagicMock(), MagicMock()
                )
            )
        assert exc.value.status_code == 400

    def test_success_returns_new_codes(self):
        from authglow.api import mfa as mfa_api

        mfa_svc = MagicMock()
        mfa_svc.generate_backup_codes = MagicMock(return_value=["aaaa-1111", "bbbb-2222"])
        mfa_svc.save_backup_codes = AsyncMock()
        audit = MagicMock()
        audit.log_event = AsyncMock()
        user = _user(mfa_enabled=True, mfa_verified=True)
        out = _run(mfa_api.regenerate_backup_codes(user, mfa_svc, audit))
        assert out["backup_codes"] == ["aaaa-1111", "bbbb-2222"]
        mfa_svc.save_backup_codes.assert_awaited_once_with(user.id, ["aaaa-1111", "bbbb-2222"])
        audit.log_event.assert_awaited_once()


class TestVerifyMfaLogin:
    def test_requires_session_token_401(self):
        from authglow.api import mfa as mfa_api
        from authglow.models.mfa import MFALoginRequest

        with pytest.raises(HTTPException) as exc:
            _run(
                mfa_api.verify_mfa_login(
                    Response(),
                    MFALoginRequest(session_token="", code="123456"),
                    MagicMock(),
                    MagicMock(),
                    MagicMock(),
                    MagicMock(),
                    _request(),
                )
            )
        assert exc.value.status_code == 401

    def test_invalid_session_token_401(self):
        from authglow.api import mfa as mfa_api
        from authglow.models.mfa import MFALoginRequest

        jwt_svc = MagicMock()
        jwt_svc.decode_token = MagicMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(
                mfa_api.verify_mfa_login(
                    Response(),
                    MFALoginRequest(session_token="sess", code="123456"),
                    MagicMock(),
                    MagicMock(),
                    jwt_svc,
                    MagicMock(),
                    _request(),
                )
            )
        assert exc.value.status_code == 401

    def test_wrong_token_type_401(self):

        harness = _LoginHarness(_user())
        with pytest.raises(HTTPException) as exc:
            harness.call(token_data=_token_data(token_type="access"))
        assert exc.value.status_code == 401

    def test_user_not_found_404(self):

        harness = _LoginHarness(_user())
        harness.storage.get_user = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            harness.call()
        assert exc.value.status_code == 404

    def test_mfa_not_enabled_400(self):

        harness = _LoginHarness(_user(mfa_enabled=False, mfa_verified=False))
        with pytest.raises(HTTPException) as exc:
            harness.call()
        assert exc.value.status_code == 400

    def test_suspended_account_423(self):

        harness = _LoginHarness(
            _user(
                mfa_enabled=True,
                mfa_verified=True,
                mfa_secret="ag1:x",
                suspended_until=utcnow() + timedelta(hours=1),
            )
        )
        with pytest.raises(HTTPException) as exc:
            harness.call()
        assert exc.value.status_code == 423

    def test_totp_missing_secret_500(self):

        harness = _LoginHarness(_user(mfa_enabled=True, mfa_verified=True, mfa_secret=None))
        with pytest.raises(HTTPException) as exc:
            harness.call()
        assert exc.value.status_code == 500

    def test_totp_success_issues_cookies(self):
        from authglow.core.crypto import encrypt_totp_secret

        harness = _LoginHarness(
            _user(
                mfa_enabled=True,
                mfa_verified=True,
                mfa_secret=encrypt_totp_secret("JBSWY3DPEHPK3PXP"),
            )
        )
        out = harness.call()
        assert out is harness.token_response
        harness.storage.update_last_login.assert_awaited_once_with("u-1")
        harness.blacklist.revoke.assert_awaited_once()
        harness.set_cookies.assert_called_once()
        harness.login.record_login.assert_awaited_once()
        assert harness.audit.log_event.await_count == 1

    def test_totp_invalid_records_failure(self):
        from authglow.core.crypto import encrypt_totp_secret

        harness = _LoginHarness(
            _user(
                mfa_enabled=True,
                mfa_verified=True,
                mfa_secret=encrypt_totp_secret("JBSWY3DPEHPK3PXP"),
            ),
            verify_totp=False,
        )
        with pytest.raises(HTTPException) as exc:
            harness.call()
        assert exc.value.status_code == 401
        harness.storage.update_last_login.assert_not_awaited()
        harness.login.record_login.assert_awaited_once()
        assert harness.login.record_login.await_args.kwargs["success"] is False

    def test_backup_code_success(self):
        harness = _LoginHarness(
            _user(mfa_enabled=True, mfa_verified=True, mfa_secret="ag1:x"),
            backup_result=True,
        )
        out = harness.call(code="BACKUP12")
        assert out is harness.token_response
        kwargs = harness.audit.log_event.await_args.kwargs
        assert kwargs["metadata"].method == "backup_code"

    def test_backup_code_invalid_401(self):
        harness = _LoginHarness(
            _user(mfa_enabled=True, mfa_verified=True, mfa_secret="ag1:x"),
            backup_result=False,
        )
        with pytest.raises(HTTPException) as exc:
            harness.call(code="BACKUP12")
        assert exc.value.status_code == 401
        # ``is_backup_code`` is only set on success, so a failed backup-code
        # attempt is reported as ``totp`` — pinned here, not endorsed.
        assert harness.audit.log_event.await_args.kwargs["metadata"].method == "totp"

    def test_totp_success_without_jti_skips_blacklist(self):
        from authglow.core.crypto import encrypt_totp_secret

        harness = _LoginHarness(
            _user(
                mfa_enabled=True,
                mfa_verified=True,
                mfa_secret=encrypt_totp_secret("JBSWY3DPEHPK3PXP"),
            )
        )
        out = harness.call(token_data=_token_data(jti=None))
        assert out is harness.token_response
        harness.blacklist.revoke.assert_not_awaited()

    def test_backup_code_locked_429(self):
        from authglow.services.mfa import BackupCodeLockedException

        harness = _LoginHarness(
            _user(mfa_enabled=True, mfa_verified=True, mfa_secret="ag1:x"),
            backup_exc=BackupCodeLockedException("u-1", 42),
        )
        with pytest.raises(HTTPException) as exc:
            harness.call(code="BACKUP12")
        assert exc.value.status_code == 429
        assert exc.value.headers["Retry-After"] == "42"


class _OAuthHarness:
    def __init__(
        self,
        *,
        session=...,
        user=...,
        client=...,
        consent=(True, None),
        backup_result=False,
        backup_exc=None,
        verify_totp=True,
    ):
        self.session = (
            SimpleNamespace(
                user_id="u-1",
                client_id="c-1",
                redirect_uri="https://cb.example",
                scope="read write",
                state="st",
                code_challenge=None,
                code_challenge_method=None,
                nonce=None,
            )
            if session is ...
            else session
        )
        self.storage = MagicMock()
        self.storage.get_user = AsyncMock(return_value=user)
        self.storage.update_last_login = AsyncMock()

        self.mfa = MagicMock()
        self.mfa.verify_totp = MagicMock(return_value=verify_totp)
        if backup_exc is not None:
            self.mfa.verify_user_backup_code = AsyncMock(side_effect=backup_exc)
        else:
            self.mfa.verify_user_backup_code = AsyncMock(return_value=backup_result)

        self.session_svc = MagicMock()
        self.session_svc.get_mfa_session = AsyncMock(return_value=self.session)
        self.session_svc.delete_mfa_session = AsyncMock()
        self.session_svc.create_consent_session = AsyncMock(
            return_value={"session_token": "consent-sess"}
        )

        self.oauth2 = MagicMock()
        self.oauth2.create_authorization_code = AsyncMock(
            return_value=SimpleNamespace(code="auth-code")
        )
        self.consent = MagicMock()
        self.consent.check_consent = AsyncMock(return_value=consent)
        self.client_storage = MagicMock()
        self.client_storage.get_client = AsyncMock(return_value=client)

    def call(self, code="123456"):
        from authglow.api import mfa as mfa_api
        from authglow.models.mfa import MFALoginRequest

        with patch.object(
            mfa_api,
            "get_settings",
            return_value=SimpleNamespace(
                issuer="https://iss.example", refresh_token_expire_days=30
            ),
        ):
            return _run(
                mfa_api.verify_oauth_mfa_login(
                    _request(),
                    MFALoginRequest(session_token="sess", code=code),
                    self.storage,
                    self.mfa,
                    self.session_svc,
                    self.oauth2,
                    self.consent,
                    self.client_storage,
                )
            )


def _oauth_user(**kw):
    base = {
        "mfa_enabled": True,
        "mfa_verified": True,
        "mfa_secret": "ag1:x",
        "is_active": True,
    }
    base.update(kw)
    return _user(**base)


class TestVerifyOAuthMfaLogin:
    def test_missing_session_401(self):
        harness = _OAuthHarness(session=None)
        with pytest.raises(HTTPException) as exc:
            harness.call()
        assert exc.value.status_code == 401

    @pytest.mark.parametrize(
        "user",
        [None, _oauth_user(is_active=False), _oauth_user(mfa_enabled=False)],
    )
    def test_user_not_eligible_401(self, user):
        harness = _OAuthHarness(user=user)
        with pytest.raises(HTTPException) as exc:
            harness.call()
        assert exc.value.status_code == 401

    def test_totp_missing_secret_500(self):
        harness = _OAuthHarness(user=_oauth_user(mfa_secret=None))
        with pytest.raises(HTTPException) as exc:
            harness.call()
        assert exc.value.status_code == 500

    def test_totp_invalid_401(self):
        from authglow.core.crypto import encrypt_totp_secret

        harness = _OAuthHarness(
            user=_oauth_user(mfa_secret=encrypt_totp_secret("JBSWY3DPEHPK3PXP")),
            verify_totp=False,
        )
        with pytest.raises(HTTPException) as exc:
            harness.call()
        assert exc.value.status_code == 401

    def test_backup_code_locked_429(self):
        from authglow.services.mfa import BackupCodeLockedException

        harness = _OAuthHarness(user=_oauth_user(), backup_exc=BackupCodeLockedException("u-1", 30))
        with pytest.raises(HTTPException) as exc:
            harness.call(code="BACKUP12")
        assert exc.value.status_code == 429

    def test_client_missing_400(self):
        from authglow.core.crypto import encrypt_totp_secret

        harness = _OAuthHarness(
            user=_oauth_user(mfa_secret=encrypt_totp_secret("JBSWY3DPEHPK3PXP")), client=None
        )
        with pytest.raises(HTTPException) as exc:
            harness.call()
        assert exc.value.status_code == 400

    def test_client_inactive_400(self):
        from authglow.core.crypto import encrypt_totp_secret

        harness = _OAuthHarness(
            user=_oauth_user(mfa_secret=encrypt_totp_secret("JBSWY3DPEHPK3PXP")),
            client=SimpleNamespace(is_active=False, require_consent=False),
        )
        with pytest.raises(HTTPException) as exc:
            harness.call()
        assert exc.value.status_code == 400

    def test_totp_success_redirect(self):
        from authglow.core.crypto import encrypt_totp_secret

        harness = _OAuthHarness(
            user=_oauth_user(mfa_secret=encrypt_totp_secret("JBSWY3DPEHPK3PXP")),
            client=SimpleNamespace(is_active=True, require_consent=False),
        )
        out = harness.call()
        assert out["redirect_url"].startswith("https://cb.example")
        harness.session_svc.delete_mfa_session.assert_awaited_once()
        harness.oauth2.create_authorization_code.assert_awaited_once()
        assert harness.oauth2.create_authorization_code.await_args.kwargs["acr"] == "2"

    def test_backup_code_success_redirect(self):
        harness = _OAuthHarness(
            user=_oauth_user(),
            client=SimpleNamespace(is_active=True, require_consent=False),
            backup_result=True,
        )
        out = harness.call(code="BACKUP12")
        assert out["redirect_url"].startswith("https://cb.example")

    def test_consent_required_returns_consent_session(self):
        from authglow.core.crypto import encrypt_totp_secret

        harness = _OAuthHarness(
            user=_oauth_user(mfa_secret=encrypt_totp_secret("JBSWY3DPEHPK3PXP")),
            client=SimpleNamespace(is_active=True, require_consent=True),
            consent=(False, None),
        )
        out = harness.call()
        assert out == {"consent_session_token": "consent-sess"}
        harness.oauth2.create_authorization_code.assert_not_awaited()
