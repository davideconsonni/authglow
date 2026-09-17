"""Execution tests for ``authglow.api.password_reset`` (COV-BE-007).

``change_expired_password`` is covered via HTTP in
``test_expired_password_flow.py``; this module pins the request/confirm
endpoints and the admin endpoints. Handlers are invoked directly with
mocked services (no disk, no network).
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request


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


def _admin():
    return _user(id="admin-1", email="admin@example.com")


def _token(**kw):
    base = {"token_id": "tok-1", "token_lookup": "lookup-1", "user_id": "u-1"}
    base.update(kw)
    return SimpleNamespace(**base)


class TestRequestPasswordReset:
    def _call(self, email, user):
        from authglow.api import password_reset as pr_api
        from authglow.models.password_reset import PasswordResetRequest

        storage = MagicMock()
        storage.get_user_by_email = AsyncMock(return_value=user)
        reset_svc = MagicMock()
        reset_svc.revoke_user_tokens = AsyncMock()
        reset_svc.create_reset_token = AsyncMock(
            return_value=(SimpleNamespace(token_id="tok-1"), "plaintext", "ABCD-EFGH-JKLM")
        )
        email_svc = MagicMock()
        email_svc.send_template = AsyncMock()
        audit = MagicMock()
        audit.log_event = AsyncMock()
        out = _run(
            pr_api.request_password_reset(
                _request(),
                PasswordResetRequest(email=email),
                reset_svc,
                storage,
                audit,
                email_svc,
            )
        )
        return out, {"storage": storage, "reset": reset_svc, "email": email_svc, "audit": audit}

    def test_unknown_email_returns_success_and_audits(self):
        out, mocks = self._call("ghost@example.com", None)
        assert "If this email exists" in out.message
        assert mocks["audit"].log_event.call_args.kwargs["event_type"] == "password_reset_failed"
        mocks["reset"].create_reset_token.assert_not_awaited()
        mocks["email"].send_template.assert_not_awaited()

    def test_inactive_user_returns_success_and_audits(self):
        out, mocks = self._call("u@example.com", _user(is_active=False))
        assert "If this email exists" in out.message
        assert mocks["audit"].log_event.call_args.kwargs["event_type"] == "password_reset_failed"
        mocks["reset"].create_reset_token.assert_not_awaited()

    def test_success_sends_email_and_audits(self):
        out, mocks = self._call("u@example.com", _user())
        assert "If this email exists" in out.message
        mocks["reset"].revoke_user_tokens.assert_awaited_once_with("u-1")
        mocks["reset"].create_reset_token.assert_awaited_once()
        mocks["email"].send_template.assert_awaited_once()
        assert mocks["audit"].log_event.call_args.kwargs["event_type"] == (
            "password_reset_requested"
        )


class TestConfirmPasswordReset:
    def _validator(self, valid=True):
        validator = MagicMock()
        validator.validate = MagicMock(
            return_value=(valid, [] if valid else ["too weak"])
        )
        return validator

    def test_invalid_code_400(self):
        from authglow.api import password_reset as pr_api
        from authglow.models.password_reset import PasswordResetConfirm

        reset_svc = MagicMock()
        reset_svc.verify_by_code = AsyncMock(return_value=None)
        audit = MagicMock()
        audit.log_event = AsyncMock()
        with pytest.raises(HTTPException) as exc:
            _run(
                pr_api.confirm_password_reset(
                    _request(),
                    PasswordResetConfirm(reset_code="ABCD-EFGH-JKLM12", new_password="brand-new-test-password"),
                    reset_svc,
                    MagicMock(),
                    audit,
                    self._validator(),
                )
            )
        assert exc.value.status_code == 400
        assert audit.log_event.call_args.kwargs["event_type"] == "password_reset_failed"

    def test_weak_password_400(self):
        from authglow.api import password_reset as pr_api
        from authglow.models.password_reset import PasswordResetConfirm

        reset_svc = MagicMock()
        reset_svc.verify_by_code = AsyncMock(return_value=_token())
        audit = MagicMock()
        audit.log_event = AsyncMock()
        with pytest.raises(HTTPException) as exc:
            _run(
                pr_api.confirm_password_reset(
                    _request(),
                    PasswordResetConfirm(reset_code="ABCD-EFGH-JKLM12", new_password="brand-new-test-password"),
                    reset_svc,
                    MagicMock(),
                    audit,
                    self._validator(valid=False),
                )
            )
        assert exc.value.status_code == 400
        assert "too weak" in exc.value.detail

    def test_unknown_user_404(self):
        from authglow.api import password_reset as pr_api
        from authglow.models.password_reset import PasswordResetConfirm

        reset_svc = MagicMock()
        reset_svc.verify_by_code = AsyncMock(return_value=_token())
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=None)
        audit = MagicMock()
        audit.log_event = AsyncMock()
        with pytest.raises(HTTPException) as exc:
            _run(
                pr_api.confirm_password_reset(
                    _request(),
                    PasswordResetConfirm(reset_code="ABCD-EFGH-JKLM12", new_password="brand-new-test-password"),
                    reset_svc,
                    storage,
                    audit,
                    self._validator(),
                )
            )
        assert exc.value.status_code == 404

    def test_success(self):
        from authglow.api import password_reset as pr_api
        from authglow.models.password_reset import PasswordResetConfirm

        reset_svc = MagicMock()
        reset_svc.verify_by_code = AsyncMock(return_value=_token())
        reset_svc.mark_token_used = AsyncMock()
        reset_svc.revoke_user_tokens = AsyncMock()
        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=_user())
        storage.update_user = AsyncMock()
        audit = MagicMock()
        audit.log_event = AsyncMock()
        rt_svc = MagicMock()
        rt_svc.revoke_user_tokens = AsyncMock()
        with (
            patch("authglow.api.password_reset.hash_password_async", return_value="hashed"),
            patch("authglow.services.refresh_token.RefreshTokenService", return_value=rt_svc),
            patch(
                "authglow.services.webhook_dispatcher.emit_webhook_event",
                return_value=None,
            ),
        ):
            out = _run(
                pr_api.confirm_password_reset(
                    _request(),
                    PasswordResetConfirm(reset_code="ABCD-EFGH-JKLM12", new_password="brand-new-test-password"),
                    reset_svc,
                    storage,
                    audit,
                    self._validator(),
                )
            )
        assert out == {"message": "Password reset successful"}
        reset_svc.mark_token_used.assert_awaited_once_with("lookup-1")
        rt_svc.revoke_user_tokens.assert_awaited_once_with("u-1")
        assert audit.log_event.call_args.kwargs["event_type"] == "password_reset_completed"


class TestAdminEndpoints:
    def _patch_perms(self, allowed=True):
        from authglow.api import password_reset as pr_api

        return (
            patch.object(
                pr_api, "user_has_any_permission", new=AsyncMock(return_value=allowed)
            ),
            patch.object(pr_api, "user_has_permission", new=AsyncMock(return_value=allowed)),
        )

    def test_factories(self):
        from authglow.api import password_reset as pr_api
        from authglow.services.audit import AuditService
        from authglow.services.password_reset import PasswordResetService
        from authglow.services.user import UserService

        assert isinstance(pr_api.get_reset_service(), PasswordResetService)
        assert isinstance(pr_api.get_user_storage(), UserService)
        assert isinstance(pr_api.get_audit_service(), AuditService)

    def test_list_resets(self):
        from authglow.api import password_reset as pr_api

        reset_svc = MagicMock()
        reset_svc.list_all_tokens = AsyncMock(return_value=["t1", "t2"])
        any_patch, _ = self._patch_perms()
        with any_patch:
            out = _run(pr_api.list_password_resets(False, 100, 0, _admin(), reset_svc))
        assert out == ["t1", "t2"]
        reset_svc.list_all_tokens.assert_awaited_once_with(
            active_only=False, limit=100, offset=0
        )

    def test_list_resets_forbidden(self):
        from authglow.api import password_reset as pr_api

        any_patch, _ = self._patch_perms(allowed=False)
        with any_patch, pytest.raises(HTTPException) as exc:
            _run(pr_api.list_password_resets(False, 100, 0, _admin(), MagicMock()))
        assert exc.value.status_code == 403

    def test_list_user_resets(self):
        from authglow.api import password_reset as pr_api

        reset_svc = MagicMock()
        reset_svc.list_user_tokens = AsyncMock(return_value=["t1"])
        any_patch, _ = self._patch_perms()
        with any_patch:
            out = _run(pr_api.list_user_password_resets("u-1", True, _admin(), reset_svc))
        assert out == ["t1"]
        reset_svc.list_user_tokens.assert_awaited_once_with("u-1", active_only=True)

    def test_list_user_resets_forbidden(self):
        from authglow.api import password_reset as pr_api

        any_patch, _ = self._patch_perms(allowed=False)
        with any_patch, pytest.raises(HTTPException) as exc:
            _run(pr_api.list_user_password_resets("u-1", True, _admin(), MagicMock()))
        assert exc.value.status_code == 403

    def test_revoke_resets_by_id(self):
        from authglow.api import password_reset as pr_api

        reset_svc = MagicMock()
        reset_svc.revoke_user_tokens = AsyncMock(return_value=3)
        audit = MagicMock()
        audit.log_event = AsyncMock()
        _, perm_patch = self._patch_perms()
        with perm_patch:
            out = _run(pr_api.revoke_user_password_resets("u-1", _admin(), reset_svc, audit))
        assert out == {"message": "Revoked 3 password reset tokens"}
        reset_svc.revoke_user_tokens.assert_awaited_once_with("u-1")

    def test_revoke_resets_by_email(self):
        from authglow.api import password_reset as pr_api
        from authglow.services.user import UserService

        reset_svc = MagicMock()
        reset_svc.revoke_user_tokens = AsyncMock(return_value=1)
        audit = MagicMock()
        audit.log_event = AsyncMock()
        storage = MagicMock()
        storage.get_user_by_email = AsyncMock(return_value=_user())
        _, perm_patch = self._patch_perms()
        with (
            perm_patch,
            patch.object(pr_api, "UserStorage", return_value=storage),
        ):
            out = _run(
                pr_api.revoke_user_password_resets("u@example.com", _admin(), reset_svc, audit)
            )
        assert out == {"message": "Revoked 1 password reset tokens"}
        reset_svc.revoke_user_tokens.assert_awaited_once_with("u-1")

    def test_revoke_resets_email_not_found(self):
        from authglow.api import password_reset as pr_api

        reset_svc = MagicMock()
        audit = MagicMock()
        audit.log_event = AsyncMock()
        storage = MagicMock()
        storage.get_user_by_email = AsyncMock(return_value=None)
        _, perm_patch = self._patch_perms()
        with (
            perm_patch,
            patch.object(pr_api, "UserStorage", return_value=storage),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(
                    pr_api.revoke_user_password_resets(
                        "ghost@example.com", _admin(), reset_svc, audit
                    )
                )
        assert exc.value.status_code == 404

    def test_revoke_resets_forbidden(self):
        from authglow.api import password_reset as pr_api

        _, perm_patch = self._patch_perms(allowed=False)
        with perm_patch, pytest.raises(HTTPException) as exc:
            _run(
                pr_api.revoke_user_password_resets("u-1", _admin(), MagicMock(), MagicMock())
            )
        assert exc.value.status_code == 403

    def test_delete_token(self):
        from authglow.api import password_reset as pr_api

        reset_svc = MagicMock()
        reset_svc.delete_token = AsyncMock(return_value=True)
        audit = MagicMock()
        audit.log_event = AsyncMock()
        _, perm_patch = self._patch_perms()
        with perm_patch:
            out = _run(pr_api.delete_password_reset("tok-1", _admin(), reset_svc, audit))
        assert out == {"message": "Token deleted successfully"}

    def test_delete_token_not_found(self):
        from authglow.api import password_reset as pr_api

        reset_svc = MagicMock()
        reset_svc.delete_token = AsyncMock(return_value=False)
        audit = MagicMock()
        audit.log_event = AsyncMock()
        _, perm_patch = self._patch_perms()
        with perm_patch, pytest.raises(HTTPException) as exc:
            _run(pr_api.delete_password_reset("nope", _admin(), reset_svc, audit))
        assert exc.value.status_code == 404

    def test_delete_token_forbidden(self):
        from authglow.api import password_reset as pr_api

        _, perm_patch = self._patch_perms(allowed=False)
        with perm_patch, pytest.raises(HTTPException) as exc:
            _run(pr_api.delete_password_reset("tok-1", _admin(), MagicMock(), MagicMock()))
        assert exc.value.status_code == 403

    def test_cleanup(self):
        from authglow.api import password_reset as pr_api

        reset_svc = MagicMock()
        reset_svc.cleanup_expired_tokens = AsyncMock(return_value=5)
        audit = MagicMock()
        audit.log_event = AsyncMock()
        _, perm_patch = self._patch_perms()
        with perm_patch:
            out = _run(pr_api.cleanup_password_resets(_admin(), reset_svc, audit))
        assert out == {"message": "Cleaned up 5 expired tokens"}

    def test_cleanup_forbidden(self):
        from authglow.api import password_reset as pr_api

        _, perm_patch = self._patch_perms(allowed=False)
        with perm_patch, pytest.raises(HTTPException) as exc:
            _run(pr_api.cleanup_password_resets(_admin(), MagicMock(), MagicMock()))
        assert exc.value.status_code == 403

    def test_stats(self):
        from authglow.api import password_reset as pr_api

        reset_svc = MagicMock()
        reset_svc.get_stats = AsyncMock(return_value={"total": 7})
        any_patch, _ = self._patch_perms()
        with any_patch:
            out = _run(pr_api.get_password_reset_stats(_admin(), reset_svc))
        assert out == {"total": 7}

    def test_stats_forbidden(self):
        from authglow.api import password_reset as pr_api

        any_patch, _ = self._patch_perms(allowed=False)
        with any_patch, pytest.raises(HTTPException) as exc:
            _run(pr_api.get_password_reset_stats(_admin(), MagicMock()))
        assert exc.value.status_code == 403
