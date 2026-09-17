"""Execution tests for ``authglow.api.email_verification`` (COV-BE-003).

Existing coverage is source-inspection only (``test_email_verification.py``)
plus service tests. These tests execute both endpoints with mocked
services: success/failure audit paths, the optional-token branch, and
the authenticated/anonymous/empty email resolution of the resend flow.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _request():
    from fastapi import Request

    request = Request({"type": "http", "method": "POST", "path": "", "headers": []})
    request.state.view_rate_limit = None
    return request


def _wired(verification=None, audit=None):
    from authglow.api import email_verification as ev_api

    if verification is None:
        verification = MagicMock()
        verification.verify_email = AsyncMock(return_value=(False, "unused"))
        verification.get_token = AsyncMock(return_value=None)
        verification.resend_verification_email = AsyncMock(return_value=(False, "unused"))
    if audit is None:
        audit = MagicMock()
        audit.log_event = AsyncMock()
    return (
        patch.object(ev_api, "get_verification_service", return_value=verification),
        patch.object(ev_api, "get_audit_service", return_value=audit),
        verification,
        audit,
    )


class TestVerifyEmailApi:
    def test_success_with_token_audits(self):
        from authglow.api import email_verification as ev_api
        from authglow.models.email_verification import EmailVerificationRequest

        token = SimpleNamespace(user_id="u-1", email="u@example.com")
        vsvc = MagicMock()
        vsvc.verify_email = AsyncMock(return_value=(True, None))
        vsvc.get_token = AsyncMock(return_value=token)
        svc_patch, audit_patch, _, audit = _wired(verification=vsvc)
        with svc_patch, audit_patch:
            out = _run(
                ev_api.verify_email_api(
                    _request(),
                    EmailVerificationRequest(token="a-valid-token-value"),
                )
            )
        assert out == {"message": "Email verified successfully"}
        audit.log_event.assert_awaited_once()
        assert audit.log_event.call_args.kwargs["event_type"] == "email_verified"
        assert audit.log_event.call_args.kwargs["user_id"] == "u-1"

    def test_success_without_token_skips_audit(self):
        from authglow.api import email_verification as ev_api
        from authglow.models.email_verification import EmailVerificationRequest

        vsvc = MagicMock()
        vsvc.verify_email = AsyncMock(return_value=(True, None))
        vsvc.get_token = AsyncMock(return_value=None)
        svc_patch, audit_patch, _, audit = _wired(verification=vsvc)
        with svc_patch, audit_patch:
            out = _run(
                ev_api.verify_email_api(
                    _request(),
                    EmailVerificationRequest(token="a-valid-token-value"),
                )
            )
        assert out == {"message": "Email verified successfully"}
        audit.log_event.assert_not_awaited()

    def test_failure_audits_and_400(self):
        from authglow.api import email_verification as ev_api
        from authglow.models.email_verification import EmailVerificationRequest

        vsvc = MagicMock()
        vsvc.verify_email = AsyncMock(return_value=(False, "bad token"))
        svc_patch, audit_patch, _, audit = _wired(verification=vsvc)
        with svc_patch, audit_patch:
            with pytest.raises(HTTPException) as exc:
                _run(
                    ev_api.verify_email_api(
                        _request(),
                        EmailVerificationRequest(token="a-valid-token-value"),
                    )
                )
        assert exc.value.status_code == 400
        audit.log_event.assert_awaited_once()
        assert audit.log_event.call_args.kwargs["event_type"] == "email_verification_failed"

    def test_factories(self):
        from authglow.api import email_verification as ev_api
        from authglow.services.audit import AuditService
        from authglow.services.email_verification import EmailVerificationService

        assert isinstance(ev_api.get_verification_service(), EmailVerificationService)
        assert isinstance(ev_api.get_audit_service(), AuditService)


class TestResendVerificationEmail:
    def test_authenticated_user(self):
        from authglow.api import email_verification as ev_api
        from authglow.models.user import User

        vsvc = MagicMock()
        vsvc.resend_verification_email = AsyncMock(return_value=(True, None))
        svc_patch, audit_patch, _, audit = _wired(verification=vsvc)
        user = User(id="u-1", email="me@example.com", hashed_password="x", scopes=[])
        with svc_patch, audit_patch:
            out = _run(ev_api.resend_verification_email(_request(), None, user))
        assert out == {"message": "Verification email sent successfully"}
        vsvc.resend_verification_email.assert_awaited_once_with("me@example.com")
        assert audit.log_event.call_args.kwargs["event_type"] == "email_verification_resent"

    def test_anonymous_with_body_email(self):
        from authglow.api import email_verification as ev_api
        from authglow.models.email_verification import ResendVerificationRequest

        vsvc = MagicMock()
        vsvc.resend_verification_email = AsyncMock(return_value=(True, None))
        svc_patch, audit_patch, _, audit = _wired(verification=vsvc)
        with svc_patch, audit_patch:
            out = _run(
                ev_api.resend_verification_email(
                    _request(), ResendVerificationRequest(email="anon@example.com"), None
                )
            )
        assert out == {"message": "Verification email sent successfully"}
        vsvc.resend_verification_email.assert_awaited_once_with("anon@example.com")

    def test_missing_email_422(self):
        from authglow.api import email_verification as ev_api

        vsvc = MagicMock()
        vsvc.resend_verification_email = AsyncMock()
        svc_patch, audit_patch, _, audit = _wired(verification=vsvc)
        with svc_patch, audit_patch:
            with pytest.raises(HTTPException) as exc:
                _run(ev_api.resend_verification_email(_request(), None, None))
        assert exc.value.status_code == 422
        audit.log_event.assert_not_awaited()
        vsvc.resend_verification_email.assert_not_awaited()

    def test_service_failure_audits_and_400(self):
        from authglow.api import email_verification as ev_api
        from authglow.models.email_verification import ResendVerificationRequest

        vsvc = MagicMock()
        vsvc.resend_verification_email = AsyncMock(return_value=(False, "rate limited"))
        svc_patch, audit_patch, _, audit = _wired(verification=vsvc)
        with svc_patch, audit_patch:
            with pytest.raises(HTTPException) as exc:
                _run(
                    ev_api.resend_verification_email(
                        _request(), ResendVerificationRequest(email="a@example.com"), None
                    )
                )
        assert exc.value.status_code == 400
        assert audit.log_event.call_args.kwargs["event_type"] == (
            "email_verification_resend_failed"
        )
