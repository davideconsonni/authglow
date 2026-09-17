"""Execution tests for ``authglow.api.phone_verification`` (COV-BE-006).

No API-layer tests existed. Both endpoints are executed with mocked
services: success/failure audit paths for request and verify, plus
the module factories.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _request():
    request = Request({"type": "http", "method": "POST", "path": "", "headers": []})
    request.state.view_rate_limit = None
    return request


def _user():
    from authglow.models.user import User

    return User(id="u-1", email="u@example.com", hashed_password="x", scopes=["read"])


def _wired(service=None, audit=None):
    from authglow.api import phone_verification as pv_api

    service = service or MagicMock()
    audit = audit or MagicMock()
    audit.log_event = AsyncMock()
    return (
        patch.object(pv_api, "get_phone_verification_service", return_value=service),
        patch.object(pv_api, "get_audit_service", return_value=audit),
        service,
        audit,
    )


class TestRequestPhoneCode:
    def test_success(self):
        from authglow.api import phone_verification as pv_api
        from authglow.models.phone_verification import PhoneCodeRequest

        svc = MagicMock()
        svc.request_code = AsyncMock(return_value=(True, None))
        svc.provider.get_provider_name = MagicMock(return_value="test-provider")
        svc_patch, audit_patch, _, audit = _wired(service=svc)
        with svc_patch, audit_patch:
            out = _run(
                pv_api.request_phone_code(
                    _request(), PhoneCodeRequest(phone="+15551234567"), _user()
                )
            )
        assert out == {"message": "Verification code sent"}
        svc.request_code.assert_awaited_once_with("u-1", "+15551234567")
        assert audit.log_event.call_args.kwargs["event_type"] == "phone_verification_sent"

    def test_failure(self):
        from authglow.api import phone_verification as pv_api
        from authglow.models.phone_verification import PhoneCodeRequest

        svc = MagicMock()
        svc.request_code = AsyncMock(return_value=(False, "rate limited"))
        svc_patch, audit_patch, _, audit = _wired(service=svc)
        with svc_patch, audit_patch:
            with pytest.raises(HTTPException) as exc:
                _run(
                    pv_api.request_phone_code(
                        _request(), PhoneCodeRequest(phone="+15551234567"), _user()
                    )
                )
        assert exc.value.status_code == 400
        assert exc.value.detail == "rate limited"
        assert audit.log_event.call_args.kwargs["event_type"] == "phone_verification_failed"


class TestVerifyPhoneCode:
    def test_success(self):
        from authglow.api import phone_verification as pv_api
        from authglow.models.phone_verification import PhoneVerifyRequest

        svc = MagicMock()
        svc.verify_code = AsyncMock(return_value=(True, None))
        svc_patch, audit_patch, _, audit = _wired(service=svc)
        with svc_patch, audit_patch:
            out = _run(
                pv_api.verify_phone_code(
                    _request(), PhoneVerifyRequest(phone="+15551234567", code="123456"), _user()
                )
            )
        assert out == {"message": "Phone number verified successfully"}
        svc.verify_code.assert_awaited_once_with("u-1", "+15551234567", "123456")
        assert audit.log_event.call_args.kwargs["event_type"] == "phone_verified"

    def test_failure(self):
        from authglow.api import phone_verification as pv_api
        from authglow.models.phone_verification import PhoneVerifyRequest

        svc = MagicMock()
        svc.verify_code = AsyncMock(return_value=(False, "wrong code"))
        svc_patch, audit_patch, _, audit = _wired(service=svc)
        with svc_patch, audit_patch:
            with pytest.raises(HTTPException) as exc:
                _run(
                    pv_api.verify_phone_code(
                        _request(),
                        PhoneVerifyRequest(phone="+15551234567", code="123456"),
                        _user(),
                    )
                )
        assert exc.value.status_code == 400
        assert audit.log_event.call_args.kwargs["event_type"] == "phone_verification_failed"


class TestFactories:
    def test_factories(self):
        from authglow.api import phone_verification as pv_api
        from authglow.services.audit import AuditService
        from authglow.services.phone_verification import PhoneVerificationService

        assert isinstance(pv_api.get_phone_verification_service(), PhoneVerificationService)
        assert isinstance(pv_api.get_audit_service(), AuditService)
