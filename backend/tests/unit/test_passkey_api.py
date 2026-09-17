"""Execution tests for the uncovered paths of ``authglow.api.passkey`` (COV-BE-004).

``test_passkey.py`` covers ``POST /auth/complete`` (account-status gate)
and malformed input. This module pins the rest: ``get_current_user``
(all rejection branches), both registration endpoints, ``/auth/begin``,
``/list`` and ``DELETE /{credential_id}``. Services are mocked;
handlers are invoked directly.
"""

import asyncio
import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _request(headers=None):
    raw = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    request = Request(
        {"type": "http", "method": "POST", "path": "", "headers": raw, "server": ("t", 80)}
    )
    request.state.view_rate_limit = None
    return request


def _user(**kw):
    from authglow.models.user import User

    base = {"id": "u-1", "email": "u@example.com", "hashed_password": "x", "scopes": ["read"]}
    base.update(kw)
    return User(**base)


def _passkey(**kw):
    from authglow.models.passkey import Passkey

    base = {
        "credential_id": "Y3JlZC0x",
        "public_key": "cHVia2V5",
        "sign_count": 0,
        "aaguid": "00000000-0000-0000-0000-000000000000",
        "user_id": "u-1",
    }
    base.update(kw)
    return Passkey(**base)


def _token_data(**kw):
    base = {"sub": "u-1", "token_type": "access", "aud": "authglow-internal"}
    base.update(kw)
    return SimpleNamespace(**base)


class TestFactories:
    def test_get_passkey_service_origin_header(self):
        from authglow.api import passkey as passkey_api

        with patch.object(passkey_api, "PasskeyService") as cls:
            passkey_api.get_passkey_service(_request({"origin": "https://id.example.com"}))
        _, kwargs = cls.call_args
        assert kwargs["rp_id"] == "id.example.com"
        assert kwargs["origin"] == "https://id.example.com"

    def test_get_passkey_service_host_fallback(self):
        from authglow.api import passkey as passkey_api

        with patch.object(passkey_api, "PasskeyService") as cls:
            passkey_api.get_passkey_service(_request({"host": "id.example.com:8443"}))
        _, kwargs = cls.call_args
        assert kwargs["rp_id"] == "id.example.com"

    def test_factories(self):
        from authglow.api import passkey as passkey_api
        from authglow.services.audit import AuditService
        from authglow.services.refresh_token import RefreshTokenService
        from authglow.services.user import UserService

        assert isinstance(passkey_api.get_user_storage(), UserService)
        assert isinstance(passkey_api.get_refresh_token_service(), RefreshTokenService)
        assert isinstance(passkey_api.get_audit_service(), AuditService)


class TestGetCurrentUser:
    def _call(self, *, credentials=None, request=None, user=None, token_data=None):
        from authglow.api import passkey as passkey_api

        storage = MagicMock()
        storage.get_user = AsyncMock(return_value=user)
        jwt_service = MagicMock()
        jwt_service.decode_token = MagicMock(return_value=token_data)
        return _run(
            passkey_api.get_current_user(
                request or _request(),
                credentials,
                storage,
                jwt_service,
            )
        )

    def test_no_token(self):
        from authglow.api import passkey as passkey_api

        assert passkey_api.settings.auth_cookie_access_name
        with pytest.raises(HTTPException) as exc:
            self._call(credentials=None, request=_request(), token_data=None)
        assert exc.value.status_code == 401

    def test_cookie_token(self):
        from authglow.api import passkey as passkey_api

        name = passkey_api.settings.auth_cookie_access_name
        out = self._call(
            credentials=None,
            request=_request({"cookie": f"{name}=tok123"}),
            user=_user(),
            token_data=_token_data(),
        )
        assert out.id == "u-1"

    def test_header_token(self):
        creds = SimpleNamespace(credentials="tok123")
        out = self._call(credentials=creds, user=_user(), token_data=_token_data())
        assert out.id == "u-1"

    def test_wrong_token_type(self):
        with pytest.raises(HTTPException) as exc:
            self._call(
                credentials=SimpleNamespace(credentials="tok"),
                user=_user(),
                token_data=_token_data(token_type="refresh"),
            )
        assert exc.value.status_code == 401

    def test_missing_aud(self):
        with pytest.raises(HTTPException) as exc:
            self._call(
                credentials=SimpleNamespace(credentials="tok"),
                user=_user(),
                token_data=_token_data(aud=None),
            )
        assert exc.value.status_code == 401

    def test_unknown_user(self):
        with pytest.raises(HTTPException) as exc:
            self._call(
                credentials=SimpleNamespace(credentials="tok"),
                user=None,
                token_data=_token_data(),
            )
        assert exc.value.status_code == 401

    def test_inactive_user(self):
        with pytest.raises(HTTPException) as exc:
            self._call(
                credentials=SimpleNamespace(credentials="tok"),
                user=_user(is_active=False),
                token_data=_token_data(),
            )
        assert exc.value.status_code == 401


class TestBeginRegistration:
    def test_returns_options_and_saves_challenge(self):
        from authglow.api import passkey as passkey_api

        svc = MagicMock()
        svc.get_user_passkeys = AsyncMock(return_value=[_passkey()])
        svc.generate_registration_options_dict = MagicMock(
            return_value=({"challenge": "Y2hhbGxlbmdl"}, "Y2hhbGxlbmdl")
        )
        svc.save_challenge = AsyncMock()
        out = _run(passkey_api.begin_registration(_request(), _user(), svc))
        assert out == {"challenge": "Y2hhbGxlbmdl"}
        svc.save_challenge.assert_awaited_once()
        challenge = svc.save_challenge.await_args.args[0]
        assert challenge.type == "registration"
        assert challenge.user_id == "u-1"


class TestCompleteRegistration:
    def _verification(self):
        from authglow.models.passkey import PasskeyRegistrationVerification

        client_data = base64.urlsafe_b64encode(json.dumps({"challenge": "abc"}).encode())
        return PasskeyRegistrationVerification(
            credential_id="Y3JlZC0x",
            client_data_json=client_data.decode(),
            attestation_object="e30",
            transports=["internal"],
            name="My Key",
        )

    def test_success(self):
        from authglow.api import passkey as passkey_api

        svc = MagicMock()
        svc.verify_registration = AsyncMock(return_value=_passkey(name="My Key"))
        audit = MagicMock()
        audit.log_event = AsyncMock()
        with patch.object(passkey_api, "AuditService", return_value=audit):
            out = _run(
                passkey_api.complete_registration(_request(), self._verification(), _user(), svc)
            )
        assert out["success"] is True
        assert out["passkey"].credential_id == "Y3JlZC0x"
        audit.log_event.assert_awaited_once()

    def test_failure_returns_400(self):
        from authglow.api import passkey as passkey_api

        svc = MagicMock()
        svc.verify_registration = AsyncMock(side_effect=ValueError("bad attestation"))
        audit = MagicMock()
        audit.log_event = AsyncMock()
        with patch.object(passkey_api, "AuditService", return_value=audit):
            with pytest.raises(HTTPException) as exc:
                _run(
                    passkey_api.complete_registration(
                        _request(), self._verification(), _user(), svc
                    )
                )
        assert exc.value.status_code == 400
        audit.log_event.assert_awaited_once()


class TestBeginAuthentication:
    def test_unknown_user(self):
        from authglow.api import passkey as passkey_api
        from authglow.api.passkey import EmailRequest

        storage = MagicMock()
        storage.get_user_by_email = AsyncMock(return_value=None)
        with pytest.raises(HTTPException) as exc:
            _run(passkey_api.begin_authentication(_request(), EmailRequest(email="x@y.z"), MagicMock(), storage))
        assert exc.value.status_code == 400

    def test_no_passkeys(self):
        from authglow.api import passkey as passkey_api
        from authglow.api.passkey import EmailRequest

        storage = MagicMock()
        storage.get_user_by_email = AsyncMock(return_value=_user())
        svc = MagicMock()
        svc.get_user_passkeys = AsyncMock(return_value=[])
        with pytest.raises(HTTPException) as exc:
            _run(passkey_api.begin_authentication(_request(), EmailRequest(email="u@e.c"), svc, storage))
        assert exc.value.status_code == 400

    def test_success(self):
        from authglow.api import passkey as passkey_api
        from authglow.api.passkey import EmailRequest

        storage = MagicMock()
        storage.get_user_by_email = AsyncMock(return_value=_user())
        svc = MagicMock()
        svc.get_user_passkeys = AsyncMock(return_value=[_passkey()])
        svc.generate_authentication_options_dict = MagicMock(
            return_value=({"challenge": "Y2hhbGxlbmdl"}, "Y2hhbGxlbmdl")
        )
        svc.save_challenge = AsyncMock()
        out = _run(passkey_api.begin_authentication(_request(), EmailRequest(email="u@e.c"), svc, storage))
        assert out == {"challenge": "Y2hhbGxlbmdl"}
        challenge = svc.save_challenge.await_args.args[0]
        assert challenge.type == "authentication"


class TestListDelete:
    def test_list_passkeys(self):
        from authglow.api import passkey as passkey_api

        svc = MagicMock()
        svc.get_user_passkeys = AsyncMock(return_value=[_passkey(), _passkey(credential_id="eTI=")])
        out = _run(passkey_api.list_passkeys(_request(), _user(), svc))
        assert [p.credential_id for p in out] == ["Y3JlZC0x", "eTI="]

    def test_delete_passkey(self):
        from authglow.api import passkey as passkey_api

        svc = MagicMock()
        svc.delete_passkey = AsyncMock(return_value=True)
        audit = MagicMock()
        audit.log_event = AsyncMock()
        with patch.object(passkey_api, "AuditService", return_value=audit):
            out = _run(passkey_api.delete_passkey(_request(), "Y3JlZC0x", _user(), svc))
        assert out["success"] is True
        audit.log_event.assert_awaited_once()

    def test_delete_missing_passkey(self):
        from authglow.api import passkey as passkey_api

        svc = MagicMock()
        svc.delete_passkey = AsyncMock(return_value=False)
        with pytest.raises(HTTPException) as exc:
            _run(passkey_api.delete_passkey(_request(), "nope", _user(), svc))
        assert exc.value.status_code == 404
