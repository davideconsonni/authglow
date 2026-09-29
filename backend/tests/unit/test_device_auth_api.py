"""Execution tests for ``authglow.api.device_auth`` (COV-BE-013).

``tests/integration/test_device_flow.py`` covers the authorize happy path,
unknown/unregistered clients and scope filtering, plus token polling.
This module drives the handlers directly to pin the client-authentication
guards, the first-party fallback, scope rejection, and the entire
user-facing verify/approve/deny/list/revoke surface.
"""

import asyncio
from contextlib import ExitStack
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException, Request

from authglow.core.datetime import utcnow

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _request():
    request = Request({"type": "http", "method": "POST", "path": "", "headers": []})
    request.state.view_rate_limit = None
    return request


def _user(user_id="u-1"):
    return SimpleNamespace(id=user_id, email=f"{user_id}@example.com")


def _client(*, confidential=False, active=True, grant_types=(DEVICE_GRANT,)):
    return SimpleNamespace(
        is_confidential=confidential, is_active=active, grant_types=list(grant_types)
    )


def _pending(**kw):
    now = utcnow()
    base = dict(
        device_code="devcode-1234567890",
        user_code="ABCD-EFGH",
        client_id="c1",
        scope="read write",
        status="pending",
        user_id=None,
        interval=5,
        created_at=now,
        expires_at=now + timedelta(seconds=600),
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _settings(**kw):
    base = dict(
        oauth2_client_id="test-client-id",
        frontend_base_url="https://app.example",
        device_code_expire_seconds=600,
    )
    base.update(kw)
    return SimpleNamespace(**base)


def _authorize(
    *,
    client=_client(),
    client_secret=None,
    scope="read",
    process_raises=False,
    returned_client=...,
    settings=None,
    first_party=None,
):
    from authglow.api import device_auth as api

    settings = settings or _settings()
    oauth2 = MagicMock()
    oauth2.client_storage.get_client = AsyncMock(
        return_value=client if returned_client is ... else returned_client
    )
    oauth2.verify_client = AsyncMock(return_value=True)
    if process_raises:
        oauth2.process_scopes = AsyncMock(side_effect=ValueError("unknown scope"))
    else:
        oauth2.process_scopes = AsyncMock(return_value=scope.split())

    device = MagicMock()
    device.create_device_authorization = AsyncMock(return_value=_pending())
    audit = MagicMock()
    audit.log_event = AsyncMock()

    with ExitStack() as stack:
        stack.enter_context(patch.object(api, "get_settings", return_value=settings))
        stack.enter_context(patch.object(api, "OAuth2Service", return_value=oauth2))
        stack.enter_context(patch.object(api, "DeviceAuthorizationService", return_value=device))
        stack.enter_context(patch.object(api, "AuditService", return_value=audit))
        if first_party is not None:
            stack.enter_context(
                patch("authglow.api.auth._first_party_oauth_client", return_value=first_party)
            )
        return _run(
            api.device_authorize(
                _request(),
                client_id=settings.oauth2_client_id,
                scope=scope,
                client_secret=client_secret,
            )
        )


def _user_endpoint(_handler_name, **service_methods):
    """Patch ``DeviceAuthorizationService`` for the user-facing handlers."""
    from authglow.api import device_auth as api

    device = MagicMock()
    for name, value in service_methods.items():
        setattr(device, name, AsyncMock(return_value=value))
    audit = MagicMock()
    audit.log_event = AsyncMock()
    return api, device, audit


class TestDeviceAuthorizeGuards:
    def test_first_party_fallback_when_client_not_persisted(self):
        out = _authorize(
            returned_client=None,
            settings=_settings(oauth2_client_id="first-party"),
            first_party=_client(),
        )
        assert out.user_code == "ABCD-EFGH"

    def test_confidential_client_missing_secret_401(self):
        from authglow.api.oauth_errors import OAuth2Error

        with pytest.raises(OAuth2Error) as exc:
            _authorize(client=_client(confidential=True), client_secret=None)
        assert exc.value.status_code == 401

    def test_confidential_client_invalid_secret_401(self):
        from authglow.api import device_auth as api
        from authglow.api.oauth_errors import OAuth2Error

        client = _client(confidential=True)
        oauth2 = MagicMock()
        oauth2.client_storage.get_client = AsyncMock(return_value=client)
        oauth2.verify_client = AsyncMock(return_value=False)
        device = MagicMock()
        audit = MagicMock()
        with (
            patch.object(api, "get_settings", return_value=_settings()),
            patch.object(api, "OAuth2Service", return_value=oauth2),
            patch.object(api, "DeviceAuthorizationService", return_value=device),
            patch.object(api, "AuditService", return_value=audit),
        ):
            with pytest.raises(OAuth2Error) as exc:
                _run(
                    api.device_authorize(
                        _request(), client_id="test-client-id", scope="read", client_secret="wrong"
                    )
                )
        assert exc.value.status_code == 401

    def test_confidential_client_valid_secret_succeeds(self):
        out = _authorize(client=_client(confidential=True), client_secret="s3cret")
        assert out.device_code == "devcode-1234567890"

    def test_invalid_scope_400(self):
        from authglow.api.oauth_errors import OAuth2Error

        with pytest.raises(OAuth2Error) as exc:
            _authorize(process_raises=True)
        assert exc.value.status_code == 400


class TestDeviceVerify:
    def test_pending_returns_client_info(self):
        from authglow.api import device_auth as api
        from authglow.api.device_auth import DeviceVerifyRequest

        _, device, _ = _user_endpoint("device_verify", verify_user_code=_pending())
        with patch.object(api, "DeviceAuthorizationService", return_value=device):
            out = _run(
                api.device_verify(_request(), DeviceVerifyRequest(user_code="ABCD-EFGH"), _user())
            )
        assert out.client_id == "c1"
        assert out.scopes == ["read", "write"]

    def test_unknown_code_404(self):
        from authglow.api import device_auth as api
        from authglow.api.device_auth import DeviceVerifyRequest

        _, device, _ = _user_endpoint("device_verify", verify_user_code=None)
        with patch.object(api, "DeviceAuthorizationService", return_value=device):
            with pytest.raises(HTTPException) as exc:
                _run(api.device_verify(_request(), DeviceVerifyRequest(user_code="NOPE"), _user()))
        assert exc.value.status_code == 404

    def test_non_pending_400(self):
        from authglow.api import device_auth as api
        from authglow.api.device_auth import DeviceVerifyRequest

        _, device, _ = _user_endpoint(
            "device_verify", verify_user_code=_pending(status="authorized")
        )
        with patch.object(api, "DeviceAuthorizationService", return_value=device):
            with pytest.raises(HTTPException) as exc:
                _run(
                    api.device_verify(
                        _request(), DeviceVerifyRequest(user_code="ABCD-EFGH"), _user()
                    )
                )
        assert exc.value.status_code == 400


class TestDeviceApprove:
    def test_approve_success_audits(self):
        from authglow.api import device_auth as api
        from authglow.api.device_auth import DeviceVerifyRequest

        _, device, audit = _user_endpoint(
            "device_approve", verify_user_code=_pending(), approve=True
        )
        with (
            patch.object(api, "DeviceAuthorizationService", return_value=device),
            patch.object(api, "AuditService", return_value=audit),
        ):
            out = _run(
                api.device_approve(_request(), DeviceVerifyRequest(user_code="ABCD-EFGH"), _user())
            )
        assert out == {"status": "approved"}
        assert audit.log_event.await_args.kwargs["metadata"].authorized_by == "u-1"

    def test_approve_failure_400(self):
        from authglow.api import device_auth as api
        from authglow.api.device_auth import DeviceVerifyRequest

        _, device, audit = _user_endpoint("device_approve", verify_user_code=None, approve=False)
        with (
            patch.object(api, "DeviceAuthorizationService", return_value=device),
            patch.object(api, "AuditService", return_value=audit),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(api.device_approve(_request(), DeviceVerifyRequest(user_code="NOPE"), _user()))
        assert exc.value.status_code == 400

    def test_approve_with_missing_snapshot_uses_unknown_placeholders(self):
        """Defensive branch: ``approve`` reported success but the pre-read
        snapshot was gone — audit must still be emitted with placeholders."""
        from authglow.api import device_auth as api
        from authglow.api.device_auth import DeviceVerifyRequest

        _, device, audit = _user_endpoint("device_approve", verify_user_code=None, approve=True)
        with (
            patch.object(api, "DeviceAuthorizationService", return_value=device),
            patch.object(api, "AuditService", return_value=audit),
        ):
            out = _run(
                api.device_approve(_request(), DeviceVerifyRequest(user_code="ABCD-EFGH"), _user())
            )
        assert out == {"status": "approved"}
        metadata = audit.log_event.await_args.kwargs["metadata"]
        assert metadata.client_id == "unknown"
        assert metadata.device_code_id == "unknown"


class TestDeviceDeny:
    def test_deny_success_audits(self):
        from authglow.api import device_auth as api
        from authglow.api.device_auth import DeviceVerifyRequest

        _, device, audit = _user_endpoint("device_deny", verify_user_code=_pending(), deny=True)
        with (
            patch.object(api, "DeviceAuthorizationService", return_value=device),
            patch.object(api, "AuditService", return_value=audit),
        ):
            out = _run(
                api.device_deny(_request(), DeviceVerifyRequest(user_code="ABCD-EFGH"), _user())
            )
        assert out == {"status": "denied"}
        audit.log_event.assert_awaited_once()

    def test_deny_failure_400(self):
        from authglow.api import device_auth as api
        from authglow.api.device_auth import DeviceVerifyRequest

        _, device, audit = _user_endpoint("device_deny", verify_user_code=None, deny=False)
        with (
            patch.object(api, "DeviceAuthorizationService", return_value=device),
            patch.object(api, "AuditService", return_value=audit),
        ):
            with pytest.raises(HTTPException) as exc:
                _run(api.device_deny(_request(), DeviceVerifyRequest(user_code="NOPE"), _user()))
        assert exc.value.status_code == 400

    def test_deny_with_missing_snapshot_uses_unknown_placeholders(self):
        from authglow.api import device_auth as api
        from authglow.api.device_auth import DeviceVerifyRequest

        _, device, audit = _user_endpoint("device_deny", verify_user_code=None, deny=True)
        with (
            patch.object(api, "DeviceAuthorizationService", return_value=device),
            patch.object(api, "AuditService", return_value=audit),
        ):
            out = _run(
                api.device_deny(_request(), DeviceVerifyRequest(user_code="ABCD-EFGH"), _user())
            )
        assert out == {"status": "denied"}
        assert audit.log_event.await_args.kwargs["metadata"].client_id == "unknown"


class TestMyAuthorizations:
    def test_list_returns_summary(self):
        from authglow.api import device_auth as api

        _, device, _ = _user_endpoint("my_device_authorizations", list_by_user=[_pending()])
        with patch.object(api, "DeviceAuthorizationService", return_value=device):
            out = _run(api.my_device_authorizations(_request(), _user()))
        assert out["total"] == 1
        entry = out["device_authorizations"][0]
        assert entry["user_code"] == "ABCD-EFGH"
        assert entry["status"] == "pending"
        assert entry["device_code"].endswith("...")

    def test_empty_list(self):
        from authglow.api import device_auth as api

        _, device, _ = _user_endpoint("my_device_authorizations", list_by_user=[])
        with patch.object(api, "DeviceAuthorizationService", return_value=device):
            out = _run(api.my_device_authorizations(_request(), _user()))
        assert out == {"device_authorizations": [], "total": 0}


class TestRevokeMyAuthorization:
    def test_revoke_success(self):
        from authglow.api import device_auth as api

        _, device, _ = _user_endpoint(
            "revoke_my_device_authorization",
            verify_user_code=_pending(user_id="u-1"),
            revoke=True,
        )
        with patch.object(api, "DeviceAuthorizationService", return_value=device):
            out = _run(api.revoke_my_device_authorization("ABCD-EFGH", _request(), _user()))
        assert out == {"status": "revoked"}

    def test_unknown_code_404(self):
        from authglow.api import device_auth as api

        _, device, _ = _user_endpoint("revoke_my_device_authorization", verify_user_code=None)
        with patch.object(api, "DeviceAuthorizationService", return_value=device):
            with pytest.raises(HTTPException) as exc:
                _run(api.revoke_my_device_authorization("NOPE", _request(), _user()))
        assert exc.value.status_code == 404

    def test_foreign_authorization_404(self):
        from authglow.api import device_auth as api

        _, device, _ = _user_endpoint(
            "revoke_my_device_authorization", verify_user_code=_pending(user_id="u-other")
        )
        with patch.object(api, "DeviceAuthorizationService", return_value=device):
            with pytest.raises(HTTPException) as exc:
                _run(api.revoke_my_device_authorization("ABCD-EFGH", _request(), _user()))
        assert exc.value.status_code == 404

    def test_revoke_failure_400(self):
        from authglow.api import device_auth as api

        _, device, _ = _user_endpoint(
            "revoke_my_device_authorization",
            verify_user_code=_pending(user_id="u-1"),
            revoke=False,
        )
        with patch.object(api, "DeviceAuthorizationService", return_value=device):
            with pytest.raises(HTTPException) as exc:
                _run(api.revoke_my_device_authorization("ABCD-EFGH", _request(), _user()))
        assert exc.value.status_code == 400
