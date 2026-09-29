"""Service-level tests for ``authglow.services.device_auth`` (COV-BE-010).

The endpoint layer (``authglow.api.device_auth``) is exercised in
``tests/integration/test_device_flow.py`` with the service mocked, and
the conformance matrix only reaches ``create_device_authorization``.
This module drives ``DeviceAuthorizationService`` against a real
file-backed repository (``test_settings`` tmp dir) so the RFC 8628
lifecycle — poll throttling, interval escalation, approve/deny, expiry
cleanup, revoke — is pinned end to end.
"""

from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock

import pytest

from authglow.core.datetime import utcnow


@pytest.fixture
def device_service(test_settings):
    from authglow.services.device_auth import DeviceAuthorizationService

    svc = DeviceAuthorizationService(settings=test_settings)
    svc.audit_service = MagicMock()
    svc.audit_service.log_event = AsyncMock()
    return svc


async def _expire(svc, auth):
    auth.expires_at = utcnow() - timedelta(seconds=1)
    await svc._repo.update(auth)
    return auth


class TestCreate:
    async def test_create_persists_pending_authorization(self, device_service, test_settings):
        auth = await device_service.create_device_authorization(
            "client-1", "read write", "https://verify.example"
        )
        assert auth.status == "pending"
        assert auth.device_code and auth.user_code
        assert auth.scope == "read write"
        assert auth.interval == test_settings.device_poll_interval_seconds
        assert auth.expires_at > utcnow()
        fetched = await device_service._repo.get_by_user_code(auth.user_code)
        assert fetched is not None and fetched.device_code == auth.device_code

    def test_user_code_format(self):
        from authglow.services.device_auth import DeviceAuthorizationService

        code = DeviceAuthorizationService._generate_user_code()
        left, right = code.split("-")
        assert len(left) == 4 and len(right) == 4
        assert code == code.upper()


class TestPoll:
    async def test_unknown_code_returns_none(self, device_service):
        assert await device_service.poll("does-not-exist") is None

    async def test_first_poll_stamps_last_poll_at(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        polled = await device_service.poll(auth.device_code)
        assert polled is not None
        assert polled.last_poll_at is not None

    async def test_immediate_second_poll_is_throttled(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        first = await device_service.poll(auth.device_code)
        second = await device_service.poll(auth.device_code)
        assert second is not None
        assert second.last_poll_at == first.last_poll_at

    async def test_poll_after_interval_refreshes_timestamp(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        auth.last_poll_at = utcnow() - timedelta(seconds=auth.interval + 1)
        await device_service._repo.update(auth)
        stale = auth.last_poll_at
        refreshed = await device_service.poll(auth.device_code)
        assert refreshed is not None
        assert refreshed.last_poll_at > stale

    async def test_poll_non_pending_does_not_touch_timestamp(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        await device_service.approve(auth.user_code, "u-1")
        polled = await device_service.poll(auth.device_code)
        assert polled is not None
        assert polled.status == "authorized"
        assert polled.last_poll_at is None


class TestEscalateInterval:
    async def test_unknown_code_returns_base_interval(self, device_service, test_settings):
        result = await device_service.escalate_interval("missing")
        assert result == test_settings.device_poll_interval_seconds

    async def test_known_code_increments_and_persists(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        base = auth.interval
        new_interval = await device_service.escalate_interval(auth.device_code)
        assert new_interval == base + device_service.SLOW_DOWN_INCREMENT_SECONDS
        persisted = await device_service._repo.get_by_device_code(auth.device_code)
        assert persisted.interval == new_interval


class TestVerifyUserCode:
    async def test_found_and_missing(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        assert (
            await device_service.verify_user_code(auth.user_code)
        ).device_code == auth.device_code
        assert await device_service.verify_user_code("nope") is None


class TestApprove:
    async def test_unknown_code_returns_false(self, device_service):
        assert await device_service.approve("missing", "u-1") is False

    async def test_non_pending_returns_false(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        await device_service.deny(auth.user_code)
        assert await device_service.approve(auth.user_code, "u-1") is False

    async def test_success_sets_authorized(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        assert await device_service.approve(auth.user_code, "u-42") is True
        persisted = await device_service._repo.get_by_device_code(auth.device_code)
        assert persisted.status == "authorized"
        assert persisted.user_id == "u-42"
        assert persisted.authorized_at is not None


class TestDeny:
    async def test_unknown_code_returns_false(self, device_service):
        assert await device_service.deny("missing") is False

    async def test_non_pending_returns_false(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        await device_service.approve(auth.user_code, "u-1")
        assert await device_service.deny(auth.user_code) is False

    async def test_success_sets_denied(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        assert await device_service.deny(auth.user_code) is True
        persisted = await device_service._repo.get_by_device_code(auth.device_code)
        assert persisted.status == "denied"


class TestCleanupExpired:
    async def test_nothing_expired_returns_zero(self, device_service):
        await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        assert await device_service.cleanup_expired() == 0
        device_service.audit_service.log_event.assert_not_awaited()

    async def test_expired_authorization_is_deleted(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        await _expire(device_service, auth)
        deleted = await device_service.cleanup_expired()
        assert deleted == 1
        assert await device_service._repo.get_by_device_code(auth.device_code) is None

    async def test_audits_each_expired_pending_authorization(self, device_service):
        """The audit loop reads the *pre-delete* snapshot.

        A mocked repository is used because the real ``list_all`` already
        re-labels expired rows as ``expired`` before the service's
        ``status == "pending"`` filter runs, leaving the loop unreachable
        through the file backend (reported, not fixed here).
        """
        from authglow.models.token import DeviceAuthorization

        expired = DeviceAuthorization(
            user_code="AAAA-1111",
            client_id="client-1",
            scope="read",
            verification_uri="https://verify.example",
            expires_at=utcnow() - timedelta(seconds=1),
            status="pending",
        )
        live = DeviceAuthorization(
            user_code="BBBB-2222",
            client_id="client-2",
            scope="read",
            verification_uri="https://verify.example",
            expires_at=utcnow() + timedelta(seconds=600),
            status="pending",
        )
        device_service._repo = MagicMock()
        device_service._repo.list_all = AsyncMock(return_value=[expired, live])
        device_service._repo.delete_expired = AsyncMock(return_value=1)

        assert await device_service.cleanup_expired() == 1
        device_service.audit_service.log_event.assert_awaited_once()
        assert device_service.audit_service.log_event.await_args.kwargs["client_id"] == "client-1"


class TestListing:
    async def test_list_all_returns_everything(self, device_service):
        await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        await device_service.create_device_authorization(
            "client-2", "read", "https://verify.example"
        )
        assert len(await device_service.list_all()) == 2

    async def test_list_all_filters_by_status(self, device_service):
        approved = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        await device_service.create_device_authorization(
            "client-2", "read", "https://verify.example"
        )
        await device_service.approve(approved.user_code, "u-1")
        authorized = await device_service.list_all("authorized")
        assert len(authorized) == 1
        assert authorized[0].device_code == approved.device_code

    async def test_list_by_user(self, device_service):
        mine = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        other = await device_service.create_device_authorization(
            "client-2", "read", "https://verify.example"
        )
        await device_service.approve(mine.user_code, "u-1")
        await device_service.approve(other.user_code, "u-2")
        result = await device_service.list_by_user("u-1")
        assert [a.device_code for a in result] == [mine.device_code]


class TestRevoke:
    async def test_unknown_code_returns_false(self, device_service):
        assert await device_service.revoke("missing") is False

    async def test_pending_is_revoked(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        assert await device_service.revoke(auth.device_code) is True
        persisted = await device_service._repo.get_by_device_code(auth.device_code)
        assert persisted.status == "denied"

    async def test_authorized_is_revoked(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        await device_service.approve(auth.user_code, "u-1")
        assert await device_service.revoke(auth.device_code) is True

    async def test_already_denied_returns_false(self, device_service):
        auth = await device_service.create_device_authorization(
            "client-1", "read", "https://verify.example"
        )
        await device_service.deny(auth.user_code)
        assert await device_service.revoke(auth.device_code) is False
