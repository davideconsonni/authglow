"""Unit tests for the signed webhook dispatcher (initiative B, fase B2).

Covers: signature determinism/known-vector, retry flow (delays patched),
SSRF blocking before any I/O, subscription+active filtering in fan_out,
and the capped deliveries log integration.

Note on URLs: delivery targets use PUBLIC IP literals so the SSRF guard's
DNS resolution never leaves the sandbox.
"""

import hashlib
import hmac
from unittest.mock import AsyncMock, MagicMock, patch

from authglow.models.webhook import WebhookEndpoint
from authglow.models.webhook_events import LOGIN_FAILED, USER_CREATED
from authglow.repositories.file.webhook import (
    FileWebhookDeliveryRepository,
    FileWebhookRepository,
)
from authglow.services.webhook_dispatcher import (
    SIGNATURE_HEADER,
    WebhookDispatcher,
    sign_payload,
)

PUBLIC_URL = "https://93.184.216.34/x"


def _wh(id="wh_disp000001", url=PUBLIC_URL, events=None,
        secret="whsec_testsecret123", active=True, insecure=False):
    return WebhookEndpoint(
        id=id, url=url, events=events or [USER_CREATED], secret=secret, active=active,
        insecure=insecure,
    )


def _resp(status_code: int):
    m = MagicMock()
    m.status_code = status_code
    return m


def _stub_http(responses=(200,), post_spy=None):
    """Return ``(post_mock, http_client_getter)`` for patching.

    The getter yields a MagicMock client whose ``post`` is *post* — this
    mirrors the real httpx.AsyncClient shape the dispatcher expects.
    """
    if post_spy is None:
        post = AsyncMock(side_effect=[_resp(s) for s in responses])
    else:
        post = post_spy
    client = MagicMock()
    client.post = post

    async def _get():
        return client

    return post, _get


def _getter_for(client):
    async def _get():
        return client

    return _get


class TestSignature:
    def test_known_vector(self):
        body = b'{"hello":"world"}'
        ts = "1700000000"
        expected = hmac.new(
            b"whsec_k", f"{ts}.".encode() + body, hashlib.sha256
        ).hexdigest()
        assert sign_payload("whsec_k", ts, body) == expected

    def test_different_timestamp_different_signature(self):
        assert sign_payload("s", "1", b"x") != sign_payload("s", "2", b"x")


class TestSsrfGuard:
    @staticmethod
    def _dispatcher(test_settings, post_mock):
        repo = FileWebhookRepository(settings=test_settings)
        drepo = FileWebhookDeliveryRepository(settings=test_settings)
        disp = WebhookDispatcher(repository=repo, delivery_repository=drepo)
        _, getter = _stub_http(post_spy=post_mock)
        patcher = patch(
            "authglow.services.webhook_dispatcher.get_http_client", getter
        )
        return disp, patcher

    async def test_loopback_ip_blocked_before_io(self, test_settings):
        post = AsyncMock()
        disp, patcher = self._dispatcher(test_settings, post)

        with patcher:
            summary = await disp.deliver_to_endpoint(
                _wh(url="http://127.0.0.1:9999/hook"), USER_CREATED
            )

        post.assert_not_called()
        assert summary["delivered"] is False

    async def test_insecure_endpoint_bypasses_ssrf_guard(self, test_settings):
        """Un endpoint flaggato ``insecure`` può consegnare a host privati."""
        post = AsyncMock(return_value=_resp(200))
        disp, patcher = self._dispatcher(test_settings, post)

        with patcher:
            summary = await disp.deliver_to_endpoint(
                _wh(url="http://127.0.0.1:9999/hook", insecure=True), USER_CREATED
            )

        post.assert_awaited_once()
        assert summary["delivered"] is True

    async def test_private_dns_resolution_blocked(self, test_settings, monkeypatch):
        # Hostname resolving into a PRIVATE range = HARD block: single
        # record, no retries, no HTTP call.
        monkeypatch.setattr(
            "authglow.services.webhook_dispatcher.socket.getaddrinfo",
            lambda host, port: [(None, None, None, "", ("192.168.1.10", 0))],
        )
        post = AsyncMock()
        disp, patcher = self._dispatcher(test_settings, post)

        with patcher:
            summary = await disp.deliver_to_endpoint(
                _wh(url="https://internal.corp/hook"), USER_CREATED
            )

        post.assert_not_called()
        assert len(summary["attempts"]) == 1
        drepo = FileWebhookDeliveryRepository(settings=test_settings)
        recorded = await drepo.list_for_webhook(summary["webhook_id"])
        assert recorded and recorded[0].ok is False
        assert "non-public" in recorded[0].error

    async def test_unresolvable_host_is_retryable_then_logged(self, test_settings, monkeypatch):
        """Transient DNS failure = delivery error (retried), NOT a hard block."""
        monkeypatch.setattr(
            "authglow.services.webhook_dispatcher.socket.getaddrinfo",
            lambda host, port: (_ for _ in ()).throw(OSError(11001, "getaddrinfo failed")),
        )
        repo = FileWebhookRepository(settings=test_settings)
        drepo = FileWebhookDeliveryRepository(settings=test_settings)
        disp = WebhookDispatcher(repository=repo, delivery_repository=drepo)

        post = AsyncMock()
        _, getter = _stub_http(post_spy=post)

        sleeps = []

        async def fake_sleep(d):
            sleeps.append(d)

        with patch("authglow.services.webhook_dispatcher.get_http_client", getter), \
             patch("authglow.services.webhook_dispatcher.asyncio.sleep", fake_sleep):
            summary = await disp.deliver_to_endpoint(
                _wh(url="https://flaky-dns.example.net/hook"), USER_CREATED
            )

        post.assert_not_called()  # mai raggiunta la fase HTTP
        assert summary["delivered"] is False
        assert len(summary["attempts"]) == 3          # partecipa ai retry
        assert sleeps == [1.0, 5.0]
        logged = await drepo.list_for_webhook(summary["webhook_id"])
        assert [d.attempt for d in logged] == [3, 2, 1]
        assert all("Cannot resolve" in (d.error or "") for d in logged)


class TestRetryFlow:
    @staticmethod
    def _dispatcher(test_settings, responses):
        repo = FileWebhookRepository(settings=test_settings)
        drepo = FileWebhookDeliveryRepository(settings=test_settings)
        disp = WebhookDispatcher(repository=repo, delivery_repository=drepo)
        post, getter = _stub_http(responses=responses)
        return disp, post, getter

    async def test_success_first_attempt_single_log(self, test_settings):
        disp, post, getter = self._dispatcher(test_settings, [200])
        sleep_mock = AsyncMock()

        with patch("authglow.services.webhook_dispatcher.get_http_client", getter), \
             patch("authglow.services.webhook_dispatcher.asyncio.sleep", sleep_mock):
            summary = await disp.deliver_to_endpoint(_wh(), USER_CREATED)

        assert summary["delivered"] is True
        post.assert_awaited_once()
        sleep_mock.assert_not_called()

        headers = post.await_args.kwargs["headers"]
        assert SIGNATURE_HEADER in headers
        assert headers[SIGNATURE_HEADER].startswith("t=") and ",v1=" in headers[SIGNATURE_HEADER]

    async def test_retries_then_succeeds_with_backoff_delays(self, test_settings):
        disp, post, getter = self._dispatcher(test_settings, [500, 500, 200])
        sleeps = []

        async def fake_sleep(d):
            sleeps.append(d)

        with patch("authglow.services.webhook_dispatcher.get_http_client", getter), \
             patch("authglow.services.webhook_dispatcher.asyncio.sleep", fake_sleep):
            summary = await disp.deliver_to_endpoint(_wh(), USER_CREATED)

        assert summary["delivered"] is True
        assert len(summary["attempts"]) == 3
        assert sleeps == [1.0, 5.0]

    async def test_exhausted_retries_all_logged(self, test_settings):
        disp, post, getter = self._dispatcher(test_settings, [500, 500, 500])

        async def fake_sleep(d):
            pass

        with patch("authglow.services.webhook_dispatcher.get_http_client", getter), \
             patch("authglow.services.webhook_dispatcher.asyncio.sleep", fake_sleep):
            summary = await disp.deliver_to_endpoint(_wh(), USER_CREATED)

        assert summary["delivered"] is False
        assert len(summary["attempts"]) == 3
        drepo = FileWebhookDeliveryRepository(settings=test_settings)
        logged = await drepo.list_for_webhook(summary["webhook_id"])
        assert [d.attempt for d in logged] == [3, 2, 1]


class TestFanOutFiltering:
    async def test_only_subscribed_active_endpoints_receive(self, test_settings):
        repo = FileWebhookRepository(settings=test_settings)
        drepo = FileWebhookDeliveryRepository(settings=test_settings)
        await repo.create(_wh("wh_fanout00001", events=[USER_CREATED]))
        await repo.create(_wh("wh_fanout00002", events=[LOGIN_FAILED]))  # not subscribed
        await repo.create(_wh("wh_fanout00003", active=False))           # inactive

        post = AsyncMock(return_value=_resp(200))
        _, getter = _stub_http(post_spy=post)
        disp = WebhookDispatcher(repository=repo, delivery_repository=drepo)

        with patch("authglow.services.webhook_dispatcher.get_http_client", getter):
            summary = await disp.fan_out(USER_CREATED, {"x": 1})

        assert len(summary) == 1
        assert summary[0]["webhook_id"] == "wh_fanout00001"
        assert post.await_count == 1
