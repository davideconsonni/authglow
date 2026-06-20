"""Performance / regression tests for the per-request OAuth2Client cache (Tier 1.5).

These tests verify that:

* :meth:`authglow.services.oauth2.OAuth2Service._get_client_cached`
  returns the same :class:`OAuth2Client` instance across multiple
  calls within a single request (the hot path of ``/oauth2/authorize``
  calls ``verify_client``, ``verify_redirect_uri``, ``verify_scopes``,
  ``process_scopes``, and ``verify_grant_type`` — five methods that
  all look up the same ``client_id``);
* the per-request cache is isolated between independent
  :class:`asyncio.Task` instances (i.e. between concurrent requests
  handled by the same process — each Task gets its own
  :class:`contextvars.Context`);
* the cache stores **negative** results (``None``) as well as
  positive ones so a single in-flight request to an unknown
  client_id triggers exactly one repository read regardless of how
  many methods call into the helper;
* distinct ``client_id`` values are cached separately.

Run with: ``pytest -m performance`` from the ``backend/`` directory.
"""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

from authglow.services.oauth2 import OAuth2Service

pytestmark = pytest.mark.performance


def _build_service_with_mock_storage(test_settings, client_responses: dict) -> OAuth2Service:
    """Build a real ``OAuth2Service`` whose underlying
    ``client_storage.get_client`` returns whatever is mapped in
    ``client_responses`` for the requested ``client_id`` (or
    ``None`` if absent). The mock records the call count so tests
    can assert that the cache avoided redundant reads.
    """
    service = OAuth2Service(settings=test_settings)
    storage = MagicMock()
    call_log: list[str] = []

    async def fake_get_client(client_id: str):
        call_log.append(client_id)
        return client_responses.get(client_id)

    storage.get_client = fake_get_client
    service.client_storage = storage
    service._test_call_log = call_log
    return service


class TestOAuth2ClientCache:
    """``_get_client_cached`` must cache per request."""

    async def test_cache_hits_within_request(self, test_settings):
        """Five calls for the same client_id → one repository read."""
        client = MagicMock()
        client.is_active = True
        service = _build_service_with_mock_storage(test_settings, {"client-A": client})

        for _ in range(5):
            got = await service._get_client_cached("client-A")
            assert got is client

        assert service._test_call_log == ["client-A"], (
            f"expected single repository read, got calls: {service._test_call_log}"
        )

    async def test_cache_isolated_between_concurrent_tasks(self, test_settings):
        """Two concurrent Tasks (simulating two requests) each see
        an independent cache. Each Task reads the repository exactly
        once for its own ``client_id``."""
        client_a = MagicMock(name="A")
        client_a.is_active = True
        client_b = MagicMock(name="B")
        client_b.is_active = True
        service = _build_service_with_mock_storage(
            test_settings, {"client-A": client_a, "client-B": client_b}
        )

        # Capture the call log per Task via a wrapper that
        # references the shared ``service._test_call_log`` (each
        # Task appends to the same list — we assert on the
        # *total* count to prove each Task triggered one read).
        async def task_a():
            for _ in range(3):
                assert await service._get_client_cached("client-A") is client_a

        async def task_b():
            for _ in range(3):
                assert await service._get_client_cached("client-B") is client_b

        await asyncio.gather(task_a(), task_b())

        assert service._test_call_log.count("client-A") == 1, (
            f"task A should read the repository once; got: "
            f"{service._test_call_log}"
        )
        assert service._test_call_log.count("client-B") == 1, (
            f"task B should read the repository once; got: "
            f"{service._test_call_log}"
        )

    async def test_cache_caches_negative_result(self, test_settings):
        """A client_id that does not exist is cached as ``None`` and
        is not re-fetched on subsequent calls within the same
        request."""
        service = _build_service_with_mock_storage(test_settings, {})

        for _ in range(5):
            got = await service._get_client_cached("unknown-client")
            assert got is None

        assert service._test_call_log == ["unknown-client"], (
            f"expected single read for unknown client, got: {service._test_call_log}"
        )

    async def test_cache_distinct_clients_cached_separately(self, test_settings):
        """Two different client_ids → two repository reads."""
        client_a = MagicMock(name="A")
        client_b = MagicMock(name="B")
        service = _build_service_with_mock_storage(
            test_settings, {"client-A": client_a, "client-B": client_b}
        )

        for _ in range(3):
            assert await service._get_client_cached("client-A") is client_a
            assert await service._get_client_cached("client-B") is client_b

        assert sorted(service._test_call_log) == ["client-A", "client-B"], (
            f"expected exactly one read per distinct client, "
            f"got: {service._test_call_log}"
        )

    async def test_cache_clears_between_request_tasks(self, test_settings):
        """A Task that exits does not pollute the cache seen by
        the next Task that runs in the same process — proves the
        contextvar is properly scoped to the Task lifecycle.

        In FastAPI, every request handler runs in a fresh
        :class:`asyncio.Task` (created by ``asyncio.create_task``).
        We simulate that here with explicit ``create_task`` calls:
        each Task sees an independent cache.
        """
        client_a = MagicMock(name="A")
        client_a.is_active = True
        service = _build_service_with_mock_storage(test_settings, {"client-A": client_a})

        async def one_request():
            await service._get_client_cached("client-A")
            await service._get_client_cached("client-A")
            await service._get_client_cached("client-A")

        # First "request" — a fresh Task that runs to completion.
        await asyncio.create_task(one_request())
        assert service._test_call_log == ["client-A"], (
            f"first request should read the repository once; got: "
            f"{service._test_call_log}"
        )

        # Second "request" — another fresh Task. The cache from
        # the first request is gone (its Task completed and its
        # context is GC'd), so the repository is read again.
        await asyncio.create_task(one_request())
        assert service._test_call_log.count("client-A") == 2, (
            f"each new Task must re-read; got: {service._test_call_log}"
        )
