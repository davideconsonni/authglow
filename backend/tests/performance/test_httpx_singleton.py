"""Performance / micro-benchmark tests for the httpx.AsyncClient singleton (Tier 1.3).

These tests verify that:

* :func:`authglow.core.http_client.get_http_client` returns the same
  :class:`httpx.AsyncClient` instance across many calls (no duplicate
  connection-pool / SSL-context construction);
* the client is configured with the limits promised by the plan
  (``max_connections=50``, ``max_keepalive_connections=20``);
* concurrent federation discovery calls share a single client;
* :func:`reset_http_client` closes the existing client and produces
  a fresh instance on the next call.

The integration tests in ``tests/integration/test_federation.py`` mock
the high-level methods (``exchange_code``, ``fetch_userinfo``) so they
do not exercise this code path. This file is the regression test for
the singleton lifecycle.

Run with: ``pytest -m performance`` from the ``backend/`` directory.
"""

import asyncio

import httpx
import pytest

pytestmark = pytest.mark.performance


class TestHttpClientSingleton:
    """``get_http_client`` must return the same cached instance."""

    async def test_http_client_reused_across_calls(self):
        from authglow.core.http_client import get_http_client

        c1 = await get_http_client()
        c2 = await get_http_client()
        c3 = await get_http_client()
        assert c1 is c2 is c3, "singleton must return the same instance"

    async def test_http_client_reused_under_concurrency(self):
        from authglow.core.http_client import get_http_client

        results = await asyncio.gather(*[get_http_client() for _ in range(50)])
        unique_ids = {id(c) for c in results}
        assert len(unique_ids) == 1, (
            f"concurrent first-callers triggered {len(unique_ids)} separate inits"
        )

    async def test_http_client_uses_configured_limits(self):
        from authglow.core import http_client
        from authglow.core.http_client import get_http_client

        assert http_client._LIMITS.max_connections == 50
        assert http_client._LIMITS.max_keepalive_connections == 20

        client = await get_http_client()
        pool = client._transport._pool
        assert pool._max_connections == 50, (
            f"expected pool max_connections=50, got {pool._max_connections}"
        )

    async def test_concurrent_discover_uses_single_client(self):
        """50 concurrent ``FederationService.discover`` calls share one
        ``httpx.AsyncClient`` instance (no per-call pool construction)."""
        from authglow.core.http_client import get_http_client
        from authglow.services.federation import FederationService

        transport = httpx.MockTransport(
            lambda req: httpx.Response(
                200,
                json={
                    "issuer": "https://idp.example.com",
                    "authorization_endpoint": "https://idp.example.com/auth",
                    "token_endpoint": "https://idp.example.com/token",
                    "userinfo_endpoint": "https://idp.example.com/userinfo",
                    "jwks_uri": "https://idp.example.com/jwks",
                },
            )
        )

        client = await get_http_client()
        client._transport = transport

        service = FederationService()
        results = await asyncio.gather(
            *[service.discover("https://idp.example.com") for _ in range(50)]
        )

        assert len(results) == 50
        assert all(r.issuer == "https://idp.example.com" for r in results)

    async def test_reset_closes_and_replaces_client(self):
        from authglow.core.http_client import get_http_client, reset_http_client

        c1 = await get_http_client()
        assert c1.is_closed is False
        await reset_http_client()
        c2 = await get_http_client()
        assert c1 is not c2, "post-reset singleton must be a fresh instance"
        assert c1.is_closed is True, "old client must be closed on reset"
        assert c2.is_closed is False
