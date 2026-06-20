"""Process-wide singleton for the outbound :class:`httpx.AsyncClient`.

Before this module existed, every call to :mod:`authglow.services.federation`
created a fresh :class:`httpx.AsyncClient` (with a brand-new SSL context
and connection pool) inside an ``async with`` block. Under load that
meant: SSL handshake + TCP setup on every request, file-descriptor
churn, and no keep-alive between back-to-back calls to the same IdP.

This module exposes a single :func:`get_http_client` that all callers
share. It is:

* **Lazy** — the client is created on first call.
* **Async-safe** — initialisation is guarded by an ``asyncio.Lock``
  with double-checked locking so concurrent first-callers do not
  trigger duplicate client construction.
* **Bounded** — the connection pool is sized via
  :data:`httpx.Limits` (``max_connections=50``,
  ``max_keepalive_connections=20``) so the process never opens more
  than 50 outbound TCP/TLS sessions total.

Tests that need a fresh client between cases should call
:func:`reset_http_client` in a fixture (see ``tests/conftest.py``).
"""

import asyncio
from typing import Optional

import httpx

_LIMITS = httpx.Limits(max_connections=50, max_keepalive_connections=20)
_TIMEOUT = httpx.Timeout(15.0)

_client: Optional[httpx.AsyncClient] = None
_lock = asyncio.Lock()


async def get_http_client() -> httpx.AsyncClient:
    """Return the process-wide :class:`httpx.AsyncClient` instance.

    On the first call this builds the client with the configured
    :data:`_LIMITS` and :data:`_TIMEOUT`. All subsequent calls return
    the same instance, allowing keep-alive between requests.
    """
    global _client
    if _client is None:
        async with _lock:
            if _client is None:
                _client = httpx.AsyncClient(timeout=_TIMEOUT, limits=_LIMITS)
    return _client


async def reset_http_client() -> None:
    """Close the cached client (if any) and drop the singleton.

    Called by autouse test fixtures to guarantee isolation between
    cases. Production code should not need to call this — the client
    lives for the lifetime of the uvicorn process.

    If the cached client was bound to an event loop that has since
    been closed (typical at test teardown), the ``aclose`` call would
    raise ``RuntimeError("Event loop is closed")``; in that case the
    client reference is dropped without explicit close — the loop's
    own teardown will release the underlying sockets.
    """
    global _client
    if _client is not None:
        try:
            await _client.aclose()
        except RuntimeError:
            pass
    _client = None
