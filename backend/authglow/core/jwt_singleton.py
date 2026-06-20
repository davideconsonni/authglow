"""Process-wide singleton for :class:`JWTService`.

Loading the JWT keyring is expensive (3-4 fsspec reads + one AES-GCM
private-key decrypt) and the resulting in-memory snapshot is reused
across every authenticated request. Before this module existed, every
``api/<router>.py`` redeclared its own ``_jwt_service`` global, so the
process held N independent singletons (one per router) and each one
eagerly loaded the keyring at first use.

This module exposes a single :func:`get_jwt_service` that all routers
and direct call sites share. It is:

* **Lazy** — the keyring is loaded only on first call.
* **Async-safe** — initialisation is guarded by an ``asyncio.Lock``
  with double-checked locking so concurrent first-callers do not
  trigger duplicate ``JWTService.new()`` invocations.
* **Invalidatable** — :func:`reset_jwt_singleton` is called by
  :meth:`JWTService.rotate_keys` and :meth:`JWTService.revoke_key` so
  the next :func:`get_jwt_service` reloads the keyring snapshot from
  disk after an admin rotation or revocation.

Tests that want a fresh singleton between cases should call
:func:`reset_jwt_singleton` in a fixture (see ``tests/conftest.py``).
"""

import asyncio
from typing import Optional

from authglow.services.jwt import JWTService

_singleton: Optional[JWTService] = None
_lock = asyncio.Lock()


async def get_jwt_service() -> JWTService:
    """Return the process-wide :class:`JWTService` instance.

    On the first call this builds the service via
    :meth:`JWTService.new` (which loads the keyring snapshot from
    fsspec and decrypts the active private key). All subsequent calls
    return the same instance without touching disk.
    """
    global _singleton
    if _singleton is None:
        async with _lock:
            if _singleton is None:
                _singleton = await JWTService.new()
    return _singleton


async def reset_jwt_singleton() -> None:
    """Drop the cached singleton so the next :func:`get_jwt_service`
    reloads the keyring from disk.

    Called automatically by :meth:`JWTService.rotate_keys` and
    :meth:`JWTService.revoke_key` after they mutate the keyring. Tests
    can also call this from an autouse fixture to guarantee isolation
    between cases.
    """
    global _singleton
    _singleton = None
