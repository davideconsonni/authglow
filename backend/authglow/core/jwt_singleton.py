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
* **Multi-replica aware** — every ``jwt_keyring_refresh_seconds``
  (default 60; ``0`` disables) a cheap staleness probe re-reads
  ``keyring.json`` from the shared backend and rebuilds the snapshot
  when another replica rotated, revoked, or bootstrapped a key. The
  probe reads the small JSON index only — no PEM reads, no private-
  key decryption — and deduplicates concurrent probes through the
  same ``asyncio.Lock`` as the initial build.

Tests that want a fresh singleton between cases should call
:func:`reset_jwt_singleton` in a fixture (see ``tests/conftest.py``).
"""

import asyncio
from datetime import datetime
from typing import Optional

import structlog

from authglow.core.datetime import utcnow
from authglow.services.jwt import JWTService

_singleton: Optional[JWTService] = None
_last_probe: Optional[datetime] = None
_lock = asyncio.Lock()

_probe_log = structlog.get_logger("authglow.keys")


async def get_jwt_service() -> JWTService:
    """Return the process-wide :class:`JWTService` instance.

    On the first call this builds the service via
    :meth:`JWTService.new` (which loads the keyring snapshot from
    fsspec and decrypts the active private key). All subsequent
    calls return the same instance without touching disk — except
    for the periodic staleness probe (see module docstring): once
    ``jwt_keyring_refresh_seconds`` have elapsed since the last
    probe, ``keyring.json`` is re-read from the shared backend and
    the snapshot is rebuilt if another replica mutated it. Probe
    I/O failures are logged and swallowed — requests keep being
    served from the (possibly stale) snapshot and the probe retries
    after the next full interval.
    """
    global _singleton, _last_probe
    if _singleton is None:
        async with _lock:
            if _singleton is None:
                _singleton = await JWTService.new()
                _last_probe = utcnow()
        return _singleton

    interval = _singleton.settings.jwt_keyring_refresh_seconds
    if interval <= 0:
        return _singleton
    if _last_probe is None or (utcnow() - _last_probe).total_seconds() < interval:
        return _singleton

    async with _lock:
        # Double-check: a concurrent caller may have probed while
        # this one waited for the lock.
        if _last_probe is not None and (utcnow() - _last_probe).total_seconds() < interval:
            return _singleton
        # Consume the interval *before* the I/O so callers racing on
        # the lock do not pile up duplicate probes; a failed probe
        # retries after one full new interval.
        _last_probe = utcnow()
        try:
            changed = await _singleton.keyring_changed_on_disk()
        except Exception:
            _probe_log.warning("keyring_probe_failed", exc_info=True)
            return _singleton
        if changed:
            _probe_log.info("keyring_reloaded_after_foreign_change")
            _singleton = await JWTService.new()
    return _singleton


async def reset_jwt_singleton() -> None:
    """Drop the cached singleton so the next :func:`get_jwt_service`
    reloads the keyring from disk.

    Called automatically by :meth:`JWTService.rotate_keys` and
    :meth:`JWTService.revoke_key` after they mutate the keyring.
    Tests can also call this from an autouse fixture to guarantee
    isolation between cases. Also clears the probe timestamp so the
    rebuilt service starts with a full probe interval.
    """
    global _singleton, _last_probe
    _singleton = None
    _last_probe = None
