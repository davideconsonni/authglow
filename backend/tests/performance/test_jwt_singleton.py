"""Performance / micro-benchmark tests for the JWTService singleton (Tier 1.2).

These tests verify that:

* :func:`authglow.core.jwt_singleton.get_jwt_service` returns the same
  instance across many calls (no duplicate keyring loads);
* :meth:`JWTService.rotate_keys` invalidates the singleton so the next
  call reloads the keyring snapshot and observes the new active kid.

The unit tests in ``tests/unit/test_jwt.py`` exercise the ``JWTService``
directly. This file focuses on the singleton lifecycle: lazy init,
double-checked locking under concurrency, and cache invalidation on
admin key rotation.

Run with: ``pytest -m performance`` from the ``backend/`` directory.
"""

import asyncio
from datetime import timedelta

import pytest
from unittest.mock import patch

from authglow.core.config import get_or_generate_keyring
from authglow.core.datetime import utcnow

pytestmark = pytest.mark.performance


class TestJwtSingleton:
    """``get_jwt_service`` must return the same cached instance."""

    async def test_singleton_reused_across_calls(self, test_settings):
        from authglow.core.jwt_singleton import get_jwt_service

        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            svc1 = await get_jwt_service()
            svc2 = await get_jwt_service()
            svc3 = await get_jwt_service()
        assert svc1 is svc2 is svc3, "singleton must return the same instance"

    async def test_singleton_reused_under_concurrency(self, test_settings):
        from authglow.core.jwt_singleton import get_jwt_service

        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            results = await asyncio.gather(*[get_jwt_service() for _ in range(50)])
        unique_ids = {id(s) for s in results}
        assert len(unique_ids) == 1, (
            f"concurrent first-callers triggered {len(unique_ids)} separate inits"
        )

    async def test_rotate_invalidates_singleton(self, test_settings, tmp_path):
        from authglow.core import jwt_singleton
        from authglow.services.jwt import JWTService

        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            svc_before = await jwt_singleton.get_jwt_service()
            old_kid = svc_before._active_kid

            rotated = await svc_before.rotate_keys()
            new_kid = rotated["new_kid"]
            assert new_kid != old_kid, "rotate_keys must produce a fresh kid"

            assert jwt_singleton._singleton is None, (
                "rotate_keys must drop the cached singleton"
            )

            svc_after = await jwt_singleton.get_jwt_service()
            assert svc_after is not svc_before, (
                "post-rotate singleton must be a fresh instance"
            )
            assert svc_after._active_kid == new_kid


class TestJwtSingletonStalenessProbe:
    """TTL staleness probe: a replica must pick up keyring
    mutations performed by *another* replica (which cannot call the
    in-process ``reset_jwt_singleton``) within
    ``jwt_keyring_refresh_seconds``."""

    def _bootstrap_private_keys_dir(self, test_settings, tmp_path, name: str) -> None:
        """Point ``test_settings`` at a private keys_dir and
        bootstrap a keyring there, so the session-shared keyring is
        not mutated by these tests."""
        keys_dir = tmp_path / name
        keys_dir.mkdir()
        test_settings.keys_dir = str(keys_dir)
        get_or_generate_keyring(str(keys_dir), test_settings.secret_key, 90, False)

    async def test_probe_rebuilds_after_foreign_rotation(self, test_settings, tmp_path):
        from authglow.core import jwt_singleton
        from authglow.repositories.file.keystore import FileKeyStoreRepository

        self._bootstrap_private_keys_dir(test_settings, tmp_path, "probe_keys")

        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            svc_before = await jwt_singleton.get_jwt_service()
            old_kid = svc_before._active_kid

            # A foreign replica rotates the shared keyring behind
            # our back — no in-process invalidation happens.
            foreign = FileKeyStoreRepository(settings=test_settings)
            new_kid = (await foreign.rotate(secret_key=test_settings.secret_key)).kid
            assert new_kid != old_kid

            # ...the probe interval elapses...
            jwt_singleton._last_probe = utcnow() - timedelta(
                seconds=test_settings.jwt_keyring_refresh_seconds + 1
            )

            # ...and the next get_jwt_service() must observe it.
            svc_after = await jwt_singleton.get_jwt_service()
            assert svc_after is not svc_before, (
                "stale replica must rebuild the snapshot after the probe"
            )
            assert svc_after._active_kid == new_kid

    async def test_probe_no_rebuild_when_keyring_unchanged(
        self, test_settings, tmp_path
    ):
        from authglow.core import jwt_singleton

        self._bootstrap_private_keys_dir(test_settings, tmp_path, "probe_stable_keys")

        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            svc = await jwt_singleton.get_jwt_service()
            jwt_singleton._last_probe = utcnow() - timedelta(
                seconds=test_settings.jwt_keyring_refresh_seconds + 1
            )
            again = await jwt_singleton.get_jwt_service()
        assert again is svc, "unchanged keyring must not rebuild the singleton"

    async def test_probe_disabled_when_interval_zero(self, test_settings, tmp_path):
        from authglow.core import jwt_singleton
        from authglow.repositories.file.keystore import FileKeyStoreRepository

        self._bootstrap_private_keys_dir(test_settings, tmp_path, "probe_off_keys")
        test_settings.jwt_keyring_refresh_seconds = 0

        with patch("authglow.services.jwt.get_settings", return_value=test_settings):
            svc = await jwt_singleton.get_jwt_service()
            old_kid = svc._active_kid

            foreign = FileKeyStoreRepository(settings=test_settings)
            foreign_kid = (
                await foreign.rotate(secret_key=test_settings.secret_key)
            ).kid
            assert foreign_kid != old_kid

            jwt_singleton._last_probe = utcnow() - timedelta(seconds=3600)
            again = await jwt_singleton.get_jwt_service()
        assert again is svc, "interval=0 must disable the staleness probe"
