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

import pytest
from unittest.mock import patch

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
