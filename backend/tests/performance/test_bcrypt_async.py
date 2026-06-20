"""Performance / micro-benchmark tests for the bcrypt async path (Tier 1.1).

These tests verify that:

* ``hash_password_async`` / ``verify_password_async`` produce identical
  results to their sync counterparts (correctness);
* the async path is safe under concurrency (50+ concurrent tasks do not
  crash and produce consistent results);
* the async path does NOT block the asyncio event loop while a bcrypt
  computation is in flight (a sentinel ``asyncio.Event`` can be set in
  the meantime);
* the async overhead vs sync is bounded (micro-benchmark, skipped on CI).

Run with: ``pytest -m performance`` from the ``backend/`` directory.
"""

import asyncio
import os
import time

import pytest

from authglow.services.password import (
    hash_password,
    hash_password_async,
    verify_password,
    verify_password_async,
)

pytestmark = pytest.mark.performance


class TestBcryptAsyncCorrectness:
    """``*_async`` functions must produce identical results to their sync twins."""

    async def test_hash_password_async_roundtrip(self):
        hashed = await hash_password_async("SecureP@ss123!")
        assert await verify_password_async("SecureP@ss123!", hashed)

    async def test_verify_password_async_wrong_password_returns_false(self):
        hashed = await hash_password_async("CorrectP@ss1")
        assert not await verify_password_async("WrongP@ss1", hashed)

    async def test_verify_password_async_empty_hash_returns_false(self):
        try:
            result = await verify_password_async("password", "")
            assert not result
        except (ValueError, TypeError):
            pass

    async def test_hash_async_produces_bcrypt_format(self):
        hashed = await hash_password_async("FormatCheck1!")
        assert hashed.startswith(("$2b$", "$2a$", "$2y$")), f"unexpected format: {hashed!r}"

    async def test_async_produces_different_salts(self):
        h1 = await hash_password_async("samepassword")
        h2 = await hash_password_async("samepassword")
        assert h1 != h2

    async def test_async_72_bytes_truncation_matches_sync(self):
        pw72 = "a" * 72
        pw73 = pw72 + "x"
        h72_async = await hash_password_async(pw72)
        assert await verify_password_async(pw72, h72_async)
        assert await verify_password_async(pw73, h72_async)
        h73_async = await hash_password_async(pw73)
        assert await verify_password_async(pw72, h73_async)
        assert await verify_password_async(pw73, h73_async)

    async def test_async_and_sync_interoperable(self):
        """A hash produced by sync must verify with async and vice versa."""
        h_sync = hash_password("Interop1!")
        h_async = await hash_password_async("Interop1!")
        assert await verify_password_async("Interop1!", h_sync)
        assert await verify_password_async("Interop1!", h_async)
        assert verify_password("Interop1!", h_sync)
        assert verify_password("Interop1!", h_async)


class TestBcryptAsyncConcurrency:
    """The async path must be safe under high concurrency."""

    async def test_50_concurrent_hash_produces_valid_hashes(self):
        passwords = [f"Conc{i}Pass!" for i in range(50)]
        hashes = await asyncio.gather(
            *[hash_password_async(pw) for pw in passwords]
        )
        assert len(hashes) == 50
        assert len(set(hashes)) == 50, "salts must be unique per concurrent call"
        for pw, h in zip(passwords, hashes):
            assert await verify_password_async(pw, h)

    async def test_50_concurrent_verify_same_hash(self):
        hashed = await hash_password_async("SharedPw1!")
        results = await asyncio.gather(
            *[verify_password_async("SharedPw1!", hashed) for _ in range(50)]
        )
        assert all(results), "all 50 concurrent verifies must succeed"

    async def test_async_does_not_block_event_loop(self):
        """While bcrypt is running off-loop, another coroutine must be able to run."""
        sentinel_set = asyncio.Event()
        sentinel_finished = asyncio.Event()

        async def sentinel():
            sentinel_set.set()
            await asyncio.sleep(0)
            sentinel_finished.set()

        sentinel_task = asyncio.create_task(sentinel())
        await sentinel_set.wait()
        hash_task = asyncio.create_task(hash_password_async("NonBlocking1!"))

        try:
            await asyncio.wait_for(sentinel_finished.wait(), timeout=2.0)
        except asyncio.TimeoutError:
            hash_task.cancel()
            sentinel_task.cancel()
            pytest.fail("event loop was blocked while bcrypt was running")

        assert await hash_task
        assert sentinel_finished.is_set()

    async def test_concurrent_mixed_hash_and_verify(self):
        """Mixed workload: 25 hashes + 25 verifies concurrently must not crash."""
        h = await hash_password_async("MixedPw1!")
        passwords_to_hash = [f"MixedHash{i}!" for i in range(25)]
        coros = (
            [hash_password_async(pw) for pw in passwords_to_hash]
            + [verify_password_async("MixedPw1!", h) for _ in range(25)]
        )
        results = await asyncio.gather(*coros)
        assert len(results) == 50
        for i, pw in enumerate(passwords_to_hash):
            assert await verify_password_async(pw, results[i])


class TestBcryptAsyncOverhead:
    """Micro-benchmark: the async wrapper must not introduce significant overhead.

    These tests are skipped in CI (``CI=true`` env var) because they are
    time-sensitive. Run locally to compare against the sync baseline.
    """

    @pytest.mark.skipif(
        os.getenv("CI") == "true", reason="micro-benchmark; skip in CI"
    )
    async def test_async_overhead_vs_sync(self):
        password = "BenchPw1!"
        n = 5

        sync_start = time.perf_counter()
        sync_hashes = [hash_password(password) for _ in range(n)]
        sync_elapsed = time.perf_counter() - sync_start

        async_start = time.perf_counter()
        async_hashes = await asyncio.gather(
            *[hash_password_async(password) for _ in range(n)]
        )
        async_elapsed = time.perf_counter() - async_start

        assert len(sync_hashes) == n
        assert len(async_hashes) == n

        print(
            f"\n[bcrypt overhead] sync={sync_elapsed*1000:.1f}ms "
            f"async={async_elapsed*1000:.1f}ms "
            f"n={n}"
        )

        assert async_elapsed <= sync_elapsed * 2.0 + 0.5, (
            f"async overhead > 2x: sync={sync_elapsed:.3f}s "
            f"async={async_elapsed:.3f}s"
        )
