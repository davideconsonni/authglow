"""Regression tests for ``main.py:lifespan`` wiring (Tier 2.1).

Verifies that the production ``ThreadPoolExecutor`` is widened after
the lifespan starts, so ``asyncio.to_thread`` calls in subsequent
request handling use the larger pool instead of CPython's default
``min(32, cpu+4)``.

The benchmark for the widened pool itself (8/64/200 concurrent ops)
lives in ``tests/performance/test_threadpool.py`` (marker:
``performance``). This file is the production-wiring regression
test — it does NOT measure throughput, only confirms the wiring.
"""

import asyncio
import time
from concurrent.futures import ThreadPoolExecutor


class TestLifespanExecutorPool:
    """Verify the default executor is widened in production (Tier 2.1)."""

    async def test_default_executor_widened_after_lifespan(self) -> None:
        """After lifespan starts, the loop's default executor is a
        ``ThreadPoolExecutor`` with ``max_workers=_DEFAULT_EXECUTOR_WORKERS``.

        Guards against accidental removal of the
        ``loop.set_default_executor`` call from ``main.py:lifespan``.
        """
        # Import inside the test so the autouse ``_override_settings``
        # fixture patches ``get_settings`` before ``main`` is loaded.
        from main import _DEFAULT_EXECUTOR_WORKERS, app

        async with app.router.lifespan_context(app):
            loop = asyncio.get_running_loop()
            executor = loop._default_executor
            assert isinstance(executor, ThreadPoolExecutor), (
                f"Expected ThreadPoolExecutor, got {type(executor).__name__}"
            )
            assert executor._max_workers == _DEFAULT_EXECUTOR_WORKERS, (
                f"Expected {executor._max_workers} workers, "
                f"plan prescribed {_DEFAULT_EXECUTOR_WORKERS}"
            )

    async def test_executor_handles_50_concurrent_to_thread(self) -> None:
        """Smoke test: 50 concurrent ``asyncio.to_thread`` ops against
        the production-widened pool do not saturate.

        With pool=32 (the cap) and each op holding the thread for
        ~50ms, 50 concurrent ops should complete in ~2 batches
        × 50ms = ~100ms. We allow 5× headroom (500ms) for CI noise
        and slow hosts. A regression to the default 8-worker pool
        would take ~350ms (7 batches) — still passes the 500ms
        threshold, so this is a smoke test, not a precise regression
        check. The precise regression lives in
        ``tests/performance/test_threadpool.py``.
        """
        from main import _DEFAULT_EXECUTOR_WORKERS, app

        async with app.router.lifespan_context(app):
            start = time.perf_counter()
            await asyncio.gather(*[asyncio.to_thread(time.sleep, 0.05) for _ in range(50)])
            elapsed = time.perf_counter() - start

        assert elapsed < 0.5, (
            f"50 concurrent to_thread calls took {elapsed * 1000:.0f}ms, "
            f"expected <500ms (pool={_DEFAULT_EXECUTOR_WORKERS})"
        )
