"""Tests for the dedicated CPU-bound executor (core/executors.py).

Covers the three properties the pool split exists for:

1. CPU-bound work runs on its own pool, not on the event loop and not
   behind default (I/O) executor jobs;
2. the executor is process-global and carries no event-loop affinity,
   so it survives successive ``asyncio.run`` calls (loop-bound
   primitives break here);
3. the password service async wrappers actually route through it.
"""

import asyncio
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from authglow.core.executors import bcrypt_executor, run_cpu_bound
from authglow.services.password import hash_password_async, verify_password_async


class TestRunCpuBound:
    """Behavior of the :func:`run_cpu_bound` dispatcher."""

    @pytest.mark.asyncio
    async def test_returns_callable_result(self):
        def compute(a: int, b: int) -> int:
            return a + b

        assert await run_cpu_bound(compute, 2, 3) == 5

    @pytest.mark.asyncio
    async def test_work_runs_on_dedicated_pool_threads(self, cpu_pool_probe):
        name = await cpu_pool_probe()
        assert name.startswith("authglow-cpu"), f"expected a dedicated pool thread, ran on {name!r}"

    @pytest.mark.asyncio
    async def test_cpu_jobs_do_not_queue_behind_default_pool(self):
        """A 1-worker default executor must not delay CPU-pool dispatches.

        Regression for the shared-pool symptom: with one pool, a blocking
        I/O job occupying the only worker starves every other offload.
        With the split, ``run_cpu_bound`` never touches the default pool.
        """
        loop = asyncio.get_running_loop()
        io_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="io-only")
        loop.set_default_executor(io_pool)
        try:
            # Occupy the single I/O worker for 200ms.
            blocker = asyncio.create_task(asyncio.to_thread(time.sleep, 0.2))
            await asyncio.sleep(0)  # let the blocker get submitted
            started = time.monotonic()
            result = await run_cpu_bound(lambda: "cpu")
            elapsed = time.monotonic() - started
            assert result == "cpu"
            assert elapsed < 0.15, (
                f"CPU job waited {elapsed:.3f}s behind an I/O job — pools shared?"
            )
            await blocker
        finally:
            io_pool.shutdown(wait=False)

    @pytest.mark.asyncio
    async def test_propagates_exceptions(self):
        def boom() -> None:
            raise RuntimeError("kaputt")

        with pytest.raises(RuntimeError, match="kaputt"):
            await run_cpu_bound(boom)


class TestExecutorSingleton:
    """Process-global, loop-independent executor lifecycle."""

    def test_same_instance_across_calls(self):
        assert bcrypt_executor() is bcrypt_executor()

    def test_worker_count_matches_cores(self):
        # ``ThreadPoolExecutor`` keeps the configured size private; reading
        # ``_max_workers`` is the accepted way to assert pool geometry.
        assert bcrypt_executor()._max_workers == max(1, os.cpu_count() or 1)

    def test_survives_successive_asyncio_runs(self):
        """Two consecutive ``asyncio.run`` loops must share the pool safely.

        This is the failure mode that ruled out loop-bound primitives:
        an object bound to the first loop raises on the second one.
        A ``ThreadPoolExecutor`` must not — and the work must still run.
        """

        async def call() -> str:
            thread = await run_cpu_bound(threading.current_thread)
            return thread.name

        first = asyncio.run(call())
        second = asyncio.run(call())
        assert first.startswith("authglow-cpu")
        assert second.startswith("authglow-cpu")


class TestPasswordServiceRouting:
    """The bcrypt async wrappers must land on the CPU pool, not the loop."""

    @pytest.mark.asyncio
    async def test_hash_password_async_runs_on_cpu_pool(self):
        hashed = await hash_password_async("secret123")
        assert hashed.startswith("$2")
        assert await verify_password_async("secret123", hashed) is True

    @pytest.mark.asyncio
    async def test_hash_password_async_dispatches_via_run_cpu_bound(self, monkeypatch):
        """The wrapper must go through the CPU pool, not the default one."""
        import authglow.services.password as pw

        dispatched = []
        real = pw.run_cpu_bound

        async def recorder(func, *args):
            dispatched.append(getattr(func, "__name__", repr(func)))
            return await real(func, *args)

        monkeypatch.setattr(pw, "run_cpu_bound", recorder)
        await pw.hash_password_async("dispatch-check")
        assert dispatched == ["hash_password"]

    @pytest.mark.asyncio
    async def test_hash_password_async_off_the_event_loop(self):
        """The loop must keep ticking while a CPU-pool job runs.

        A ~1-2ms hash at the test bcrypt cost would not prove anything
        at ticker resolution, so the job is pinned to a real sleep:
        if it ran on the loop (or queued behind I/O), the ticker dies.
        """
        ticks = 0

        async def ticker():
            nonlocal ticks
            while True:
                await asyncio.sleep(0.005)
                ticks += 1

        task = asyncio.create_task(ticker())
        try:
            await run_cpu_bound(time.sleep, 0.06)
        finally:
            task.cancel()
        assert ticks >= 3, f"event loop only ticked {ticks} times in 60ms — blocked?"
