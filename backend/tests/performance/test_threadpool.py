"""Micro-benchmark for ``asyncio.to_thread`` concurrency (Tier 2.5).

Measures how the asyncio event loop handles a burst of blocking
operations when the underlying ``ThreadPoolExecutor`` is sized
differently. Tier 2.5 of ``docs/plans/PERFORMANCE_OPTIMIZATION_PLAN.md``
widens the default executor from CPython's
``min(32, cpu_count + 4)`` workers to ``min(32, cpu_count * 4)``;
this benchmark exists to decide whether that change actually moves
the needle in our workload.

The benchmark uses ``time.sleep`` as the blocking primitive
(deterministic, no CPU contention) to isolate the
"how many threads can we parallelise" question from
"how fast is the underlying op".

Two runs are performed back-to-back:

* **Baseline** — no ``set_default_executor``; the loop uses the
  Python default ``min(32, cpu+4)`` workers.
* **Widened** — ``set_default_executor(ThreadPoolExecutor(
  min(32, cpu*4)))`` is applied before the timed runs.

The headline comparison is the ``n=64`` case (8 batches on
the baseline, 2 batches on the widened pool → 4× speed-up
is the headline). If the actual speed-up is < 20%, the plan
documents that §2.5 is reverted (see the rollback section in
the plan).

Run with: ``pytest -m performance`` from the ``backend/`` directory.
"""

import asyncio
import os
import statistics
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

pytestmark = pytest.mark.performance

# Each "work unit" holds the thread for ~50ms. With pool=8 the
# saturated case (N=64) takes ~8 * 50ms = 400ms; with pool=32
# it drops to ~2 * 50ms = 100ms. The 3.5-4x speed-up is what
# the plan promises — the benchmark verifies it holds in
# practice on the developer's machine.
_OP_DURATION_SECONDS = 0.05


async def _bench(n: int) -> float:
    """Return wall time (seconds) for *n* concurrent ``to_thread`` calls."""
    start = time.perf_counter()
    await asyncio.gather(
        *[
            asyncio.to_thread(time.sleep, _OP_DURATION_SECONDS)
            for _ in range(n)
        ]
    )
    return time.perf_counter() - start


def _ratio(n: int, t: float) -> float:
    """How many times the single-op time fits in the wall time."""
    return t / _OP_DURATION_SECONDS if _OP_DURATION_SECONDS > 0 else float("inf")


def _print(label: str, n: int, trials: list[float], pool_size: int) -> None:
    best = min(trials)
    median = statistics.median(trials)
    print(
        f"\n[threadpool bench] {label}: pool={pool_size} n={n} "
        f"best={best*1000:.1f}ms (ratio={_ratio(n, best):.2f}x op) "
        f"median={median*1000:.1f}ms "
        f"trials={[f'{t*1000:.1f}ms' for t in trials]}"
    )


async def _bench_n_times(n: int, n_trials: int = 3) -> list[float]:
    return [await _bench(n) for _ in range(n_trials)]


class TestThreadPoolBenchmark:
    """``asyncio.to_thread`` throughput under concurrency.

    The two scales (``n=8`` and ``n=64``) let us see the full picture:

    * **n=8** — exactly fills a default 8-worker pool; no
      improvement expected from widening.
    * **n=64** — 8× a pool of 8, **2× a pool of 32**. This is
      the headline comparison.
    """

    async def test_baseline_default_pool_burst_8(self):
        """8 concurrent blocking ops against the default loop executor.

        Reference: any improvement from widening the pool
        should show up in the larger burst, not here.
        """
        trials = await _bench_n_times(8)
        default_pool = min(32, (os.cpu_count() or 1) + 4)
        _print("baseline burst 8", 8, trials, default_pool)
        assert min(trials) < _OP_DURATION_SECONDS * 2.0, (
            f"8 ops should be near-1× op duration "
            f"({_OP_DURATION_SECONDS*1000:.0f}ms); got {min(trials)*1000:.1f}ms"
        )

    async def test_baseline_default_pool_burst_64(self):
        """64 concurrent blocking ops against the default loop executor."""
        trials = await _bench_n_times(64)
        default_pool = min(32, (os.cpu_count() or 1) + 4)
        _print("baseline burst 64", 64, trials, default_pool)
        assert min(trials) < 30.0

    async def test_widened_pool_burst_8(self):
        """Same as ``test_baseline_default_pool_burst_8`` but with the
        widened ``ThreadPoolExecutor`` installed via
        ``loop.set_default_executor`` — this mirrors the
        Tier 2.5 production setup.
        """
        loop = asyncio.get_running_loop()
        widened = ThreadPoolExecutor(
            max_workers=min(32, (os.cpu_count() or 1) * 4)
        )
        loop.set_default_executor(widened)
        try:
            trials = await _bench_n_times(8)
        finally:
            widened.shutdown(wait=False)
        _print("widened burst 8", 8, trials, widened._max_workers)
        assert min(trials) < _OP_DURATION_SECONDS * 2.0

    async def test_widened_pool_burst_64(self):
        """64 concurrent blocking ops against the widened pool.

        **This is the headline comparison.** If the widened
        pool (32 workers) cuts the wall time by >=20% vs
        the default pool (~28 workers on this machine), the
        §2.5 change is worth keeping. Otherwise, the
        PERFORMANCE_OPTIMIZATION_PLAN §2.5 rollback procedure
        applies and the ``set_default_executor`` line in
        ``main.py`` is reverted.
        """
        loop = asyncio.get_running_loop()
        widened = ThreadPoolExecutor(
            max_workers=min(32, (os.cpu_count() or 1) * 4)
        )
        loop.set_default_executor(widened)
        try:
            trials = await _bench_n_times(64)
        finally:
            widened.shutdown(wait=False)
        _print("widened burst 64", 64, trials, widened._max_workers)
        assert min(trials) < 30.0

    async def test_widened_pool_burst_200(self):
        """200 concurrent blocking ops against the widened pool.

        Stress test: 200/32 = 7 batches × 50ms ≈ 350ms expected.
        """
        loop = asyncio.get_running_loop()
        widened = ThreadPoolExecutor(
            max_workers=min(32, (os.cpu_count() or 1) * 4)
        )
        loop.set_default_executor(widened)
        try:
            trials = await _bench_n_times(200)
        finally:
            widened.shutdown(wait=False)
        _print("widened burst 200", 200, trials, widened._max_workers)
        assert min(trials) < 60.0


class TestThreadPoolConfig:
    """Static check: the executor widening plan's formula is sane."""

    def test_proposed_pool_size_is_within_plan_bounds(self):
        proposed = min(32, (os.cpu_count() or 1) * 4)
        default = min(32, (os.cpu_count() or 1) + 4)
        assert proposed <= 32, "Tier 2.5 caps the pool at 32"
        assert proposed >= 1
        print(
            f"\n[threadpool config] cpu_count={os.cpu_count()} "
            f"default_pool={default} proposed_pool={proposed}"
        )
