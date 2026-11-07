"""Dedicated thread executors for off-loop work.

``asyncio.to_thread`` schedules everything on the event loop's single
default executor. That pool is right for blocking file/network I/O —
many workers, each mostly sleeping in the kernel. bcrypt is the
opposite kind of work: a cost-12 hash is ~200-300ms of real CPU, and
running more of them than there are cores only adds GIL contention.
Sharing one pool means a login burst occupies every worker and a 1ms
record read queues behind 300ms CPU jobs.

This module owns the CPU-bound pool; blocking I/O stays on the default
executor (widened in ``main.py``'s lifespan). The executor is a
process-global singleton created on first use: ``run_in_executor``
binds nothing to an event loop, so the same pool survives successive
``asyncio.run`` calls — unlike loop-bound primitives (``asyncio.Lock``),
which pin to the loop that first sees them.

Thread lifetime: pool threads are joined by ``concurrent.futures`` at
interpreter shutdown, so no explicit teardown is wired into the
lifespan. The process outlives the loop, not the other way round.
"""

import asyncio
import os
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Optional, TypeVar

_R = TypeVar("_R")

# One bcrypt op saturates one core (the C hash loop releases the GIL,
# but there is no benefit queuing more than one CPU job per core).
_BCRYPT_WORKERS = max(1, os.cpu_count() or 1)

_bcrypt_executor: Optional[ThreadPoolExecutor] = None


def bcrypt_executor() -> ThreadPoolExecutor:
    """Return the process-global CPU-bound executor, creating it on first use."""
    global _bcrypt_executor
    if _bcrypt_executor is None:
        _bcrypt_executor = ThreadPoolExecutor(
            max_workers=_BCRYPT_WORKERS,
            thread_name_prefix="authglow-cpu",
        )
    return _bcrypt_executor


async def run_cpu_bound(func: Callable[..., _R], *args: Any) -> _R:
    """Run a blocking, CPU-bound callable on the dedicated pool.

    Drop-in replacement for ``asyncio.to_thread`` for bcrypt-sized
    work: keeps the event loop responsive AND keeps CPU jobs out of
    the I/O pool, so a login burst cannot delay record reads.
    """
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(bcrypt_executor(), func, *args)
