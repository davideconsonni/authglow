"""Concurrency primitives for protecting read-modify-write operations.

Two layers of defense against race conditions:

1. **AsyncNamedLock** — Per-key ``asyncio.Lock`` that serializes read-modify-write
   sequences within a single process.  Acquired with ``async with lock(key):``.
   Prevents the most common race: two async coroutines interleaving their
   read-modify-write on the same resource.

2. **ConcurrentWriteError** — Raised by the optimistic-concurrency CAS helpers
   in ``async_io.py`` when a record's ``_version`` field has changed between the
   read and the write.  Callers should retry the entire RMW operation.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Dict


class ConcurrentWriteError(Exception):
    """Raised when an optimistic-concurrency write detects a version mismatch.

    The caller should re-read the record, re-apply the business-logic
    modification, and attempt the write again.
    """

    pass


class AsyncNamedLock:
    """A collection of named ``asyncio.Lock`` instances.

    Usage::

        lock = AsyncNamedLock()
        async with lock("user:123"):
            user = await read(...)
            user.field = new_value
            await write(...)

    Locks are created lazily and never evicted.  In practice the total
    number of distinct keys is small (one per active user / token / code),
    so memory is not a concern.
    """

    def __init__(self) -> None:
        self._locks: Dict[str, asyncio.Lock] = {}

    @asynccontextmanager
    async def __call__(self, key: str):
        """Acquire the lock for *key* for the duration of the context."""
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
        async with lock:
            yield

    def is_held(self, key: str) -> bool:
        """Return True if the lock for *key* is currently held."""
        lock = self._locks.get(key)
        return lock is not None and lock.locked()


_named_lock: AsyncNamedLock | None = None


def named_lock() -> AsyncNamedLock:
    """Return the process-global ``AsyncNamedLock`` singleton."""
    global _named_lock
    if _named_lock is None:
        _named_lock = AsyncNamedLock()
    return _named_lock
