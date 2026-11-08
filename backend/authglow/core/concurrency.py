"""Concurrency primitives for protecting read-modify-write operations.

Three layers of defense against race conditions:

1. **AsyncNamedLock** — Per-key ``asyncio.Lock`` that serializes read-modify-write
   sequences within a single process.  Acquired with ``async with lock(key):``.
   Prevents the most common race: two async coroutines interleaving their
   read-modify-write on the same resource.  Entries are evicted when the last
   participant leaves, so the registry stays proportional to the sections in
   flight and no lock ever outlives the event loop that contended on it.

2. **ThreadNamedLock** — Per-key ``threading.Lock`` for critical sections that
   run on an ``asyncio.to_thread`` worker.  It carries no event-loop affinity
   and is released only by the thread that holds it, so cancelling the awaiting
   coroutine cannot open the section while the worker is still running.
   Entries are evicted when the last thread leaves, so the registry stays
   proportional to the writes in flight.

3. **ConcurrentWriteError** — Raised by the optimistic-concurrency CAS helpers
   in ``async_io.py`` when a record's ``_version`` field has changed between the
   read and the write.  Callers should retry the entire RMW operation.
"""

import asyncio
import threading
from contextlib import asynccontextmanager, contextmanager
from typing import Dict, Iterator


class ConcurrentWriteError(Exception):
    """Raised when an optimistic-concurrency write detects a version mismatch.

    The caller should re-read the record, re-apply the business-logic
    modification, and attempt the write again.
    """

    pass


class AsyncNamedLock:
    """A collection of named ``asyncio.Lock`` instances with eviction.

    Usage::

        lock = AsyncNamedLock()
        async with lock("user:123"):
            user = await read(...)
            user.field = new_value
            await write(...)

    Locks are created lazily and evicted as soon as the last coroutine
    holding or waiting on a key leaves, mirroring :class:`ThreadNamedLock`.
    The registry therefore stays proportional to the critical sections in
    flight, not to every key ever seen (hot paths mint a fresh key per
    request: auth codes, PAR requests, reset tokens, consents).  Eviction
    also removes the loop-affinity hazard: an ``asyncio.Lock`` that was
    contended under one event loop raises ``RuntimeError`` when a second
    loop contends on it, so entries must not survive the loop that used
    them.  Because an entry only exists while participants are counted,
    the next ``asyncio.run()`` builds a fresh lock bound to its own loop.
    """

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._entries: Dict[str, _AsyncLockEntry] = {}

    @asynccontextmanager
    async def __call__(self, key: str):
        """Acquire the lock for *key* for the duration of the context."""
        with self._guard:
            entry = self._entries.get(key)
            if entry is None:
                entry = _AsyncLockEntry()
                self._entries[key] = entry
            # Counted while holding ``_guard`` so an entry can never be
            # evicted between the lookup and the increment: ``users``
            # reaches 0 only when no coroutine is holding or waiting.
            # A waiter cancelled while acquiring still decrements in the
            # ``finally`` below — ``asyncio.Lock.acquire()`` guarantees it
            # does not hold the lock when it raises ``CancelledError``.
            entry.users += 1
        try:
            await entry.lock.acquire()
            try:
                yield
            finally:
                entry.lock.release()
        finally:
            with self._guard:
                entry.users -= 1
                if entry.users == 0:
                    del self._entries[key]

    def is_held(self, key: str) -> bool:
        """Return True if the lock for *key* is currently held."""
        entry = self._entries.get(key)
        return entry is not None and entry.lock.locked()


class _AsyncLockEntry:
    """An ``asyncio.Lock`` plus the count of coroutines holding or waiting on it."""

    __slots__ = ("lock", "users")

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.users = 0


class _LockEntry:
    """A ``threading.Lock`` plus the count of threads holding or waiting on it."""

    __slots__ = ("lock", "users")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.users = 0


class ThreadNamedLock:
    """A collection of named ``threading.Lock`` instances with eviction.

    Counterpart to :class:`AsyncNamedLock` for code that runs on an
    ``asyncio.to_thread`` worker.  A ``threading.Lock`` is used instead of
    an ``asyncio.Lock`` because the guarded code has no access to the event
    loop: the lock must be acquirable from the worker thread, must not bind
    to one loop (tests drive scenarios on fresh loops with ``asyncio.run``),
    and must stay held until the thread finishes even if the awaiting
    coroutine is cancelled.

    Entries are evicted as soon as the last thread holding or waiting on a
    key leaves (same scheme as :class:`AsyncNamedLock`).  The registry
    therefore stays proportional to the writes in flight, not to every key
    ever seen.

    Usage::

        locks = ThreadNamedLock()
        with locks("path/to/record.json"):
            ...
    """

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._entries: Dict[str, _LockEntry] = {}

    @contextmanager
    def __call__(self, key: str) -> Iterator[None]:
        """Acquire the lock for *key* for the duration of the context."""
        with self._guard:
            entry = self._entries.get(key)
            if entry is None:
                entry = _LockEntry()
                self._entries[key] = entry
            # Counted while holding ``_guard`` so an entry can never be
            # evicted between the lookup and the increment: ``users``
            # reaches 0 only when no thread is holding or waiting.
            entry.users += 1
        try:
            with entry.lock:
                yield
        finally:
            with self._guard:
                entry.users -= 1
                if entry.users == 0:
                    del self._entries[key]


_named_lock: AsyncNamedLock | None = None
_thread_named_lock: ThreadNamedLock | None = None


def named_lock() -> AsyncNamedLock:
    """Return the process-global ``AsyncNamedLock`` singleton."""
    global _named_lock
    if _named_lock is None:
        _named_lock = AsyncNamedLock()
    return _named_lock


def thread_named_lock() -> ThreadNamedLock:
    """Return the process-global ``ThreadNamedLock`` singleton."""
    global _thread_named_lock
    if _thread_named_lock is None:
        _thread_named_lock = ThreadNamedLock()
    return _thread_named_lock
