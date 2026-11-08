"""Process-wide instances for the root index repositories.

The file backend's root indexes (email index, federated identities)
hold their data cache in memory; constructing a fresh repository per
request made that cache useless — every user-cache miss re-parsed the
whole index file again. This registry keeps **one** repository per
``(entity, storage location)`` alive for the lifetime of the process,
so the cache is shared by every code path that resolves the repository
through ``authglow.repositories.dependencies`` (API routers, service
constructors, direct call sites alike).

Only the ``file`` backend is shared. The repositories hold no
event-loop-bound state (plain dicts and timestamps), so reuse across
``asyncio.run()`` sessions is safe. (``AsyncNamedLock`` guards against
the same hazard by evicting each entry as soon as no coroutine holds or
waits on it, so a lock never outlives the loop that contended on it.)
Tests reset the registry around every case (``tests/conftest.py``).
"""

from typing import Any, Callable, Dict, Tuple

_shared: Dict[Tuple[str, str, str], Any] = {}


def get_shared_index_repository(entity: str, settings: Any, factory: Callable[..., Any]) -> Any:
    """Return the process-wide repository instance for *entity*.

    Keyed by ``(entity, storage_backend, storage_path)`` so a settings
    change — a different storage location, e.g. a per-test
    ``tmp_path`` — transparently builds and caches a fresh instance
    instead of serving a repository bound to the old one. Construction
    performs no I/O, and the dict get/set pair is synchronous on the
    event-loop thread, so no lock is needed: a benign duplicate build
    can only lose one constructor, never corrupt the cache.
    """
    key = (entity, str(settings.storage_backend), str(settings.storage_path))
    repo = _shared.get(key)
    if repo is None:
        repo = factory(settings=settings)
        _shared[key] = repo
    return repo


def reset_shared_index_repositories() -> None:
    """Drop all cached instances so the next call rebuilds them.

    Used by the test suite for isolation; production code never calls
    it (a settings change at runtime does not recreate the process
    settings object anyway — ``get_settings`` is ``lru_cache``d).
    """
    _shared.clear()
