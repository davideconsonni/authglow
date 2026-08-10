"""Unified caching layer for AuthGlow.

Two patterns are used deliberately for different purposes:

- ``functools.lru_cache`` (stdlib) for **pure-function memoization**:
  results are invariant for the same inputs (e.g. ``ui_context``,
  ``get_settings()``). No TTL needed — the result never changes at runtime.
  Used as a decorator on the function itself.

- ``cachetools.TTLCache`` for **data caches with temporal eviction**:
  many entries that expire by age and are memory-bounded (e.g. user
  lookups, refresh-token prefix-index bypass). Configured via Settings
  (``CACHE_USER_MAXSIZE``, ``CACHE_USER_TTL``, etc.).

All caches are in-process only. For serverless multi-instance deployments,
this provides repeated-read savings per warm instance without introducing
a distributed-cache dependency (planned for Phase 5 / Redis / Memcached).
"""

from typing import Dict, Optional

from cachetools import TTLCache

_cache_registry: Optional[Dict[str, "CacheRegistry"]] = None


class CacheRegistry:
    """Singleton holding all application TTLCache instances.

    Lazy-initialized from Settings on first access via
    ``get_cache_registry()``.  Each cache is a ``cachetools.TTLCache``
    with bounds configured through environment variables.
    """

    def __init__(self, maxsize: int, ttl: int, name: str = ""):
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)
        self._name = name

    def get(self, key, default=None):
        return self._cache.get(key, default)

    def pop(self, key, default=None):
        return self._cache.pop(key, default)

    def __setitem__(self, key, value):
        self._cache[key] = value

    def __getitem__(self, key):
        return self._cache[key]

    def __contains__(self, key):
        return key in self._cache

    def __delitem__(self, key):
        del self._cache[key]

    def __len__(self) -> int:
        return len(self._cache)

    @property
    def maxsize(self) -> int:
        return int(self._cache.maxsize)

    @property
    def ttl(self) -> int:
        return int(self._cache.ttl)


def get_cache_registry() -> Dict[str, CacheRegistry]:
    """Return a dict of named ``CacheRegistry`` instances, lazy-init from Settings."""
    global _cache_registry
    if _cache_registry is None:
        from authglow.core.config import get_settings

        s = get_settings()
        _cache_registry = {
            "refresh_token": CacheRegistry(
                maxsize=s.cache_refresh_token_maxsize,
                ttl=s.cache_refresh_token_ttl,
                name="refresh_token",
            ),
            "user": CacheRegistry(
                maxsize=s.cache_user_maxsize,
                ttl=s.cache_user_ttl,
                name="user",
            ),
            "user_by_id": CacheRegistry(
                maxsize=s.cache_user_by_id_maxsize,
                ttl=s.cache_user_by_id_ttl,
                name="user_by_id",
            ),
            "oauth_client": CacheRegistry(
                maxsize=s.cache_oauth_client_maxsize,
                ttl=s.cache_oauth_client_ttl,
                name="oauth_client",
            ),
            "api_key": CacheRegistry(
                maxsize=s.cache_api_key_maxsize,
                ttl=s.cache_api_key_ttl,
                name="api_key",
            ),
            "jti": CacheRegistry(
                maxsize=s.cache_jti_maxsize,
                ttl=s.cache_jti_ttl,
                name="jti",
            ),
        }
    return _cache_registry


def _reset_cache_registry() -> None:
    """Reset the cache registry (for testing only)."""
    global _cache_registry
    _cache_registry = None


# Module-level proxies — drop-in compatible with the previous hardcoded
# TTLCache instances.  Usage unchanged:
#
#     from authglow.core.cache import user_cache
#     user_cache.get(key)
#     user_cache[key] = value
#     user_cache.pop(key, None)
#
class _CacheProxy:
    """Lazy proxy that forwards to the appropriate CacheRegistry entry."""

    def __init__(self, key: str):
        self._key = key

    def _resolve(self):
        return get_cache_registry()[self._key]

    def get(self, key, default=None):
        return self._resolve().get(key, default)

    def pop(self, key, default=None):
        return self._resolve().pop(key, default)

    def __setitem__(self, key, value):
        self._resolve()[key] = value

    def __getitem__(self, key):
        return self._resolve()[key]

    def __contains__(self, key):
        return key in self._resolve()

    def __delitem__(self, key):
        del self._resolve()[key]


refresh_token_cache = _CacheProxy("refresh_token")
user_cache = _CacheProxy("user")
user_by_id_cache = _CacheProxy("user_by_id")
oauth_client_cache = _CacheProxy("oauth_client")
api_key_cache = _CacheProxy("api_key")
jti_cache = _CacheProxy("jti")
