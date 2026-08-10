"""Pluggable asynchronous cache backends.

The application exposes named caches through this module while keeping the
storage implementation behind a small asynchronous interface.  The default
backend is an in-process ``cachetools.TTLCache``; Redis is optional and is
selected with ``CACHE_BACKEND=redis``.
"""

from __future__ import annotations

import pickle
from typing import Any, Dict, Optional, Protocol, runtime_checkable

from cachetools import TTLCache


@runtime_checkable
class CacheBackend(Protocol):
    """Asynchronous contract implemented by all cache backends."""

    async def get(self, key: str, default: Any = None) -> Any:
        """Return a cached value or ``default``."""

    async def set(self, key: str, value: Any) -> None:
        """Store a value using the namespace TTL."""

    async def delete(self, key: str) -> None:
        """Delete a key if present."""

    async def set_if_absent(self, key: str, value: Any) -> bool:
        """Store a value only when the key does not already exist."""

    async def contains(self, key: str) -> bool:
        """Return whether a non-expired key exists."""


class InMemoryCacheBackend:
    """Bounded TTL cache for local development, tests, and single workers."""

    def __init__(self, maxsize: int, ttl: int) -> None:
        self._cache: TTLCache = TTLCache(maxsize=maxsize, ttl=ttl)

    async def get(self, key: str, default: Any = None) -> Any:
        return self._cache.get(key, default)

    async def set(self, key: str, value: Any) -> None:
        self._cache[key] = value

    async def set_if_absent(self, key: str, value: Any) -> bool:
        if key in self._cache:
            return False
        self._cache[key] = value
        return True

    async def delete(self, key: str) -> None:
        self._cache.pop(key, None)

    async def contains(self, key: str) -> bool:
        return key in self._cache

    @property
    def maxsize(self) -> int:
        return int(self._cache.maxsize)

    @property
    def ttl(self) -> int:
        return int(self._cache.ttl)


class RedisCacheBackend:
    """Redis-backed implementation using the official asyncio client.

    Redis is an infrastructure dependency, so the import is intentionally
    lazy.  Values are pickled because cache entries are internal Pydantic
    models and are never treated as user-controlled input.  Redis must be
    protected as a trusted internal service.
    """

    def __init__(self, redis_client: Any, prefix: str, ttl: int) -> None:
        self._redis = redis_client
        self._prefix = prefix
        self._ttl = ttl

    def _key(self, key: str) -> str:
        return f"{self._prefix}:{key}"

    async def get(self, key: str, default: Any = None) -> Any:
        value = await self._redis.get(self._key(key))
        if value is None:
            return default
        return pickle.loads(value)

    async def set(self, key: str, value: Any) -> None:
        await self._redis.set(self._key(key), pickle.dumps(value), ex=self._ttl)

    async def delete(self, key: str) -> None:
        await self._redis.delete(self._key(key))

    async def set_if_absent(self, key: str, value: Any) -> bool:
        result = await self._redis.set(
            self._key(key), pickle.dumps(value), ex=self._ttl, nx=True
        )
        return bool(result)

    async def contains(self, key: str) -> bool:
        return bool(await self._redis.exists(self._key(key)))


_cache_registry: Optional[Dict[str, CacheNamespace]] = None


class CacheNamespace:
    """Named cache facade used by services."""

    def __init__(self, backend: CacheBackend) -> None:
        self._backend = backend

    async def get(self, key: str, default: Any = None) -> Any:
        return await self._backend.get(key, default)

    async def set(self, key: str, value: Any) -> None:
        await self._backend.set(key, value)

    async def set_if_absent(self, key: str, value: Any) -> bool:
        return await self._backend.set_if_absent(key, value)

    async def delete(self, key: str) -> None:
        await self._backend.delete(key)

    async def pop(self, key: str, default: Any = None) -> Any:
        value = await self._backend.get(key, default)
        await self._backend.delete(key)
        return value

    async def contains(self, key: str) -> bool:
        return await self._backend.contains(key)

    @property
    def maxsize(self) -> int:
        return int(getattr(self._backend, "maxsize", 0))

    @property
    def ttl(self) -> int:
        return int(getattr(self._backend, "ttl", 0))


def _build_backend(
    settings: Any, name: str, maxsize: int, ttl: int, redis_client: Any = None
) -> CacheBackend:
    """Build one configured backend without importing Redis in memory mode."""
    if settings.cache_backend == "memory":
        return InMemoryCacheBackend(maxsize=maxsize, ttl=ttl)

    if settings.cache_backend == "redis":
        try:
            from redis.asyncio import Redis
        except ImportError as exc:
            raise RuntimeError(
                "CACHE_BACKEND=redis requires the optional 'redis' dependency"
            ) from exc
        client = redis_client or Redis.from_url(settings.redis_url, decode_responses=False)
        prefix = f"{settings.redis_key_prefix}:{name}"
        return RedisCacheBackend(client, prefix=prefix, ttl=ttl)

    raise ValueError(f"Unsupported cache backend: {settings.cache_backend!r}")


def get_cache_registry() -> Dict[str, CacheNamespace]:
    """Return all configured named cache namespaces."""
    global _cache_registry
    if _cache_registry is None:
        from authglow.core.config import get_settings

        settings = get_settings()
        definitions = {
            "refresh_token": (settings.cache_refresh_token_maxsize, settings.cache_refresh_token_ttl),
            "user": (settings.cache_user_maxsize, settings.cache_user_ttl),
            "user_by_id": (settings.cache_user_by_id_maxsize, settings.cache_user_by_id_ttl),
            "oauth_client": (settings.cache_oauth_client_maxsize, settings.cache_oauth_client_ttl),
            "api_key": (settings.cache_api_key_maxsize, settings.cache_api_key_ttl),
            "jti": (settings.cache_jti_maxsize, settings.cache_jti_ttl),
        }
        redis_client = None
        if settings.cache_backend == "redis":
            try:
                from redis.asyncio import Redis
            except ImportError as exc:
                raise RuntimeError(
                    "CACHE_BACKEND=redis requires the optional 'redis' dependency"
                ) from exc
            redis_client = Redis.from_url(settings.redis_url, decode_responses=False)
        _cache_registry = {
            name: CacheNamespace(_build_backend(settings, name, maxsize, ttl, redis_client))
            for name, (maxsize, ttl) in definitions.items()
        }
    return _cache_registry


def _reset_cache_registry() -> None:
    """Reset the lazy registry for test isolation."""
    global _cache_registry
    _cache_registry = None


def get_cache(name: str) -> CacheNamespace:
    """Return a named cache namespace."""
    return get_cache_registry()[name]


class _CacheProxy:
    """Lazy namespace proxy so settings can be replaced in tests."""

    def __init__(self, name: str) -> None:
        self._name = name

    def _resolve(self) -> CacheNamespace:
        return get_cache(self._name)

    async def get(self, key: str, default: Any = None) -> Any:
        return await self._resolve().get(key, default)

    async def set(self, key: str, value: Any) -> None:
        await self._resolve().set(key, value)

    async def set_if_absent(self, key: str, value: Any) -> bool:
        return await self._resolve().set_if_absent(key, value)

    async def delete(self, key: str) -> None:
        await self._resolve().delete(key)

    async def pop(self, key: str, default: Any = None) -> Any:
        return await self._resolve().pop(key, default)

    async def contains(self, key: str) -> bool:
        return await self._resolve().contains(key)


# Temporary name retained for callers that inspect the configured memory
# cache. New code should depend on CacheBackend instead.
CacheRegistry = InMemoryCacheBackend


refresh_token_cache = _CacheProxy("refresh_token")
user_cache = _CacheProxy("user")
user_by_id_cache = _CacheProxy("user_by_id")
oauth_client_cache = _CacheProxy("oauth_client")
api_key_cache = _CacheProxy("api_key")
jti_cache = _CacheProxy("jti")
