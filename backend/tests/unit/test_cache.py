import pytest
import warnings
from unittest.mock import patch, MagicMock
from authglow.core.cache import (
    get_cache_registry,
    _reset_cache_registry,
    user_cache,
    refresh_token_cache,
    CacheRegistry,
    RedisCacheBackend,
)
from authglow.core.config import Settings


class TestCacheRegistry:
    def test_singleton_returns_same_dict(self, test_settings):
        with patch("authglow.core.config.get_settings", return_value=test_settings):
            _reset_cache_registry()
            r1 = get_cache_registry()
            r2 = get_cache_registry()
            assert r1 is r2

    def test_singleton_keys(self, test_settings):
        with patch("authglow.core.config.get_settings", return_value=test_settings):
            _reset_cache_registry()
            r = get_cache_registry()
            assert "user" in r
            assert "refresh_token" in r

    def test_user_cache_maxsize_from_settings(self, monkeypatch):
        s = Settings(
            secret_key="a" * 32,
            storage_path="/tmp/test_cache",
            storage_backend="file",
            cache_user_maxsize=100,
            cache_user_ttl=42,
        )
        monkeypatch.setattr("authglow.core.config.get_settings", lambda: s)
        _reset_cache_registry()
        r = get_cache_registry()
        assert r["user"].maxsize == 100
        assert r["user"].ttl == 42

    def test_refresh_token_cache_maxsize_from_settings(self, monkeypatch):
        s = Settings(
            secret_key="a" * 32,
            storage_path="/tmp/test_cache",
            storage_backend="file",
            cache_refresh_token_maxsize=999,
            cache_refresh_token_ttl=77,
        )
        monkeypatch.setattr("authglow.core.config.get_settings", lambda: s)
        _reset_cache_registry()
        r = get_cache_registry()
        assert r["refresh_token"].maxsize == 999
        assert r["refresh_token"].ttl == 77

    def test_default_values_applied(self, test_settings):
        with patch("authglow.core.config.get_settings", return_value=test_settings):
            _reset_cache_registry()
            r = get_cache_registry()
            assert r["user"].maxsize == 2000
            assert r["user"].ttl == 300
            assert r["refresh_token"].maxsize == 5000
            assert r["refresh_token"].ttl == 60

    def test_reset_cache_registry(self, monkeypatch):
        s1 = Settings(
            secret_key="a" * 32,
            storage_path="/tmp/test_cache",
            storage_backend="file",
            cache_user_maxsize=10,
            cache_user_ttl=10,
        )
        s2 = Settings(
            secret_key="a" * 32,
            storage_path="/tmp/test_cache",
            storage_backend="file",
            cache_user_maxsize=20,
            cache_user_ttl=20,
        )
        monkeypatch.setattr("authglow.core.config.get_settings", lambda: s1)
        _reset_cache_registry()
        r1 = get_cache_registry()
        assert r1["user"].maxsize == 10

        _reset_cache_registry()
        monkeypatch.setattr("authglow.core.config.get_settings", lambda: s2)
        r2 = get_cache_registry()
        assert r2["user"].maxsize == 20


class TestCacheProxyCRUD:
    async def test_get_set_contains_delete(self, monkeypatch):
        s = Settings(
            secret_key="a" * 32,
            storage_path="/tmp/test_cache",
            storage_backend="file",
            cache_user_maxsize=100,
            cache_user_ttl=300,
        )
        monkeypatch.setattr("authglow.core.config.get_settings", lambda: s)
        _reset_cache_registry()

        uc = user_cache
        assert await uc.get("missing") is None
        assert await uc.get("missing", "default") == "default"

        await uc.set("key1", "val1")
        assert await uc.get("key1") == "val1"
        assert await uc.contains("key1")
        assert await uc.get("key1") == "val1"

        assert await uc.pop("key1") == "val1"
        assert await uc.get("key1") is None
        assert not await uc.contains("key1")

    async def test_pop_default(self, monkeypatch):
        s = Settings(
            secret_key="a" * 32,
            storage_path="/tmp/test_cache",
            storage_backend="file",
        )
        monkeypatch.setattr("authglow.core.config.get_settings", lambda: s)
        _reset_cache_registry()

        assert await user_cache.pop("nonexistent", "fallback") == "fallback"
        assert await user_cache.pop("nonexistent") is None

    async def test_del_item(self, monkeypatch):
        s = Settings(
            secret_key="a" * 32,
            storage_path="/tmp/test_cache",
            storage_backend="file",
        )
        monkeypatch.setattr("authglow.core.config.get_settings", lambda: s)
        _reset_cache_registry()

        await user_cache.set("x", "y")
        assert await user_cache.contains("x")
        await user_cache.delete("x")
        assert not await user_cache.contains("x")


class TestCacheRegistryMaxsize:
    def test_cache_registry_maxsize_property(self):
        cr = CacheRegistry(maxsize=50, ttl=10)
        assert cr.maxsize == 50
        assert cr.ttl == 10


class _FakeRedis:
    def __init__(self):
        self.values = {}

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value, ex, nx=False):
        if nx and key in self.values:
            return False
        self.values[key] = value
        return True

    async def delete(self, key):
        self.values.pop(key, None)

    async def exists(self, key):
        return int(key in self.values)


class TestRedisCacheBackend:
    async def test_round_trip_and_namespace(self):
        backend = RedisCacheBackend(_FakeRedis(), prefix="authglow:user", ttl=60)

        assert await backend.get("missing") is None
        await backend.set("user-1", {"active": True})

        assert await backend.get("user-1") == {"active": True}
        assert await backend.contains("user-1")
        assert not await backend.set_if_absent("user-1", {"active": False})
        assert list(backend._redis.values) == ["authglow:user:user-1"]

        await backend.delete("user-1")
        assert not await backend.contains("user-1")

    async def test_set_if_absent_is_atomic_contract(self):
        backend = RedisCacheBackend(_FakeRedis(), prefix="authglow:jti", ttl=60)

        assert await backend.set_if_absent("jti-1", True)
        assert not await backend.set_if_absent("jti-1", True)


class TestCacheNoSideEffects:
    async def test_refresh_token_cache_independent_from_user_cache(self, monkeypatch):
        s = Settings(
            secret_key="a" * 32,
            storage_path="/tmp/test_cache",
            storage_backend="file",
            cache_user_maxsize=10,
            cache_refresh_token_maxsize=50,
        )
        monkeypatch.setattr("authglow.core.config.get_settings", lambda: s)
        _reset_cache_registry()

        await user_cache.set("u1", "user1")
        await user_cache.set("u2", "user2")
        await refresh_token_cache.set("rt1", "token1")

        assert await user_cache.get("u1") == "user1"
        assert await refresh_token_cache.get("rt1") == "token1"
        assert await refresh_token_cache.get("u1") is None
