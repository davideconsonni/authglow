import pytest
import warnings
from unittest.mock import patch, MagicMock
from authglow.core.cache import (
    get_cache_registry,
    _reset_cache_registry,
    user_cache,
    refresh_token_cache,
    CacheRegistry,
)
from authglow.core.config import Settings


class TestUIContextCache:
    def test_same_object_on_repeated_calls(self, test_settings):
        ctx1 = test_settings.ui_context
        ctx2 = test_settings.ui_context
        assert ctx1 is ctx2

    def test_cache_hit_avoids_rebuild(self, test_settings):
        ctx1 = test_settings.ui_context
        ctx1["app_name"] = "Mutated"
        ctx2 = test_settings.ui_context
        assert ctx2["app_name"] == "Mutated"

    def test_cached_property_works_across_instances(self, test_settings):
        ctx = test_settings.ui_context
        assert isinstance(ctx, dict)
        assert "app_name" in ctx


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
    def test_get_set_contains_delete(self, monkeypatch):
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
        assert uc.get("missing") is None
        assert uc.get("missing", "default") == "default"

        uc["key1"] = "val1"
        assert uc.get("key1") == "val1"
        assert "key1" in uc
        assert uc["key1"] == "val1"

        assert uc.pop("key1") == "val1"
        assert uc.get("key1") is None
        assert "key1" not in uc

    def test_pop_default(self, monkeypatch):
        s = Settings(
            secret_key="a" * 32,
            storage_path="/tmp/test_cache",
            storage_backend="file",
        )
        monkeypatch.setattr("authglow.core.config.get_settings", lambda: s)
        _reset_cache_registry()

        assert user_cache.pop("nonexistent", "fallback") == "fallback"
        assert user_cache.pop("nonexistent") is None

    def test_del_item(self, monkeypatch):
        s = Settings(
            secret_key="a" * 32,
            storage_path="/tmp/test_cache",
            storage_backend="file",
        )
        monkeypatch.setattr("authglow.core.config.get_settings", lambda: s)
        _reset_cache_registry()

        user_cache["x"] = "y"
        assert "x" in user_cache
        del user_cache["x"]
        assert "x" not in user_cache


class TestCacheRegistryMaxsize:
    def test_cache_registry_maxsize_property(self):
        cr = CacheRegistry(maxsize=50, ttl=10)
        assert cr.maxsize == 50
        assert cr.ttl == 10


class TestCacheNoSideEffects:
    def test_refresh_token_cache_independent_from_user_cache(self, monkeypatch):
        s = Settings(
            secret_key="a" * 32,
            storage_path="/tmp/test_cache",
            storage_backend="file",
            cache_user_maxsize=10,
            cache_refresh_token_maxsize=50,
        )
        monkeypatch.setattr("authglow.core.config.get_settings", lambda: s)
        _reset_cache_registry()

        user_cache["u1"] = "user1"
        user_cache["u2"] = "user2"
        refresh_token_cache["rt1"] = "token1"

        assert user_cache.get("u1") == "user1"
        assert refresh_token_cache.get("rt1") == "token1"
        assert refresh_token_cache.get("u1") is None
