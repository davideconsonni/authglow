"""Tests for ``FileTokenBlacklistRepository`` (one-file-per-JTI) and
``services.auth.token_blacklist.TokenBlacklist`` service.

Repository tests cover individual ``save`` / ``load_all`` /
``cleanup_expired``. Service tests cover revoke / is_revoked,
cross-instance visibility via filesystem, and singleton lifecycle.
"""

import os
import time

import pytest

from authglow.repositories.file.token_blacklist import FileTokenBlacklistRepository
from authglow.services.auth.token_blacklist import (
    TokenBlacklist,
    _reset_token_blacklist,
    token_blacklist,
)


@pytest.fixture
def repo(test_settings):
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "authglow.repositories.file.base.get_settings",
            lambda: test_settings,
        )
        return FileTokenBlacklistRepository()


@pytest.fixture
def repo_p(tmp_path, test_settings):
    storage_path = str(tmp_path / "blacklist_repo_test")
    os.makedirs(storage_path, exist_ok=True)
    custom = test_settings.model_copy(update={"storage_path": storage_path})
    return FileTokenBlacklistRepository(settings=custom)


@pytest.fixture(autouse=True)
def _reset_singleton():
    _reset_token_blacklist()
    yield
    _reset_token_blacklist()


# ---------------------------------------------------------------------------
# Repository — save / load / cleanup
# ---------------------------------------------------------------------------


class TestRepositoryLoadSave:
    @pytest.mark.asyncio
    async def test_load_missing_returns_empty_dict(self, repo):
        assert await repo.load_all() == {}

    @pytest.mark.asyncio
    async def test_save_then_load_roundtrip(self, repo):
        await repo.save("jti-a", 1000.0)
        await repo.save("jti-b", 2000.0)
        loaded = await repo.load_all()
        assert loaded == {"jti-a": 1000.0, "jti-b": 2000.0}

    @pytest.mark.asyncio
    async def test_save_overwrites_existing(self, repo):
        await repo.save("jti-x", 1.0)
        await repo.save("jti-x", 2.0)
        loaded = await repo.load_all()
        assert loaded == {"jti-x": 2.0}

    @pytest.mark.asyncio
    async def test_persistence_survives_new_instance(self, repo_p):
        await repo_p.save("persisted", 42.0)
        repo2 = FileTokenBlacklistRepository(settings=repo_p._settings)
        assert await repo2.load_all() == {"persisted": 42.0}

    @pytest.mark.asyncio
    async def test_storage_path_respects_settings(self, repo_p):
        assert repo_p._storage_path.endswith("/token_blacklist")

    @pytest.mark.asyncio
    async def test_cleanup_expired_removes_stale(self, repo):
        await repo.save("keep", time.time() + 60)
        await repo.save("gone", 1.0)
        removed = await repo.cleanup_expired()
        assert removed >= 1
        loaded = await repo.load_all()
        assert "keep" in loaded
        assert "gone" not in loaded


# ---------------------------------------------------------------------------
# Repository — Protocol conformance
# ---------------------------------------------------------------------------


class TestRepositoryConforms:
    def test_implements_token_blacklist_repository_protocol(self, repo):
        from authglow.repositories.protocols import TokenBlacklistRepository

        assert isinstance(repo, TokenBlacklistRepository)

    def test_load_all_is_coroutine(self, repo):
        import inspect

        assert inspect.iscoroutinefunction(repo.load_all)

    def test_save_is_coroutine(self, repo):
        import inspect

        assert inspect.iscoroutinefunction(repo.save)


# ---------------------------------------------------------------------------
# Service — constructor
# ---------------------------------------------------------------------------


class TestServiceConstruction:
    def test_default_repository_is_file(self, test_settings):
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "authglow.repositories.dependencies.get_token_blacklist_repository",
                lambda: FileTokenBlacklistRepository(),
            )
            svc = TokenBlacklist()
        assert isinstance(svc._repository, FileTokenBlacklistRepository)

    def test_explicit_repository_is_used(self):
        class StubRepo:
            async def save(self, jti, expires_at):
                pass

            async def load_all(self):
                return {}

            async def cleanup_expired(self):
                return 0

        stub = StubRepo()
        svc = TokenBlacklist(repository=stub)  # type: ignore[arg-type]
        assert svc._repository is stub


# ---------------------------------------------------------------------------
# Service — startup_hydrate
# ---------------------------------------------------------------------------


class TestServiceHydrate:
    @pytest.mark.asyncio
    async def test_hydrate_from_empty_disk(self, repo):
        svc = TokenBlacklist(repository=repo)
        await svc.startup_hydrate()
        assert svc._store == {}
        assert svc._initialized is True

    @pytest.mark.asyncio
    async def test_hydrate_loads_persisted_entries(self, repo_p):
        await repo_p.save("jti-keep", time.time() + 60)
        await repo_p.save("jti-gone", 1.0)
        svc = TokenBlacklist(repository=FileTokenBlacklistRepository(settings=repo_p._settings))
        await svc.startup_hydrate()
        assert "jti-keep" in svc._store
        assert "jti-gone" not in svc._store


# ---------------------------------------------------------------------------
# Service — revoke / is_revoked
# ---------------------------------------------------------------------------


class TestServiceRevokeAndCheck:
    @pytest.mark.asyncio
    async def test_revoke_then_is_revoked_returns_true(self, repo):
        svc = TokenBlacklist(repository=repo)
        await svc.startup_hydrate()
        await svc.revoke("jti-1", time.time() + 60)
        assert svc.is_revoked("jti-1") is True

    @pytest.mark.asyncio
    async def test_unknown_jti_is_not_revoked(self, repo):
        svc = TokenBlacklist(repository=repo)
        await svc.startup_hydrate()
        assert svc.is_revoked("never-revoked") is False

    @pytest.mark.asyncio
    async def test_is_revoked_false_before_hydrate(self):
        class NeverLoad:
            async def save(self, jti, expires_at):
                raise AssertionError("must not be called from is_revoked")

            async def load_all(self):
                raise AssertionError("must not be called from is_revoked")

            async def cleanup_expired(self):
                return 0

        svc = TokenBlacklist(repository=NeverLoad())  # type: ignore[arg-type]
        assert svc.is_revoked("anything") is False

    @pytest.mark.asyncio
    async def test_revoking_past_expiry_is_ignored(self, repo):
        svc = TokenBlacklist(repository=repo)
        await svc.startup_hydrate()
        await svc.revoke("expired-jti", 1.0)
        assert svc.is_revoked("expired-jti") is False

    @pytest.mark.asyncio
    async def test_revoke_persists_to_disk(self, repo_p):
        svc = TokenBlacklist(repository=FileTokenBlacklistRepository(settings=repo_p._settings))
        await svc.startup_hydrate()
        future = time.time() + 60
        await svc.revoke("persisted-jti", future)

        repo2 = FileTokenBlacklistRepository(settings=repo_p._settings)
        loaded = await repo2.load_all()
        assert "persisted-jti" in loaded
        assert loaded["persisted-jti"] == pytest.approx(future, abs=1)

    @pytest.mark.asyncio
    async def test_revoke_is_idempotent(self, repo):
        svc = TokenBlacklist(repository=repo)
        await svc.startup_hydrate()
        future = time.time() + 60
        await svc.revoke("dup", future)
        await svc.revoke("dup", future + 100)
        assert svc.is_revoked("dup") is True

    def test_cross_instance_visibility(self, repo_p):
        """Instance B's is_revoked sees what A wrote to disk, without
        startup_hydrate (the disk fallback in _check_disk)."""
        import asyncio

        async def _run():
            svc_a = TokenBlacklist(
                repository=FileTokenBlacklistRepository(settings=repo_p._settings)
            )
            await svc_a.startup_hydrate()
            await svc_a.revoke("multi-jti", time.time() + 60)

            svc_b = TokenBlacklist(
                repository=FileTokenBlacklistRepository(settings=repo_p._settings)
            )
            assert svc_b.is_revoked("multi-jti") is True

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# Service — sweep on MAX_ENTRIES
# ---------------------------------------------------------------------------


class TestServiceSweep:
    @pytest.mark.asyncio
    async def test_sweep_drops_expired_on_max(self, repo, monkeypatch):
        svc = TokenBlacklist(repository=repo)
        await svc.startup_hydrate()
        monkeypatch.setattr(TokenBlacklist, "MAX_ENTRIES", 3)

        now = time.time()
        await svc.revoke("alive-1", now + 60)
        await svc.revoke("alive-2", now + 60)
        await svc.revoke("expired-1", 1.0)
        assert len(svc._store) == 2

        svc._store["expired-2"] = 1.0
        assert len(svc._store) == 3

        await svc.revoke("alive-3", now + 60)
        assert "expired-2" not in svc._store
        assert "alive-1" in svc._store


# ---------------------------------------------------------------------------
# Service — singleton
# ---------------------------------------------------------------------------


class TestServiceSingleton:
    def test_singleton_returns_same_instance(self):
        a = token_blacklist()
        b = token_blacklist()
        assert a is b

    def test_reset_creates_fresh_instance(self):
        a = token_blacklist()
        _reset_token_blacklist()
        b = token_blacklist()
        assert a is not b
