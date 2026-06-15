"""Tests for ``FileTokenBlacklistRepository`` and the
``services.auth.token_blacklist.TokenBlacklist`` service.

The repository tests cover the I/O primitives (load + atomic save,
missing/corrupt files, persistence across instances). The service
tests cover the in-memory behaviour (revoke / is_revoked, sweep,
singleton lifecycle, hot-path sync ``is_revoked`` returning the
in-memory state without I/O).
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

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def repo(test_settings):
    """Fresh ``FileTokenBlacklistRepository`` pointing at the test temp dir."""
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(
            "authglow.repositories.file.base.get_settings",
            lambda: test_settings,
        )
        return FileTokenBlacklistRepository()


@pytest.fixture
def repo_p(tmp_path, test_settings):
    """Variant that points the repository at a *different* storage
    path than the autouse ``test_settings``, exercising the
    constructor's ``settings=`` argument."""
    storage_path = str(tmp_path / "blacklist_repo_test")
    os.makedirs(storage_path, exist_ok=True)
    custom = test_settings.model_copy(update={"storage_path": storage_path})
    return FileTokenBlacklistRepository(settings=custom)


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Ensure each test starts with a clean ``TokenBlacklist`` singleton."""
    _reset_token_blacklist()
    yield
    _reset_token_blacklist()


# ---------------------------------------------------------------------------
# Repository — load / save
# ---------------------------------------------------------------------------


class TestRepositoryLoadSave:
    @pytest.mark.asyncio
    async def test_load_missing_returns_empty_dict(self, repo):
        assert await repo.load_all() == {}

    @pytest.mark.asyncio
    async def test_load_corrupt_returns_empty_dict(self, repo):
        with open(repo._entries_path, "w") as f:
            f.write("{not valid json")
        assert await repo.load_all() == {}

    @pytest.mark.asyncio
    async def test_save_then_load_roundtrip(self, repo):
        entries = {"jti-a": 1000.0, "jti-b": 2000.0, "jti-c": 3000.0}
        await repo.save_all(entries)
        loaded = await repo.load_all()
        assert loaded == entries

    @pytest.mark.asyncio
    async def test_save_does_not_leave_tmp_file(self, repo):
        await repo.save_all({"x": 1.0})
        assert not os.path.exists(repo._entries_path + ".tmp")
        assert os.path.exists(repo._entries_path)

    @pytest.mark.asyncio
    async def test_save_overwrites_existing(self, repo):
        await repo.save_all({"old": 1.0})
        await repo.save_all({"new": 2.0})
        assert await repo.load_all() == {"new": 2.0}

    @pytest.mark.asyncio
    async def test_persistence_survives_new_instance(self, repo_p):
        """A second repository instance on the same path must see
        what the first instance wrote."""
        await repo_p.save_all({"persisted": 42.0})
        repo2 = FileTokenBlacklistRepository(settings=repo_p._settings)
        assert await repo2.load_all() == {"persisted": 42.0}

    @pytest.mark.asyncio
    async def test_storage_path_respects_settings(self, repo_p):
        assert repo_p._storage_path == f"{repo_p._settings.storage_path}/token_blacklist"
        assert repo_p._entries_path == f"{repo_p._storage_path}/entries.json"

    @pytest.mark.asyncio
    async def test_empty_entries_is_persisted(self, repo):
        await repo.save_all({})
        with open(repo._entries_path) as f:
            import json

            assert json.load(f) == {"entries": {}}
        assert await repo.load_all() == {}


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

    def test_save_all_is_coroutine(self, repo):
        import inspect

        assert inspect.iscoroutinefunction(repo.save_all)


# ---------------------------------------------------------------------------
# Service — constructor / dependency injection
# ---------------------------------------------------------------------------


class TestServiceConstruction:
    def test_default_repository_is_file(self, test_settings):
        """Constructing without arguments should use the file impl."""
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "authglow.repositories.dependencies.get_token_blacklist_repository",
                lambda: FileTokenBlacklistRepository(),
            )
            svc = TokenBlacklist()
        assert isinstance(svc._repository, FileTokenBlacklistRepository)

    def test_explicit_repository_is_used(self):
        """The constructor must accept an alternative repository."""

        class StubRepo:
            def __init__(self):
                self.load_calls = 0
                self.save_calls = 0
                self.saved: dict = {}

            async def load_all(self):
                self.load_calls += 1
                return {}

            async def save_all(self, entries):
                self.save_calls += 1
                self.saved = dict(entries)

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
        await repo_p.save_all({"jti-keep": time.time() + 60, "jti-gone": 1.0})
        svc = TokenBlacklist(repository=FileTokenBlacklistRepository(settings=repo_p._settings))
        await svc.startup_hydrate()
        assert "jti-keep" in svc._store
        assert "jti-gone" not in svc._store

    @pytest.mark.asyncio
    async def test_hydrate_persists_pruned_entries(self, repo):
        await repo.save_all({"alive": time.time() + 60, "dead": 1.0})
        svc = TokenBlacklist(repository=repo)
        await svc.startup_hydrate()
        reloaded = await repo.load_all()
        assert "alive" in reloaded
        assert "dead" not in reloaded


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
        """Pre-hydrate, is_revoked must return False (no I/O)."""

        class NeverLoad:
            async def load_all(self):
                raise AssertionError("must not be called from is_revoked")

            async def save_all(self, entries):
                raise AssertionError("must not be called from is_revoked")

        svc = TokenBlacklist(repository=NeverLoad())  # type: ignore[arg-type]
        assert svc.is_revoked("anything") is False

    @pytest.mark.asyncio
    async def test_revoking_past_expiry_is_silently_ignored(self, repo):
        """Pre-refactor: revoke() short-circuits when expires_at <= now."""
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
        assert loaded["persisted-jti"] == future

    @pytest.mark.asyncio
    async def test_revoke_is_idempotent(self, repo):
        svc = TokenBlacklist(repository=repo)
        await svc.startup_hydrate()
        future = time.time() + 60
        await svc.revoke("dup", future)
        await svc.revoke("dup", future + 100)
        assert svc.is_revoked("dup") is True


# ---------------------------------------------------------------------------
# Service — sweep on MAX_ENTRIES
# ---------------------------------------------------------------------------


class TestServiceSweep:
    @pytest.mark.asyncio
    async def test_sweep_drops_expired_entries_on_max(self, repo, monkeypatch):
        svc = TokenBlacklist(repository=repo)
        await svc.startup_hydrate()
        monkeypatch.setattr(TokenBlacklist, "MAX_ENTRIES", 3)

        now = time.time()
        await svc.revoke("alive-1", now + 60)
        await svc.revoke("alive-2", now + 60)
        await svc.revoke("expired-1", 1.0)
        # _store currently has 2 entries (revoke() rejects expired)
        assert len(svc._store) == 2

        # Bypass the early-return by inserting directly, then trigger sweep
        svc._store["expired-2"] = 1.0
        assert len(svc._store) == 3

        await svc.revoke("alive-3", now + 60)
        # sweep should have removed expired-2
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
