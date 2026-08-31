"""Unit tests for the FileRateLimitConfigRepository.

Covers the single-document layout, JSON round-trip, full-replace
semantics, corrupt/absent file handling, and Protocol conformance.
"""

from pathlib import Path

from authglow.models.rate_limit_config import RateLimitConfig
from authglow.repositories.file.rate_limit_config import (
    FileRateLimitConfigRepository,
)
from authglow.repositories.protocols import RateLimitConfigRepository


def _make_repo(test_settings) -> FileRateLimitConfigRepository:
    return FileRateLimitConfigRepository(settings=test_settings)


class TestFileRateLimitConfigRepositoryInit:
    def test_creates_storage_dir(self, test_settings):
        repo = _make_repo(test_settings)
        expected = Path(test_settings.storage_path) / "rate_limit_config"
        assert Path(repo._storage_path) == expected
        assert expected.exists()

    def test_subdir_constant(self):
        assert FileRateLimitConfigRepository._subdir == "rate_limit_config"

    def test_settings_persisted(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._settings is test_settings


class TestFileRateLimitConfigRepositoryProtocol:
    def test_satisfies_protocol(self, test_settings):
        repo = _make_repo(test_settings)
        assert isinstance(repo, RateLimitConfigRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = _make_repo(test_settings)
        for method in ("load", "save"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))


class TestFileRateLimitConfigRepositorySaveLoad:
    async def test_save_creates_file(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.save(RateLimitConfig(enabled=False))
        assert Path(repo._path("config.json")).exists()

    async def test_load_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        assert await repo.load() is None

    async def test_round_trip(self, test_settings):
        repo = _make_repo(test_settings)
        original = RateLimitConfig(
            enabled=False,
            overrides={"/api/auth/login": "5/minute", "/api/meta": "1/second"},
        )
        await repo.save(original)
        loaded = await repo.load()

        assert loaded is not None
        assert loaded.enabled is False
        assert loaded.overrides == original.overrides
        assert loaded.updated_at == original.updated_at

    async def test_save_full_replaces(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.save(
            RateLimitConfig(enabled=True, overrides={"/api/old": "1/minute"})
        )
        await repo.save(RateLimitConfig(enabled=False, overrides={}))

        loaded = await repo.load()
        assert loaded.enabled is False
        assert loaded.overrides == {}

    async def test_load_returns_none_for_corrupt_json(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("config.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not valid json")
        assert await repo.load() is None

    async def test_load_returns_none_for_wrong_shape(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("config.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('["a", "list"]')
        assert await repo.load() is None
