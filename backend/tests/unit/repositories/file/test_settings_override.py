"""Unit tests for the FileSettingsOverrideRepository.

Covers the single-document layout, JSON round-trip, full-replace
semantics, corrupt/absent file handling, and Protocol conformance.
"""

from pathlib import Path

from authglow.repositories.file.settings_override import (
    FileSettingsOverrideRepository,
)
from authglow.repositories.protocols import SettingsOverrideRepository


def _make_repo(test_settings) -> FileSettingsOverrideRepository:
    return FileSettingsOverrideRepository(settings=test_settings)


class TestFileSettingsOverrideRepositoryInit:
    def test_creates_storage_dir(self, test_settings):
        repo = _make_repo(test_settings)
        expected = Path(test_settings.storage_path) / "settings_override"
        assert Path(repo._storage_path) == expected
        assert expected.exists()

    def test_subdir_constant(self):
        assert FileSettingsOverrideRepository._subdir == "settings_override"

    def test_settings_persisted(self, test_settings):
        repo = _make_repo(test_settings)
        assert repo._settings is test_settings


class TestFileSettingsOverrideRepositoryProtocol:
    def test_satisfies_protocol(self, test_settings):
        repo = _make_repo(test_settings)
        assert isinstance(repo, SettingsOverrideRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = _make_repo(test_settings)
        for method in ("load", "save"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))


class TestFileSettingsOverrideRepositorySaveLoad:
    async def test_save_creates_file(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.save({"app_name": "Renamed"})
        assert Path(repo._path("overrides.json")).exists()

    async def test_load_returns_none_for_missing(self, test_settings):
        repo = _make_repo(test_settings)
        assert await repo.load() is None

    async def test_round_trip(self, test_settings):
        repo = _make_repo(test_settings)
        original = {
            "app_name": "Renamed",
            "debug": True,
            "access_token_expire_minutes": 120,
        }
        await repo.save(original)
        loaded = await repo.load()

        assert loaded == original

    async def test_save_full_replaces(self, test_settings):
        repo = _make_repo(test_settings)
        await repo.save({"app_name": "First", "company_name": "Old"})
        await repo.save({"app_name": "Second"})

        loaded = await repo.load()
        assert loaded == {"app_name": "Second"}

    async def test_load_returns_none_for_corrupt_json(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("overrides.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("{not valid json")
        assert await repo.load() is None

    async def test_load_returns_none_for_non_dict(self, test_settings):
        repo = _make_repo(test_settings)
        path = Path(repo._path("overrides.json"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('["a", "list"]')
        assert await repo.load() is None
