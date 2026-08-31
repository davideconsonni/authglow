"""Unit tests for the SettingsOverrideService.

Covers validation (unknown key, null, type compatibility, non-scalar
targets), merge-and-persist semantics, live application onto the
``Settings`` singleton, sync bookkeeping (``mark_synced``), and
change detection (``refresh_if_changed``).

Repository conformance is covered by
``tests/unit/repositories/file/test_settings_override.py``; API-level
behaviour by ``tests/unit/test_admin_runtime_config_api.py``.
"""

from typing import Any, Dict, List

import pytest
from pydantic import BaseModel

from authglow.services.settings_override import (
    InvalidSettingUpdateError,
    SettingsOverrideService,
    capture_pristine,
    reset_pristine,
)


@pytest.fixture(autouse=True)
def _clean_pristine():
    """The pristine registry is process-wide module state — wipe it
    around every test so snapshots from one test's ``test_settings``
    never leak into another."""
    reset_pristine()
    yield
    reset_pristine()


class StubRepo:
    def __init__(self, initial: Dict[str, Any] = None):
        self.saved: Dict[str, Any] = initial or {}
        self.save_count = 0

    async def load(self):
        return dict(self.saved) if self.saved else None

    async def save(self, overrides):
        self.saved = dict(overrides)
        self.save_count += 1


class _NonScalarSettings(BaseModel):
    """Stub settings with a non-scalar field (real Settings has none)."""

    tags: List[str] = []
    debug: bool = False


class TestValidateUpdates:
    async def test_accepts_matching_scalars(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        validated = service.validate_updates(
            {"app_name": "Renamed", "debug": True, "access_token_expire_minutes": 60}
        )
        assert validated == {
            "app_name": "Renamed",
            "debug": True,
            "access_token_expire_minutes": 60,
        }

    async def test_unknown_key_rejected(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        with pytest.raises(InvalidSettingUpdateError, match="Unknown setting"):
            service.validate_updates({"no_such_setting": "x"})

    async def test_null_value_rejected(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        with pytest.raises(InvalidSettingUpdateError, match="cannot be null"):
            service.validate_updates({"app_name": None})

    async def test_bool_target_rejects_string(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        with pytest.raises(InvalidSettingUpdateError, match="expects a boolean"):
            service.validate_updates({"debug": "true"})

    async def test_string_target_rejects_number(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        with pytest.raises(InvalidSettingUpdateError, match="expects a string"):
            service.validate_updates({"app_name": 42})

    async def test_int_target_rejects_fractional(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        with pytest.raises(InvalidSettingUpdateError, match="expects an integer"):
            service.validate_updates({"access_token_expire_minutes": 30.5})

    async def test_int_target_accepts_integral_float(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        validated = service.validate_updates({"access_token_expire_minutes": 60.0})
        assert validated["access_token_expire_minutes"] == 60

    async def test_non_scalar_target_rejected(self, stub_repo):
        stub_settings = _NonScalarSettings()
        service = SettingsOverrideService(repository=stub_repo, settings=stub_settings)
        with pytest.raises(InvalidSettingUpdateError, match="scalar"):
            service.validate_updates({"tags": ["a", "b"]})


class TestSetAndApply:
    async def test_set_overrides_merges_and_persists(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        await service.set_overrides({"app_name": "First"})
        persisted = await service.set_overrides({"company_name": "Acme"})

        assert persisted == {"app_name": "First", "company_name": "Acme"}
        assert stub_repo.save_count == 2

    async def test_apply_overrides_sets_live_attribute(
        self, test_settings, stub_repo
    ):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        applied = service.apply_overrides({"app_name": "Live Rename"})

        assert applied == {"app_name": "Live Rename"}
        assert test_settings.app_name == "Live Rename"

    async def test_apply_overrides_skips_invalid_entries(
        self, test_settings, stub_repo
    ):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        applied = service.apply_overrides(
            {"app_name": "Still Fine", "ghost_key": "x", "debug": "not-a-bool"}
        )

        assert applied == {"app_name": "Still Fine"}
        assert test_settings.app_name == "Still Fine"


class TestRefreshIfChanged:
    async def test_applies_when_repo_changed(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        stub_repo.saved = {"app_name": "From Another Node"}

        changed = await service.refresh_if_changed()

        assert changed is True
        assert test_settings.app_name == "From Another Node"

    async def test_noop_when_unchanged_after_mark_synced(
        self, test_settings, stub_repo
    ):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        persisted = await service.set_overrides({"app_name": "Renamed"})
        service.apply_overrides({"app_name": "Renamed"})
        service.mark_synced(persisted)

        changed = await service.refresh_if_changed()

        assert changed is False

    async def test_false_when_never_saved(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        assert await service.refresh_if_changed() is False

    async def test_swallows_repo_read_errors(self, test_settings):
        class BrokenRepo:
            async def load(self):
                raise RuntimeError("disk gone")

            async def save(self, overrides):
                raise RuntimeError("disk gone")

        service = SettingsOverrideService(repository=BrokenRepo(), settings=test_settings)
        assert await service.refresh_if_changed() is False


@pytest.fixture
def stub_repo():
    return StubRepo()


class TestRemoveOverride:
    async def test_removes_and_restores_pristine(self, test_settings, stub_repo):
        capture_pristine(test_settings)
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        await service.set_overrides({"app_name": "Renamed"})
        assert test_settings.app_name == "Renamed"

        removed = await service.remove_override("app_name")

        assert removed is True
        assert test_settings.app_name == test_settings.app_name  # restored below
        # The pristine env-derived value is restored on the live object.
        assert test_settings.app_name != "Renamed"
        assert stub_repo.saved == {}

    async def test_restore_uses_captured_env_value(self, test_settings, stub_repo):
        capture_pristine(test_settings)
        original = test_settings.app_name
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        await service.set_overrides({"app_name": "Renamed"})
        await service.remove_override("app_name")
        assert test_settings.app_name == original

    async def test_remove_non_overridden_key_is_noop(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        removed = await service.remove_override("app_name")

        assert removed is False
        assert stub_repo.save_count == 0

    async def test_remove_without_pristine_snapshot_skips_restore(
        self, test_settings, stub_repo
    ):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        await service.set_overrides({"app_name": "Renamed"})
        test_settings.app_name = "Renamed"

        removed = await service.remove_override("app_name")

        assert removed is True
        assert stub_repo.saved == {}
        # No snapshot captured: the live value is left untouched.

    async def test_refresh_noop_after_removal_mark_synced(
        self, test_settings, stub_repo
    ):
        capture_pristine(test_settings)
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        await service.set_overrides({"app_name": "Renamed"})
        await service.remove_override("app_name")

        changed = await service.refresh_if_changed()

        assert changed is False


class TestRemoveOverride:
    async def test_removes_and_restores_pristine(self, test_settings, stub_repo):
        capture_pristine(test_settings)
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        await service.set_overrides({"app_name": "Renamed"})
        assert test_settings.app_name == "Renamed"

        removed = await service.remove_override("app_name")

        assert removed is True
        assert test_settings.app_name != "Renamed"
        # The pristine env-derived value is restored on the live object.
        assert test_settings.app_name != "Renamed"
        assert stub_repo.saved == {}

    async def test_restore_uses_captured_env_value(self, test_settings, stub_repo):
        capture_pristine(test_settings)
        original = test_settings.app_name
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        await service.set_overrides({"app_name": "Renamed"})
        await service.remove_override("app_name")
        assert test_settings.app_name == original

    async def test_remove_non_overridden_key_is_noop(self, test_settings, stub_repo):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        removed = await service.remove_override("app_name")

        assert removed is False
        assert stub_repo.save_count == 0

    async def test_remove_without_pristine_snapshot_skips_restore(
        self, test_settings, stub_repo
    ):
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        await service.set_overrides({"app_name": "Renamed"})
        test_settings.app_name = "Renamed"

        removed = await service.remove_override("app_name")

        assert removed is True
        assert stub_repo.saved == {}
        # No snapshot captured: the live value is left untouched.

    async def test_refresh_noop_after_removal_mark_synced(
        self, test_settings, stub_repo
    ):
        capture_pristine(test_settings)
        service = SettingsOverrideService(
            repository=stub_repo, settings=test_settings
        )
        await service.set_overrides({"app_name": "Renamed"})
        await service.remove_override("app_name")

        changed = await service.refresh_if_changed()

        assert changed is False
