"""Unit tests for the config-driven repository registry.

Covers the ``dependencies.py`` selector introduced by the storage
plugin plan: default ``file`` resolution, ``settings=`` propagation
to every factory, fail-fast on unknown backends, and
``register_backend()`` for future backends (e.g. Postgres).
"""

import inspect
from types import SimpleNamespace

import pytest

import authglow.repositories.dependencies as deps
from authglow.repositories.file.csrf import FileCSRFTokenRepository
from authglow.repositories.file.user import FileUserRepository
from authglow.repositories.protocols import CSRFTokenRepository, UserRepository


class TestRegistryDefaults:
    def test_repository_backend_defaults_to_file(self, test_settings):
        assert test_settings.repository_backend == "file"

    def test_factories_resolve_file_impls(self, test_settings):
        csrf = deps.get_csrf_token_repository(settings=test_settings)
        user = deps.get_user_repository(settings=test_settings)
        assert isinstance(csrf, FileCSRFTokenRepository)
        assert isinstance(user, FileUserRepository)
        assert isinstance(csrf, CSRFTokenRepository)
        assert isinstance(user, UserRepository)

    def test_factories_work_without_explicit_settings(self, test_settings):
        # Falls back to the patched get_settings() singleton.
        csrf = deps.get_csrf_token_repository()
        assert isinstance(csrf, FileCSRFTokenRepository)

    def test_all_factories_accept_settings_kwarg(self):
        missing = []
        for name in deps.__all__:
            if name == "register_backend":
                continue
            fn = getattr(deps, name)
            try:
                sig = inspect.signature(fn)
            except (TypeError, ValueError):
                missing.append(name)
                continue
            if "settings" not in sig.parameters:
                missing.append(name)
        assert missing == []

    def test_settings_propagated_to_repo(self, test_settings):
        user = deps.get_user_repository(settings=test_settings)
        assert user._settings is test_settings


class TestRegistryFailFast:
    def test_unknown_backend_raises_value_error(self, test_settings):
        bad = SimpleNamespace(repository_backend="nope")
        with pytest.raises(ValueError, match="Unknown repository_backend"):
            deps.get_csrf_token_repository(settings=bad)

    def test_unregistered_postgres_raises_value_error(self, test_settings):
        pg = SimpleNamespace(repository_backend="postgres")
        with pytest.raises(ValueError, match="Unknown repository_backend"):
            deps.get_user_repository(settings=pg)

    def test_mocked_settings_fall_back_to_file(self, test_settings):
        from unittest.mock import MagicMock

        mocked = MagicMock()
        mocked.storage_backend = "file"
        mocked.get_storage_options = lambda: {}
        mocked.storage_path = test_settings.storage_path
        csrf = deps.get_csrf_token_repository(settings=mocked)
        assert isinstance(csrf, FileCSRFTokenRepository)
        # Backend selection tolerates the mock (no real string
        # repository_backend → "file"); the mock itself is still
        # forwarded to the constructor (pre-registry behaviour).
        assert csrf._settings is mocked


class TestRegisterBackend:
    def test_custom_backend_resolves(self, test_settings):
        sentinel = object()

        def _fake_factory(settings=None):
            return sentinel

        deps.register_backend("fake", {"csrf_token": _fake_factory})
        try:
            fake_settings = SimpleNamespace(repository_backend="fake")
            assert deps.get_csrf_token_repository(settings=fake_settings) is sentinel
        finally:
            deps._REGISTRY.pop("fake", None)

    def test_custom_backend_missing_entity_raises(self, test_settings):
        deps.register_backend("fake", {})
        try:
            fake_settings = SimpleNamespace(repository_backend="fake")
            with pytest.raises(ValueError, match="has no repository for entity"):
                deps.get_csrf_token_repository(settings=fake_settings)
        finally:
            deps._REGISTRY.pop("fake", None)
