"""Unit tests for the File-backed federation-provider repository.

Covers ``FileFederationProviderRepository``. The service-level
behaviour (``FederationProviderService.create_provider`` /
``get_provider`` / ``update_provider`` / ``delete_provider`` /
``list_providers``, with ``named_lock("federation:*")`` held
across the multi-step path) is exercised by the existing
``tests/integration/test_federation.py`` (28 tests).

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method;
* validates Protocol conformance via
  ``isinstance(repo, <Protocol>)``.

Conventions:

* The repository sets ``created_at`` and ``updated_at`` on
  create (matches the pre-refactor service-side behaviour
  where the timestamps were set before the write).
* ``update`` ignores ``None`` values in the ``updates`` dict
  and sets ``updated_at`` to the current UTC time on success.
* ``list`` returns providers (optionally filtered by
  ``enabled``) and silently skips corrupt JSON files
  (matches the pre-refactor ``try/except Exception: continue``
  pattern in ``FederationStorage.list_providers``).
"""

from unittest.mock import patch

from authglow.models.federation import ExternalIdpConfig
from authglow.repositories.file.federation import (
    FileFederationProviderRepository,
)
from authglow.repositories.protocols import FederationProviderRepository

# ---------------------------------------------------------------------------
# FileFederationProviderRepository
# ---------------------------------------------------------------------------


def _make_provider(
    provider_id: str = "prov-1",
    *,
    enabled: bool = True,
    issuer: str = "https://idp.example.com",
    client_id: str = "client-abc",
) -> ExternalIdpConfig:
    """Build a minimal valid ``ExternalIdpConfig`` for tests.

    Only the fields required by the Pydantic model are
    populated; tests override individual fields when they
    care about a specific one.
    """
    return ExternalIdpConfig(
        id=provider_id,
        label=f"Provider {provider_id}",
        enabled=enabled,
        issuer=issuer,
        client_id=client_id,
        client_secret="dummy-cleartext-secret",
    )


class TestFileFederationProviderRepository:
    def _make_repo(self, test_settings) -> FileFederationProviderRepository:
        return FileFederationProviderRepository(settings=test_settings)

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, FederationProviderRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in ("create", "get_by_id", "update", "delete", "list"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    def test_subdir_layout(self, test_settings):
        """Pre-refactor layout: ``<storage>/federation/<provider_id>.json``."""
        repo = self._make_repo(test_settings)
        assert repo._subdir == "federation"
        assert repo._provider_path("abc") == f"{repo._storage_root}/federation/abc.json"

    # ----- create + get_by_id round-trip -----

    async def test_create_then_get_by_id_round_trip(self, test_settings):
        repo = self._make_repo(test_settings)
        provider = _make_provider("rt")
        await repo.create(provider)
        fetched = await repo.get_by_id("rt")
        assert fetched is not None
        assert fetched.id == "rt"
        assert fetched.enabled is True
        assert fetched.issuer == "https://idp.example.com"

    async def test_get_by_id_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_id("nobody") is None

    async def test_create_sets_timestamps(self, test_settings):
        """The repository must set ``created_at`` and
        ``updated_at`` to the current UTC time (matches the
        pre-refactor service-side behaviour)."""
        from authglow.core.datetime import utcnow as _now

        repo = self._make_repo(test_settings)
        before = _now()
        provider = _make_provider("ts")
        await repo.create(provider)
        after = _now()
        fetched = await repo.get_by_id("ts")
        assert fetched is not None
        assert before <= fetched.created_at <= after
        assert before <= fetched.updated_at <= after

    # ----- update -----

    async def test_update_modifies_fields(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_provider("upd", enabled=True))
        updated = await repo.update("upd", {"enabled": False, "client_id": "new-client"})
        assert updated is not None
        assert updated.enabled is False
        assert updated.client_id == "new-client"

    async def test_update_ignores_none_values(self, test_settings):
        """``None`` values in ``updates`` must be ignored
        (matches the pre-refactor service-side
        ``if value is not None: setattr(...)`` behaviour) —
        passing ``None`` for a field must NOT clear it."""
        repo = self._make_repo(test_settings)
        await repo.create(_make_provider("ignore", client_id="keep-me"))
        updated = await repo.update("ignore", {"client_id": None, "enabled": False})
        assert updated.client_id == "keep-me"
        assert updated.enabled is False

    async def test_update_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        result = await repo.update("ghost", {"enabled": False})
        assert result is None

    async def test_update_bumps_updated_at(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_provider("bump"))
        first = await repo.get_by_id("bump")
        # Force a clock tick so updated_at advances
        from datetime import timedelta

        with patch("authglow.core.datetime.utcnow") as mock_now:
            mock_now.return_value = first.updated_at + timedelta(seconds=10)
            updated = await repo.update("bump", {"enabled": False})
        assert updated.updated_at > first.updated_at

    # ----- delete -----

    async def test_delete_existing(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_provider("del"))
        assert await repo.delete("del") is True
        assert await repo.get_by_id("del") is None

    async def test_delete_missing_returns_false(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.delete("ghost") is False

    # ----- list -----

    async def test_list_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.list() == []

    async def test_list_returns_all(self, test_settings):
        repo = self._make_repo(test_settings)
        for i in range(3):
            await repo.create(_make_provider(f"p-{i}"))
        providers = await repo.list()
        assert len(providers) == 3
        assert {p.id for p in providers} == {"p-0", "p-1", "p-2"}

    async def test_list_filters_by_enabled(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_provider("on", enabled=True))
        await repo.create(_make_provider("off", enabled=False))
        providers = await repo.list(enabled_only=True)
        assert len(providers) == 1
        assert providers[0].id == "on"

    async def test_list_skips_corrupt_json(self, test_settings):
        """The repository must silently skip corrupt JSON
        files (matches the pre-refactor
        ``try/except Exception: continue`` pattern in
        ``FederationStorage.list_providers``)."""
        repo = self._make_repo(test_settings)
        await repo.create(_make_provider("ok"))
        # Write a corrupt file directly to the federation subdir
        from pathlib import Path

        corrupt_path = Path(repo._provider_path("corrupt"))
        corrupt_path.parent.mkdir(parents=True, exist_ok=True)
        corrupt_path.write_text("not valid json {")
        providers = await repo.list()
        assert len(providers) == 1
        assert providers[0].id == "ok"

    # ----- corrupt-JSON tolerance -----

    async def test_get_by_id_returns_none_on_corrupt_json(self, test_settings):
        repo = self._make_repo(test_settings)
        from pathlib import Path

        path = Path(repo._provider_path("corrupt"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not valid json {")
        assert await repo.get_by_id("corrupt") is None


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFileFederationProviderRepositoryWithPatchedSettings:
    def test_constructs_via_get_settings(self, tmp_path):
        """Smoke test: the file-based constructor resolves
        ``get_settings()`` via ``BaseFileRepository``'s binding.
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        from authglow.core.config import Settings
        from authglow.core.crypto import encrypt_private_key

        storage_path = str(tmp_path / "data" / "users")
        keys_dir = tmp_path / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        priv_path = str(keys_dir / "private_key.pem")

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        encrypted_priv = encrypt_private_key(
            priv_bytes, secret_key="test-secret-key-for-authglow-testing-32chars!"
        )
        with open(priv_path, "wb") as f:
            f.write(encrypted_priv)

        settings = Settings(
            secret_key="test-secret-key-for-authglow-testing-32chars!",
            storage_path=storage_path,
            storage_backend="file",
            keys_dir=str(keys_dir),
            private_key_path=priv_path,
            public_key_path=str(keys_dir / "public_key.pem"),
        )

        with patch("authglow.repositories.file.base.get_settings", return_value=settings):
            repo = FileFederationProviderRepository()
            assert repo._subdir == "federation"
