"""Unit tests for the File-backed federated-identity repository.

Covers ``FileFederatedIdentityRepository``. The service-level
behaviour (``UserStorage.link_federated_identity``,
``get_by_external_id``, with ``named_lock("federated_identities")``
held across the multi-step path) is exercised by the existing
``tests/integration/test_federation.py``.

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method;
* validates Protocol conformance via ``isinstance(repo, <Protocol>)``.
"""

import pytest

from authglow.repositories.exceptions import EntityAlreadyExistsError
from authglow.repositories.file.federated_identity import (
    FileFederatedIdentityRepository,
)
from authglow.repositories.protocols import FederatedIdentityRepository

# ---------------------------------------------------------------------------
# FileFederatedIdentityRepository
# ---------------------------------------------------------------------------


class TestFileFederatedIdentityRepository:
    def _make_repo(self, test_settings) -> FileFederatedIdentityRepository:
        return FileFederatedIdentityRepository(settings=test_settings)

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, FederatedIdentityRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in ("lookup", "link", "unlink"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    def test_index_lives_at_storage_root(self, test_settings):
        repo = self._make_repo(test_settings)
        # Pre-refactor layout: <storage>/federated_identities.json
        assert repo._index_path() == f"{repo._storage_root}/federated_identities.json"
        # _storage_path was collapsed back to the root
        assert repo._storage_path == repo._storage_root

    # ----- link + lookup -----

    async def test_link_then_lookup(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.link("user-1", "provider-a", "external-123")
        assert await repo.lookup("provider-a", "external-123") == "user-1"

    async def test_lookup_returns_none_for_unknown(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.lookup("provider-a", "unknown") is None

    async def test_link_overwrites_when_same_user(self, test_settings):
        """Re-linking the same (provider, external) pair to the
        SAME user is a no-op semantically (still same mapping).
        """
        repo = self._make_repo(test_settings)
        await repo.link("user-1", "provider-a", "external-1")
        await repo.link("user-1", "provider-a", "external-1")
        assert await repo.lookup("provider-a", "external-1") == "user-1"

    async def test_link_raises_on_different_user(self, test_settings):
        """Linking the same (provider, external) pair to a
        DIFFERENT user must raise EntityAlreadyExistsError."""
        repo = self._make_repo(test_settings)
        await repo.link("user-1", "provider-a", "external-1")
        with pytest.raises(EntityAlreadyExistsError) as exc_info:
            await repo.link("user-2", "provider-a", "external-1")
        # The exception identifies the conflicting composite key
        assert "provider-a|external-1" in str(exc_info.value)
        assert exc_info.value.identifier == "provider-a|external-1"

    async def test_lookup_distinct_providers(self, test_settings):
        """Same external_id under different providers is a
        distinct mapping (composite key)."""
        repo = self._make_repo(test_settings)
        await repo.link("user-1", "provider-a", "shared-id")
        await repo.link("user-2", "provider-b", "shared-id")
        assert await repo.lookup("provider-a", "shared-id") == "user-1"
        assert await repo.lookup("provider-b", "shared-id") == "user-2"

    async def test_lookup_distinct_external_ids(self, test_settings):
        """Distinct external_ids under the same provider are
        distinct mappings."""
        repo = self._make_repo(test_settings)
        await repo.link("user-1", "provider-a", "ext-1")
        await repo.link("user-2", "provider-a", "ext-2")
        assert await repo.lookup("provider-a", "ext-1") == "user-1"
        assert await repo.lookup("provider-a", "ext-2") == "user-2"

    # ----- unlink -----

    async def test_unlink_existing(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.link("user-1", "provider-a", "external-1")
        await repo.unlink("provider-a", "external-1")
        assert await repo.lookup("provider-a", "external-1") is None

    async def test_unlink_unknown_is_noop(self, test_settings):
        repo = self._make_repo(test_settings)
        # No prior link; unlink must not raise.
        await repo.unlink("provider-a", "unknown")
        assert await repo.lookup("provider-a", "unknown") is None

    async def test_unlink_keeps_other_entries(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.link("user-1", "provider-a", "ext-1")
        await repo.link("user-2", "provider-b", "ext-2")
        await repo.unlink("provider-a", "ext-1")
        assert await repo.lookup("provider-a", "ext-1") is None
        assert await repo.lookup("provider-b", "ext-2") == "user-2"

    async def test_unlink_then_relink_to_different_user(self, test_settings):
        """After unlink, the (provider, external) pair must be
        re-linkable to a different user (no stale state)."""
        repo = self._make_repo(test_settings)
        await repo.link("user-1", "provider-a", "ext-1")
        await repo.unlink("provider-a", "ext-1")
        await repo.link("user-2", "provider-a", "ext-1")
        assert await repo.lookup("provider-a", "ext-1") == "user-2"

    # ----- composite key format -----

    def test_composite_key_format(self, test_settings):
        """The composite key is ``f"{provider_id}|{external_id}"``
        — the pre-refactor ``_make_identity_key`` contract."""
        repo = self._make_repo(test_settings)
        assert repo._make_key("provider-a", "ext-1") == "provider-a|ext-1"
        assert repo._make_key("", "") == "|"

    # ----- corrupt-JSON tolerance -----

    async def test_lookup_returns_none_on_corrupt_json(self, test_settings):
        """The repository must tolerate a corrupt federated
        identities file (return None for lookup) rather than
        raising."""
        repo = self._make_repo(test_settings)
        with open(repo._index_path(), "w", encoding="utf-8") as f:
            f.write("not valid json {")
        assert await repo.lookup("provider-a", "ext-1") is None

    async def test_link_recovers_from_corrupt_json(self, test_settings):
        """A corrupt index file must be overwritten on the next
        ``link`` call (no manual cleanup required)."""
        repo = self._make_repo(test_settings)
        with open(repo._index_path(), "w", encoding="utf-8") as f:
            f.write("not valid json {")
        await repo.link("user-1", "provider-a", "ext-1")
        assert await repo.lookup("provider-a", "ext-1") == "user-1"


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFileFederatedIdentityRepositoryWithPatchedSettings:
    def test_constructs_via_get_settings(self, tmp_path):
        """Smoke test: the file-based constructor resolves
        ``get_settings()`` via ``BaseFileRepository``'s binding.
        """
        from unittest.mock import patch

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
            repo = FileFederatedIdentityRepository()
            assert repo._storage_path == repo._storage_root
