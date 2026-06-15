"""Unit tests for the File-backed email-index repository.

Covers ``FileEmailIndexRepository``. The service-level behaviour
(``UserStorage.create_user`` / ``update_email`` / ``delete_user``,
which coordinate email index + user file under ``named_lock``) is
exercised by the existing test suite (``test_storage.py``,
``test_admin_users_phase2.py``, ``test_admin_pagination.py``,
``test_concurrency.py``, etc.).

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method;
* validates Protocol conformance via ``isinstance(repo, <Protocol>)``.

Conventions:

* The repository lower-cases / HMAC-hashes the email internally.
  Test fixtures pass lower-cased emails to match the service
  layer's invariant.
* ``hash_index_key`` is exercised indirectly: after ``insert``,
  the index file is JSON with the **HMAC-hashed** key, not the
  plaintext email.
"""

from authglow.core.crypto import hash_index_key
from authglow.repositories.file.email_index import (
    FileEmailIndexRepository,
)
from authglow.repositories.protocols import EmailIndexRepository

# ---------------------------------------------------------------------------
# FileEmailIndexRepository
# ---------------------------------------------------------------------------


class TestFileEmailIndexRepository:
    def _make_repo(self, test_settings) -> FileEmailIndexRepository:
        return FileEmailIndexRepository(settings=test_settings)

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, EmailIndexRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in ("lookup", "insert", "remove", "all"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    def test_index_lives_at_storage_root(self, test_settings):
        repo = self._make_repo(test_settings)
        # Pre-refactor layout: <storage>/email_index.json
        assert repo._index_path() == f"{repo._storage_root}/email_index.json"
        # _storage_path was collapsed back to the root (no "./"
        # subdir prefix leaking into the path).
        assert repo._storage_path == repo._storage_root

    # ----- insert + lookup -----

    async def test_insert_then_lookup(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.insert("alice@example.com", "user-1")
        assert await repo.lookup("alice@example.com") == "user-1"

    async def test_lookup_returns_none_for_unknown(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.lookup("nobody@example.com") is None

    async def test_insert_overwrites_existing(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.insert("bob@example.com", "user-old")
        await repo.insert("bob@example.com", "user-new")
        assert await repo.lookup("bob@example.com") == "user-new"

    async def test_index_uses_hmac_hashed_keys(self, test_settings):
        """The on-disk file MUST use HMAC-hashed keys (never the
        plaintext email). This is a security requirement."""
        import json

        repo = self._make_repo(test_settings)
        await repo.insert("plaintext@example.com", "user-1")
        raw = repo._index_path()
        # Read the file directly to verify the key is hashed
        with open(raw, encoding="utf-8") as f:
            data = json.load(f)
        assert "plaintext@example.com" not in data
        assert hash_index_key("plaintext@example.com") in data

    async def test_lookup_is_case_sensitive_via_hash(self, test_settings):
        """The repository hashes whatever the caller passes. The
        service layer is responsible for lower-casing emails before
        calling the repo. This test documents the contract:
        passing two different cases of the same email yields two
        different mappings (each with its own HMAC-hashed key)."""
        repo = self._make_repo(test_settings)
        await repo.insert("carol@example.com", "user-lc")
        await repo.insert("Carol@Example.com", "user-mixed")
        assert await repo.lookup("carol@example.com") == "user-lc"
        assert await repo.lookup("Carol@Example.com") == "user-mixed"

    # ----- remove -----

    async def test_remove_existing(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.insert("dave@example.com", "user-1")
        await repo.remove("dave@example.com")
        assert await repo.lookup("dave@example.com") is None

    async def test_remove_unknown_is_noop(self, test_settings):
        repo = self._make_repo(test_settings)
        # No prior insert; remove must not raise.
        await repo.remove("nobody@example.com")
        assert await repo.lookup("nobody@example.com") is None

    async def test_remove_keeps_other_entries(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.insert("alice@example.com", "user-1")
        await repo.insert("bob@example.com", "user-2")
        await repo.remove("alice@example.com")
        assert await repo.lookup("alice@example.com") is None
        assert await repo.lookup("bob@example.com") == "user-2"

    # ----- all -----

    async def test_all_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.all() == {}

    async def test_all_returns_snapshot(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.insert("alice@example.com", "user-1")
        await repo.insert("bob@example.com", "user-2")
        snap = await repo.all()
        assert len(snap) == 2
        # Snapshot is a copy: mutating it must not affect the repo
        snap["injected"] = "x"
        snap2 = await repo.all()
        assert "injected" not in snap2

    async def test_all_after_remove(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.insert("alice@example.com", "user-1")
        await repo.insert("bob@example.com", "user-2")
        await repo.remove("alice@example.com")
        snap = await repo.all()
        assert len(snap) == 1
        # Remaining key is the HMAC-hashed form of bob's email
        assert hash_index_key("bob@example.com") in snap

    # ----- corrupt-JSON tolerance -----

    async def test_lookup_returns_none_on_corrupt_json(self, test_settings):
        """The repository must tolerate a corrupt email index file
        (return None for lookup) rather than raising — the
        on-disk state is inherently racy in a file-based system.
        """
        repo = self._make_repo(test_settings)
        with open(repo._index_path(), "w", encoding="utf-8") as f:
            f.write("not valid json {")
        assert await repo.lookup("alice@example.com") is None

    async def test_all_returns_empty_on_corrupt_json(self, test_settings):
        repo = self._make_repo(test_settings)
        with open(repo._index_path(), "w", encoding="utf-8") as f:
            f.write("not valid json {")
        assert await repo.all() == {}


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFileEmailIndexRepositoryWithPatchedSettings:
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
            repo = FileEmailIndexRepository()
            assert repo._storage_path == repo._storage_root
