"""VAPT-040: secondary-index files and the token-blacklist store
live JTIs / key IDs / JTI pseudonyms in plaintext on disk.

This test module covers the three pieces of the fix:

* refresh-token ``id_index.json`` and ``active_index.json`` are
  encrypted with the private-key envelope (``agk1:`` prefix);
* API-key ``prefix_index/<prefix>.json`` is encrypted the same way;
* token-blacklist files are renamed to an HMAC-SHA256 pseudonym
  of the JTI (so the JTI never appears in the filename);
* storage directories are created with mode ``0o700``.

Each test exercises one invariant on real file storage.
"""

import json
import os
import re
import time
from pathlib import Path

import pytest

from authglow.core.crypto import (
    decrypt_index_value,
    encrypt_index_value,
    hmac_index_filename,
)
from authglow.models.api_key import APIKey
from authglow.models.refresh_token import RefreshToken
from authglow.repositories.file.api_key import FileAPIKeyRepository
from authglow.repositories.file.refresh_token import FileRefreshTokenRepository
from authglow.repositories.file.token_blacklist import FileTokenBlacklistRepository
from authglow.services.auth.token_blacklist import TokenBlacklist

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _asyncio_run(coro):
    import asyncio

    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _hex64(name: str) -> bool:
    """True for a 64-char lowercase hex string (HMAC-SHA256 digest)."""
    return bool(re.fullmatch(r"[0-9a-f]{64}", name))


# ---------------------------------------------------------------------------
# Refresh token — index files are encrypted
# ---------------------------------------------------------------------------


class TestVapt040RefreshTokenIndexesEncrypted:
    def _build_repo(self, test_settings, tmp_path):
        storage_path = tmp_path / "rt"
        storage_path.mkdir(parents=True, exist_ok=True)
        custom = test_settings.model_copy(update={"storage_path": str(storage_path)})
        return FileRefreshTokenRepository(settings=custom)

    def test_id_index_file_on_disk_starts_with_agk1(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        token = RefreshToken(
            token_id="tid-1",
            token_lookup="lookup-1",
            token_hash="hash-1",
            user_id="u-1",
            client_id="c-1",
            scopes=["read"],
            created_at="2026-06-28T00:00:00",
            expires_at="2026-07-28T00:00:00",
        )
        _asyncio_run(repo.create(token))
        _asyncio_run(repo.add_to_id_index("tid-1", "lookup-1"))

        raw = Path(repo._id_index_path).read_text(encoding="utf-8")
        assert raw.startswith("agk1:"), (
            f"VAPT-040: id_index.json must start with the agk1: envelope, got prefix {raw[:8]!r}"
        )

    def test_active_index_file_on_disk_starts_with_agk1(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        _asyncio_run(repo.add_to_active_index("tid-1"))
        _asyncio_run(repo.add_to_active_index("tid-2"))

        raw = Path(repo._active_index_path).read_text(encoding="utf-8")
        assert raw.startswith("agk1:")

    def test_id_index_roundtrip_preserves_data(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        _asyncio_run(repo.add_to_id_index("tid-1", "lookup-1"))
        _asyncio_run(repo.add_to_id_index("tid-2", "lookup-2"))

        loaded = _asyncio_run(repo.load_id_index())
        assert loaded == {"tid-1": "lookup-1", "tid-2": "lookup-2"}

    def test_active_index_roundtrip_preserves_data(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        _asyncio_run(repo.add_to_active_index("tid-1"))
        _asyncio_run(repo.add_to_active_index("tid-2"))

        loaded = _asyncio_run(repo.load_active_index())
        assert loaded == ["tid-1", "tid-2"]

    def test_plaintext_id_index_is_read_tolerantly_and_rewritten(self, test_settings, tmp_path):
        """Pre-VAPT-040 deployments may still have plaintext
        ``id_index.json``. The repository must read them and
        re-encrypt on the next write."""
        repo = self._build_repo(test_settings, tmp_path)
        legacy = {"legacy-tid": "legacy-lookup"}
        Path(repo._id_index_path).write_text(json.dumps(legacy), encoding="utf-8")

        # Read: legacy plaintext is returned as-is.
        loaded = _asyncio_run(repo.load_id_index())
        assert loaded == legacy

        # Write: the file is now encrypted.
        _asyncio_run(repo.add_to_id_index("new-tid", "new-lookup"))
        raw = Path(repo._id_index_path).read_text(encoding="utf-8")
        assert raw.startswith("agk1:")

        # And the new content includes both the legacy entry and
        # the new one (decryption is round-trip-clean).
        loaded_after = _asyncio_run(repo.load_id_index())
        assert loaded_after == {
            "legacy-tid": "legacy-lookup",
            "new-tid": "new-lookup",
        }


# ---------------------------------------------------------------------------
# API key — prefix index is encrypted
# ---------------------------------------------------------------------------


class TestVapt040ApiKeyPrefixIndexEncrypted:
    def _build_repo(self, test_settings, tmp_path):
        storage_path = tmp_path / "apikeys"
        storage_path.mkdir(parents=True, exist_ok=True)
        custom = test_settings.model_copy(update={"storage_path": str(storage_path)})
        return FileAPIKeyRepository(settings=custom)

    def test_prefix_index_file_on_disk_starts_with_agk1(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        api_key = APIKey(
            key_id="kid-1",
            name="test-key",
            key_prefix="ak_abcdef1234",
            key_hash="h",
            user_id="u-1",
            created_by="u-1",
            scopes=["read"],
            created_at="2026-06-28T00:00:00",
        )
        _asyncio_run(repo.create(api_key))
        _asyncio_run(repo.add_to_prefix_index(api_key))

        path = Path(repo._index_path_for(api_key.key_prefix))
        raw = path.read_text(encoding="utf-8")
        assert raw.startswith("agk1:")

    def test_prefix_index_roundtrip(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        api_key = APIKey(
            key_id="kid-1",
            name="test-key",
            key_prefix="ak_abcdef1234",
            key_hash="h",
            user_id="u-1",
            created_by="u-1",
            scopes=["read"],
            created_at="2026-06-28T00:00:00",
        )
        _asyncio_run(repo.create(api_key))
        _asyncio_run(repo.add_to_prefix_index(api_key))

        loaded = _asyncio_run(repo.load_prefix_index(api_key.key_prefix))
        assert loaded == ["kid-1"]

    def test_prefix_index_plaintext_migrated_on_write(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        legacy_prefix = "ak_legacy1234"
        path = Path(repo._index_path_for(legacy_prefix))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"key_ids": ["legacy-kid"]}), encoding="utf-8")

        loaded = _asyncio_run(repo.load_prefix_index(legacy_prefix))
        assert loaded == ["legacy-kid"]

        # Add a new entry — this rewrites the file encrypted.
        api_key = APIKey(
            key_id="new-kid",
            name="test-key",
            key_prefix=legacy_prefix,
            key_hash="h",
            user_id="u-1",
            created_by="u-1",
            scopes=["read"],
            created_at="2026-06-28T00:00:00",
        )
        _asyncio_run(repo.create(api_key))
        _asyncio_run(repo.add_to_prefix_index(api_key))

        raw = path.read_text(encoding="utf-8")
        assert raw.startswith("agk1:")
        loaded_after = _asyncio_run(repo.load_prefix_index(legacy_prefix))
        assert loaded_after == ["legacy-kid", "new-kid"]


# ---------------------------------------------------------------------------
# Token blacklist — HMAC pseudonym in filename
# ---------------------------------------------------------------------------


class TestVapt040TokenBlacklistHmacFilename:
    def _build_repo(self, test_settings, tmp_path):
        storage_path = tmp_path / "blacklist"
        storage_path.mkdir(parents=True, exist_ok=True)
        custom = test_settings.model_copy(update={"storage_path": str(storage_path)})
        return FileTokenBlacklistRepository(settings=custom)

    def test_jti_does_not_appear_in_filename(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        _asyncio_run(repo.save("plaintext-jti-value", time.time() + 60))

        files = os.listdir(repo._storage_path)
        assert len(files) == 1
        filename = files[0]
        # The JTI itself must not appear anywhere in the filename.
        assert "plaintext-jti-value" not in filename
        # The filename is the 64-char hex HMAC digest + .json.
        assert _hex64(filename.removesuffix(".json"))

    def test_filename_matches_hmac_index_filename_helper(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        _asyncio_run(repo.save("jti-xyz", time.time() + 60))

        expected_name = f"{hmac_index_filename('jti-xyz')}.json"
        assert os.path.exists(Path(repo._storage_path) / expected_name)

    def test_legacy_plaintext_filename_is_ignored_on_load(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        # Simulate a pre-VAPT-040 file with the JTI in the filename.
        legacy = Path(repo._storage_path) / "legacy-jti.json"
        legacy.write_text(json.dumps({"expires_at": time.time() + 60}), encoding="utf-8")

        loaded = _asyncio_run(repo.load_all())
        # The legacy file is skipped — only HMAC-named files
        # populate the in-memory store.
        assert loaded == {}
        # And the file is still on disk (so the cleanup task can
        # reap it later).
        assert legacy.exists()

    def test_load_all_returns_hmac_pseudonym_keys(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        _asyncio_run(repo.save("jti-a", time.time() + 60))
        _asyncio_run(repo.save("jti-b", time.time() + 60))

        loaded = _asyncio_run(repo.load_all())
        assert hmac_index_filename("jti-a") in loaded
        assert hmac_index_filename("jti-b") in loaded

    def test_exists_uses_hmac_filename(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        _asyncio_run(repo.save("jti-known", time.time() + 60))
        assert repo.exists("jti-known") is True
        assert repo.exists("jti-unknown") is False

    def test_delete_uses_hmac_filename(self, test_settings, tmp_path):
        repo = self._build_repo(test_settings, tmp_path)
        _asyncio_run(repo.save("jti-del", time.time() + 60))
        assert repo.delete("jti-del") is True
        # Second delete returns False — the file is gone.
        assert repo.delete("jti-del") is False

    def test_service_uses_hmac_keys_in_memory(self, test_settings, tmp_path):
        """The service-level ``_store`` is keyed by HMAC pseudonym,
        not by the plaintext JTI. Public API still receives JTIs."""
        repo = self._build_repo(test_settings, tmp_path)
        svc = TokenBlacklist(repository=repo)
        _asyncio_run(svc.startup_hydrate())
        _asyncio_run(svc.revoke("jti-public", time.time() + 60))

        # In-memory: HMAC pseudonym.
        assert hmac_index_filename("jti-public") in svc._store
        # On-disk: HMAC-named file.
        files = os.listdir(repo._storage_path)
        assert "jti-public" not in str(files)
        # Public API: still JTI-keyed.
        assert svc.is_revoked("jti-public") is True
        assert svc.is_revoked("jti-unknown") is False


# ---------------------------------------------------------------------------
# Storage directories — mode 0700
# ---------------------------------------------------------------------------


class TestVapt040DirectoryPermissions:
    def test_newly_created_storage_path_has_mode_0o700(self, test_settings, tmp_path):
        """VAPT-040: a freshly-created storage directory must be
        mode ``0o700`` so a directory-read attacker with a
        non-owner account cannot enumerate the index files."""
        if os.name == "nt":
            pytest.skip("chmod 0o700 is unreliable on Windows")

        from authglow.repositories.file.user import FileUserRepository

        storage_path = str(tmp_path / "data" / "users")
        custom = test_settings.model_copy(update={"storage_path": storage_path})
        # Force the path not to exist yet.
        assert not os.path.exists(storage_path)
        FileUserRepository(settings=custom)

        mode = os.stat(storage_path).st_mode & 0o777
        assert mode == 0o700, (
            f"Expected 0o700, got {oct(mode)} — VAPT-040 directory "
            "permission tightening did not apply"
        )

    def test_existing_directory_is_tightened_to_0o700(self, test_settings, tmp_path):
        """An existing directory with looser permissions (e.g. ``0o755``)
        must be tightened on the next repository construction."""
        if os.name == "nt":
            pytest.skip("chmod 0o700 is unreliable on Windows")

        from authglow.repositories.file.user import FileUserRepository

        storage_path = str(tmp_path / "data" / "users")
        os.makedirs(storage_path, mode=0o755)
        # Sanity: the dir is currently 0o755.
        assert (os.stat(storage_path).st_mode & 0o777) == 0o755

        custom = test_settings.model_copy(update={"storage_path": storage_path})
        FileUserRepository(settings=custom)

        mode = os.stat(storage_path).st_mode & 0o777
        assert mode == 0o700


# ---------------------------------------------------------------------------
# Crypto helpers — roundtrip + migration
# ---------------------------------------------------------------------------


class TestVapt040CryptoHelpers:
    def test_encrypt_decrypt_index_roundtrip(self):
        from authglow.core.config import get_settings

        plaintext = json.dumps({"key_ids": ["kid-1", "kid-2"]})
        ciphertext = encrypt_index_value(plaintext)
        assert ciphertext.startswith("agk1:")
        assert plaintext not in ciphertext  # encrypted — no plaintext leak
        # Decrypt with the live Settings — they should match.
        del get_settings  # touch import
        # Use a stable secret_key to keep the test deterministic.

        # Decryption through the live settings (test_settings
        # already injected via the autouse _override_settings
        # fixture).
        assert decrypt_index_value(ciphertext) == plaintext

    def test_decrypt_tolerates_legacy_plaintext(self):
        """A pre-VAPT-040 plaintext payload must round-trip
        through ``decrypt_index_value`` unchanged so the
        caller can read legacy data."""
        legacy = json.dumps({"token_ids": ["t-1", "t-2"]})
        assert decrypt_index_value(legacy) == legacy

    def test_decrypt_raises_on_garbage_agk1_payload(self):
        """A ciphertext with the right prefix but a corrupt body
        must raise (so the caller can detect on-disk tamper)."""
        bad = "agk1:" + "x" * 100  # not valid base64
        with pytest.raises(Exception):
            decrypt_index_value(bad)

    def test_hmac_index_filename_is_64_hex(self):
        result = hmac_index_filename("some-jti-value")
        assert _hex64(result)

    def test_hmac_index_filename_is_deterministic(self):
        a = hmac_index_filename("jti-1")
        b = hmac_index_filename("jti-1")
        assert a == b

    def test_hmac_index_filename_changes_per_jti(self):
        a = hmac_index_filename("jti-1")
        b = hmac_index_filename("jti-2")
        assert a != b

    def test_hmac_index_filename_is_portable(self):
        """The returned value must be safe to use as a filename
        on every supported platform (no colons, slashes, etc.)."""
        for jti in [
            "jti-a",
            "uuid:550e8400-e29b-41d4-a716-446655440000",
            "with/slash",
            "with\\backslash",
            "with:colon",
        ]:
            result = hmac_index_filename(jti)
            # Reject characters that Windows / POSIX consider
            # reserved in filenames.
            assert not any(c in result for c in '<>:"/\\|?*'), (
                f"hmac_index_filename({jti!r}) produced {result!r} "
                "with a reserved filename character"
            )

    def test_hmac_index_filename_rotates_with_secret_key(self):
        a = hmac_index_filename("jti-1", secret_key="secret-A-" + "x" * 32)
        b = hmac_index_filename("jti-1", secret_key="secret-B-" + "x" * 32)
        assert a != b
