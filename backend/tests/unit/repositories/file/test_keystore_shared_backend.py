"""Cross-backend keyring smoke test.

The whole point of moving the keyring onto fsspec (Fase 22) is
that the configured ``STORAGE_BACKEND`` is the single source of
truth for the keyring. This test proves the property by running
two ``FileKeyStoreRepository`` instances against the same
in-memory backend (via fsspec's ``MemoryFileSystem``) and
asserting that writes from instance A are visible to instance B
after a reload — the same property that lets multiple
application instances share a keyring on a shared backend
(NFS, S3, GCS, etc.).

The test is backend-agnostic: any fsspec-compatible storage
backend that supports ``exists`` + ``read_bytes`` + ``write_bytes``
+ ``makedirs`` will work the same way (s3, gcs, abfs, memory,
local, etc.). We use ``MemoryFileSystem`` here because it needs
zero external setup.
"""

from __future__ import annotations

import asyncio
import os
import shutil

import pytest


def _make_settings(keys_dir: str):
    """Minimal settings stub pointing the keyring at a
    custom directory. ``storage_backend`` is configurable so
    the test can target any fsspec backend (memory, s3, ...).
    """

    class _StubSettings:
        storage_backend = "memory"

        def __init__(self, kd: str) -> None:
            self.keys_dir = kd

        def get_storage_options(self) -> dict:
            return {}

    return _StubSettings(keys_dir)


class TestKeyStoreSharedMemoryBackend:
    """Two ``FileKeyStoreRepository`` instances pointing at the
    same in-memory backend must read each other's writes —
    the same property that lets multiple application instances
    share a keyring on a shared object store."""

    def test_two_repo_instances_observe_each_others_writes(self, tmp_path):
        """Simulates two application instances against the same
        keyring (e.g. two pods sharing an S3 bucket)."""

        # Use a per-test memory "namespace" so concurrent
        # test classes don't share state.
        keys_dir = "/shared-backend-smoke"

        async def _scenario() -> None:
            repo_a = FileKeyStoreRepository(settings=_make_settings(keys_dir))
            repo_b = FileKeyStoreRepository(settings=_make_settings(keys_dir))

            # Empty keyring on both
            assert await repo_a.get_active_keypair() is None
            assert await repo_b.get_active_keypair() is None

            # Instance A bootstraps a keyring
            await repo_a.bootstrap_if_missing(secret_key="shared-secret-32chars-min!")
            kid_a = await repo_a.get_active_kid()
            assert kid_a is not None

            # Instance B sees the same keyring after reloading
            await repo_b.reload()
            kid_b = await repo_b.get_active_kid()
            assert kid_b == kid_a, (
                f"Instance B sees kid={kid_b!r} but instance A wrote kid={kid_a!r}"
            )

            # Instance A rotates
            new_kp = await repo_a.rotate(secret_key="shared-secret-32chars-min!")
            new_kid = new_kp.kid
            assert new_kid != kid_a

            # Instance B sees the rotation
            await repo_b.reload()
            assert await repo_b.get_active_kid() == new_kid

            # Both instances expose the rotated public key set
            pub_a = {k.kid for k in await repo_a.get_public_keys()}
            pub_b = {k.kid for k in await repo_b.get_public_keys()}
            assert pub_a == pub_b

        asyncio.run(_scenario())

    def test_repository_uses_configured_storage_backend(self, tmp_path):
        """The repository's fsspec filesystem must be the one
        selected by ``Settings.storage_backend`` — never a
        hard-coded local filesystem."""

        keys_dir = "/storage-backend-respects-config"

        # The settings stub above sets storage_backend = "memory"
        # — assert the repository picked it up.
        repo = FileKeyStoreRepository(settings=_make_settings(keys_dir))

        assert repo._settings.storage_backend == "memory"
        # The fsspec filesystem instance must be the memory one.
        assert type(repo._filesystem).__name__ == "MemoryFileSystem"

    def test_keyring_survives_re_instantiation(self, tmp_path):
        """The keyring on the shared backend is durable across
        process restarts (modelled here as re-instantiation
        of the repository)."""

        keys_dir = "/durability-smoke"

        async def _scenario() -> None:
            repo1 = FileKeyStoreRepository(settings=_make_settings(keys_dir))
            await repo1.bootstrap_if_missing(secret_key="durability-secret-32chars!")
            kid1 = await repo1.get_active_kid()

            # Simulate a process restart
            repo2 = FileKeyStoreRepository(settings=_make_settings(keys_dir))
            kid2 = await repo2.get_active_kid()
            assert kid1 == kid2, (
                "Keyring on shared backend must survive re-instantiation"
            )

        asyncio.run(_scenario())

    def test_keyring_data_format_is_unchanged(self, tmp_path):
        """The on-disk keyring.json format must remain
        backward-compatible (same fields, same shape) so
        existing keyrings created before the fsspec refactor
        still load. We assert the canonical field set is
        present."""

        keys_dir = "/format-compat-smoke"

        async def _scenario() -> None:
            repo = FileKeyStoreRepository(settings=_make_settings(keys_dir))
            await repo.bootstrap_if_missing(secret_key="format-compat-secret-32char")
            raw = await repo._afs.read_json(repo._keyring_path())

            assert "_version" in raw
            assert raw["_version"] >= 1
            assert "active_kid" in raw
            assert "keys" in raw
            for kid, meta in raw["keys"].items():
                assert "created_at" in meta
                assert meta["status"] in ("active", "verifying", "revoked")
                assert meta["algorithm"] == "RS256"
                assert meta["key_size"] in (2048, 3072, 4096)

        asyncio.run(_scenario())


class TestKeyStoreLegacyMigration:
    """The pre-Fase 22 keyring format (no ``_version`` field,
    legacy single-key files) must still load. This is the
    backward-compat path for installations that upgrade."""

    def test_legacy_keyring_without_version_field_loads(self, tmp_path):
        # Use a real local tmp directory so we can write files
        # directly via the filesystem to simulate a pre-refactor
        # keyring.
        keys_dir = str(tmp_path / "legacy_keys")
        os.makedirs(keys_dir, exist_ok=True)

        class _StubSettings:
            storage_backend = "file"

            def __init__(self, kd: str) -> None:
                self.keys_dir = kd

            def get_storage_options(self) -> dict:
                return {}

        # Simulate a pre-refactor keyring: no _version field.
        legacy = {
            "active_kid": "klegacy",
            "keys": {
                "klegacy": {
                    "created_at": "2025-01-01T00:00:00+00:00",
                    "status": "active",
                    "algorithm": "RS256",
                    "key_size": 2048,
                }
            },
        }
        # Write the keyring.json + per-kid PEMs via the local fs
        kid_dir = os.path.join(keys_dir, "klegacy")
        os.makedirs(kid_dir, exist_ok=True)
        with open(os.path.join(kid_dir, "public_key.pem"), "wb") as f:
            f.write(b"-----BEGIN PUBLIC KEY-----\nfake\n-----END PUBLIC KEY-----\n")
        with open(os.path.join(kid_dir, "private_key.pem"), "wb") as f:
            f.write(b"encrypted-blob")
        with open(os.path.join(keys_dir, "keyring.json"), "w", encoding="utf-8") as f:
            import json as _json

            _json.dump(legacy, f)

        # The repository must load it (no _version field) and
        # accept it.
        async def _scenario() -> None:
            repo = FileKeyStoreRepository(settings=_StubSettings(keys_dir))
            await repo._load_keyring()
            active = await repo.get_active_kid()
            assert active == "klegacy"

        asyncio.run(_scenario())


# Re-import the repository at module level so the test classes
# above can reference it. The import is delayed to the bottom of
# the file so any conftest-level patches are applied first.
from authglow.repositories.file.keystore import (  # noqa: E402
    FileKeyStoreRepository,
)
