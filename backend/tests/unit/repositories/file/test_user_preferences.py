"""Unit tests for the File-backed user-preferences repository.

Covers ``FileUserPreferencesRepository``. The service-level
behaviour (``UserProfileService.get_user_preferences`` /
``update_user_preferences`` / ``delete_account``, with
``named_lock("preferences:<id>")`` held across the
multi-step path) is exercised by the existing
``tests/unit/test_user_profile.py``.

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method;
* validates Protocol conformance via
  ``isinstance(repo, <Protocol>)``.

Conventions:

* The repository stores ``UserPreferences`` Pydantic models
  (via ``model_dump()``) and re-hydrates them via
  ``UserPreferences(**data)`` on read.
* ``get`` returns ``None`` for missing users (the service
  layer maps that to ``UserPreferences(user_id=user_id)``
  defaults — verified by the existing service tests).
* ``delete`` is a no-op for missing users (no error).
"""

from pathlib import Path

from authglow.models.user_profile import UserPreferences
from authglow.repositories.file.user_preferences import (
    FileUserPreferencesRepository,
)
from authglow.repositories.protocols import UserPreferencesRepository

# ---------------------------------------------------------------------------
# FileUserPreferencesRepository
# ---------------------------------------------------------------------------


class TestFileUserPreferencesRepository:
    def _make_repo(self, test_settings) -> FileUserPreferencesRepository:
        return FileUserPreferencesRepository(settings=test_settings)

    def _make_preferences(self, user_id: str = "user-1", **overrides) -> UserPreferences:
        """Build a ``UserPreferences`` with non-default values
        for the tests that depend on specific fields."""
        defaults = {
            "theme": "dark",
            "language": "it",
            "email_notifications": False,
            "marketing_emails": True,
        }
        defaults.update(overrides)
        return UserPreferences(user_id=user_id, **defaults)

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, UserPreferencesRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in ("get", "save", "delete"):
            assert hasattr(repo, method)
            assert callable(getattr(repo, method))

    def test_subdir_layout(self, test_settings):
        repo = self._make_repo(test_settings)
        assert repo._subdir == "user_preferences"
        # Pre-refactor layout: <storage>/user_preferences/<user_id>.json
        assert repo._prefs_path("u-1") == f"{repo._storage_root}/user_preferences/u-1.json"

    # ----- get / save round-trip -----

    async def test_get_returns_none_for_unknown(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get("nobody") is None

    async def test_save_then_get_round_trip(self, test_settings):
        repo = self._make_repo(test_settings)
        prefs = self._make_preferences(user_id="rt")
        await repo.save(prefs)
        fetched = await repo.get("rt")
        assert fetched is not None
        assert fetched.user_id == "rt"
        assert fetched.theme == "dark"
        assert fetched.language == "it"
        assert fetched.email_notifications is False
        assert fetched.marketing_emails is True

    async def test_save_overwrites_existing(self, test_settings):
        repo = self._make_repo(test_settings)
        first = self._make_preferences(user_id="over", theme="light")
        await repo.save(first)
        second = self._make_preferences(user_id="over", theme="dark")
        await repo.save(second)
        fetched = await repo.get("over")
        assert fetched.theme == "dark"

    async def test_save_preserves_user_id(self, test_settings):
        """The user_id in the file MUST match the user_id in
        the model — even if a caller accidentally passes a
        different key to ``save`` (the path is derived from
        ``preferences.user_id``)."""
        repo = self._make_repo(test_settings)
        prefs = self._make_preferences(user_id="alice")
        await repo.save(prefs)
        # Saved under alice, not bob
        assert await repo.get("alice") is not None
        assert await repo.get("bob") is None

    # ----- delete -----

    async def test_delete_existing(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.save(self._make_preferences(user_id="del"))
        await repo.delete("del")
        assert await repo.get("del") is None

    async def test_delete_unknown_is_noop(self, test_settings):
        repo = self._make_repo(test_settings)
        # No prior save; delete must not raise.
        await repo.delete("nobody")
        assert await repo.get("nobody") is None

    async def test_delete_keeps_other_entries(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.save(self._make_preferences(user_id="keep-1"))
        await repo.save(self._make_preferences(user_id="keep-2"))
        await repo.delete("keep-1")
        assert await repo.get("keep-1") is None
        assert (await repo.get("keep-2")) is not None

    # ----- isolation between users -----

    async def test_users_have_isolated_preferences(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.save(self._make_preferences(user_id="alice", theme="dark"))
        await repo.save(self._make_preferences(user_id="bob", theme="light"))
        alice = await repo.get("alice")
        bob = await repo.get("bob")
        assert alice.theme == "dark"
        assert bob.theme == "light"

    # ----- corrupt-JSON tolerance -----

    async def test_get_returns_none_on_corrupt_json(self, test_settings):
        """The repository must tolerate a corrupt preferences
        file (return None for get) rather than raising — the
        on-disk state is inherently racy in a file-based
        system. The service layer maps ``None`` to a default
        ``UserPreferences(user_id=user_id)``."""
        repo = self._make_repo(test_settings)
        path = Path(repo._prefs_path("corrupt"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not valid json {")
        assert await repo.get("corrupt") is None

    async def test_save_recovers_from_corrupt_json(self, test_settings):
        """A corrupt preferences file must be overwritten on
        the next ``save`` call (no manual cleanup required)."""
        repo = self._make_repo(test_settings)
        path = Path(repo._prefs_path("recover"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("not valid json {")
        await repo.save(self._make_preferences(user_id="recover"))
        fetched = await repo.get("recover")
        assert fetched is not None

    async def test_get_returns_none_for_non_dict_json(self, test_settings):
        """If the file contains valid JSON but is not a dict
        (e.g. a stray ``[]`` or ``42``), the repository must
        return ``None`` rather than crashing."""
        repo = self._make_repo(test_settings)
        path = Path(repo._prefs_path("list-shape"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("[1, 2, 3]")
        assert await repo.get("list-shape") is None


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFileUserPreferencesRepositoryWithPatchedSettings:
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
            repo = FileUserPreferencesRepository()
            assert repo._subdir == "user_preferences"
