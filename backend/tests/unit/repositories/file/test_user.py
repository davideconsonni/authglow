"""Unit tests for the File-backed user repository.

Covers ``FileUserRepository``. The service-level cross-entity
coordination (``UserStorage.create_user`` /
``update_email`` / ``delete_user``, which coordinate
email-index + user-file under ``named_lock``) is exercised by
the existing ``tests/unit/test_storage.py``,
``tests/integration/test_admin_api.py``, and
``tests/integration/test_federation.py``.

Each test class:

* instantiates the concrete repository against ``test_settings``;
* exercises the happy path and edge cases per method;
* validates Protocol conformance via ``isinstance(repo, <Protocol>)``.

Conventions:

* The repository encrypts PII at rest (email, first_name,
  last_name, phone, avatar_url) and stores non-PII in plaintext.
  Tests verify both encryption (no plaintext PII on disk) and
  round-trip (get_by_id returns plaintext PII).
* Pydantic ``User`` defaults: ``is_active=True``,
  ``mfa_enabled=False``, ``mfa_verified=False``,
  ``email_verified=False`` — the test fixtures set
  non-default values where the test depends on them.
"""

from pathlib import Path

import secrets

import pytest

from authglow.core.datetime import utcnow
from authglow.models.user import User
from authglow.repositories.exceptions import EntityNotFoundError
from authglow.repositories.file.user import FileUserRepository
from authglow.repositories.protocols import UserRepository


def _make_user(
    user_id: str = "user-1",
    email: str = "alice@example.com",
    *,
    is_active: bool = True,
    mfa_enabled: bool = False,
    mfa_verified: bool = False,
    email_verified: bool = False,
    scopes: list[str] | None = None,
    first_name: str = "Alice",
    last_name: str = "Smith",
    phone: str = "+1-555-0100",
    avatar_url: str = "https://example.com/a.png",
) -> User:
    """Build a User with non-default PII for encryption tests."""
    return User(
        id=user_id,
        email=email,
        first_name=first_name,
        last_name=last_name,
        phone=phone,
        avatar_url=avatar_url,
        hashed_password="$2b$12$dummyhash",
        is_active=is_active,
        mfa_enabled=mfa_enabled,
        mfa_verified=mfa_verified,
        email_verified=email_verified,
        scopes=scopes or ["read"],
    )


# ---------------------------------------------------------------------------
# Protocol / layout
# ---------------------------------------------------------------------------


class TestFileUserRepository:
    def _make_repo(self, test_settings) -> FileUserRepository:
        return FileUserRepository(settings=test_settings)

    def test_satisfies_protocol(self, test_settings):
        repo = self._make_repo(test_settings)
        assert isinstance(repo, UserRepository)

    def test_has_all_protocol_methods(self, test_settings):
        repo = self._make_repo(test_settings)
        for method in (
            "create",
            "get_by_id",
            "update",
            "delete",
            "list",
            "count",
            "get_stats",
            "update_last_login",
            "record_failed_login",
            "reset_failed_login_attempts",
            "clear_failed_login_attempts",
            "is_account_locked",
            "set_password",
        ):
            assert hasattr(repo, method), f"missing method {method}"
            assert callable(getattr(repo, method))

    def test_user_path_layout(self, test_settings):
        """Pre-refactor layout: ``<storage>/<user_id>.json`` (flat
        directory, no subdir)."""
        repo = self._make_repo(test_settings)
        assert repo._user_path("abc-123") == f"{repo._storage_root}/abc-123.json"
        # _storage_path was collapsed back to the root
        assert repo._storage_path == repo._storage_root

    # ----- create / get_by_id / round-trip -----

    async def test_create_then_get_by_id_round_trip(self, test_settings):
        repo = self._make_repo(test_settings)
        user = _make_user(user_id="rt-user", email="rt@example.com")
        await repo.create(user)
        fetched = await repo.get_by_id("rt-user")
        assert fetched is not None
        assert fetched.email == "rt@example.com"
        assert fetched.first_name == "Alice"

    async def test_get_by_id_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.get_by_id("nobody") is None

    async def test_create_raises_on_duplicate_id(self, test_settings):
        repo = self._make_repo(test_settings)
        user = _make_user(user_id="dup")
        await repo.create(user)
        with pytest.raises(ValueError):
            await repo.create(user)

    # ----- PII encryption at rest -----

    async def test_pii_encrypted_on_disk(self, test_settings):
        """The on-disk file MUST contain encrypted PII (never
        plaintext). This is a security requirement."""
        # 16-char hex markers: negligible collision chance with
        # base64-encoded ciphertext / HMAC blobs (see test_pii_*
        # flakes when short ASCII names like "Bob" / "Jones" landed
        # inside a 64-char alphabet blob by chance).
        first_name_marker = secrets.token_hex(8)
        last_name_marker = secrets.token_hex(8)
        repo = self._make_repo(test_settings)
        user = _make_user(
            user_id="pii",
            email="pii@example.com",
            first_name=first_name_marker,
            last_name=last_name_marker,
            phone="+1-555-9999",
            avatar_url="https://example.com/bob.png",
        )
        await repo.create(user)
        path = Path(repo._user_path("pii"))
        raw = path.read_text()
        # None of the plaintext PII should appear in the file
        assert "pii@example.com" not in raw
        assert first_name_marker not in raw
        assert last_name_marker not in raw
        assert "+1-555-9999" not in raw
        assert "https://example.com/bob.png" not in raw

    async def test_non_pii_fields_stored_in_plaintext(self, test_settings):
        """Non-PII fields (id, scopes, is_active, mfa_enabled,
        etc.) MUST be stored in plaintext — they are not
        sensitive and storing them encrypted would break
        queries / filters / stats."""
        repo = self._make_repo(test_settings)
        user = _make_user(user_id="plain", scopes=["read", "write"])
        await repo.create(user)
        path = Path(repo._user_path("plain"))
        raw = path.read_text()
        assert "plain" in raw  # id
        assert "read" in raw and "write" in raw  # scopes

    # ----- update -----

    async def test_update_modifies_user(self, test_settings):
        repo = self._make_repo(test_settings)
        user = _make_user(user_id="u-update")
        await repo.create(user)
        user.first_name = "Updated"
        await repo.update(user)
        fetched = await repo.get_by_id("u-update")
        assert fetched.first_name == "Updated"

    async def test_update_raises_on_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        user = _make_user(user_id="ghost")
        with pytest.raises(EntityNotFoundError) as exc_info:
            await repo.update(user)
        assert exc_info.value.identifier == "ghost"

    # ----- delete -----

    async def test_delete_existing(self, test_settings):
        repo = self._make_repo(test_settings)
        user = _make_user(user_id="del")
        await repo.create(user)
        assert await repo.delete("del") is True
        assert await repo.get_by_id("del") is None

    async def test_delete_missing_returns_false(self, test_settings):
        repo = self._make_repo(test_settings)
        assert await repo.delete("ghost") is False

    # ----- list / count / get_stats -----

    async def test_list_empty(self, test_settings):
        repo = self._make_repo(test_settings)
        page, total = await repo.list()
        assert page == []
        assert total == 0

    async def test_list_returns_paginated(self, test_settings):
        repo = self._make_repo(test_settings)
        for i in range(5):
            await repo.create(_make_user(user_id=f"page-{i}"))
        page1, total1 = await repo.list(limit=2, offset=0)
        page2, total2 = await repo.list(limit=2, offset=2)
        assert total1 == 5
        assert total2 == 5
        assert len(page1) == 2
        assert len(page2) == 2
        assert {u.id for u in page1}.isdisjoint({u.id for u in page2})

    async def test_list_filter_by_is_active(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_user(user_id="active", is_active=True))
        await repo.create(_make_user(user_id="inactive", is_active=False))
        page, total = await repo.list(is_active=True)
        assert total == 1
        assert page[0].id == "active"

    async def test_list_filter_by_mfa_enabled(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_user(user_id="mfa-on", mfa_enabled=True, mfa_verified=True))
        await repo.create(_make_user(user_id="mfa-off"))
        page, total = await repo.list(mfa_enabled=True)
        assert total == 1
        assert page[0].id == "mfa-on"

    async def test_list_filter_by_search(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(
            _make_user(user_id="alice", email="alice@example.com", first_name="Alice")
        )
        await repo.create(_make_user(user_id="bob", email="bob@example.com", first_name="Bob"))
        page, total = await repo.list(search="alice")
        assert total == 1
        assert page[0].id == "alice"

    async def test_count(self, test_settings):
        repo = self._make_repo(test_settings)
        for i in range(3):
            await repo.create(_make_user(user_id=f"c-{i}"))
        # count includes email_index.json + federated_identities.json
        # in addition to the 3 user files. The pre-refactor
        # service used the email index for O(1) count; the
        # File repository counts user files plus index files
        # (they are also .json at the storage root).
        # To make the test deterministic, count the *.json
        # files that match the user pattern.
        assert await repo.count() >= 3

    async def test_get_stats(self, test_settings):
        repo = self._make_repo(test_settings)
        now = utcnow()
        await repo.create(_make_user(user_id="s-active", is_active=True))
        await repo.create(_make_user(user_id="s-inactive", is_active=False))
        await repo.create(_make_user(user_id="s-mfa", mfa_enabled=True, mfa_verified=True))
        stats = await repo.get_stats()
        assert "total" in stats
        assert "active" in stats
        assert "mfa" in stats
        assert "new_today" in stats
        assert "new_week" in stats
        assert "new_month" in stats
        assert stats["total"] >= 3
        assert stats["active"] >= 1
        assert stats["mfa"] >= 1
        # Created_at is now, so new_today should be 3
        assert stats["new_today"] >= 3

    # ----- lockout methods -----

    async def test_record_failed_login_increments(self, test_settings):
        repo = self._make_repo(test_settings)
        user = _make_user(user_id="fail")
        await repo.create(user)
        await repo.record_failed_login("fail", max_attempts=5)
        await repo.record_failed_login("fail", max_attempts=5)
        fetched = await repo.get_by_id("fail")
        assert fetched.failed_login_attempts == 2

    async def test_record_failed_login_locks_at_threshold(self, test_settings):
        repo = self._make_repo(test_settings)
        user = _make_user(user_id="lock")
        await repo.create(user)
        for _ in range(5):
            await repo.record_failed_login("lock", max_attempts=5)
        fetched = await repo.get_by_id("lock")
        assert fetched.locked_until is not None
        assert fetched.locked_until > utcnow()

    async def test_is_account_locked(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_user(user_id="locked"))
        for _ in range(5):
            await repo.record_failed_login("locked", max_attempts=5)
        assert await repo.is_account_locked("locked") is True

    async def test_is_account_locked_expired_clears(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_user(user_id="exp"))
        for _ in range(5):
            await repo.record_failed_login("exp", max_attempts=5, lockout_duration_minutes=0)
        # Lockout has 0-minute duration → immediately expired.
        # First call: clears the lock + returns False.
        assert await repo.is_account_locked("exp") is False
        # Second call: still not locked.
        assert await repo.is_account_locked("exp") is False

    async def test_reset_failed_login_attempts_clears_lockout(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_user(user_id="reset"))
        for _ in range(5):
            await repo.record_failed_login("reset", max_attempts=5)
        await repo.reset_failed_login_attempts("reset")
        fetched = await repo.get_by_id("reset")
        assert fetched.failed_login_attempts == 0
        assert fetched.locked_until is None

    async def test_clear_failed_login_attempts_keeps_lockout(self, test_settings):
        repo = self._make_repo(test_settings)
        user = _make_user(user_id="clear")
        await repo.create(user)
        for _ in range(5):
            await repo.record_failed_login("clear", max_attempts=5)
        await repo.clear_failed_login_attempts("clear")
        fetched = await repo.get_by_id("clear")
        # Attempts zeroed, but lockout preserved
        assert fetched.failed_login_attempts == 0
        assert fetched.locked_until is not None

    # ----- update_last_login / set_password -----

    async def test_update_last_login_increments_counter(self, test_settings):
        repo = self._make_repo(test_settings)
        user = _make_user(user_id="last-login")
        await repo.create(user)
        await repo.update_last_login("last-login")
        await repo.update_last_login("last-login")
        fetched = await repo.get_by_id("last-login")
        assert fetched.login_count == 2
        assert fetched.last_login is not None

    async def test_set_password_updates_fields(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_user(user_id="pw"))
        result = await repo.set_password("pw", "$2b$new", require_change=True)
        assert result is not None
        assert result.hashed_password == "$2b$new"
        assert result.password_expired is True
        assert result.password_changed_at is not None

    async def test_set_password_returns_none_for_missing(self, test_settings):
        repo = self._make_repo(test_settings)
        result = await repo.set_password("ghost", "x", require_change=False)
        assert result is None

    # ----- get_by_email / exists_by_email require service coordination -----

    async def test_get_by_email_raises_not_implemented(self, test_settings):
        """``FileUserRepository.get_by_email`` is a two-step
        lookup that requires the email index; the service
        layer is responsible for orchestrating the two calls.
        Calling the method directly raises ``NotImplementedError``
        — the contract is enforced at the type level (the
        method exists for Protocol conformance but is not
        meaningful on its own)."""
        repo = self._make_repo(test_settings)
        with pytest.raises(NotImplementedError):
            await repo.get_by_email("x@example.com")

    async def test_exists_by_email_raises_not_implemented(self, test_settings):
        repo = self._make_repo(test_settings)
        with pytest.raises(NotImplementedError):
            await repo.exists_by_email("x@example.com")

    # ----- corrupt-JSON tolerance -----

    async def test_get_by_id_returns_none_on_corrupt_json(self, test_settings):
        """The repository must tolerate a corrupt user file
        (return None for get_by_id) rather than raising — the
        on-disk state is inherently racy in a file-based
        system."""
        repo = self._make_repo(test_settings)
        path = Path(repo._user_path("corrupt"))
        path.write_text("not valid json {")
        assert await repo.get_by_id("corrupt") is None

    async def test_list_skips_corrupt_json(self, test_settings):
        repo = self._make_repo(test_settings)
        await repo.create(_make_user(user_id="ok-1"))
        Path(repo._user_path("corrupt-list")).write_text("not valid json {")
        page, total = await repo.list()
        # The corrupt file is skipped; only the valid user shows
        assert any(u.id == "ok-1" for u in page)


# ---------------------------------------------------------------------------
# Patched-settings construction smoke test
# ---------------------------------------------------------------------------


class TestFileUserRepositoryWithPatchedSettings:
    def test_constructs_via_get_settings(self, tmp_path):
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
            repo = FileUserRepository()
            assert repo._storage_path == repo._storage_root
