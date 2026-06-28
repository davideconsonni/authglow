"""VAPT-038: UserService.verify_and_maybe_rehash_password contract tests.

Covers the bcrypt cost migration on successful login — the
end-to-end flow from ``UserService.verify_and_maybe_rehash_password``
through the file repository, asserting that the on-disk hash is
updated transparently when the stored cost is below the configured
``bcrypt_rounds`` setting.
"""

import asyncio
import json
from pathlib import Path

from authglow.models.user import User
from authglow.services.password import hash_password
from authglow.services.user import UserService as UserStorage


def _read_user_hash(user_id: str, settings) -> str:
    """Read the raw hashed_password field from the on-disk user JSON.

    The ``UserRepository`` stores PII encrypted at rest, but
    ``hashed_password`` is one of the few plaintext fields
    (it is already a one-way function) — so it can be inspected
    directly to verify the re-hash happened.
    """
    user_path = Path(settings.storage_path) / f"{user_id}.json"
    data = json.loads(user_path.read_text(encoding="utf-8"))
    return data["hashed_password"]


class TestVapt038RehashOnLogin:
    def test_rehash_persists_when_stored_hash_below_target(self, test_settings, monkeypatch):
        """A stale hash (cost < settings.bcrypt_rounds) is migrated
        transparently on the next successful verify."""
        with monkeypatch.context() as m:
            m.setattr(test_settings, "bcrypt_rounds", 4)
            storage = UserStorage()
            # Sanity: the storage picks up the patched setting.
            assert storage.settings.bcrypt_rounds == 4

            user = User(
                email="vapt038-rehash@example.com",
                hashed_password=hash_password("Vapt038P@ss1!"),
                scopes=["read"],
            )
            asyncio.get_event_loop().run_until_complete(storage.create_user(user))

            # Bump the target cost: any pre-existing hash at cost 4 is now stale.
            m.setattr(test_settings, "bcrypt_rounds", 5)

            # The on-disk hash is at cost 4 (the original cost).
            old_hash = _read_user_hash(user.id, test_settings)
            assert old_hash.startswith("$2b$04$"), old_hash

            # Verify → should re-hash and persist at cost 5.
            is_valid, returned = asyncio.get_event_loop().run_until_complete(
                storage.verify_and_maybe_rehash_password(user, "Vapt038P@ss1!")
            )
            assert is_valid is True
            assert returned is user

            new_hash = _read_user_hash(user.id, test_settings)
            assert new_hash.startswith("$2b$05$"), (
                f"Expected cost=5, got hash prefix={new_hash[:7]!r}"
            )
            assert new_hash != old_hash

    def test_no_rehash_when_stored_hash_meets_target(self, test_settings, monkeypatch):
        """If the stored hash already meets the configured cost,
        the verify does not touch the on-disk record."""
        with monkeypatch.context() as m:
            m.setattr(test_settings, "bcrypt_rounds", 4)
            storage = UserStorage()

            user = User(
                email="vapt038-norehash@example.com",
                hashed_password=hash_password("Vapt038P@ss1!"),
                scopes=["read"],
            )
            asyncio.get_event_loop().run_until_complete(storage.create_user(user))

            old_hash = _read_user_hash(user.id, test_settings)
            assert old_hash.startswith("$2b$04$")

            is_valid, returned = asyncio.get_event_loop().run_until_complete(
                storage.verify_and_maybe_rehash_password(user, "Vapt038P@ss1!")
            )
            assert is_valid is True
            assert returned is user

            # The on-disk hash must be unchanged (no extra bcrypt round).
            assert _read_user_hash(user.id, test_settings) == old_hash

    def test_wrong_password_returns_none_and_does_not_touch_hash(self, test_settings, monkeypatch):
        """A failed verify never re-hashes (avoids amplifying CPU
        cost on brute-force attempts and prevents the timing
        side-channel of a fail/rehash-vs-fail/no-rehash path)."""
        with monkeypatch.context() as m:
            m.setattr(test_settings, "bcrypt_rounds", 4)
            storage = UserStorage()

            user = User(
                email="vapt038-wrong@example.com",
                hashed_password=hash_password("Vapt038P@ss1!"),
                scopes=["read"],
            )
            asyncio.get_event_loop().run_until_complete(storage.create_user(user))

            old_hash = _read_user_hash(user.id, test_settings)

            is_valid, returned = asyncio.get_event_loop().run_until_complete(
                storage.verify_and_maybe_rehash_password(user, "WrongPassword1!")
            )
            assert is_valid is False
            assert returned is None
            assert _read_user_hash(user.id, test_settings) == old_hash

    def test_rehash_picks_up_runtime_setting_change(self, test_settings, monkeypatch):
        """The cost-factor source-of-truth is the live
        ``Settings`` object — operators can bump it at runtime
        via env-var-driven restart and the next login will
        migrate the stored hash automatically."""
        with monkeypatch.context() as m:
            # First the cost is 4 — all new hashes go in at 4.
            m.setattr(test_settings, "bcrypt_rounds", 4)
            storage = UserStorage()
            user = User(
                email="vapt038-runtime@example.com",
                hashed_password=hash_password("Vapt038P@ss1!"),
                scopes=["read"],
            )
            asyncio.get_event_loop().run_until_complete(storage.create_user(user))

            assert _read_user_hash(user.id, test_settings).startswith("$2b$04$")

            # Operator raises the cost factor at runtime (e.g. via
            # config reload — out of scope here, just the setattr).
            m.setattr(test_settings, "bcrypt_rounds", 6)

            asyncio.get_event_loop().run_until_complete(
                storage.verify_and_maybe_rehash_password(user, "Vapt038P@ss1!")
            )
            assert _read_user_hash(user.id, test_settings).startswith("$2b$06$")

    def test_new_hash_actually_verifies(self, test_settings, monkeypatch):
        """After a re-hash, the new on-disk hash still authenticates
        the same plaintext (no accidental hash corruption)."""
        from authglow.services.password import verify_password

        with monkeypatch.context() as m:
            m.setattr(test_settings, "bcrypt_rounds", 4)
            storage = UserStorage()
            user = User(
                email="vapt038-verify-after@example.com",
                hashed_password=hash_password("Vapt038P@ss1!"),
                scopes=["read"],
            )
            asyncio.get_event_loop().run_until_complete(storage.create_user(user))

            m.setattr(test_settings, "bcrypt_rounds", 5)
            asyncio.get_event_loop().run_until_complete(
                storage.verify_and_maybe_rehash_password(user, "Vapt038P@ss1!")
            )

            fresh = _read_user_hash(user.id, test_settings)
            assert verify_password("Vapt038P@ss1!", fresh) is True
            assert verify_password("WrongPassword1!", fresh) is False
