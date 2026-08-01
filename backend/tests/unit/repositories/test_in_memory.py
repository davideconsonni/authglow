"""In-memory smoke-test for the Repository pattern.

This module defines **trivial in-memory** implementations of a
handful of repository Protocols, then exercises the
``UserService`` facade against them. The point is to prove
the Repository pattern actually works: the service layer
calls only Protocol methods, and any impl that satisfies
the Protocol can be substituted in.

Why this matters
----------------

Without an in-memory impl, every service test spins up the
full File stack (``fsspec`` + ``AsyncFileSystem`` + per-test
``tmp_path`` + keyring + PII encryption). The File
implementation is heavy, and bugs that span the
service↔repo boundary (e.g. forgetting to call
``super().update()`` after a partial mutation) get hidden
behind the File layer's noise. An in-memory impl strips all
that away and lets the test assert on the service's
behaviour directly.

If you add a Sql / Firestore / S3 backend in the future, the
pattern is: write the new impl + add it to
``tests/unit/repositories/test_in_memory.py``'s conformance
check. The test should pass without any service changes.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

import pytest

from authglow.core.config import get_settings
from authglow.core.crypto import hash_index_key
from authglow.models.user import User
from authglow.services.user import UserService

# ---------------------------------------------------------------------------
# In-memory implementations of the 3 repositories the UserService depends on
# ---------------------------------------------------------------------------


class InMemoryUserRepository:
    """In-memory implementation of :class:`UserRepository`.

    Stores users in a plain dict keyed by ``user_id``. The
    public surface (method signatures + return types) is a
    strict subset of :class:`FileUserRepository` — enough to
    satisfy the :class:`UserRepository` Protocol for
    non-encrypted / non-FederatedIdentity tests.

    Note: PII encryption is NOT simulated here (the in-memory
    store holds plaintext). The point of the smoke test is
    to verify the service↔repo protocol boundary, not the
    PII-encryption behaviour (that's covered by
    ``tests/unit/repositories/file/test_user.py``).
    """

    def __init__(self) -> None:
        self._users: Dict[str, User] = {}

    async def create(self, user: User) -> None:
        if user.id in self._users:
            raise ValueError(f"User with id {user.id} already exists")
        self._users[user.id] = user

    async def get_by_id(self, user_id: str) -> Optional[User]:
        return self._users.get(user_id)

    async def update(self, user: User) -> None:
        if user.id not in self._users:
            from authglow.repositories.exceptions import (
                EntityNotFoundError,
            )

            raise EntityNotFoundError("user", user.id)
        self._users[user.id] = user

    async def delete(self, user_id: str) -> bool:
        return self._users.pop(user_id, None) is not None

    async def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
        mfa_enabled: Optional[bool] = None,
        email_verified: Optional[bool] = None,
        scopes: Optional[List[str]] = None,
        created_after: Optional[Any] = None,
        created_before: Optional[Any] = None,
        last_login_after: Optional[Any] = None,
        last_login_before: Optional[Any] = None,
    ) -> tuple[List[User], int]:
        filtered = list(self._users.values())
        if search:
            sl = search.lower()
            filtered = [
                u
                for u in filtered
                if sl in u.email.lower()
                or (u.first_name and sl in u.first_name.lower())
                or (u.last_name and sl in u.last_name.lower())
            ]
        if is_active is not None:
            filtered = [u for u in filtered if u.is_active == is_active]
        if mfa_enabled is not None:
            filtered = [u for u in filtered if u.mfa_enabled == mfa_enabled]
        if email_verified is not None:
            filtered = [
                u for u in filtered if u.email_verified == email_verified
            ]
        if scopes is not None:
            filtered = [u for u in filtered if all(s in u.scopes for s in scopes)]
        total = len(filtered)
        return filtered[offset : offset + limit], total

    async def count(self) -> int:
        return len(self._users)

    async def get_stats(self) -> Dict[str, int]:
        total = len(self._users)
        active = sum(1 for u in self._users.values() if u.is_active)
        mfa = sum(
            1
            for u in self._users.values()
            if u.mfa_enabled and u.mfa_verified
        )
        return {
            "total": total,
            "active": active,
            "inactive": total - active,
            "mfa": mfa,
            "new_today": 0,
            "new_week": 0,
            "new_month": 0,
        }

    # Convenience methods required by UserService
    async def get_by_email(self, email: str) -> Optional[User]:
        return None  # in-memory impl does not maintain the index

    async def exists_by_email(self, email: str) -> bool:
        return False

    async def update_last_login(self, user_id: str) -> None:
        pass

    async def record_failed_login(
        self, user_id: str, max_attempts: int = 5,
        lockout_duration_minutes: int = 15
    ) -> Optional[Any]:
        return None

    async def reset_failed_login_attempts(self, user_id: str) -> None:
        pass

    async def clear_failed_login_attempts(self, user_id: str) -> None:
        pass

    async def is_account_locked(self, user_id: str) -> bool:
        return False

    async def set_password(
        self, user_id: str, hashed_password: str, require_change: bool = False
    ) -> Optional[User]:
        return None


class InMemoryEmailIndexRepository:
    """In-memory implementation of :class:`EmailIndexRepository`."""

    def __init__(self) -> None:
        self._index: Dict[str, str] = {}  # hash(email) -> user_id

    async def lookup(self, email: str) -> Optional[str]:
        return self._index.get(hash_index_key(email))

    async def insert(self, email: str, user_id: str) -> None:
        self._index[hash_index_key(email)] = user_id

    async def remove(self, email: str) -> None:
        self._index.pop(hash_index_key(email), None)

    async def all(self) -> Dict[str, str]:
        return dict(self._index)


class InMemoryFederatedIdentityRepository:
    """In-memory implementation of :class:`FederatedIdentityRepository`."""

    def __init__(self) -> None:
        self._links: Dict[str, str] = {}  # "provider|external" -> user_id

    async def lookup(
        self, provider_id: str, external_id: str
    ) -> Optional[str]:
        return self._links.get(f"{provider_id}|{external_id}")

    async def link(
        self, user_id: str, provider_id: str, external_id: str
    ) -> None:
        self._links[f"{provider_id}|{external_id}"] = user_id

    async def unlink(self, provider_id: str, external_id: str) -> None:
        self._links.pop(f"{provider_id}|{external_id}", None)


# ---------------------------------------------------------------------------
# Smoke test: UserService against the in-memory impls
# ---------------------------------------------------------------------------


class TestUserServiceWithInMemoryRepositories:
    """The UserService facade MUST work against any impl that
    satisfies the Protocol contracts. This test asserts the
    cross-entity methods (create_user / update_email /
    delete_user / get_by_external_id) work end-to-end with
    the InMemory impls — no File stack involved.
    """

    @pytest.fixture
    def user_repo(self) -> InMemoryUserRepository:
        return InMemoryUserRepository()

    @pytest.fixture
    def email_index_repo(self) -> InMemoryEmailIndexRepository:
        return InMemoryEmailIndexRepository()

    @pytest.fixture
    def federated_repo(self) -> InMemoryFederatedIdentityRepository:
        return InMemoryFederatedIdentityRepository()

    @pytest.fixture
    def service(
        self,
        user_repo: InMemoryUserRepository,
        email_index_repo: InMemoryEmailIndexRepository,
        federated_repo: InMemoryFederatedIdentityRepository,
    ) -> UserService:
        # Build a UserService that bypasses the fsspec /
        # AsyncFileSystem / Settings._keys_dir dance: we
        # inject the in-memory repos directly and stub the
        # fsspec-derived attributes the service expects.
        svc = UserService.__new__(UserService)
        svc._user_repo = user_repo
        svc._email_index_repo = email_index_repo
        svc._federated_identity_repo = federated_repo
        svc.settings = get_settings()
        # UserService._lock is a named_lock() instance used for
        # in-process safety; the in-memory impl is single-
        # threaded, so we use a no-op async context manager.
        from contextlib import asynccontextmanager

        @asynccontextmanager
        async def _noop_lock(name: str):
            yield

        svc._lock = lambda name: _noop_lock(name)
        # ``_afs`` is only used by get_user_by_email's
        # timing-leak padding; we leave it unset because the
        # in-memory test path never exercises the
        # ``timing_leak_protection`` branch (the test_settings
        # default has it enabled, but the noop branch is
        # only reached when the email index returns None).
        return svc

    async def test_create_user_cross_entity(
        self,
        service: UserService,
        user_repo: InMemoryUserRepository,
        email_index_repo: InMemoryEmailIndexRepository,
    ):
        user = User(
            id="smoke-1",
            email="smoke@example.com",
            hashed_password="$2b$hashed",
            is_active=True,
        )
        await service.create_user(user)
        # User file is written
        assert await user_repo.get_by_id("smoke-1") is not None
        # Email index is updated
        assert (
            await email_index_repo.lookup("smoke@example.com") == "smoke-1"
        )

    async def test_update_user_can_reuse_outer_user_lock(
        self,
        service: UserService,
        user_repo: InMemoryUserRepository,
    ):
        """Profile operations must not deadlock on the per-user lock."""
        from authglow.core.concurrency import named_lock

        user = User(
            id="locked-update-1",
            email="locked-update@example.com",
            hashed_password="$2b$hashed",
            is_active=True,
        )
        await user_repo.create(user)
        service._lock = named_lock()

        async with service._lock(f"user:{user.id}"):
            await asyncio.wait_for(service.update_user(user, acquire_lock=False), timeout=0.1)

        assert await user_repo.get_by_id(user.id) is user

    async def test_create_user_duplicate_email_raises(
        self, service: UserService, user_repo: InMemoryUserRepository
    ):
        user_a = User(
            id="smoke-2a", email="dup@example.com", hashed_password="x"
        )
        user_b = User(
            id="smoke-2b", email="dup@example.com", hashed_password="x"
        )
        await service.create_user(user_a)
        with pytest.raises(ValueError, match="already exists"):
            await service.create_user(user_b)

    async def test_update_email_cross_entity(
        self,
        service: UserService,
        user_repo: InMemoryUserRepository,
        email_index_repo: InMemoryEmailIndexRepository,
    ):
        user = User(
            id="smoke-3",
            email="old@example.com",
            hashed_password="x",
            is_active=True,
        )
        await service.create_user(user)
        result = await service.update_email("smoke-3", "new@example.com")
        assert result is not None
        assert result.email == "new@example.com"
        # Old mapping is removed, new mapping points to smoke-3
        assert await email_index_repo.lookup("old@example.com") is None
        assert await email_index_repo.lookup("new@example.com") == "smoke-3"

    async def test_delete_user_cross_entity(
        self,
        service: UserService,
        user_repo: InMemoryUserRepository,
        email_index_repo: InMemoryEmailIndexRepository,
    ):
        user = User(
            id="smoke-4",
            email="del@example.com",
            hashed_password="x",
            is_active=True,
        )
        await service.create_user(user)
        deleted = await service.delete_user("smoke-4")
        assert deleted is True
        assert await user_repo.get_by_id("smoke-4") is None
        assert await email_index_repo.lookup("del@example.com") is None

    async def test_get_by_external_id(
        self,
        service: UserService,
        user_repo: InMemoryUserRepository,
        federated_repo: InMemoryFederatedIdentityRepository,
    ):
        user = User(
            id="smoke-5",
            email="fed@example.com",
            hashed_password="x",
            is_active=True,
        )
        await user_repo.create(user)
        await federated_repo.link("smoke-5", "google", "ext-123")
        result = await service.get_by_external_id("google", "ext-123")
        assert result is not None
        assert result.id == "smoke-5"

    async def test_link_federated_identity(
        self,
        service: UserService,
        federated_repo: InMemoryFederatedIdentityRepository,
    ):
        await service.link_federated_identity("smoke-6", "github", "gh-42")
        assert (
            await federated_repo.lookup("github", "gh-42") == "smoke-6"
        )

    async def test_get_user_by_email_uses_index(
        self,
        service: UserService,
        user_repo: InMemoryUserRepository,
        email_index_repo: InMemoryEmailIndexRepository,
    ):
        user = User(
            id="smoke-7",
            email="lookup@example.com",
            hashed_password="x",
            is_active=True,
        )
        await user_repo.create(user)
        await email_index_repo.insert("lookup@example.com", "smoke-7")
        result = await service.get_user_by_email("lookup@example.com")
        assert result is not None
        assert result.id == "smoke-7"
