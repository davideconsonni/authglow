"""User service — thin facade over the User domain repositories.

Persistence is delegated to three dedicated repositories (Fase 17):

* :class:`FileUserRepository` (Fase 17c) — user CRUD + lockout
  + last-login + password setters + list/stats. Handles PII
  encryption at rest.
* :class:`FileEmailIndexRepository` (Fase 17a) — secondary
  index mapping ``hash(email)`` to ``user_id``.
* :class:`FileFederatedIdentityRepository` (Fase 17b) — secondary
  index mapping ``(provider_id, external_id)`` to ``user_id``.

The service is a thin facade for cross-entity operations
(``create_user``, ``update_email``, ``delete_user``,
``link_federated_identity``) that need a single ``named_lock``
across multiple repositories. Single-file mutations delegate
to the repository which is itself lock-free at the
``BaseFileRepository`` level.

The ``UserService`` class is the canonical name (Fase 18). The
legacy ``UserStorage`` alias lives in ``services/storage.py``
as a deprecation shim for the 100+ call sites in ``api/`` that
still import the old name. Fase 21 will remove the alias and
update the call sites to inject the repositories directly.

All PII fields (email, name, phone, avatar_url) are encrypted
at rest with AES-256-GCM (handled by the FileUserRepository).
The email index uses HMAC-SHA256 keys — plaintext email is
never stored on disk.
"""

import asyncio
import os
import secrets
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

import fsspec

from authglow.core.async_io import AsyncFileSystem
from authglow.core.cache import user_by_id_cache, user_cache
from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.models.audit_events import AuditEventType
from authglow.models.audit_metadata import AccountLockMetadata, ConcurrentSessionMetadata
from authglow.models.user import User
from authglow.services.audit import AuditService

if TYPE_CHECKING:
    from authglow.repositories.protocols import (
        EmailIndexRepository,
        FederatedIdentityRepository,
        UserRepository,
    )


class UserService:
    """Thin facade for user persistence + cross-entity coordination.

    The service is a ``UserRepository`` thin wrapper for
    in-process-safety locks (``named_lock``), the user cache,
    and the email-index / federated-identity coordination that
    requires a multi-step transaction.
    """

    def __init__(
        self,
        user_repository: Optional["UserRepository"] = None,
        email_index_repository: Optional["EmailIndexRepository"] = None,
        federated_identity_repository: Optional["FederatedIdentityRepository"] = None,
    ):
        """Initialise the service.

        All three repositories are optional; when ``None`` a
        fresh instance is created via the FastAPI factory.
        Tests can pass a stub or an in-memory implementation
        directly.
        """
        self.settings = get_settings()
        self.storage_path = self.settings.storage_path
        self.storage_options = self.settings.get_storage_options()

        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(self.settings.storage_backend, **self.storage_options)

        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()
        self.audit_service = AuditService()

        if user_repository is None:
            from authglow.repositories.dependencies import get_user_repository

            self._user_repo: "UserRepository" = get_user_repository(settings=self.settings)
        else:
            self._user_repo = user_repository

        if email_index_repository is None:
            from authglow.repositories.dependencies import (
                get_email_index_repository,
            )

            self._email_index_repo: "EmailIndexRepository" = get_email_index_repository(
                settings=self.settings
            )
        else:
            self._email_index_repo = email_index_repository

        if federated_identity_repository is None:
            from authglow.repositories.dependencies import (
                get_federated_identity_repository,
            )

            self._federated_identity_repo: "FederatedIdentityRepository" = (
                get_federated_identity_repository(settings=self.settings)
            )
        else:
            self._federated_identity_repo = federated_identity_repository

    def _user_cache_key(self, user_id: str) -> str:
        """Namespace user-id cache entries by the backing storage."""
        return f"{getattr(self, 'storage_path', '')}:{user_id}"

    def _email_cache_key(self, email: str) -> str:
        """Namespace email cache entries by the backing storage."""
        return f"{getattr(self, 'storage_path', '')}:{email.lower()}"

    # ------------------------------------------------------------------
    # Cross-entity / lock-coordinated public API
    # ------------------------------------------------------------------

    async def create_user(self, user: User) -> User:
        """Create a new user (email index + user file, atomic)."""
        async with self._lock(f"user:{user.id}"), self._lock("email_index"):
            if await self._email_index_repo.lookup(user.email.lower()) is not None:
                raise ValueError(f"User with email {user.email} already exists")
            await self._user_repo.create(user)
            await self._email_index_repo.insert(user.email.lower(), user.id)

        from authglow.models.webhook_events import USER_CREATED
        from authglow.services.webhook_dispatcher import emit_webhook_event

        emit_webhook_event(USER_CREATED, {"user_id": user.id, "email": user.email})
        return user

    async def update_email(self, user_id: str, new_email: str) -> Optional[User]:
        """Update a user's email (user file + email index, atomic)."""
        async with self._lock(f"user:{user_id}"), self._lock("email_index"):
            user = await self._user_repo.get_by_id(user_id)
            if user is None:
                return None

            old_email = user.email.lower()
            new_email_lc = new_email.lower()

            if old_email == new_email_lc:
                user.email = new_email
                await self._user_repo.update(user)
                return user

            existing = await self._email_index_repo.lookup(new_email_lc)
            if existing is not None and existing != user_id:
                raise ValueError(f"User with email {new_email} already exists")

            await self._email_index_repo.remove(old_email)
            await self._email_index_repo.insert(new_email_lc, user_id)

            user.email = new_email
            await user_cache.delete(self._email_cache_key(old_email))
            await user_cache.delete(self._email_cache_key(new_email_lc))
            await user_by_id_cache.delete(self._user_cache_key(user_id))
            await self._user_repo.update(user)
            return user

    async def delete_user(self, user_id: str) -> bool:
        """Delete a user (email index + user file, atomic)."""
        async with self._lock(f"user:{user_id}"), self._lock("email_index"):
            user = await self._user_repo.get_by_id(user_id)
            if user is None:
                return False
            await self._email_index_repo.remove(user.email.lower())
            deleted = await self._user_repo.delete(user_id)
            if deleted:
                await user_cache.delete(self._email_cache_key(user.email))
                await user_by_id_cache.delete(self._user_cache_key(user_id))

        if deleted:
            from authglow.models.webhook_events import USER_DELETED
            from authglow.services.webhook_dispatcher import emit_webhook_event

            emit_webhook_event(USER_DELETED, {"user_id": user_id, "email": user.email})
        return deleted

    async def get_by_external_id(self, provider_id: str, external_id: str) -> Optional[User]:
        """Find a user by their federated identity
        (provider_id, external_id)."""
        user_id = await self._federated_identity_repo.lookup(provider_id, external_id)
        if not user_id:
            return None
        return await self._user_repo.get_by_id(user_id)

    async def link_federated_identity(
        self, user_id: str, provider_id: str, external_id: str
    ) -> None:
        """Link a federated (provider_id, external_id) pair to a
        local user."""
        async with self._lock("federated_identities"):
            await self._federated_identity_repo.link(user_id, provider_id, external_id)

    # ------------------------------------------------------------------
    # Public API delegating to UserRepository (lock-free or single-key lock)
    # ------------------------------------------------------------------

    async def get_user(self, user_id: str) -> Optional[User]:
        """Get user by ID with cross-request caching.

        Every authenticated request calls this through
        ``get_current_user``. The cache avoids a file-system read
        (JSON parse + PII decrypt + Pydantic validation) on every
        request for the same user within the TTL window.
        """
        cache_key = self._user_cache_key(user_id)
        cached: User | None = await user_by_id_cache.get(cache_key)
        if cached is not None:
            return cached

        user = await self._user_repo.get_by_id(user_id)
        if user is not None:
            await user_by_id_cache.set(cache_key, user)
        return user

    async def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email (O(1) via the email index).

        Includes the pre-refactor ``timing_leak_protection`` and
        ``user_cache`` semantics — these are service-layer
        concerns (caching + side-channel protection), not
        storage concerns.
        """
        key = email.lower()
        cache_key = self._email_cache_key(key)
        cached: User | None = await user_cache.get(cache_key)
        if cached is not None:
            return cached

        user_id = await self._email_index_repo.lookup(key)

        result = None
        if user_id:
            result = await self._user_repo.get_by_id(user_id)

        if self.settings.timing_leak_protection:
            if result is None:
                try:
                    # Read a non-existent padding file to match the
                    # I/O cost of a real read.
                    await self._afs.read_json(f"{self.storage_path}/__timing_padding.json")
                except Exception:
                    pass
            jitter_ms = secrets.randbelow(50)
            await asyncio.sleep(jitter_ms / 1000.0)

        if result is not None:
            await user_cache.set(cache_key, result)

        return result

    async def update_user(self, user: User, *, acquire_lock: bool = True) -> User:
        """Update an existing user, optionally reusing an outer user lock."""
        if acquire_lock:
            async with self._lock(f"user:{user.id}"):
                await self._user_repo.update(user)
        else:
            await self._user_repo.update(user)
        await user_cache.delete(self._email_cache_key(user.email))
        await user_by_id_cache.delete(self._user_cache_key(user.id))
        return user

    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
        mfa_enabled: Optional[bool] = None,
        email_verified: Optional[bool] = None,
        scopes: Optional[list[str]] = None,
        created_after: Optional[datetime] = None,
        created_before: Optional[datetime] = None,
        last_login_after: Optional[datetime] = None,
        last_login_before: Optional[datetime] = None,
    ) -> tuple[List[User], int]:
        """List users with optional server-side filtering and
        pagination. Delegates to ``UserRepository.list``."""
        return await self._user_repo.list(
            limit=limit,
            offset=offset,
            search=search,
            is_active=is_active,
            mfa_enabled=mfa_enabled,
            email_verified=email_verified,
            scopes=scopes,
            created_after=created_after,
            created_before=created_before,
            last_login_after=last_login_after,
            last_login_before=last_login_before,
        )

    async def count_users(self) -> int:
        """Count total number of users (uses the email index for
        O(1) count, matching the pre-refactor behaviour)."""
        return len(await self._email_index_repo.all())

    def _get_user_path(self, user_id: str) -> str:
        """Get the on-disk path for a user file. Retained as a
        back-compat shim for tests that introspect storage paths
        directly — the canonical path lives on
        :class:`FileUserRepository` (``self._user_repo._user_path``)."""
        return f"{self.storage_path}/{user_id}.json"

    async def get_user_stats(self) -> dict:
        """Compute aggregate user statistics (delegates to
        ``UserRepository.get_stats``)."""
        return await self._user_repo.get_stats()

    async def update_last_login(self, user_id: str) -> None:
        """Update user's last login timestamp and increment login counter."""
        async with self._lock(f"user:{user_id}"):
            await self._user_repo.update_last_login(user_id)

    async def record_failed_login(
        self,
        user_id: str,
        max_attempts: int = 5,
        lockout_duration_minutes: int = 15,
    ) -> Optional[datetime]:
        """Record a failed login attempt and lock account if
        threshold exceeded."""
        async with self._lock(f"user:{user_id}"):
            # Read user before to check if lockout will be triggered
            user = await self._user_repo.get_by_id(user_id)
            if user is None:
                return None

            # Check if this attempt will trigger lockout
            will_lock = user.failed_login_attempts + 1 >= 5

            locked_until = await self._user_repo.record_failed_login(
                user_id, max_attempts, lockout_duration_minutes
            )

            # Audit: account locked
            if will_lock and locked_until:
                await self.audit_service.log_event(
                    event_type=AuditEventType.ACCOUNT_LOCKED,
                    user_id=user_id,
                    email=user.email,
                    metadata=AccountLockMetadata(
                        lockout_reason="brute_force",
                        locked_until=locked_until,
                        failed_count=user.failed_login_attempts + 1,
                    ),
                    severity="critical",
                )

            return locked_until

    async def reset_failed_login_attempts(self, user_id: str) -> None:
        """Reset failed login attempts and clear lockout."""
        async with self._lock(f"user:{user_id}"):
            # Check if user was locked before resetting
            user = await self._user_repo.get_by_id(user_id)
            was_locked = user is not None and user.locked_until is not None

            await self._user_repo.reset_failed_login_attempts(user_id)

            # Audit: account unlocked
            if was_locked:
                await self.audit_service.log_event(
                    event_type=AuditEventType.ACCOUNT_UNLOCKED,
                    user_id=user_id,
                    email=user.email if user else None,
                    metadata=AccountLockMetadata(
                        lockout_reason="admin_reset",
                        locked_until=None,
                    ),
                    severity="info",
                )

    async def clear_failed_login_attempts(self, user_id: str) -> None:
        """Zero out failed_login_attempts without clearing lockout."""
        async with self._lock(f"user:{user_id}"):
            await self._user_repo.clear_failed_login_attempts(user_id)

    async def is_account_locked(self, user_id: str) -> bool:
        """Check if account is currently locked."""
        async with self._lock(f"user:{user_id}"):
            return await self._user_repo.is_account_locked(user_id)

    async def set_password(
        self,
        user_id: str,
        hashed_password: str,
        require_change: bool = False,
    ) -> Optional[User]:
        """Set a new password for a user.

        Invalidates BOTH caches (by-id and by-email). The login flow
        resolves users through ``get_user_by_email``, so a stale
        email-keyed entry would keep verifying credentials against the OLD
        hash (and report the OLD ``password_expired`` flag) until the TTL
        expires — an infinite forced-change loop.
        """
        async with self._lock(f"user:{user_id}"):
            result = await self._user_repo.set_password(user_id, hashed_password, require_change)
        if result is not None:
            await user_cache.delete(self._email_cache_key(result.email))
        await user_by_id_cache.delete(self._user_cache_key(user_id))
        return result

    async def verify_and_maybe_rehash_password(
        self, user: User, plain_password: str
    ) -> tuple[bool, Optional[User]]:
        """Verify a user's password and transparently re-hash if needed (VAPT-038).

        On a successful verify the stored hash is checked against
        the current ``bcrypt_rounds`` setting. If the on-disk
        cost is below the target, a fresh hash is generated and
        persisted via :meth:`set_password` (acquires the same
        per-user lock the login flow already held, so concurrent
        verifications for the same user cannot race the
        migration).

        Returns:
            ``(is_valid, user_or_None)``:

            * ``(True, user)`` when the password matches. ``user``
              is the in-memory object — its ``hashed_password``
              field is unchanged; the persisted file on disk is
              the one updated by :meth:`set_password`.
            * ``(False, None)`` on a mismatch. The caller is
              expected to route through the existing
              ``handle_failed_login`` / lockout machinery.

        The function never raises on a malformed
        ``user.hashed_password`` (treats it as a non-match) so
        login flows stay linear.
        """
        from authglow.services.password import verify_and_maybe_rehash_async

        is_valid, new_hash = await verify_and_maybe_rehash_async(
            plain_password, user.hashed_password
        )
        if not is_valid:
            return False, None
        if new_hash is not None:
            try:
                await self.set_password(user.id, new_hash)
            except Exception:
                # The login still succeeds — the fresh hash will
                # be re-attempted on the next successful verify.
                # The failure path is intentionally swallow-and-log
                # so an I/O blip on the user file does not turn
                # into a 500 on the login endpoint.
                import structlog

                structlog.get_logger("authglow.audit").warning(
                    "bcrypt_rehash_persist_failed",
                    user_id=user.id,
                )
        return True, user

    async def check_and_enforce_concurrent_sessions(
        self,
        user_id: str,
        client_id: str,
        request_ip: Optional[str] = None,
        request_ua: Optional[str] = None,
    ) -> None:
        """Check if user has exceeded max concurrent sessions and revoke oldest if needed.

        This is called after a successful login to enforce the max concurrent sessions limit.
        If the user has more active sessions than the limit, the oldest ones are revoked.
        """
        settings = self.settings
        max_sessions = getattr(settings, "max_concurrent_sessions", 5)

        # 0 = unlimited
        if max_sessions <= 0:
            return

        # Get all active refresh tokens for this user
        from authglow.services.refresh_token import RefreshTokenService

        refresh_token_service = RefreshTokenService()
        active_tokens = await refresh_token_service.list_all_tokens(
            active_only=True, user_id=user_id, limit=1000
        )

        # Filter tokens for this client if applicable
        client_tokens = [t for t in active_tokens[0] if t.client_id == client_id]

        if len(client_tokens) <= max_sessions:
            return

        # Sort by created_at (oldest first) and revoke excess tokens
        client_tokens.sort(key=lambda t: t.created_at)
        excess_count = len(client_tokens) - max_sessions
        tokens_to_revoke = client_tokens[:excess_count]

        # Revoke the oldest tokens
        for token in tokens_to_revoke:
            if token.token:
                await refresh_token_service.revoke_token(
                    token.token, reason="Concurrent session limit exceeded"
                )

        # Audit: concurrent session limit exceeded
        await self.audit_service.log_event(
            event_type=AuditEventType.CONCURRENT_SESSION_LIMIT_EXCEEDED,
            user_id=user_id,
            metadata=ConcurrentSessionMetadata(
                current_count=len(client_tokens) + 1,  # +1 for the new session
                limit=max_sessions,
                action_taken="revoked_oldest",
            ),
        )
