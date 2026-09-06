"""File-system-backed repository for the User domain.

On-disk layout (relative to ``settings.storage_path``):

* ``<storage>/<user_id>.json`` — one file per user. All PII fields
  (email, first_name, last_name, phone, avatar_url) are encrypted
  at rest with AES-256-GCM via
  :func:`authglow.core.crypto.encrypt_field` /
  :func:`decrypt_field`. The encryption key is derived from
  ``Settings.secret_key``.

The pre-refactor ``UserStorage`` (in ``services/storage.py``) owned
all of this inline — the file I/O, the encryption / decryption,
and the PII fields knowledge. The ``UserStorage`` service now
delegates to this repository for the file I/O and the PII
encryption (both of which are storage-backend-specific concerns,
not business logic).

Cross-entity atomicity (e.g. ``create_user`` writes the user
file + updates the email index under the same ``named_lock``)
is delegated to the service layer. The repository is single-shot
and lock-free at the ``BaseFileRepository`` level.

Service-level cross-entity methods (kept in ``UserStorage``):

* ``create_user`` (email_index + user file)
* ``update_email`` (user file + email_index)
* ``delete_user`` (email_index + user file)

Pure-repository methods (moved here):

* ``get_by_id`` / ``get_by_email`` / ``exists_by_email``
* ``create`` / ``update`` / ``delete``
* ``list`` / ``count`` / ``get_stats``
* ``update_last_login`` / ``record_failed_login`` /
  ``reset_failed_login_attempts`` / ``clear_failed_login_attempts`` /
  ``is_account_locked`` / ``set_password``

The ``update_*`` and lockout methods are exposed as repository
methods (rather than only via the service) because they only
touch a single user file — no cross-entity coordination
required. The service layer can still wrap them in
``named_lock(f"user:{user_id}")`` for in-process safety.
"""

from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from authglow.core.crypto import decrypt_field, encrypt_field
from authglow.core.datetime import utcnow
from authglow.models.user import User
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import UserRepository

if TYPE_CHECKING:
    from authglow.core.config import Settings


# Fields encrypted at rest with AES-256-GCM. Other fields
# (id, created_at, scopes, is_active, etc.) are stored in
# plaintext — they are not PII.
_PII_FIELDS = ("email", "first_name", "last_name", "phone", "avatar_url")


class FileUserRepository(BaseFileRepository, UserRepository):
    """File-backed implementation of :class:`UserRepository`.

    Stores each user as a JSON file at ``<storage>/<user_id>.json``.
    PII fields are encrypted at rest; non-PII fields are stored
    in plaintext. The repository handles the encrypt / decrypt
    round-trip transparently — callers see Pydantic ``User``
    instances with plaintext PII.

    The repository is single-shot: ``create`` / ``update`` /
    ``delete`` / ``record_failed_login`` / etc. do not acquire
    locks themselves. The service layer is responsible for
    ``named_lock`` semantics and cross-entity coordination.
    """

    _subdir = ""  # users live at the storage root, not in a subdir
    _filename_pattern = "{user_id}.json"

    def __init__(self, settings: Optional["Settings"] = None) -> None:
        # BaseFileRepository requires a non-empty _subdir; we pass
        # "." and collapse back to the root (matches the email-index
        # and federated-identity index patterns).
        super().__init__(settings=settings, subdir=".")
        self._storage_path = self._storage_root

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def _user_path(self, user_id: str) -> str:
        """Return the on-disk path for a user file.

        Pre-refactor layout: ``<storage>/<user_id>.json`` (flat
        directory of user files at the storage root).
        """
        return f"{self._storage_root}/{user_id}.json"

    # ------------------------------------------------------------------
    # PII encryption helpers (responsibility of the File backend)
    # ------------------------------------------------------------------

    @staticmethod
    def _encrypt_user_for_storage(user: User) -> Dict[str, Any]:
        """Encrypt the PII fields of a User for at-rest storage."""
        data = user.model_dump(mode="json")
        for field in _PII_FIELDS:
            if data.get(field):
                data[field] = encrypt_field(data[field])
        return data

    @staticmethod
    def _decrypt_user_from_storage(data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt the PII fields of a User dict read from disk."""
        for field in _PII_FIELDS:
            if data.get(field):
                data[field] = decrypt_field(data[field])
        return data

    # ------------------------------------------------------------------
    # I/O helpers
    # ------------------------------------------------------------------

    async def _read_user(self, user_id: str) -> Optional[User]:
        """Read and decrypt a user from disk. Returns ``None``
        on missing / corrupt file."""
        data = await self._read_json(self._user_path(user_id))
        if not isinstance(data, dict):
            return None
        try:
            return User(**self._decrypt_user_from_storage(data))
        except Exception:
            return None

    async def _write_user_raw(self, user: User) -> None:
        """Encrypt and write a user. Caller is responsible for
        ``updated_at`` and any lock semantics."""
        user.updated_at = utcnow()
        user_data = self._encrypt_user_for_storage(user)
        await self._write_json(self._user_path(user.id), user_data)

    # ------------------------------------------------------------------
    # Protocol: create
    # ------------------------------------------------------------------

    async def create(self, user: User) -> None:
        """Persist a new user. Raises :class:`ValueError` if a
        user with the same ``id`` already exists.

        Note: cross-entity uniqueness (email index, federated
        identity) is the service layer's responsibility —
        ``UserStorage.create_user`` checks the email index under
        ``named_lock("email_index")`` before calling this method.
        """
        existing = await self._read_user(user.id)
        if existing is not None:
            raise ValueError(f"User with id {user.id} already exists")
        await self._write_user_raw(user)

    # ------------------------------------------------------------------
    # Protocol: get_by_id
    # ------------------------------------------------------------------

    async def get_by_id(self, user_id: str) -> Optional[User]:
        """Return the user with the given ID, or ``None``."""
        return await self._read_user(user_id)

    # ------------------------------------------------------------------
    # Protocol: get_by_email / exists_by_email
    # ------------------------------------------------------------------

    async def get_by_email(self, email: str) -> Optional[User]:
        """Return the user with the given (lower-cased) email, or ``None``.

        Implementation note: the File backend keeps email -> user_id
        mappings in a separate ``EmailIndexRepository``. The
        service layer is responsible for invoking the email
        index first and then calling ``get_by_id`` — this method
        is here for protocol completeness but the service
        orchestrates the two-step lookup for O(1) email access.
        """
        raise NotImplementedError(
            "FileUserRepository.get_by_email is a two-step lookup "
            "that requires EmailIndexRepository. Use "
            "UserStorage.get_user_by_email which orchestrates the "
            "two calls under a single lock."
        )

    async def exists_by_email(self, email: str) -> bool:
        """Cheap existence check that does not return the full record.

        See ``get_by_email`` for the implementation rationale:
        the service layer is the one that knows about the
        email index. This implementation cannot satisfy the
        contract on its own.
        """
        raise NotImplementedError(
            "FileUserRepository.exists_by_email requires "
            "EmailIndexRepository coordination. See get_by_email."
        )

    # ------------------------------------------------------------------
    # Protocol: update
    # ------------------------------------------------------------------

    async def update(self, user: User) -> None:
        """Persist changes to an existing user. Raises
        :class:`EntityNotFoundError` if the user no longer exists.

        Sets ``user.updated_at`` to ``utcnow()`` as a side effect.
        """
        from authglow.repositories.exceptions import EntityNotFoundError

        existing = await self._read_user(user.id)
        if existing is None:
            raise EntityNotFoundError("user", user.id)
        await self._write_user_raw(user)

    # ------------------------------------------------------------------
    # Protocol: delete
    # ------------------------------------------------------------------

    async def delete(self, user_id: str) -> bool:
        """Hard-delete the user. Returns ``True`` on success,
        ``False`` if the user did not exist."""
        return await self._delete(self._user_path(user_id))

    # ------------------------------------------------------------------
    # Protocol: list / count / get_stats
    # ------------------------------------------------------------------

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
        created_after: Optional[datetime] = None,
        created_before: Optional[datetime] = None,
        last_login_after: Optional[datetime] = None,
        last_login_before: Optional[datetime] = None,
    ) -> Tuple[List[User], int]:
        """Return a paginated, filtered slice of users.

        The File backend reads the email index (a flat dict of
        ``hash -> user_id``) and then ``get_by_id`` for each id.
        Filtering is done in Python; for non-File backends the
        repository is expected to push the filters into the
        database.

        The second element of the tuple is the total count of
        users matching the filters (ignoring ``limit`` /
        ``offset``) — this is the existing pre-refactor
        behaviour, where pagination metadata is computed by the
        repository.
        """
        # Discover users by reading every *.json file at the
        # storage root. The pre-refactor service used the
        # email_index to enumerate user_ids; the new pattern
        # globs the directory directly so the repository does
        # not depend on the email index (the service still
        # uses the email index for O(1) email lookups).
        pattern = f"{self._storage_root}/*.json"
        files = await self._glob(pattern)
        filtered: List[User] = []
        for file_path in files:
            data = await self._read_json(file_path)
            if not isinstance(data, dict):
                continue
            try:
                user = User(**self._decrypt_user_from_storage(data))
            except Exception:
                continue
            if not self._matches_filters(
                user,
                search=search,
                is_active=is_active,
                mfa_enabled=mfa_enabled,
                email_verified=email_verified,
                scopes=scopes,
                created_after=created_after,
                created_before=created_before,
                last_login_after=last_login_after,
                last_login_before=last_login_before,
            ):
                continue
            filtered.append(user)
        total = len(filtered)
        return filtered[offset : offset + limit], total

    @staticmethod
    def _matches_filters(
        user: User,
        *,
        search: Optional[str],
        is_active: Optional[bool],
        mfa_enabled: Optional[bool],
        email_verified: Optional[bool],
        scopes: Optional[List[str]],
        created_after: Optional[datetime],
        created_before: Optional[datetime],
        last_login_after: Optional[datetime],
        last_login_before: Optional[datetime],
    ) -> bool:
        """Apply the pre-refactor service-side filters to a User
        (extracted verbatim from ``UserStorage.list_users``)."""
        if search:
            sl = search.lower()
            if not (
                sl in user.email.lower()
                or (user.first_name and sl in user.first_name.lower())
                or (user.last_name and sl in user.last_name.lower())
            ):
                return False

        if is_active is not None and user.is_active != is_active:
            return False
        if mfa_enabled is not None and user.mfa_enabled != mfa_enabled:
            return False
        if email_verified is not None and user.email_verified != email_verified:
            return False
        if scopes is not None and not all(s in user.scopes for s in scopes):
            return False
        if created_after is not None and user.created_at < created_after:
            return False
        if created_before is not None and user.created_at > created_before:
            return False
        if last_login_after is not None and (
            user.last_login is None or user.last_login < last_login_after
        ):
            return False
        if last_login_before is not None and (
            user.last_login is None or user.last_login > last_login_before
        ):
            return False
        return True

    async def count(self) -> int:
        """Return the total number of users.

        The File backend enumerates the storage directory; the
        service layer typically prefers ``EmailIndexRepository.all``
        for O(1) counts (the two stay in sync because the
        service is the only writer).
        """
        pattern = f"{self._storage_root}/*.json"
        files = await self._glob(pattern)
        return len(files)

    async def get_stats(self) -> Dict[str, int]:
        """Compute aggregate statistics in a single repository-level
        call. The pre-refactor implementation already aggregated
        in Python by walking the email index; this repository
        walks the storage directory directly to keep the
        ``UserRepository`` self-contained.
        """
        from datetime import timedelta

        now = utcnow()
        today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
        week_start = today_start - timedelta(days=7)
        month_start = today_start - timedelta(days=30)

        total = active = mfa = new_today = new_week = new_month = 0
        pattern = f"{self._storage_root}/*.json"
        files = await self._glob(pattern)
        for file_path in files:
            data = await self._read_json(file_path)
            if not isinstance(data, dict):
                continue
            try:
                user = User(**self._decrypt_user_from_storage(data))
            except Exception:
                continue
            total += 1
            if user.is_active:
                active += 1
            if user.mfa_enabled and user.mfa_verified:
                mfa += 1
            if user.created_at >= today_start:
                new_today += 1
            if user.created_at >= week_start:
                new_week += 1
            if user.created_at >= month_start:
                new_month += 1

        return {
            "total": total,
            "active": active,
            "inactive": total - active,
            "mfa": mfa,
            "new_today": new_today,
            "new_week": new_week,
            "new_month": new_month,
        }

    # ------------------------------------------------------------------
    # Convenience: lockout / last-login / password setters
    # (single-file mutations; no cross-entity coordination needed)
    # ------------------------------------------------------------------

    async def update_last_login(self, user_id: str) -> None:
        """Update user's last login timestamp and increment login counter."""
        user = await self._read_user(user_id)
        if user is None:
            return
        user.last_login = utcnow()
        user.login_count = user.login_count + 1
        await self._write_user_raw(user)

    async def record_failed_login(
        self,
        user_id: str,
        max_attempts: int = 5,
        lockout_duration_minutes: int = 15,
    ) -> Optional[datetime]:
        """Record a failed login attempt. Returns the new
        ``locked_until`` if the account is now locked, else ``None``."""
        from datetime import timedelta

        user = await self._read_user(user_id)
        if user is None:
            return None
        user.failed_login_attempts += 1
        user.failed_login_count = user.failed_login_count + 1
        if user.failed_login_attempts >= max_attempts:
            user.locked_until = utcnow() + timedelta(minutes=lockout_duration_minutes)
        await self._write_user_raw(user)
        return user.locked_until

    async def reset_failed_login_attempts(self, user_id: str) -> None:
        """Reset failed login attempts and clear lockout."""
        user = await self._read_user(user_id)
        if user is None:
            return
        user.failed_login_attempts = 0
        user.locked_until = None
        await self._write_user_raw(user)

    async def clear_failed_login_attempts(self, user_id: str) -> None:
        """Zero out ``failed_login_attempts`` without clearing lockout."""
        user = await self._read_user(user_id)
        if user is None:
            return
        user.failed_login_attempts = 0
        await self._write_user_raw(user)

    async def is_account_locked(self, user_id: str) -> bool:
        """Check if the account is currently locked. Side effect:
        if the lockout has expired, clears the lock state and
        resets ``failed_login_attempts``."""
        user = await self._read_user(user_id)
        if user is None or not user.locked_until:
            return False
        if utcnow() >= user.locked_until:
            user.locked_until = None
            user.failed_login_attempts = 0
            await self._write_user_raw(user)
            return False
        return True

    async def set_password(
        self,
        user_id: str,
        hashed_password: str,
        require_change: bool = False,
    ) -> Optional[User]:
        """Set a new password for a user. Returns the updated
        user, or ``None`` if the user does not exist."""
        user = await self._read_user(user_id)
        if user is None:
            return None
        user.hashed_password = hashed_password
        user.password_expired = require_change
        user.password_changed_at = utcnow()
        await self._write_user_raw(user)
        return user
