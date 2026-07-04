"""Repository Protocols — backend-agnostic contracts for storage I/O.

Each ``Protocol`` defines a single entity's storage operations in
domain terms (no paths, no locks, no JSON serialisation details). Any
backend — fsspec+JSON today, SQL/Firestore/KV tomorrow — can satisfy
the contract by providing a concrete class that implements the methods.

Design rules for the Protocols in this module:

* **Domain-shaped**: method names and parameters speak the language of
  the entity (``create(user)``, ``get_by_email(email)``), not the
  storage layer (``write_json_at_path``).
* **Async-only**: matches FastAPI's async event loop.
* **No I/O primitives leak**: callers never see ``fsspec`` paths,
  ``AsyncFileSystem`` instances, or raw dicts on the read path
  (the File implementations serialise Pydantic models themselves).
* **Pydantic round-trip**: every entity method takes and returns the
  Pydantic model class declared in ``authglow.models``. The concrete
  implementation handles the ``model_dump`` / ``model_validate``
  round-trip transparently.
* **Optimistic concurrency is an implementation detail**: when CAS is
  required (e.g. for cross-process safety on rotation or revocation),
  the concrete implementation raises ``ConcurrentWriteError`` from
  ``authglow.core.concurrency``. Services catch and retry.

Adding a new backend:

1. Create ``repositories/<backend>/<entity>.py`` with a concrete class
   implementing the Protocol.
2. Register the concrete class in ``repositories/dependencies.py``.

The services and routes do not need to change.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

from authglow.models.api_key import APIKey
from authglow.models.api_key_claim_policy import APIKeyClaimPolicy
from authglow.models.claim_policy import ClientClaimPolicy
from authglow.models.email_verification import EmailVerificationToken
from authglow.models.federation import ExternalIdpConfig
from authglow.models.mfa import BackupCodeAttempt, BackupCodes, TrustedDevice
from authglow.models.oauth_client import OAuth2Client
from authglow.models.oauth_consent import OAuth2Consent
from authglow.models.passkey import Passkey, PasskeyChallenge
from authglow.models.password_reset import PasswordResetToken
from authglow.models.rbac import Permission, Role, UserRole
from authglow.models.refresh_token import RefreshToken
from authglow.models.session import MFASession
from authglow.models.token import AuthorizationCode, DeviceAuthorization
from authglow.models.user import User
from authglow.models.user_profile import UserPreferences

# Type alias for the "dict-based" records that do not yet have a
# dedicated Pydantic model (login history, admin actions, security
# events). They are stored as plain dicts on disk today and exposed as
# dicts by the protocol — the File implementation can later be
# upgraded to typed models without breaking the contract.
Record = Dict[str, Any]


# ---------------------------------------------------------------------------
# User domain
# ---------------------------------------------------------------------------


@runtime_checkable
class UserRepository(Protocol):
    """Persistence operations for ``User`` entities.

    The repository is responsible for serialisation (including PII
    encryption at rest on the File backend) and for maintaining the
    ``email_index`` / ``federated_identities`` secondary indexes on
    implementations that need them. The EmailIndex and
    FederatedIdentity concerns are split out into dedicated
    Protocols so that alternative backends (e.g. SQL with a unique
    constraint) do not have to mimic the file-system "index file"
    pattern.
    """

    async def create(self, user: User) -> None:
        """Persist a new user. Raises ``EntityAlreadyExistsError`` on
        duplicate email/identity."""

    async def get_by_id(self, user_id: str) -> Optional[User]:
        """Return the user with the given ID, or ``None``."""

    async def get_by_email(self, email: str) -> Optional[User]:
        """Return the user with the given (lower-cased) email, or ``None``.

        Implementations are expected to be O(1) on SQL and KV
        backends; the File backend uses an HMAC-hashed index. Timing
        side-channel protection is the service layer's responsibility.
        """

    async def exists_by_email(self, email: str) -> bool:
        """Cheap existence check that does not return the full record."""

    async def update(self, user: User) -> None:
        """Persist changes to an existing user. Raises
        ``EntityNotFoundError`` if the user no longer exists."""

    async def delete(self, user_id: str) -> bool:
        """Hard-delete the user. Returns ``True`` on success, ``False``
        if the user did not exist."""

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
    ) -> tuple[List[User], int]:
        """Return a paginated, filtered slice of users.

        The second element of the tuple is the total count of users
        matching the filters (ignoring ``limit``/``offset``) so the
        service layer can build a paginator.
        """

    async def count(self) -> int:
        """Return the total number of users."""

    async def get_stats(self) -> Dict[str, int]:
        """Compute aggregate statistics in a single repository-level
        call: ``total``, ``active``, ``mfa``, ``new_today``,
        ``new_week``, ``new_month``. The service layer maps these to
        its public DTO. The default service-side implementation that
        calls ``list`` once and aggregates in Python is acceptable but
        less efficient than a backend-native aggregation."""

    async def update_last_login(self, user_id: str) -> None:
        """Update a user's ``last_login`` timestamp and increment
        the ``login_count``. No-op if the user is missing."""

    async def record_failed_login(
        self,
        user_id: str,
        max_attempts: int = 5,
        lockout_duration_minutes: int = 15,
    ) -> Optional[datetime]:
        """Record a failed login attempt. Returns the new
        ``locked_until`` timestamp if the account is now locked,
        else ``None``."""

    async def reset_failed_login_attempts(self, user_id: str) -> None:
        """Reset ``failed_login_attempts`` and clear ``locked_until``.
        No-op if the user is missing."""

    async def clear_failed_login_attempts(self, user_id: str) -> None:
        """Zero out ``failed_login_attempts`` without clearing
        ``locked_until`` (the lockout is preserved)."""

    async def is_account_locked(self, user_id: str) -> bool:
        """Return ``True`` if the account is currently locked.
        Side effect: if the lockout has expired, clears the
        lock state and resets ``failed_login_attempts``."""

    async def set_password(
        self,
        user_id: str,
        hashed_password: str,
        require_change: bool = False,
    ) -> Optional[User]:
        """Set a new password for a user. Returns the updated
        user, or ``None`` if the user does not exist."""


@runtime_checkable
class EmailIndexRepository(Protocol):
    """Secondary index mapping email -> user_id.

    On backends with native unique constraints (SQL), this Protocol
    can be implemented as a no-op that delegates to the parent
    UserRepository's unique index.
    """

    async def lookup(self, email: str) -> Optional[str]:
        """Return the user_id for *email*, or ``None``."""

    async def insert(self, email: str, user_id: str) -> None:
        """Insert a new email -> user_id mapping."""

    async def remove(self, email: str) -> None:
        """Remove the mapping for *email*. No-op if absent."""

    async def all(self) -> Dict[str, str]:
        """Return a snapshot of the entire index as a dict (debug +
        ``count``/``list`` fallback only)."""


@runtime_checkable
class FederatedIdentityRepository(Protocol):
    """Maps a (provider_id, external_id) pair to a local user_id.

    Used by OIDC federation flows to look up a local user account by
    their IdP subject claim. On SQL backends this is a table with a
    composite unique key.
    """

    async def lookup(self, provider_id: str, external_id: str) -> Optional[str]:
        """Return the user_id linked to the given (provider, external)
        pair, or ``None``."""

    async def link(self, user_id: str, provider_id: str, external_id: str) -> None:
        """Insert or update the (provider, external) -> user_id
        mapping. Raises ``EntityAlreadyExistsError`` if the pair is
        already linked to a different user."""

    async def unlink(self, provider_id: str, external_id: str) -> None:
        """Remove the mapping. No-op if absent."""


# ---------------------------------------------------------------------------
# Token domain
# ---------------------------------------------------------------------------


@runtime_checkable
class RefreshTokenRepository(Protocol):
    """Persistence for OAuth2 refresh tokens with rotation support.

    The plaintext token is **never** persisted: implementations
    receive a ``RefreshToken`` whose ``token_hash`` (bcrypt) and
    ``token_lookup`` (HMAC-SHA256 of the plaintext) are already set.
    The File backend maintains two secondary indexes for O(1)
    lookups: ``id_index`` (token_id -> token_lookup) and
    ``active_index`` (list of active token_ids). SQL backends
    replace the JSON index files with native indexes.
    """

    async def create(self, token: RefreshToken) -> None:
        """Persist a freshly-generated refresh token."""

    async def get_by_id(self, token_id: str) -> Optional[RefreshToken]:
        """Return the token with the given ``token_id`` via the
        internal id index, or ``None``."""

    async def get_by_lookup(self, token_lookup: str) -> Optional[RefreshToken]:
        """Return the token with the given HMAC lookup key, or
        ``None`` (O(1) file access on the File backend)."""

    async def update(self, token: RefreshToken) -> None:
        """Persist changes to an existing token (e.g. marking it
        used, updating last-used IP). May raise
        ``ConcurrentWriteError`` on cross-process race."""

    async def delete(self, token_id: str) -> bool:
        """Hard-delete the token. Returns ``True`` if it existed."""

    async def list_active(self, *, user_id: Optional[str] = None) -> List[RefreshToken]:
        """Return all non-revoked, non-expired tokens, optionally
        filtered by user_id."""

    async def list_all(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        user_id: Optional[str] = None,
        active_only: bool = False,
    ) -> tuple[List[RefreshToken], int]:
        """Return a paginated slice of tokens plus the total count."""

    async def cleanup_expired(self) -> int:
        """Delete every expired token. Returns the deletion count."""

    async def revoke_user_tokens(self, user_id: str, client_id: Optional[str] = None) -> int:
        """Revoke every non-revoked token for a user, optionally
        filtered by ``client_id``. Returns the count of newly-revoked
        tokens (already-revoked tokens are skipped, not double-counted)."""

    async def load_id_index(self) -> Dict[str, str]:
        """Return a snapshot of the ``token_id -> token_lookup`` index."""

    async def add_to_id_index(self, token_id: str, token_lookup: str) -> None:
        """Register a ``token_id -> token_lookup`` entry."""

    async def remove_from_id_index(self, token_id: str) -> None:
        """Unregister a ``token_id`` from the id_index. No-op if absent."""

    async def load_active_index(self) -> List[str]:
        """Return a snapshot of the active token_ids list."""

    async def add_to_active_index(self, token_id: str) -> None:
        """Add a ``token_id`` to the active_index. Idempotent."""

    async def remove_from_active_index(self, token_id: str) -> None:
        """Remove a ``token_id`` from the active_index. No-op if absent."""


@runtime_checkable
class AuthorizationCodeRepository(Protocol):
    """Persistence for OAuth2 single-use authorization codes.

    The cross-process CAS for ``mark_used`` is handled internally by
    the implementation: callers simply observe the boolean return
    value. The service layer does not need to retry.
    """

    async def create(self, code: AuthorizationCode) -> None:
        """Persist a new authorization code."""

    async def get_by_code(self, code: str) -> Optional[AuthorizationCode]:
        """Return the code by its plaintext, or ``None`` if absent /
        expired / already used."""

    async def mark_used(self, code: str) -> bool:
        """Atomically mark the code as used. Returns ``True`` on the
        first successful use, ``False`` on subsequent uses / missing
        code. Uses internal CAS to prevent double-redemption."""

    async def delete(self, code: str) -> None:
        """Delete the code regardless of state. No-op if absent."""


@runtime_checkable
class DeviceAuthorizationRepository(Protocol):
    """Persistence for OAuth 2.0 Device Authorization Grants (RFC 8628).

    Lookups by ``device_code`` (high-entropy, for polling) and
    ``user_code`` (8-char human-friendly, for browser approval).
    """

    async def create(self, auth: "DeviceAuthorization") -> None:
        """Persist a new device authorization."""

    async def get_by_device_code(self, device_code: str) -> Optional["DeviceAuthorization"]:
        """Return the authorization by its device code, or ``None``."""

    async def get_by_user_code(self, user_code: str) -> Optional["DeviceAuthorization"]:
        """Return the authorization by its user code, or ``None``."""

    async def update(self, auth: "DeviceAuthorization") -> None:
        """Update an existing device authorization (status change)."""

    async def delete_expired(self) -> int:
        """Delete all expired entries. Returns count of deleted entries."""

    async def list_all(self, status_filter: Optional[str] = None) -> List["DeviceAuthorization"]:
        """Return all device authorizations, optionally filtered by status."""

    async def delete(self, device_code: str) -> None:
        """Delete a single device authorization. No-op if absent."""


@runtime_checkable
class CSRFTokenRepository(Protocol):
    """Persistence for CSRF tokens keyed by HMAC(session_id).

    Storage is intentionally non-enumerable: the lookup key is the
    HMAC of the session id, not the session id itself. Implementations
    are not required to support glob-based enumeration; cleanup is
    done by a periodic sweep based on the per-file ``expires_at``.
    """

    async def save(
        self,
        session_lookup: str,
        token_hash: str,
        expires_at: float,
        created_at: float,
    ) -> None:
        """Persist the CSRF state for a session. Replaces any prior
        entry for the same session."""

    async def get(self, session_lookup: str) -> Optional[Dict[str, Any]]:
        """Return ``{token_hash, expires_at, created_at}`` or
        ``None``. Implementations may auto-delete expired entries on
        read."""

    async def delete(self, session_lookup: str) -> None:
        """Remove the entry. No-op if absent."""

    async def cleanup_expired(self) -> None:
        """Delete all entries whose ``expires_at`` is in the past."""


@runtime_checkable
class TokenBlacklistRepository(Protocol):
    """Persistence for revoked JWT JTI -> expiry_epoch mappings.

    One file per revoked JTI so multi-instance deployments sharing a
    single filesystem see each other's revocations without restart.
    The service layer handles the in-memory cache; the repository
    is responsible for async hydration, writes, periodic cleanup
    and the *sync* hot-path primitives (``exists`` / ``delete``)
    that ``is_revoked`` calls on a cache miss without yielding the
    event loop.
    """

    async def save(self, jti: str, expires_at: float) -> None:
        """Persist a single revoked JTI as ``{jti}.json``."""

    async def load_all(self) -> Dict[str, float]:
        """Return every persisted jti -> expires_at mapping. Expired
        entries may be included; the service layer filters on read."""

    def exists(self, jti: str) -> bool:
        """Hot-path check: is the JTI file present?

        SYNC — the service calls this on a cache miss without
        yielding the event loop. The File impl uses ``os.path``
        (fast); a SQL impl would need to expose a sync primitive
        (e.g. a sync driver) or change the service to async.
        """

    def delete(self, jti: str) -> bool:
        """Delete a single JTI file. Returns ``True`` if it existed.

        SYNC — paired with :meth:`exists` for the lazy cleanup
        of expired entries on the hot path.
        """

    async def cleanup_expired(self) -> int:
        """Delete expired entries. Returns the count of removed files."""


# ---------------------------------------------------------------------------
# OAuth2 / OIDC client domain
# ---------------------------------------------------------------------------


@runtime_checkable
class OAuth2ClientRepository(Protocol):
    """Persistence for dynamically-registered OAuth2 clients."""

    async def create(self, client: OAuth2Client) -> None:
        """Persist a new client (with hashed secret)."""

    async def get_by_id(self, client_id: str) -> Optional[OAuth2Client]:
        """Return the client, or ``None``."""

    async def update(self, client: OAuth2Client) -> None:
        """Persist changes. May raise ``ConcurrentWriteError`` for
        concurrent rotations of the secret."""

    async def delete(self, client_id: str) -> bool:
        """Hard-delete. Returns ``True`` if it existed."""

    async def list(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        active_only: bool = False,
    ) -> List[OAuth2Client]:
        """Return a paginated slice of clients."""


@runtime_checkable
class OAuth2ConsentRepository(Protocol):
    """Persistence for per-user OAuth2 consent records.

    The File backend uses deterministic path layout
    ``{user_id}/{client_id}.json`` for O(1) direct access. The
    ``get_by_id`` and ``list_for_user`` operations scan on the File
    backend — that is acceptable since they are admin / cold paths.
    """

    async def create(self, consent: OAuth2Consent) -> None:
        """Persist a new consent (upsert semantics: re-creating a
        consent for the same user+client replaces the prior one)."""

    async def get_by_id(self, consent_id: str) -> Optional[OAuth2Consent]:
        """Admin-only: find a consent by its UUID. Cold path."""

    async def get_for_user_client(self, user_id: str, client_id: str) -> Optional[OAuth2Consent]:
        """O(1) direct lookup on the File backend."""

    async def update(self, consent: OAuth2Consent) -> None:
        """Persist changes (e.g. revocation)."""

    async def list_for_user(self, user_id: str) -> List[OAuth2Consent]:
        """Return every consent granted by *user_id* (sorted by
        ``granted_at`` desc)."""

    async def list_all(self, *, limit: int = 100, offset: int = 0) -> List[OAuth2Consent]:
        """Admin-only: scan every consent record on disk. Cold path."""

    async def delete_for_user_client(self, user_id: str, client_id: str) -> bool:
        """Delete the consent for the (user, client) pair."""

    async def delete_for_user(self, user_id: str) -> int:
        """VAPT-082: drop **every** consent belonging to a user
        (across all client_ids). Returns the deletion count.
        Used by the GDPR right-to-erasure path."""

    async def cleanup_expired(self, *, cutoff: Optional[str] = None) -> int:
        """Delete every consent whose ``expires_at`` is in the
        past, or whose ``revoked_at`` is older than ``cutoff``.

        VAPT-086: ``cutoff`` is an ISO-8601 string; if supplied,
        revoked consents older than ``cutoff`` are also
        dropped (drives the retention sweep). ``expires_at``
        dropping is independent of the cutoff and runs on the
        natural expiry."""


# ---------------------------------------------------------------------------
# Identity / email domain
# ---------------------------------------------------------------------------


@runtime_checkable
class EmailVerificationRepository(Protocol):
    """Persistence for email-verification tokens.

    VAPT-022 alignment: tokens are stored with HMAC filenames keyed
    on the human-friendly ``verification_code``; the plaintext code
    is stored in the JSON body for O(1) lookups.
    """

    async def create(self, token: EmailVerificationToken) -> None:
        """Persist a new verification token."""

    async def get_by_lookup(self, code_lookup: str) -> Optional[EmailVerificationToken]:
        """Return the token with the given HMAC lookup, or ``None``."""

    async def update(self, token: EmailVerificationToken) -> None:
        """Persist changes. May raise ``ConcurrentWriteError``."""

    async def delete(self, code_lookup: str) -> None:
        """Remove the token. No-op if absent."""

    async def cleanup_expired(self) -> int:
        """Delete every expired token."""


@runtime_checkable
class PasswordResetRepository(Protocol):
    """Persistence for password-reset tokens.

    The File backend writes two mirror files per token (one indexed
    by the bearer-token HMAC, one by the reset-code HMAC — VAPT-022).
    The Protocol hides this from the service layer.
    """

    async def create(self, token: PasswordResetToken) -> None:
        """Persist a new reset token (writes both mirror files)."""

    async def get_by_token_lookup(self, token_lookup: str) -> Optional[PasswordResetToken]:
        """Return the token by its bearer-token HMAC lookup."""

    async def get_by_code_lookup(self, code_lookup: str) -> Optional[PasswordResetToken]:
        """Return the token by its reset-code HMAC lookup
        (VAPT-022 email-based flow)."""

    async def update(self, token: PasswordResetToken) -> None:
        """Persist changes. Updates both mirror files. May raise
        ``ConcurrentWriteError``."""

    async def delete_by_token_lookup(self, token_lookup: str) -> bool:
        """Delete the token (and its mirror). Returns ``True`` if it
        existed."""

    async def list_for_user(
        self, user_id: str, active_only: bool = True
    ) -> List[PasswordResetToken]:
        """Return every token issued for a user, optionally filtered
        to active (unused + unexpired)."""

    async def list_all(
        self,
        *,
        active_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[PasswordResetToken]:
        """Admin: return a paginated slice of all reset tokens."""

    async def cleanup_expired(self) -> int:
        """Delete every used or expired token. Returns the count."""

    async def stats(self) -> Dict[str, int]:
        """Return ``{total, active, expired, used}`` counts in a
        single repository call."""


# ---------------------------------------------------------------------------
# Session / MFA domain
# ---------------------------------------------------------------------------


@runtime_checkable
class SessionRepository(Protocol):
    """Persistence for temporary MFA and consent sessions.

    Both flavours are stored under the same on-disk directory but
    distinguished by filename prefix (``<lookup>.json`` for MFA,
    ``consent_<lookup>.json`` for consent). The protocol exposes them
    as two separate method families to keep the service layer free of
    naming conventions.
    """

    async def save_mfa_session(self, session: MFASession) -> None:
        """Persist a new MFA session."""

    async def get_mfa_session(self, token_lookup: str) -> Optional[MFASession]:
        """Return the MFA session by lookup, or ``None`` (also
        auto-deletes expired)."""

    async def delete_mfa_session(self, token_lookup: str) -> None:
        """Remove the MFA session. No-op if absent."""

    async def save_consent_session(self, data: Record) -> None:
        """Persist a new consent session. The dict shape mirrors the
        historical on-disk format: ``session_token``, ``user_id``,
        ``client_id``, ``redirect_uri``, ``scope``, ``state``,
        ``code_challenge``, ``code_challenge_method``, ``nonce``,
        ``expires_at`` (ISO 8601)."""

    async def get_consent_session(self, token_lookup: str) -> Optional[Record]:
        """Return the consent session by lookup, or ``None`` (auto-
        deletes expired)."""

    async def delete_consent_session(self, token_lookup: str) -> None:
        """Remove the consent session. No-op if absent."""


@runtime_checkable
class BackupCodeRepository(Protocol):
    """Persistence for MFA backup codes (bcrypt-hashed at rest)."""

    async def save(self, codes: BackupCodes) -> None:
        """Persist (overwrite) the backup-codes set for a user."""

    async def get(self, user_id: str) -> Optional[BackupCodes]:
        """Return the backup-codes set for a user, or ``None``."""

    async def delete(self, user_id: str) -> None:
        """Remove the backup-codes set. No-op if absent."""

    async def use_code(self, user_id: str, code_hash: str) -> bool:
        """Atomically remove ``code_hash`` from the user's set and
        increment ``used_count``. Returns ``True`` if a matching code
        was found, ``False`` otherwise. Caller is responsible for the
        brute-force lockout policy."""


@runtime_checkable
class BackupCodeAttemptRepository(Protocol):
    """Persistence for the per-user failed-attempt counter that
    rate-limits backup-code verification."""

    async def get(self, user_id: str) -> Optional[BackupCodeAttempt]:
        """Return the attempt counter, or ``None``."""

    async def save(self, attempts: BackupCodeAttempt) -> None:
        """Persist the attempt counter (overwrite)."""

    async def delete(self, user_id: str) -> None:
        """Remove the attempt counter. No-op if absent."""


@runtime_checkable
class TrustedDeviceRepository(Protocol):
    """Persistence for per-user WebAuthn trusted devices."""

    async def add(self, device: TrustedDevice) -> None:
        """Persist a new trusted device."""

    async def get(self, device_id: str) -> Optional[TrustedDevice]:
        """Return the device, or ``None``."""

    async def update(self, device: TrustedDevice) -> None:
        """Persist changes (e.g. last_used)."""

    async def delete(self, device_id: str) -> bool:
        """Remove the device. Returns ``True`` if it existed."""

    async def list_for_user(self, user_id: str) -> List[TrustedDevice]:
        """Return every non-expired trusted device for a user."""

    async def find_trusted(self, user_id: str, fingerprint: str) -> Optional[TrustedDevice]:
        """Return the device matching ``(user_id, fingerprint)`` if
        it exists and is not expired, or ``None``."""

    async def cleanup_expired(self) -> int:
        """Delete every expired device. Returns the count."""


# ---------------------------------------------------------------------------
# RBAC domain
# ---------------------------------------------------------------------------


@runtime_checkable
class PermissionRepository(Protocol):
    """Persistence for RBAC permissions."""

    async def create(self, permission: Permission) -> None:
        """Persist a new permission."""

    async def get_by_id(self, permission_id: str) -> Optional[Permission]:
        """Return the permission, or ``None``."""

    async def get_by_name(self, name: str) -> Optional[Permission]:
        """Return the permission with the given name, or ``None``."""

    async def delete(self, permission_id: str) -> bool:
        """Remove the permission. Returns ``True`` if it existed."""

    async def list(self) -> List[Permission]:
        """Return every permission, sorted by name."""


@runtime_checkable
class RoleRepository(Protocol):
    """Persistence for RBAC roles."""

    async def create(self, role: Role) -> None:
        """Persist a new role."""

    async def get_by_id(self, role_id: str) -> Optional[Role]:
        """Return the role, or ``None``."""

    async def get_by_name(self, name: str) -> Optional[Role]:
        """Return the role with the given name, or ``None``."""

    async def update(self, role: Role) -> None:
        """Persist changes."""

    async def delete(self, role_id: str) -> bool:
        """Remove the role. Returns ``True`` if it existed. The
        service layer is responsible for refusing to delete system
        roles."""

    async def list(self) -> List[Role]:
        """Return every role, sorted by name."""


@runtime_checkable
class UserRoleRepository(Protocol):
    """Persistence for user <-> role assignments."""

    async def assign(self, user_role: UserRole) -> None:
        """Persist a new assignment."""

    async def get_by_id(self, assignment_id: str) -> Optional[UserRole]:
        """Return the assignment, or ``None``."""

    async def find_assignment(self, user_id: str, role_id: str) -> Optional[UserRole]:
        """Return the first assignment matching ``(user_id, role_id)``,
        or ``None``. Used by ``remove_role_from_user`` to find the
        assignment_id to delete."""

    async def remove(self, assignment_id: str) -> bool:
        """Remove the assignment by its ``assignment_id``. Returns
        ``True`` if it existed."""

    async def list_for_user(self, user_id: str) -> List[UserRole]:
        """Return every non-expired assignment for the user."""


# ---------------------------------------------------------------------------
# WebAuthn domain
# ---------------------------------------------------------------------------


@runtime_checkable
class PasskeyRepository(Protocol):
    """Persistence for WebAuthn passkey credentials."""

    async def save(self, passkey: Passkey) -> None:
        """Persist a new passkey (no CAS; used for first-time
        registration)."""

    async def get(self, user_id: str, credential_id: str) -> Optional[Passkey]:
        """Return the passkey, or ``None``."""

    async def update(self, passkey: Passkey) -> None:
        """Persist changes to an existing passkey (last_used_at,
        sign_count). May raise ``ConcurrentWriteError`` on
        cross-process race; the service layer retries inside an
        in-process lock."""

    async def delete(self, user_id: str, credential_id: str) -> bool:
        """Remove the passkey. Returns ``True`` if it existed."""

    async def list_for_user(self, user_id: str) -> List[Passkey]:
        """Return every passkey for a user, sorted by
        ``created_at`` desc."""


@runtime_checkable
class WebAuthnChallengeRepository(Protocol):
    """Persistence for ephemeral WebAuthn ceremony challenges."""

    async def save(self, challenge: PasskeyChallenge) -> None:
        """Persist a new challenge (upsert by challenge string)."""

    async def get(self, challenge: str) -> Optional[PasskeyChallenge]:
        """Return the challenge, or ``None`` (auto-deletes expired)."""

    async def delete(self, challenge: str) -> None:
        """Remove the challenge. No-op if absent."""


# ---------------------------------------------------------------------------
# API key domain
# ---------------------------------------------------------------------------


@runtime_checkable
class APIKeyRepository(Protocol):
    """Persistence for API keys (bcrypt-hashed at rest).

    The File backend maintains a secondary index keyed by the
    12-character key prefix to enable O(1) lookup on validation.
    Backends with native indexes (SQL) implement the three
    ``load/add/remove`` helpers via a native unique key on
    ``key_prefix``; they may no-op ``add`` / ``remove`` and use
    a native query for ``load``.
    """

    async def create(self, key: APIKey) -> None:
        """Persist a new API key."""

    async def get_by_id(self, key_id: str) -> Optional[APIKey]:
        """Return the key, or ``None``."""

    async def get_by_prefix(self, prefix: str) -> List[APIKey]:
        """Return every candidate key sharing *prefix* (there may be
        multiple, e.g. after key rotation). The service layer
        ``verify``s each candidate against the provided plaintext."""

    async def update(self, key: APIKey) -> None:
        """Persist changes (e.g. usage stats, revocation)."""

    async def delete(self, key_id: str) -> bool:
        """Hard-delete the key. Returns ``True`` if it existed."""

    async def list_for_user(self, user_id: str) -> List[APIKey]:
        """Return every key owned by a user, sorted by
        ``created_at`` desc."""

    async def list_all(
        self, *, limit: int = 100, offset: int = 0, active_only: bool = False
    ) -> List[APIKey]:
        """Admin: return a paginated slice of every key."""

    async def cleanup_expired(self) -> int:
        """Delete every expired + inactive key. Returns the count."""

    async def load_prefix_index(self, prefix: str) -> List[str]:
        """Return the list of ``key_id``s registered for *prefix*.

        Used by the service layer to do O(1) lookup on validation
        before the per-candidate bcrypt verify.
        """

    async def add_to_prefix_index(self, key: APIKey) -> None:
        """Register *key*'s ``key_id`` under ``key.key_prefix``.

        Idempotent: re-adding an existing ``key_id`` is a no-op.
        """

    async def remove_from_prefix_index(self, prefix: str, key_id: str) -> None:
        """Unregister *key_id* from *prefix*. No-op if absent."""


# ---------------------------------------------------------------------------
# Audit / history domain
# ---------------------------------------------------------------------------


@runtime_checkable
class LoginHistoryRepository(Protocol):
    """Persistence for per-user login attempt history (90-day retention)."""

    async def record(
        self,
        *,
        user_id: str,
        email: str,
        success: bool,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        failure_reason: Optional[str] = None,
        entry_id: Optional[str] = None,
        timestamp: Optional[str] = None,
    ) -> Record:
        """Append a new login-attempt record.

        ``entry_id`` and ``timestamp`` default to a server-generated
        UUID and ``utcnow().isoformat()`` respectively; the caller
        (typically the service layer) may pass them explicitly to
        keep its in-memory representation consistent with the
        persisted record. Returns the persisted record (with the
        effective ``id`` and ``timestamp``).
        """

    async def list_for_user(
        self, user_id: str, *, limit: int = 50, offset: int = 0
    ) -> tuple[List[Record], int]:
        """Return a paginated slice of history for a user, plus the
        total count."""

    async def cleanup_old(self, user_id: str, cutoff: str) -> int:
        """Delete every record with ``timestamp < cutoff`` for a
        user. ``cutoff`` is an ISO-8601 string (the same format
        used by ``LoginHistoryEntry.to_dict()`` and
        ``datetime.isoformat()``). Returns the deletion count."""

    async def delete_for_user(self, user_id: str) -> int:
        """VAPT-082: GDPR Art. 17 right-to-erasure hook.

        Drop **every** record belonging to ``user_id`` regardless
        of age. Returns the deletion count. Called from
        ``UserProfileService.delete_account`` after the user
        record itself has been removed.
        """


@runtime_checkable
class AdminActionRepository(Protocol):
    """Persistence for admin actions targeting users (365-day retention)."""

    async def record(
        self,
        *,
        admin_user_id: str,
        admin_email: str,
        action_type: str,
        target_user_id: str,
        target_user_email: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        """Append a new admin-action record."""

    async def list_for_user(
        self, target_user_id: str, *, limit: int = 50, offset: int = 0
    ) -> tuple[List[Record], int]:
        """Return a paginated slice of actions against a user, plus
        the total count."""

    async def delete_for_user(self, target_user_id: str) -> int:
        """VAPT-082: drop **every** admin-action record whose
        ``target_user_id`` matches. Used by the GDPR
        right-to-erasure path. Returns the deletion count."""


@runtime_checkable
class SecurityEventRepository(Protocol):
    """Persistence for per-user security events (365-day retention)."""

    async def record(
        self,
        *,
        user_id: str,
        event_type: str,
        email: Optional[str] = None,
        description: Optional[str] = None,
        ip_address: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Append a new security event."""

    async def list_for_user(
        self, user_id: str, *, limit: int = 50, offset: int = 0
    ) -> tuple[List[Record], int]:
        """Return a paginated slice of security events for a user,
        plus the total count."""

    async def delete_for_user(self, user_id: str) -> int:
        """VAPT-082: drop **every** security event for a user.
        Returns the deletion count."""


# ---------------------------------------------------------------------------
# Federation domain
# ---------------------------------------------------------------------------


@runtime_checkable
class FederationProviderRepository(Protocol):
    """Persistence for external OIDC IdP configurations."""

    async def create(self, provider: ExternalIdpConfig) -> None:
        """Persist a new IdP configuration."""

    async def get_by_id(self, provider_id: str) -> Optional[ExternalIdpConfig]:
        """Return the provider, or ``None``."""

    async def update(
        self, provider_id: str, updates: Dict[str, Any]
    ) -> Optional[ExternalIdpConfig]:
        """Apply the given non-None field updates and persist. Returns
        the updated provider, or ``None`` if it was missing."""

    async def delete(self, provider_id: str) -> bool:
        """Remove the provider. Returns ``True`` if it existed."""

    async def list(self, enabled_only: bool = False) -> List[ExternalIdpConfig]:
        """Return every provider, optionally filtered by ``enabled``."""


# ---------------------------------------------------------------------------
# User preferences domain
# ---------------------------------------------------------------------------


@runtime_checkable
class UserPreferencesRepository(Protocol):
    """Persistence for per-user UI / notification preferences."""

    async def get(self, user_id: str) -> Optional[UserPreferences]:
        """Return the preferences for a user, or ``None``."""

    async def save(self, preferences: UserPreferences) -> None:
        """Persist (upsert) the preferences for a user."""

    async def delete(self, user_id: str) -> None:
        """Remove the preferences. No-op if absent."""


# ---------------------------------------------------------------------------
# Claim policy domain
# ---------------------------------------------------------------------------


@runtime_checkable
class ClientClaimPolicyRepository(Protocol):
    """Persistence for the per-OAuth2-client claim policy.

    A claim policy is a list of declarative rules that decide
    which custom claims (RBAC roles, RBAC permissions, user
    attributes, static values, JWT metadata) are embedded in
    access tokens / ID tokens / UserInfo responses, and where
    the values come from. See
    ``authglow.models.claim_policy.ClientClaimPolicy`` for the
    payload schema and ``authglow.services.claim_policy`` for
    the interpretation.

    The policy is looked up at token-issuance time by
    ``client_id`` (one policy per client, replaced on
    update). Missing policies are not an error — the
    ``ClaimPolicyService`` falls back to the built-in default
    (the namespaced RBAC roles + permissions claim pair).
    """

    async def get_by_client(self, client_id: str) -> Optional[ClientClaimPolicy]:
        """Return the policy for *client_id*, or ``None`` if no
        policy is configured for that client."""

    async def save(self, policy: ClientClaimPolicy) -> None:
        """Persist the policy. Overwrites any prior policy for the
        same ``client_id`` (the repository owns the
        client_id → policy mapping)."""

    async def delete(self, client_id: str) -> bool:
        """Remove the policy for *client_id*. Returns ``True`` on
        success, ``False`` if no policy was configured."""


@runtime_checkable
class APIKeyClaimPolicyRepository(Protocol):
    """Persistence for the per-API-key claim policy.

    API key counterpart of :class:`ClientClaimPolicyRepository`.
    The payload is the same ``rules`` list; the owner key is
    ``api_key_id`` instead of ``client_id``.

    Missing policies are not an error — the
    ``ClaimPolicyService`` falls back to the built-in default
    (the namespaced RBAC roles + permissions claim pair).
    """

    async def get_by_api_key(self, api_key_id: str) -> Optional[APIKeyClaimPolicy]:
        """Return the policy for *api_key_id*, or ``None`` if no
        policy is configured for that key."""

    async def save(self, policy: APIKeyClaimPolicy) -> None:
        """Persist the policy. Overwrites any prior policy for the
        same ``api_key_id`` (the repository owns the
        api_key_id → policy mapping)."""

    async def delete(self, api_key_id: str) -> bool:
        """Remove the policy for *api_key_id*. Returns ``True`` on
        success, ``False`` if no policy was configured."""


# ---------------------------------------------------------------------------
# KeyStore domain
# ---------------------------------------------------------------------------


@runtime_checkable
class KeyStoreRepository(Protocol):
    """Persistence for the RSA keyring used to sign JWTs.

    The keyring is a collection of RSA key pairs (one per
    ``kid`` = key ID) with rotation + revocation semantics.
    The active ``kid`` is the one used for new signatures;
    older kids remain in the ring during a ``verifying``
    window so existing tokens can still be verified.

    The repository is the single owner of the on-disk
    ``keyring.json`` index + the per-kid PEM files. Cross-entity
    safety (legacy-file migration, auto-rotation check on
    startup) is delegated to the service layer / ``Settings``.
    """

    async def get_active_keypair(self) -> object:
        """Return the active ``KeyPair`` (private + public PEM
        + metadata) for signing new JWTs, or ``None`` if the
        keyring is missing."""

    async def get_keypair_by_kid(self, kid: str) -> object:
        """Return the ``KeyPair`` for *kid*, or ``None`` if
        the kid is not in the ring (or the on-disk file is
        missing)."""

    async def get_public_keys(self) -> list:
        """Return every public key in the ring as ``PublicKey``
        entries for the JWKS endpoint. Revoked keys are
        excluded (they cannot be used to verify signatures)."""

    async def read_public_key(self, kid: str) -> "Optional[bytes]":
        """Return the raw PEM-encoded public key for *kid*,
        or ``None`` if the kid is unknown or the file is
        missing.

        Implemented as an async, fsspec-routed accessor so the
        ``/.well-known/jwks.json`` route handler does not block
        the event loop on per-kid file reads (Tier 1.8 of
        ``docs/plans/PERFORMANCE_OPTIMIZATION_PLAN.md``)."""

    async def rotate(self, secret_key: str, key_size: int = 2048) -> object:
        """Generate a new RSA key pair, mark the current
        active key as ``verifying``, and persist. Returns
        the new active ``KeyPair``."""

    async def revoke(self, kid: str) -> None:
        """Mark *kid* as ``revoked`` and persist. The kid
        remains in the ring (for audit) but is excluded from
        ``get_public_keys``. No-op if *kid* is not in the
        ring."""


# ---------------------------------------------------------------------------
# Sentinel — to verify at import time that the module is well-formed.
# ---------------------------------------------------------------------------


_ALL_PROTOCOLS: tuple[type, ...] = (
    APIKeyRepository,
    AdminActionRepository,
    APIKeyClaimPolicyRepository,
    AuthorizationCodeRepository,
    BackupCodeAttemptRepository,
    BackupCodeRepository,
    ClientClaimPolicyRepository,
    CSRFTokenRepository,
    EmailIndexRepository,
    EmailVerificationRepository,
    FederatedIdentityRepository,
    FederationProviderRepository,
    KeyStoreRepository,
    LoginHistoryRepository,
    OAuth2ClientRepository,
    OAuth2ConsentRepository,
    PasswordResetRepository,
    PasskeyRepository,
    PermissionRepository,
    RefreshTokenRepository,
    RoleRepository,
    SecurityEventRepository,
    SessionRepository,
    TrustedDeviceRepository,
    UserPreferencesRepository,
    UserRepository,
    WebAuthnChallengeRepository,
)
