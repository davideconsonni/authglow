"""API Key storage and management service.

Persistence is delegated to a single :class:`APIKeyRepository`. The
pre-refactor service built its own fsspec/AsyncFileSystem plumbing
in ``__init__`` and would have crashed on any non-``file`` backend
(``s3`` / ``gcs`` / ``abfs``) with a confusing ``ValueError`` from
fsspec. The refactored service routes through the standard
``BaseFileRepository._init_filesystem`` via the factory, which
honours ``Settings.storage_backend``.

Pure-crypto helpers (``_verify_api_key`` bcrypt check,
``_generate_api_key`` plaintext+hash generation) and the
brute-force lockout policy stay in the service because they are
business logic with no I/O. The in-process ``named_lock`` wraps
read-modify-write critical sections (lockout counter, usage
stats, revoke, etc.) so concurrent updates from the same process
are serialised.
"""

import asyncio
import ipaddress
import secrets
from datetime import datetime, timedelta
from typing import List, Optional

import structlog

from authglow.core.cache import api_key_cache
from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.api_key import APIKey, APIKeyCreate
from authglow.repositories.protocols import APIKeyRepository
from authglow.services.password import hash_password, verify_password

PREFIX_LENGTH = 12

logger = structlog.get_logger("authglow.audit")


def _enforce_scope_subset(
    requested: List[str],
    caller_scopes: Optional[List[str]],
    is_admin: bool,
) -> List[str]:
    """Return a scope list that is a subset of the caller's own scopes.

    Admins bypass the filter (full delegation). Non-admin callers get
    the intersection of ``requested`` with their own scopes. This is
    the BOPLA guard (OWASP API3:2023): a user can never mint or
    update a key with scopes they do not already possess.
    """
    if is_admin:
        return list(requested)
    allowed = set(caller_scopes or [])
    return [s for s in (requested or []) if s in allowed]


def _ip_allowed(client_ip: Optional[str], allowed_ips: List[str]) -> bool:
    """Return True when *client_ip* matches any allowlist entry.

    Entries may be single IPs (``"203.0.113.5"``, IPv4/IPv6) or CIDR
    networks (``"198.51.100.0/24"``). Unparseable entries are skipped,
    never matched — an admin typo must fail CLOSED, not open.
    """
    if not client_ip:
        return False
    try:
        addr = ipaddress.ip_address(client_ip.strip())
    except ValueError:
        return False
    for entry in allowed_ips or []:
        entry = (entry or "").strip()
        if not entry:
            continue
        try:
            if addr == ipaddress.ip_address(entry):
                return True
        except ValueError:
            pass
        try:
            if addr in ipaddress.ip_network(entry, strict=False):
                return True
        except ValueError:
            continue
    return False


class APIKeyLockedException(Exception):
    """Raised when an API key is temporarily locked due to brute-force attempts."""

    def __init__(self, key_id: str, locked_until: datetime):
        self.key_id = key_id
        self.locked_until = locked_until
        super().__init__(f"API key {key_id} is locked until {locked_until.isoformat()}")


class APIKeyService:
    """Service for managing API keys."""

    def __init__(self, repository: Optional[APIKeyRepository] = None):
        """Initialize API key service with settings and repository.

        ``repository`` defaults to ``None`` and is resolved lazily via
        :func:`get_api_key_repository` (which returns a
        :class:`FileAPIKeyRepository`). Tests can pass a stub or an
        in-memory implementation directly.
        """
        from authglow.repositories.dependencies import get_api_key_repository

        self.settings = get_settings()
        self._repo = repository or get_api_key_repository()
        self._lock = named_lock()

    # ------------------------------------------------------------------
    # Pure crypto helpers — no I/O
    # ------------------------------------------------------------------

    def _generate_api_key(self) -> tuple[str, str, str]:
        """Generate a new API key.

        Returns:
            tuple: (full_key, prefix, hash)
        """
        random_part = secrets.token_urlsafe(32)
        full_key = f"ak_{random_part}"

        prefix = full_key[:PREFIX_LENGTH]

        key_hash = hash_password(full_key)

        return full_key, prefix, key_hash

    def _verify_api_key(self, key_hash: str, provided_key: str) -> bool:
        """Verify an API key against its hash."""
        try:
            return verify_password(provided_key, key_hash)
        except Exception:
            return False

    # ------------------------------------------------------------------
    # CRUD + listing — persistence
    # ------------------------------------------------------------------

    async def create_key(
        self,
        user_id: str,
        key_data: APIKeyCreate,
        created_by: str,
        caller_scopes: Optional[List[str]] = None,
        is_admin: bool = False,
    ) -> tuple[APIKey, str]:
        """Create a new API key.

        Returns:
            tuple: (APIKey, plaintext_key)

        When ``caller_scopes`` is provided, the requested scopes are
        filtered to be a strict subset of the caller's own scopes
        (unless ``is_admin`` is True). This is the BOPLA guard against
        privilege escalation via API key creation.
        """
        full_key, prefix, key_hash = self._generate_api_key()

        expires_at = None
        if not key_data.never_expires and key_data.expires_in_days:
            expires_at = utcnow() + timedelta(days=key_data.expires_in_days)

        effective_scopes: List[str]
        if caller_scopes is not None:
            effective_scopes = _enforce_scope_subset(
                requested=key_data.scopes,
                caller_scopes=caller_scopes,
                is_admin=is_admin,
            )
            filtered = sorted(set(key_data.scopes or []) - set(effective_scopes))
            if filtered:
                logger.warning(
                    "api_key_scope_filtered",
                    key_name=key_data.name,
                    requested_scopes=key_data.scopes,
                    granted_scopes=effective_scopes,
                    filtered_scopes=filtered,
                    created_by=created_by,
                    is_admin=is_admin,
                )
        else:
            effective_scopes = list(key_data.scopes)

        api_key = APIKey(
            user_id=user_id,
            name=key_data.name,
            description=key_data.description,
            key_prefix=prefix,
            key_hash=key_hash,
            scopes=effective_scopes,
            expires_at=expires_at,
            never_expires=key_data.never_expires,
            created_by=created_by,
            allowed_ips=key_data.allowed_ips,
        )

        async with self._lock(f"api_key_create:{api_key.key_prefix}"):
            await self._repo.create(api_key)
            await self._repo.add_to_prefix_index(api_key)

        return api_key, full_key

    async def get_key(self, key_id: str) -> Optional[APIKey]:
        """Get an API key by ID with cross-request caching.

        On every request authenticated with an API key this is
        called 2-3 times (lockout check + verify loop). The
        cache avoids repeated file-system reads for the same key.
        """
        cached: APIKey | None = await api_key_cache.get(key_id)
        if cached is not None:
            return cached

        key = await self._repo.get_by_id(key_id)
        if key is not None:
            await api_key_cache.set(key_id, key)
        return key

    async def get_user_keys(self, user_id: str) -> List[APIKey]:
        """Get all API keys for a user."""
        return await self._repo.list_for_user(user_id)

    async def list_all_keys(
        self, limit: int = 100, offset: int = 0, active_only: bool = False
    ) -> List[APIKey]:
        """List all API keys (admin)."""
        return await self._repo.list_all(limit=limit, offset=offset, active_only=active_only)

    # ------------------------------------------------------------------
    # Validation — guarded by named_lock for brute-force lockout
    # ------------------------------------------------------------------

    async def validate_key(self, provided_key: str) -> Optional[APIKey]:
        """Validate an API key using prefix index for O(1) lookup.

        Raises APIKeyLockedException if any candidate key is locked.
        Records failed attempts on all candidates on mismatch.
        Resets failed attempts on successful match.
        """
        if not provided_key or not provided_key.startswith("ak_"):
            return None

        prefix = provided_key[:PREFIX_LENGTH]
        candidate_ids = await self._repo.load_prefix_index(prefix)

        if not candidate_ids:
            return None

        for key_id in candidate_ids:
            if await self.is_key_locked(key_id):
                api_key = await self._repo.get_by_id(key_id)
                if api_key and api_key.locked_until:
                    raise APIKeyLockedException(key_id, api_key.locked_until)

        for key_id in candidate_ids:
            api_key = await self._repo.get_by_id(key_id)
            if api_key is None:
                continue

            if await asyncio.to_thread(self._verify_api_key, api_key.key_hash, provided_key):
                if not api_key.is_active:
                    return None

                if api_key.expires_at and api_key.expires_at < utcnow():
                    return None

                await self.reset_failed_validations(key_id)
                return api_key

        for key_id in candidate_ids:
            await self.record_failed_validation(key_id)

        return None

    async def validate_and_track(
        self,
        provided_key: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Optional[APIKey]:
        """Unified entry point: validate an API key and atomically record
        its usage in a single, race-safe pipeline.

        Order of checks (all in-process ``named_lock`` for cross-method
        atomicity):

        1. Prefix lookup (O(1) via the secondary index).
        2. Brute-force lockout check (raises :class:`APIKeyLockedException`).
        3. bcrypt verification against each candidate.
        4. ``is_active`` + ``expires_at`` checks.
        5. **IP allowlist enforcement** (was missing from
           ``record_usage`` and ``get_current_user`` — VAPT gap).
        6. Reset the failed-attempt counter on success, otherwise
           increment it on every candidate.
        7. On success, atomically update ``last_used_at``,
           ``last_used_ip``, ``last_used_ua``, and ``total_requests``.

        Returns the matching :class:`APIKey` or ``None`` if no candidate
        matched (or the only match was blocked by IP allowlist, expiry,
        or revocation).
        """
        if not provided_key or not provided_key.startswith("ak_"):
            return None

        prefix = provided_key[:PREFIX_LENGTH]
        candidate_ids = await self._repo.load_prefix_index(prefix)

        if not candidate_ids:
            return None

        for key_id in candidate_ids:
            if await self.is_key_locked(key_id):
                api_key = await self._repo.get_by_id(key_id)
                if api_key and api_key.locked_until:
                    raise APIKeyLockedException(key_id, api_key.locked_until)

        for key_id in candidate_ids:
            api_key = await self._repo.get_by_id(key_id)
            if api_key is None:
                continue

            if not await asyncio.to_thread(self._verify_api_key, api_key.key_hash, provided_key):
                continue

            if not api_key.is_active:
                return None

            if api_key.expires_at and api_key.expires_at < utcnow():
                return None

            if api_key.allowed_ips and not _ip_allowed(ip_address, api_key.allowed_ips):
                logger.warning(
                    "api_key_ip_blocked",
                    key_id=key_id,
                    key_name=api_key.name,
                    client_ip=ip_address,
                )
                return None

            async with self._lock(f"api_key:{key_id}"):
                api_key = await self._repo.get_by_id(key_id)
                if not api_key:
                    return None
                api_key.failed_validation_attempts = 0
                api_key.locked_until = None
                api_key.last_used_at = utcnow()
                api_key.total_requests += 1
                if ip_address:
                    api_key.last_used_ip = ip_address
                if user_agent:
                    api_key.last_used_ua = user_agent
                await self._repo.update(api_key)
            await api_key_cache.delete(key_id)
            return api_key

        for key_id in candidate_ids:
            await self.record_failed_validation(key_id)

        return None

    async def record_failed_validation(self, key_id: str) -> None:
        """Record a failed API key validation attempt. Locks the key if threshold reached."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self._repo.get_by_id(key_id)
            if not api_key or not api_key.is_active:
                return

            api_key.failed_validation_attempts += 1

            if api_key.failed_validation_attempts >= self.settings.api_key_max_failed_attempts:
                api_key.locked_until = utcnow() + timedelta(
                    minutes=self.settings.api_key_lockout_minutes
                )

            await self._repo.update(api_key)
            await api_key_cache.delete(key_id)

    async def is_key_locked(self, key_id: str) -> bool:
        """Check if an API key is currently locked. Auto-unlocks on expiry."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self._repo.get_by_id(key_id)
            if not api_key or not api_key.locked_until:
                return False

            if utcnow() >= api_key.locked_until:
                api_key.locked_until = None
                api_key.failed_validation_attempts = 0
                await self._repo.update(api_key)
                await api_key_cache.delete(key_id)
                return False

            return True

    async def reset_failed_validations(self, key_id: str) -> None:
        """Reset failed validation attempts and clear lockout."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self._repo.get_by_id(key_id)
            if not api_key:
                return

            api_key.failed_validation_attempts = 0
            api_key.locked_until = None

            await self._repo.update(api_key)
            await api_key_cache.delete(key_id)

    # ------------------------------------------------------------------
    # Usage tracking + updates — guarded by named_lock
    # ------------------------------------------------------------------

    async def record_usage(
        self,
        key_id: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Optional[APIKey]:
        """Update an API key's usage statistics."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self._repo.get_by_id(key_id)
            if not api_key:
                return None

            api_key.last_used_at = utcnow()
            api_key.total_requests += 1
            if ip_address:
                api_key.last_used_ip = ip_address
            if user_agent:
                api_key.last_used_ua = user_agent

            await self._repo.update(api_key)
            await api_key_cache.delete(key_id)
            return api_key

    async def update_key(
        self,
        key_id: str,
        updates: dict,
        caller_scopes: Optional[List[str]] = None,
        is_admin: bool = False,
    ) -> Optional[APIKey]:
        """Update an API key's metadata.

        When ``updates`` contains ``scopes`` and ``caller_scopes`` is
        provided, the requested scopes are filtered to be a strict
        subset of the caller's own scopes (unless ``is_admin`` is True).
        BOPLA guard against privilege escalation via PATCH.

        Expiration fields are DERIVED, not written verbatim:
        ``never_expires=True`` clears ``expires_at``; an
        ``expires_in_days`` value recomputes ``expires_at`` from now
        (and re-arms ``never_expires=False``). When both are sent the
        explicit day-window wins.
        """
        clear_expiry = updates.pop("never_expires", None) is True
        expires_in_days = updates.pop("expires_in_days", None)

        if "scopes" in updates and caller_scopes is not None:
            requested = updates.get("scopes") or []
            effective = _enforce_scope_subset(
                requested=requested,
                caller_scopes=caller_scopes,
                is_admin=is_admin,
            )
            filtered = sorted(set(requested) - set(effective))
            if filtered:
                logger.warning(
                    "api_key_scope_filtered",
                    key_id=key_id,
                    requested_scopes=requested,
                    granted_scopes=effective,
                    filtered_scopes=filtered,
                    is_admin=is_admin,
                )
            updates = {**updates, "scopes": effective}

        async with self._lock(f"api_key:{key_id}"):
            api_key = await self._repo.get_by_id(key_id)
            if not api_key:
                return None

            if clear_expiry or expires_in_days:
                if expires_in_days:
                    # Explicit day-window wins over a simultaneous clear.
                    api_key.expires_at = utcnow() + timedelta(days=expires_in_days)
                    api_key.never_expires = False
                else:
                    api_key.expires_at = None
                    api_key.never_expires = True

            for field, value in updates.items():
                if hasattr(api_key, field):
                    setattr(api_key, field, value)

            await self._repo.update(api_key)
            await api_key_cache.delete(key_id)
            return api_key

    async def revoke_key(self, key_id: str, revoked_by: str) -> bool:
        """Revoke an API key."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self._repo.get_by_id(key_id)
            if not api_key:
                return False

            api_key.is_active = False
            api_key.revoked_at = utcnow()
            api_key.revoked_by = revoked_by

            await self._repo.update(api_key)
            await api_key_cache.delete(key_id)
            return True

    async def delete_key(self, key_id: str) -> bool:
        """Permanently delete an API key."""
        api_key = await self._repo.get_by_id(key_id)
        if not api_key:
            return False

        async with self._lock(f"api_key_delete:{api_key.key_prefix}"):
            await self._repo.remove_from_prefix_index(api_key.key_prefix, key_id)
            result = await self._repo.delete(key_id)
            await api_key_cache.delete(key_id)
            return result

    async def track_usage(self, key_id: str, ip_address: Optional[str] = None) -> bool:
        """Track API key usage."""
        async with self._lock(f"api_key:{key_id}"):
            api_key = await self._repo.get_by_id(key_id)
            if not api_key:
                return False

            if api_key.allowed_ips and ip_address:
                if not _ip_allowed(ip_address, api_key.allowed_ips):
                    return False

            api_key.last_used_at = utcnow()
            api_key.total_requests += 1

            await self._repo.update(api_key)
            await api_key_cache.delete(key_id)
            return True

    async def cleanup_expired_keys(self) -> int:
        """Delete expired API keys. Returns count of deleted keys."""
        return await self._repo.cleanup_expired()
