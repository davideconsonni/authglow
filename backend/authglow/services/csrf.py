"""CSRF protection service.

CSRF tokens are persisted via the ``CSRFTokenRepository`` Protocol.
The service owns:

* the cryptographic helpers (``_new_session_id``, ``_new_token``,
  ``_compute_lookup``, ``_hash_token``) — pure functions, no I/O;
* the in-process throttling of the periodic expired-token sweep;
* the public ``generate_token`` / ``validate_token`` API that route
  handlers depend on.

The repository is responsible for the file layout, JSON serialisation,
and bulk-cleanup glob logic. A default ``FileCSRFTokenRepository`` is
constructed when no repository is injected — FastAPI's
``Depends(get_csrf_service)`` factory uses the default. Tests can
inject a custom repository (e.g. an in-memory mock) by passing
``repository=...`` to the service constructor.
"""

import hashlib
import hmac
import secrets
import time
from typing import TYPE_CHECKING, Optional

from authglow.core.config import Settings, get_settings
from authglow.repositories.protocols import CSRFTokenRepository

if TYPE_CHECKING:
    from fastapi import Request

SESSION_ID_COOKIE = "csrf_session_id"
TOKEN_EXPIRY_SECONDS = 1800
CLEANUP_INTERVAL = 600
_LAST_CLEANUP = 0.0


class CSRFTokenService:
    """CSRF token service backed by an injected repository."""

    def __init__(
        self,
        repository: Optional[CSRFTokenRepository] = None,
        *,
        settings: Optional[Settings] = None,
    ) -> None:
        self._settings: Settings = settings or get_settings()
        self._repository: CSRFTokenRepository = (
            repository if repository is not None else _default_repository(self._settings)
        )
        self._secret_bytes = self._settings.secret_key.encode()

    @property
    def repository(self) -> CSRFTokenRepository:
        """The underlying repository (exposed for tests / admin tools)."""
        return self._repository

    @staticmethod
    def _new_session_id() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def _new_token() -> str:
        return secrets.token_urlsafe(32)

    def _compute_lookup(self, session_id: str) -> str:
        """Compute HMAC lookup key from session_id."""
        return hmac.new(self._secret_bytes, session_id.encode(), hashlib.sha256).hexdigest()

    @staticmethod
    def _hash_token(token: str) -> str:
        """Compute SHA-256 hash of a token string."""
        return hashlib.sha256(token.encode()).hexdigest()

    async def _cleanup_expired(self) -> None:
        """Throttled wrapper around ``repository.cleanup_expired()``.

        The throttling is in-process state (a module-level timestamp)
        so the service keeps ownership of the policy; the repository
        does the actual I/O.
        """
        global _LAST_CLEANUP
        now = time.time()
        if now - _LAST_CLEANUP < CLEANUP_INTERVAL:
            return
        _LAST_CLEANUP = now
        try:
            await self._repository.cleanup_expired()
        except Exception:
            pass

    async def generate_token(self, session_id: str) -> str:
        """Generate a new CSRF token for the given session.

        Replaces any existing token for that session.
        """
        await self._cleanup_expired()

        token = self._new_token()
        token_hash = self._hash_token(token)
        now = time.time()
        expires_at = now + TOKEN_EXPIRY_SECONDS
        lookup = self._compute_lookup(session_id)

        await self._repository.save(
            session_lookup=lookup,
            token_hash=token_hash,
            expires_at=expires_at,
            created_at=now,
        )

        return token

    async def validate_token(self, session_id: str, submitted_token: str) -> bool:
        """Validate a submitted token against the stored hash.

        Returns True if valid, False otherwise.

        Non-consuming (T0-1 / VAPT-066): the entry is NOT deleted on
        success. The token is bound to the holder's ``csrf_session_id``
        httpOnly cookie, expires after 30 minutes and is worthless to
        any origin that cannot read the issuing response, so one-time
        semantics buy nothing — while single-use consumption made the
        double enforcement (global middleware + endpoint-level checks)
        and parallel in-flight requests mutually incompatible.
        """
        await self._cleanup_expired()

        lookup = self._compute_lookup(session_id)
        data = await self._repository.get(lookup)
        if data is None:
            return False

        if time.time() > float(data.get("expires_at", 0)):
            try:
                await self._repository.delete(lookup)
            except Exception:
                pass
            return False

        stored_hash = data.get("token_hash", "")
        submitted_hash = self._hash_token(submitted_token)

        return secrets.compare_digest(stored_hash, submitted_hash)


def _default_repository(settings: Settings) -> CSRFTokenRepository:
    from authglow.repositories.file.csrf import FileCSRFTokenRepository

    return FileCSRFTokenRepository(settings)


def get_csrf_service() -> CSRFTokenService:
    """FastAPI dependency factory for CSRFTokenService."""
    return CSRFTokenService()


def get_or_create_session_id(request: "Request") -> str:
    """Read csrf_session_id from cookie, or generate a new one."""
    cookie: str | None = request.cookies.get(SESSION_ID_COOKIE)
    if cookie:
        return cookie
    return CSRFTokenService._new_session_id()
