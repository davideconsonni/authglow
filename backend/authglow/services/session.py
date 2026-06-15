"""Session management for MFA and OAuth2 consent flows.

Sessions are persisted via the ``SessionRepository`` Protocol. The
service owns:

* the cryptographic helper ``_compute_lookup`` (HMAC-SHA256 of the
  plaintext session token) — pure function, no I/O;
* the plaintext session-token generation (``secrets.token_urlsafe``);
* the expiry checks and the deletion of expired entries;
* the public ``create_mfa_session`` / ``get_mfa_session`` /
  ``delete_mfa_session`` / ``create_consent_session`` /
  ``get_consent_session`` / ``delete_consent_session`` API that route
  handlers depend on.

The repository is responsible for the file layout, JSON
serialisation, and Pydantic round-trip for MFA sessions. A default
``FileSessionRepository`` is constructed when no repository is
injected — FastAPI's ``Depends(get_session_service)`` factory uses
the default. Tests can inject a custom repository (e.g. an in-memory
mock) by passing ``repository=...`` to the service constructor.

Security: the ``session_token`` is the HMAC lookup key, not stored in
plaintext on disk. The exception is ``create_consent_session``, where
the historical on-disk format includes the plaintext token; this is
preserved as-is by the refactor and tracked separately as a VAPT
follow-up.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from authglow.core.config import Settings, get_settings
from authglow.core.datetime import utcnow
from authglow.models.session import MFASession
from authglow.repositories.protocols import SessionRepository


class SessionService:
    """Service for managing temporary MFA and consent sessions."""

    def __init__(
        self,
        repository: Optional[SessionRepository] = None,
        *,
        settings: Optional[Settings] = None,
    ) -> None:
        self._settings: Settings = settings or get_settings()
        self._repository: SessionRepository = (
            repository if repository is not None else _default_repository(self._settings)
        )
        self._secret_bytes = self._settings.secret_key.encode()

    @property
    def repository(self) -> SessionRepository:
        """The underlying repository (exposed for tests / admin tools)."""
        return self._repository

    def _compute_lookup(self, session_token: str) -> str:
        """Compute HMAC lookup key from a plaintext session token."""
        return hmac.new(self._secret_bytes, session_token.encode(), hashlib.sha256).hexdigest()

    # ------------------------------------------------------------------
    # MFA sessions
    # ------------------------------------------------------------------

    async def create_mfa_session(
        self,
        user_id: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> MFASession:
        """Create a temporary MFA session (5 minutes)."""
        plaintext = secrets.token_urlsafe(32)
        token_lookup = self._compute_lookup(plaintext)

        session = MFASession(
            session_token=plaintext,
            token_lookup=token_lookup,
            user_id=user_id,
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            expires_at=utcnow() + timedelta(minutes=5),
        )

        await self._repository.save_mfa_session(session)
        return session

    async def get_mfa_session(self, session_token: str) -> Optional[MFASession]:
        """Get and validate an MFA session.

        Uses O(1) HMAC lookup — no directory scanning. Expired
        sessions are deleted on read.
        """
        token_lookup = self._compute_lookup(session_token)
        session = await self._repository.get_mfa_session(token_lookup)
        if session is None:
            return None

        if utcnow() > session.expires_at:
            await self._repository.delete_mfa_session(token_lookup)
            return None

        session.session_token = session_token
        return session

    async def delete_mfa_session(self, session_token: str) -> None:
        """Delete an MFA session."""
        token_lookup = self._compute_lookup(session_token)
        try:
            await self._repository.delete_mfa_session(token_lookup)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Consent sessions
    # ------------------------------------------------------------------

    async def create_consent_session(
        self,
        user_id: str,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        nonce: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a temporary consent session (10 minutes).

        Returns a dict mirroring the historical on-disk format. The
        ``session_token`` is the plaintext token the caller will
        return to the user; the ``token_lookup`` is the HMAC
        filename key (never persisted as the plaintext token).
        """
        plaintext = secrets.token_urlsafe(32)
        token_lookup = self._compute_lookup(plaintext)

        session_data: Dict[str, Any] = {
            "session_token": plaintext,
            "token_lookup": token_lookup,
            "user_id": user_id,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": code_challenge_method,
            "nonce": nonce,
            "expires_at": (utcnow() + timedelta(minutes=10)).isoformat(),
        }

        await self._repository.save_consent_session(session_data)
        return session_data

    async def get_consent_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Get and validate a consent session.

        Expired sessions are deleted on read.
        """
        token_lookup = self._compute_lookup(session_token)
        session_data = await self._repository.get_consent_session(token_lookup)
        if session_data is None:
            return None

        expires_at_str = session_data.get("expires_at")
        if not expires_at_str:
            return None
        try:
            expires_at = datetime.fromisoformat(expires_at_str)
        except (TypeError, ValueError):
            return None

        if utcnow() > expires_at:
            await self._repository.delete_consent_session(token_lookup)
            return None

        return session_data

    async def delete_consent_session(self, session_token: str) -> None:
        """Delete a consent session."""
        token_lookup = self._compute_lookup(session_token)
        try:
            await self._repository.delete_consent_session(token_lookup)
        except Exception:
            pass


def _default_repository(settings: Settings) -> SessionRepository:
    from authglow.repositories.file.session import FileSessionRepository

    return FileSessionRepository(settings)
