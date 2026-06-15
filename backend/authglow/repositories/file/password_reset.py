"""File-backed persistence for password-reset tokens.

VAPT-022: the same ``PasswordResetToken`` record is indexed by
two HMAC keys — the bearer-token lookup (``token_lookup``) and
the human-friendly reset-code lookup (``code_lookup``). Both
files contain the same JSON payload; ``mark_token_used``,
``cleanup_expired``, and ``delete_by_token_lookup`` operate on
both so the email-based flow and the bearer-token flow always
see the same ``is_used`` / expiry state.

File layout::

    <storage_path>/password_resets/<token_lookup>.json         (primary)
    <storage_path>/password_resets/code_<code_lookup>.json     (mirror)

The repository owns the file layout, the dual-mirror write logic,
and the HMAC computation of the code lookup key (so callers do
not need to compute the code lookup themselves before calling
``create`` or ``update``). The service layer is responsible for
the bcrypt verification of a presented plaintext against the
stored hash, the in-process ``named_lock`` that serialises
cross-coroutine mark-used calls, the CAS retry loop, and the
``generate_reset_code`` helper (alphabet + format).

The on-disk format is ``PasswordResetToken.model_dump_json(indent=2)``
— raw text, not the dict form. This is preserved exactly from the
pre-refactor implementation to keep the existing test fixtures
working without JSON reformatting noise in diffs.
"""

from datetime import timedelta
from typing import Any, Dict, List, Optional

from authglow.core.config import Settings
from authglow.core.crypto import reset_code_lookup_key
from authglow.core.datetime import utcnow
from authglow.models.password_reset import PasswordResetToken
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import PasswordResetRepository

# 24-hour grace period between expiry and hard delete, matching the
# pre-refactor behaviour in ``services/password_reset.py``.
_GRACE_PERIOD = timedelta(hours=24)


class FilePasswordResetRepository(BaseFileRepository, PasswordResetRepository):
    """Persists password-reset tokens with dual-mirror files.

    ``create`` and ``update`` write both the primary file
    (``<token_lookup>.json``) and the mirror file
    (``code_<code_lookup>.json``). ``delete_by_token_lookup``
    and ``cleanup_expired`` delete both. The mirror is
    automatically skipped during ``list_for_user``,
    ``list_all``, and ``stats`` (those operations enumerate
    primary files only — mirrors would double-count).
    """

    _subdir = "password_resets"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    # ------------------------------------------------------------------
    # Path helpers (public — tests use them to inspect / manipulate
    # the on-disk files directly).
    # ------------------------------------------------------------------

    def _token_path(self, token_lookup: str) -> str:
        return self._path(f"{token_lookup}.json")

    def _code_path(self, code_lookup: str) -> str:
        return self._path(f"code_{code_lookup}.json")

    def _code_lookup_for(self, code: str) -> str:
        """HMAC-SHA256 lookup key for a reset code (VAPT-022).

        Exposed for callers that need to know the mirror filename
        (the service's ``verify_by_code`` calls
        ``get_by_code_lookup`` with this value).
        """
        return reset_code_lookup_key(self._settings.secret_key, code)

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create(self, token: PasswordResetToken) -> None:
        """Persist the token to both primary and mirror files."""
        payload = token.model_dump_json(indent=2)
        await self._write_text(self._token_path(token.token_lookup), payload)
        if token.reset_code:
            code_lookup = self._code_lookup_for(token.reset_code)
            await self._write_text(self._code_path(code_lookup), payload)

    async def get_by_token_lookup(self, token_lookup: str) -> Optional[PasswordResetToken]:
        """Return the token by bearer-token lookup, or ``None``."""
        path = self._token_path(token_lookup)
        if not await self._exists(path):
            return None
        content = await self._read_text(path)
        if content is None:
            return None
        try:
            return PasswordResetToken.model_validate_json(content)
        except Exception:
            return None

    async def get_by_code_lookup(self, code_lookup: str) -> Optional[PasswordResetToken]:
        """Return the token by reset-code lookup, or ``None``
        (VAPT-022 email-based flow)."""
        path = self._code_path(code_lookup)
        if not await self._exists(path):
            return None
        content = await self._read_text(path)
        if content is None:
            return None
        try:
            return PasswordResetToken.model_validate_json(content)
        except Exception:
            return None

    async def update(self, token: PasswordResetToken) -> None:
        """Persist changes to both primary and mirror files.

        The on-disk format is raw text (not versioned-JSON), so
        the in-service CAS loop's ``read_json_versioned`` always
        returns version 0 (no ``_version`` field is written) —
        this matches the pre-refactor behaviour exactly. A future
        refactor can layer proper versioned writes here without
        changing the service.
        """
        payload = token.model_dump_json(indent=2)
        await self._write_text(self._token_path(token.token_lookup), payload)
        if token.reset_code:
            code_lookup = self._code_lookup_for(token.reset_code)
            await self._write_text(self._code_path(code_lookup), payload)

    async def delete_by_token_lookup(self, token_lookup: str) -> bool:
        """Delete the token (and its mirror, if any).

        Returns ``True`` if the primary file existed. To delete
        the mirror, the repository reads the primary to recover
        ``reset_code`` and computes the code lookup.
        """
        primary = self._token_path(token_lookup)
        existing = await self._exists(primary)
        if not existing:
            return False
        # Read the primary to find reset_code, then delete the mirror.
        content = await self._read_text(primary)
        if content is not None:
            try:
                token = PasswordResetToken.model_validate_json(content)
                if token.reset_code:
                    code_lookup = self._code_lookup_for(token.reset_code)
                    await self._delete(self._code_path(code_lookup))
            except Exception:
                pass
        await self._delete(primary)
        return True

    # ------------------------------------------------------------------
    # Listing / stats
    # ------------------------------------------------------------------

    async def list_for_user(
        self, user_id: str, active_only: bool = True
    ) -> List[PasswordResetToken]:
        """Return every token for *user_id*, optionally filtered to
        active (unused + unexpired). Skips mirror files."""
        return await self._list_tokens(user_id=user_id, active_only=active_only)

    async def list_all(
        self,
        active_only: bool = False,
        limit: int = 100,
        offset: int = 0,
    ) -> List[PasswordResetToken]:
        """Return a paginated slice of every token (admin)."""
        tokens = await self._list_tokens(active_only=active_only)
        tokens.sort(key=lambda t: t.created_at, reverse=True)
        return tokens[offset : offset + limit]

    async def cleanup_expired(self) -> int:
        """Delete every used or expired token (and its mirror).

        A token is considered eligible for cleanup if it is
        ``is_used`` OR more than 24 hours past its expiry. Returns
        the number of primary files deleted.
        """
        paths = await self._primary_files()
        count = 0
        for path in paths:
            content = await self._read_text(path)
            if content is None:
                continue
            try:
                token = PasswordResetToken.model_validate_json(content)
            except Exception:
                continue
            should_delete = token.is_used or utcnow() > token.expires_at + _GRACE_PERIOD
            if not should_delete:
                continue
            if token.reset_code:
                code_lookup = self._code_lookup_for(token.reset_code)
                await self._delete(self._code_path(code_lookup))
            await self._delete(path)
            count += 1
        return count

    async def stats(self) -> Dict[str, int]:
        """Return ``{total, active, expired, used}`` counts.

        Mirrors are not double-counted (we iterate primary files
        only).
        """
        paths = await self._primary_files()
        total = 0
        active = 0
        expired = 0
        used = 0
        now = utcnow()
        for path in paths:
            content = await self._read_text(path)
            if content is None:
                continue
            try:
                token = PasswordResetToken.model_validate_json(content)
            except Exception:
                continue
            total += 1
            if token.is_used:
                used += 1
            elif now > token.expires_at:
                expired += 1
            else:
                active += 1
        return {"total": total, "active": active, "expired": expired, "used": used}

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _list_tokens(
        self,
        *,
        user_id: Optional[str] = None,
        active_only: bool = True,
    ) -> List[PasswordResetToken]:
        """Common implementation of ``list_for_user`` and
        ``list_all`` (before pagination)."""
        paths = await self._primary_files()
        tokens: List[PasswordResetToken] = []
        for path in paths:
            content = await self._read_text(path)
            if content is None:
                continue
            try:
                token = PasswordResetToken.model_validate_json(content)
            except Exception:
                continue
            if user_id is not None and token.user_id != user_id:
                continue
            if active_only and (token.is_used or utcnow() > token.expires_at):
                continue
            tokens.append(token)
        tokens.sort(key=lambda t: t.created_at, reverse=True)
        return tokens

    async def _primary_files(self) -> List[str]:
        """Enumerate primary token files (skip ``code_*.json`` mirrors)."""
        items: Any = await self._ls()
        if not isinstance(items, list):
            return []
        result: List[str] = []
        for item in items:
            if not isinstance(item, str):
                continue
            if not item.endswith(".json"):
                continue
            # Mirror files have ``code_`` right before the basename.
            basename = item.rsplit("/", 1)[-1]
            if basename.startswith("code_"):
                continue
            result.append(item)
        return result
