"""File-backed persistence for phone verification OTP tokens.

The record is indexed by the HMAC of ``phone:code`` (the
``code_lookup`` field). The file layout is a single file per token::

    <storage_path>/phone_verifications/<code_lookup>.json

The plaintext numeric ``code`` is stored in the JSON body
(intentional, mirroring the email-verification flow). The on-disk
HMAC filename plus the short single-use window provide the security
model — there is no bearer token for this flow.

The repository owns the file layout, JSON serialisation, Pydantic
round-trip, versioned read / write (CAS), per-phone listing (used by
the service for rate limiting), and bulk expired-token cleanup. The
service layer owns HMAC computation, constant-time code comparison,
attempt counting, and user-state orchestration.
"""

from typing import List, Optional

from authglow.core.config import Settings
from authglow.core.datetime import utcnow
from authglow.models.phone_verification import PhoneVerificationToken
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import PhoneVerificationRepository


class FilePhoneVerificationRepository(BaseFileRepository, PhoneVerificationRepository):
    """Persists phone-verification tokens one JSON file per code lookup.

    File layout::

        <storage_path>/phone_verifications/<hmac(phone:code)>.json
    """

    _subdir = "phone_verifications"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    @staticmethod
    def _filename(code_lookup: str) -> str:
        return f"{code_lookup}.json"

    async def create(self, token: PhoneVerificationToken) -> None:
        """Persist a new verification token. Overwrites any prior
        entry for the same lookup."""
        path = self._path(self._filename(token.code_lookup))
        await self._write_json(path, token.model_dump(mode="json"))

    async def get_by_lookup(self, code_lookup: str) -> Optional[PhoneVerificationToken]:
        """Return the token with the given lookup, or ``None``.

        Missing file, corrupt JSON, or invalid Pydantic payload all
        return ``None``.
        """
        path = self._path(self._filename(code_lookup))
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return PhoneVerificationToken(**data)
        except Exception:
            return None

    async def update(self, token: PhoneVerificationToken) -> None:
        """Persist changes via versioned write.

        Raises ``ConcurrentWriteError`` on cross-process races; the
        service layer retries the read-mutate-write loop.
        """
        path = self._path(self._filename(token.code_lookup))
        _, version = await self._read_json_versioned(path)
        await self._write_json_versioned(path, token.model_dump(mode="json"), version)

    async def delete(self, code_lookup: str) -> None:
        """Remove the token. No-op if absent."""
        path = self._path(self._filename(code_lookup))
        await self._delete(path)

    async def list_for_phone(self, phone: str) -> List[PhoneVerificationToken]:
        """Return every token issued for a phone number.

        Used by the service for per-number rate limiting (sends per
        hour + resend cooldown). Corrupt files are skipped.
        """
        glob_pattern = f"{self._storage_path}/*.json"
        paths = await self._glob(glob_pattern)
        tokens: List[PhoneVerificationToken] = []
        for path in paths:
            data = await self._read_json(path)
            if data is None:
                continue
            try:
                token = PhoneVerificationToken(**data)
            except Exception:
                continue
            if token.phone == phone:
                tokens.append(token)
        return tokens

    async def cleanup_expired(self) -> int:
        """Delete every token whose ``expires_at`` is in the past.

        Returns the deletion count. Corrupt files are skipped.
        """
        glob_pattern = f"{self._storage_path}/*.json"
        paths = await self._glob(glob_pattern)
        now = utcnow()
        deleted = 0
        for path in paths:
            data = await self._read_json(path)
            if data is None:
                continue
            try:
                token = PhoneVerificationToken(**data)
            except Exception:
                continue
            if now > token.expires_at:
                await self._delete(path)
                deleted += 1
        return deleted
