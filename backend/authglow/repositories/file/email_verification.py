"""File-backed persistence for email verification tokens.

Tokens are stored as ``<token_lookup>.json`` (HMAC of the plaintext
token; the plaintext itself is never persisted). The bcrypt-hashed
representation of the token is the only on-disk credential.

The repository owns:

* the file layout and JSON serialisation;
* the Pydantic round-trip (``EmailVerificationToken.model_dump`` /
  ``model_validate``);
* the versioned read / write used by ``mark_token_used``'s CAS
  retry loop (``update`` raises ``ConcurrentWriteError`` on stale
  version);
* the bulk expired-token cleanup that returns a deletion count.

The service layer is responsible for the HMAC lookup computation,
the bcrypt verification of a presented plaintext, the in-process
``named_lock`` that serialises cross-coroutine mark-used calls, and
the multi-entity orchestration in ``verify_email``.
"""

from typing import Optional

from authglow.core.config import Settings
from authglow.core.datetime import utcnow
from authglow.models.email_verification import EmailVerificationToken
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import EmailVerificationRepository


class FileEmailVerificationRepository(BaseFileRepository, EmailVerificationRepository):
    """Persists email-verification tokens one JSON file per lookup.

    File layout::

        <storage_path>/email_verifications/<hmac(plaintext)>.json

    The ``token`` Pydantic field is ``exclude=True``, so the plaintext
    is never serialised — the on-disk payload contains only
    ``token_hash`` (bcrypt) plus the user / expiry metadata.
    """

    _subdir = "email_verifications"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    @staticmethod
    def _filename(token_lookup: str) -> str:
        return f"{token_lookup}.json"

    async def create(self, token: EmailVerificationToken) -> None:
        """Persist a new verification token. Overwrites any prior
        entry for the same lookup."""
        path = self._path(self._filename(token.token_lookup))
        await self._write_json(path, token.model_dump())

    async def get_by_lookup(self, token_lookup: str) -> Optional[EmailVerificationToken]:
        """Return the token with the given lookup, or ``None``.

        Missing file, corrupt JSON, or invalid Pydantic payload all
        return ``None`` (the on-disk state is inherently racy in a
        file-based system).
        """
        path = self._path(self._filename(token_lookup))
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return EmailVerificationToken(**data)
        except Exception:
            return None

    async def update(self, token: EmailVerificationToken) -> None:
        """Persist changes to an existing token via versioned write.

        Raises ``ConcurrentWriteError`` if the file was modified by
        a different process between the read and the write. The
        service layer is responsible for catching this error and
        retrying the read-mutate-write loop (``mark_token_used``).

        The first ``update`` after ``create`` succeeds with
        ``expected_version=0`` (the payload created by ``create``
        has no ``_version`` field, so ``read_json_versioned``
        returns 0 by default). After the first update, the file
        has ``_version: 1`` and the CAS loop protects subsequent
        concurrent updates.
        """
        path = self._path(self._filename(token.token_lookup))
        _, version = await self._read_json_versioned(path)
        await self._write_json_versioned(path, token.model_dump(), version)

    async def delete(self, token_lookup: str) -> None:
        """Remove the token. No-op if absent."""
        path = self._path(self._filename(token_lookup))
        await self._delete(path)

    async def cleanup_expired(self) -> int:
        """Delete every token whose ``expires_at`` is in the past.

        Returns the deletion count. Corrupt or invalid files are
        skipped (a corrupt file is not deleted automatically — it
        will keep failing on the next sweep until an operator
        intervenes).
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
                token = EmailVerificationToken(**data)
            except Exception:
                continue
            if now > token.expires_at:
                await self._delete(path)
                deleted += 1
        return deleted
