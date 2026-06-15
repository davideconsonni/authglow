"""File-system-backed repositories for the WebAuthn / passkey domain.

Two repositories share the same parent storage directory but each
owns its own subdirectory so the File path layout mirrors the
historical on-disk structure of the pre-refactor service:

* ``passkeys/<user_id>_<credential_id>.json`` —
  :class:`FilePasskeyRepository`
* ``challenges/<challenge>.json`` —
  :class:`FileWebAuthnChallengeRepository`

The pre-refactor ``PasskeyService`` used ``fsspec.core.url_to_fs`` to
build its filesystem handle. That call bypassed the Settings-driven
``storage_backend`` selection in ``BaseFileRepository._init_filesystem``,
which means the historical code would have crashed on any non-``file``
backend (e.g. ``s3`` / ``gcs`` / ``abfs``) with a confusing
``ValueError`` from fsspec. Both repositories below resolve their
filesystem via the shared base class, so the FIX is in scope.

Cross-process concurrency: ``update`` on the passkey repository uses
optimistic concurrency (``_version`` field) for ``last_used_at`` /
``sign_count`` updates; the service layer catches
``ConcurrentWriteError`` and retries inside an in-process lock.
"""

from typing import List, Optional

from authglow.core.datetime import utcnow
from authglow.models.passkey import Passkey, PasskeyChallenge
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import (
    PasskeyRepository,
    WebAuthnChallengeRepository,
)


class FilePasskeyRepository(BaseFileRepository, PasskeyRepository):
    """File-backed implementation of :class:`PasskeyRepository`.

    Stores one ``Passkey`` document per ``(user_id, credential_id)``
    pair at ``<storage>/passkeys/<user_id>_<credential_id>.json``.
    The on-disk document is the Pydantic ``model_dump(mode="json")``
    round-trip. ``update`` is CAS-protected via ``_version`` so
    concurrent ``last_used_at`` updates from different processes
    surface as :class:`ConcurrentWriteError` and can be retried.
    """

    _subdir = "passkeys"

    def _path_for(self, user_id: str, credential_id: str) -> str:
        """Return the on-disk path for the ``(user_id, credential_id)``
        passkey document."""
        return self._path(f"{user_id}_{credential_id}.json")

    async def save(self, passkey: Passkey) -> None:
        """Persist a new passkey (no CAS — used for first-time
        registration only)."""
        path = self._path_for(passkey.user_id, passkey.credential_id)
        await self._write_json(path, passkey.model_dump(mode="json"))

    async def get(self, user_id: str, credential_id: str) -> Optional[Passkey]:
        """Return the passkey, or ``None``."""
        path = self._path_for(user_id, credential_id)
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return Passkey(**data)
        except (ValueError, TypeError):
            return None

    async def update(self, passkey: Passkey) -> None:
        """Persist changes to an existing passkey with CAS.

        Raises ``FileNotFoundError`` if the passkey does not exist
        on disk (an ``update`` must not silently create a new file —
        use ``save`` for first-time registration).

        Raises ``ConcurrentWriteError`` if the on-disk ``_version``
        does not match the read-time version (cross-process race).
        The service layer is expected to retry inside an in-process
        lock.
        """
        path = self._path_for(passkey.user_id, passkey.credential_id)
        current_data, version = await self._read_json_versioned(path)
        if current_data is None:
            raise FileNotFoundError(
                f"Passkey {passkey.credential_id} for user "
                f"{passkey.user_id} not found; cannot update"
            )
        await self._write_json_versioned(path, passkey.model_dump(mode="json"), version)

    async def delete(self, user_id: str, credential_id: str) -> bool:
        """Remove the passkey. Returns ``True`` if it existed."""
        path = self._path_for(user_id, credential_id)
        return await self._delete(path)

    async def list_for_user(self, user_id: str) -> List[Passkey]:
        """Return every passkey for a user, sorted by
        ``created_at`` desc."""
        pattern = f"{self._storage_path}/{user_id}_*.json"
        files = await self._glob(pattern)
        passkeys: List[Passkey] = []
        for file_path in files:
            data = await self._read_json(file_path)
            if data is None:
                continue
            try:
                passkeys.append(Passkey(**data))
            except (ValueError, TypeError):
                continue
        passkeys.sort(key=lambda p: p.created_at, reverse=True)
        return passkeys


class FileWebAuthnChallengeRepository(BaseFileRepository, WebAuthnChallengeRepository):
    """File-backed implementation of :class:`WebAuthnChallengeRepository`.

    Stores one ``PasskeyChallenge`` document per challenge string at
    ``<storage>/challenges/<challenge>.json``. The on-disk document is
    the Pydantic ``model_dump(mode="json")`` round-trip. ``get``
    auto-deletes expired challenges on read so the service layer
    treats ``None`` as "absent or expired".
    """

    _subdir = "challenges"

    def _path_for(self, challenge: str) -> str:
        """Return the on-disk path for *challenge*'s document."""
        return self._path(f"{challenge}.json")

    async def save(self, challenge: PasskeyChallenge) -> None:
        """Persist a new challenge (upsert by challenge string)."""
        path = self._path_for(challenge.challenge)
        await self._write_json(path, challenge.model_dump(mode="json"))

    async def get(self, challenge: str) -> Optional[PasskeyChallenge]:
        """Return the challenge, or ``None`` (auto-deletes expired)."""
        path = self._path_for(challenge)
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            parsed = PasskeyChallenge(**data)
        except (ValueError, TypeError):
            return None
        if parsed.expires_at < utcnow():
            await self._delete(path)
            return None
        return parsed

    async def delete(self, challenge: str) -> None:
        """Remove the challenge. No-op if absent."""
        path = self._path_for(challenge)
        await self._delete(path)
