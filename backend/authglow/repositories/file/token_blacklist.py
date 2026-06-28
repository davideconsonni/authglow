"""File-backed persistence for the JWT revocation blacklist.

One JSON file per revoked JTI so that multiple instances sharing a
single filesystem can detect each other's revocations without restart.
The service layer handles the in-memory cache and sync ``os.path``
checks on the hot path; the repository is responsible for async
hydration, writes, and periodic cleanup.

VAPT-040: the JTI used to appear in the on-disk filename
(``<jti>.json``), so a directory-read attacker could enumerate the
set of revoked JTIs. The fix is to replace the filename with an
HMAC-SHA256 pseudonym derived from the JTI + ``Settings.secret_key``
(same private-key context as the keyring). The file content is
unchanged (just ``{"expires_at": <epoch>}``) because the only
identifier that leaked was the JTI itself, and the filename
HMAC removes that.
"""

import os
from typing import Dict, Optional

from authglow.core.config import Settings
from authglow.core.crypto import hmac_index_filename
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import TokenBlacklistRepository


class FileTokenBlacklistRepository(BaseFileRepository, TokenBlacklistRepository):
    """Persists each revoked JTI as a separate JSON file.

    File layout::

        <storage_path>/token_blacklist/<hmac_pseudonym>.json

    where ``<hmac_pseudonym>`` is the ``agk1:``-prefixed HMAC of
    the JTI. The JTI itself never appears on disk.

    Payload shape::

        {"expires_at": <epoch_float>}

    Expired files are NOT auto-deleted on read — the service or a
    periodic cleanup job is responsible for pruning them.

    VAPT-040: pre-VAPT-040 deployments may still have files
    named ``<plaintext_jti>.json`` on disk. ``load_all`` and
    ``cleanup_expired`` skip them silently (the JSON content
    has the same shape so the on-disk leak is just the filename
    — the next service restart will re-revoke and write the
    new HMAC-named file). The in-memory cache rebuilds
    exclusively from HMAC-named files; legacy files are
    harmless orphans.
    """

    _subdir = "token_blacklist"

    def __init__(self, settings: Optional[Settings] = None) -> None:
        super().__init__(settings)

    @staticmethod
    def _filename(jti: str) -> str:
        """Map a JTI to its on-disk filename (HMAC pseudonym)."""
        return f"{hmac_index_filename(jti)}.json"

    @staticmethod
    def _is_legacy_filename(name: str) -> bool:
        """True for pre-VAPT-040 filenames (plaintext JTI, not a 64-char hex digest).

        VAPT-040 filenames are 64 hex chars (the HMAC-SHA256
        output of the JTI). Legacy plaintext JTI filenames
        are typically shorter (UUIDs, short tokens) and
        contain non-hex characters like ``-`` or ``_``. The
        ``startswith("agk1:")`` check is kept as a secondary
        signature for any tooling that may have written
        older experimental files under the prefix.
        """
        if name.startswith("agk1:"):
            return False
        if len(name) != 64:
            return True
        try:
            int(name, 16)
            return False
        except ValueError:
            return True

    # ------------------------------------------------------------------
    # Protocol: TokenBlacklistRepository
    # ------------------------------------------------------------------

    async def save(self, jti: str, expires_at: float) -> None:
        """Persist or overwrite the entry for *jti*.

        VAPT-040: filename is the JTI's HMAC pseudonym, not the
        JTI itself.
        """
        path = self._path(self._filename(jti))
        await self._write_json(path, {"expires_at": expires_at})

    async def load_all(self) -> Dict[str, float]:
        """Scan the directory and return every ``hmac_pseudonym -> expires_at``.

        VAPT-040: keys are HMAC pseudonyms (not JTIs) — the
        service translates to/from JTIs at the API boundary.
        Pre-VAPT-040 files (plaintext JTI filenames) are
        skipped to keep the in-memory store consistent with
        the on-disk envelope.
        """
        entries: Dict[str, float] = {}
        paths = await self._glob(f"{self._storage_path}/*.json")
        for path in paths:
            basename = os.path.splitext(os.path.basename(path))[0]
            if self._is_legacy_filename(basename):
                continue
            data = await self._read_json(path)
            if data is None:
                continue
            expires = data.get("expires_at")
            if not isinstance(expires, (int, float)):
                continue
            entries[basename] = float(expires)
        return entries

    async def cleanup_expired(self) -> int:
        """Delete every entry whose ``expires_at`` is in the past.

        VAPT-040: legacy plaintext-named files are also
        pruned to avoid leaving orphans on disk that an
        operator would have to clean up by hand.
        """
        import time

        now = time.time()
        removed = 0
        paths = await self._glob(f"{self._storage_path}/*.json")
        for path in paths:
            data = await self._read_json(path)
            if data is None:
                continue
            expires = data.get("expires_at")
            if isinstance(expires, (int, float)) and float(expires) <= now:
                await self._delete(path)
                removed += 1
        return removed

    # ------------------------------------------------------------------
    # Protocol: exists / delete (SYNC hot-path primitives)
    # ------------------------------------------------------------------

    def exists(self, jti: str) -> bool:
        """Hot-path check: is the JTI's HMAC-named file present on disk?

        Implemented with ``os.path`` because the service calls this
        on every cache miss. The cost is one ``stat()`` per
        unknown JTI (typically rare after the in-memory cache
        warms up).

        VAPT-040: looks up the HMAC pseudonym — pre-VAPT-040
        files (plaintext JTI filenames) are not detected.
        """
        import os

        return os.path.isfile(self._path(self._filename(jti)))

    def delete(self, jti: str) -> bool:
        """Delete the HMAC-named file for *jti*. Returns ``True`` if it existed.

        SYNC — paired with :meth:`exists` for the lazy cleanup
        of expired entries on the hot path.

        VAPT-040: deletes the HMAC-named file, not the legacy
        plaintext-named file (the legacy file is not addressed
        by the in-memory cache either, so it would only be
        reaped by :meth:`cleanup_expired`).
        """
        import os

        path = self._path(self._filename(jti))
        try:
            os.remove(path)
            return True
        except FileNotFoundError:
            return False

    # ------------------------------------------------------------------
    # Protocol: cleanup_expired (async bulk)
    # ------------------------------------------------------------------
    # (defined above, alongside ``save`` / ``load_all``)
