"""File-system-backed repositories for the MFA domain.

Three repositories share the same ``mfa/`` on-disk subdirectory but
each owns its own sub-subdirectory so the File path layout mirrors
the historical on-disk structure of the pre-refactor service:

* ``mfa/backup_codes/<user_id>.json`` — ``FileBackupCodeRepository``
* ``mfa/backup_code_attempts/<user_id>.json`` —
  ``FileBackupCodeAttemptRepository``
* ``mfa/trusted_devices/<device_id>.json`` —
  ``FileTrustedDeviceRepository``

Cross-process concurrency: MFA backup-code redemption is the only
state in this module that needs optimistic concurrency control (a
concurrent ``verify`` from two coroutines must not double-remove the
same code). The CAS is implemented in the ``use_code`` method of
``FileBackupCodeRepository`` — the service layer observes the
boolean return value and does **not** need its own retry loop.

In-process serialisation (``named_lock``) stays in the service layer
because the lock spans multiple repositories (e.g. reading
``backup_codes`` and updating ``backup_code_attempts`` in the same
critical section).
"""

from typing import List, Optional

from authglow.core.concurrency import named_lock
from authglow.core.datetime import utcnow
from authglow.models.mfa import BackupCodeAttempt, BackupCodes, TrustedDevice
from authglow.repositories.file.base import BaseFileRepository
from authglow.repositories.protocols import (
    BackupCodeAttemptRepository,
    BackupCodeRepository,
    TrustedDeviceRepository,
)


class FileBackupCodeRepository(BaseFileRepository, BackupCodeRepository):
    """File-backed implementation of :class:`BackupCodeRepository`.

    Stores one ``BackupCodes`` document per user at
    ``<storage>/mfa/backup_codes/<user_id>.json``. The on-disk
    document is the Pydantic ``model_dump(mode="json")`` round-trip —
    no field-level encryption (the bcrypt hashes inside the ``codes``
    list are already one-way).
    """

    _subdir = "mfa/backup_codes"

    def _path_for(self, user_id: str) -> str:
        """Return the on-disk path for the *user_id*'s document."""
        return self._path(f"{user_id}.json")

    async def save(self, codes: BackupCodes) -> None:
        """Persist (overwrite) the backup-codes set for ``codes.user_id``."""
        path = self._path_for(codes.user_id)
        await self._write_json(path, codes.model_dump(mode="json"))

    async def get(self, user_id: str) -> Optional[BackupCodes]:
        """Return the backup-codes set for *user_id*, or ``None``."""
        path = self._path_for(user_id)
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return BackupCodes(**data)
        except (ValueError, TypeError):
            return None

    async def delete(self, user_id: str) -> None:
        """Remove the backup-codes set. No-op if absent."""
        path = self._path_for(user_id)
        await self._delete(path)

    async def use_code(self, user_id: str, code_hash: str) -> bool:
        """Atomically remove *code_hash* and bump ``used_count``.

        Returns ``True`` if the hash was found and removed, ``False``
        otherwise. Implementation detail: the read-modify-write is
        guarded by an internal lock so two concurrent ``verify`` calls
        on the same user cannot double-remove the same code. We use
        ``named_lock`` (a process-wide singleton) rather than
        ``self._lock`` to ensure the lock spans repository instances
        created in different scopes (the in-process singleton is the
        correctness unit for this critical section, not the
        per-instance attribute).
        """
        lock = named_lock()
        async with lock(f"backup_codes_atomic:{user_id}"):
            current = await self.get(user_id)
            if current is None:
                return False
            if code_hash not in current.codes:
                return False
            current.codes.remove(code_hash)
            current.used_count += 1
            await self.save(current)
            return True


class FileBackupCodeAttemptRepository(BaseFileRepository, BackupCodeAttemptRepository):
    """File-backed implementation of :class:`BackupCodeAttemptRepository`.

    Stores one ``BackupCodeAttempt`` document per user at
    ``<storage>/mfa/backup_code_attempts/<user_id>.json``. Used by
    the service layer to enforce per-user brute-force lockout on
    backup-code verification.
    """

    _subdir = "mfa/backup_code_attempts"

    def _path_for(self, user_id: str) -> str:
        """Return the on-disk path for the *user_id*'s document."""
        return self._path(f"{user_id}.json")

    async def get(self, user_id: str) -> Optional[BackupCodeAttempt]:
        """Return the attempt counter, or ``None``."""
        path = self._path_for(user_id)
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return BackupCodeAttempt(**data)
        except (ValueError, TypeError):
            return None

    async def save(self, attempts: BackupCodeAttempt) -> None:
        """Persist the attempt counter (overwrite)."""
        path = self._path_for(attempts.user_id)
        await self._write_json(path, attempts.model_dump(mode="json"))

    async def delete(self, user_id: str) -> None:
        """Remove the attempt counter. No-op if absent."""
        path = self._path_for(user_id)
        await self._delete(path)


class FileTrustedDeviceRepository(BaseFileRepository, TrustedDeviceRepository):
    """File-backed implementation of :class:`TrustedDeviceRepository`.

    Stores one ``TrustedDevice`` document per device id at
    ``<storage>/mfa/trusted_devices/<device_id>.json``. The on-disk
    document is the Pydantic ``model_dump(mode="json")`` round-trip.

    The ``update`` method (used for ``last_used`` bookkeeping on a
    trusted-device hit) uses optimistic concurrency control via the
    ``_version`` field: a concurrent rotation / revocation from
    another process will surface as ``ConcurrentWriteError`` and the
    service layer retries. The in-process lock is the service
    layer's responsibility (it already holds one for the
    ``is_device_trusted`` critical section).
    """

    _subdir = "mfa/trusted_devices"

    def _path_for(self, device_id: str) -> str:
        """Return the on-disk path for the *device_id*'s document."""
        return self._path(f"{device_id}.json")

    async def add(self, device: TrustedDevice) -> None:
        """Persist a new trusted device."""
        path = self._path_for(device.id)
        await self._write_json(path, device.model_dump(mode="json"))

    async def get(self, device_id: str) -> Optional[TrustedDevice]:
        """Return the device, or ``None``."""
        path = self._path_for(device_id)
        data = await self._read_json(path)
        if data is None:
            return None
        try:
            return TrustedDevice(**data)
        except (ValueError, TypeError):
            return None

    async def update(self, device: TrustedDevice) -> None:
        """Persist changes (e.g. last_used) with optimistic concurrency."""
        path = self._path_for(device.id)
        current_data, version = await self._read_json_versioned(path)
        if current_data is None:
            raise FileNotFoundError(f"TrustedDevice {device.id} not found; cannot update")
        await self._write_json_versioned(path, device.model_dump(mode="json"), version)

    async def delete(self, device_id: str) -> bool:
        """Remove the device. Returns ``True`` if it existed."""
        path = self._path_for(device_id)
        return await self._delete(path)

    async def list_for_user(self, user_id: str) -> List[TrustedDevice]:
        """Return every non-expired trusted device for a user.

        ``expires_at`` filtering is enforced in the repository so the
        service layer can treat the return value as "still trusted".
        """
        return await self._collect(user_id=user_id, include_expired=False)

    async def find_trusted(self, user_id: str, fingerprint: str) -> Optional[TrustedDevice]:
        """Return the device matching ``(user_id, fingerprint)`` if it
        exists and is not expired, or ``None``.

        The File backend scans every device file (no index on
        fingerprint); this is acceptable because trusted devices are
        O(dozens) per user and the lookup is a cold path on the
        ``is_device_trusted`` route. The service layer holds an
        in-process lock for the entire ``find + update last_used``
        critical section.
        """
        devices = await self._collect(user_id=user_id, include_expired=False)
        for device in devices:
            if device.device_fingerprint == fingerprint:
                return device
        return None

    async def cleanup_expired(self) -> int:
        """Delete every expired device. Returns the count."""
        devices = await self._collect(include_expired=True)
        now = utcnow()
        deleted = 0
        for device in devices:
            if device.expires_at <= now:
                if await self._delete(self._path_for(device.id)):
                    deleted += 1
        return deleted

    async def _collect(
        self, *, user_id: Optional[str] = None, include_expired: bool
    ) -> List[TrustedDevice]:
        """Scan ``<storage>/mfa/trusted_devices/*.json`` and return a
        filtered, Pydantic-validated list of devices.

        ``user_id`` filters by owner; ``include_expired`` toggles
        ``expires_at`` enforcement (``True`` is used by
        ``cleanup_expired`` so the sweeper can inspect devices whose
        ``expires_at`` has just passed).
        """
        pattern = f"{self._storage_path}/*.json"
        files = await self._glob(pattern)
        devices: List[TrustedDevice] = []
        for file_path in files:
            data = await self._read_json(file_path)
            if data is None:
                continue
            try:
                device = TrustedDevice(**data)
            except (ValueError, TypeError):
                continue
            if user_id is not None and device.user_id != user_id:
                continue
            if not include_expired:
                if device.expires_at <= utcnow():
                    continue
            devices.append(device)
        return devices
