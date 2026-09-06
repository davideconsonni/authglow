"""MFA (TOTP) service for two-factor authentication."""

import asyncio
import base64
import hashlib
import hmac
import io
import secrets
from datetime import timedelta
from typing import List, Optional

import pyotp
import qrcode

from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.audit_events import AuditEventType
from authglow.models.audit_metadata import TrustedDeviceMetadata
from authglow.models.mfa import BackupCodeAttempt, BackupCodes, TrustedDevice
from authglow.repositories.protocols import (
    BackupCodeAttemptRepository,
    BackupCodeRepository,
    TrustedDeviceRepository,
)
from authglow.services.audit import AuditService
from authglow.services.password import hash_password


class BackupCodeLockedException(Exception):
    """Raised when backup code verification is locked due to too many failures."""

    def __init__(self, user_id: str, retry_after_seconds: int):
        self.user_id = user_id
        self.retry_after_seconds = retry_after_seconds
        super().__init__(
            f"Backup code verification locked for user {user_id}. "
            f"Retry after {retry_after_seconds} seconds."
        )


class MFAService:
    """Service for MFA operations.

    All persistence is delegated to three repositories:

    * ``self._bc_repo`` — :class:`BackupCodeRepository`
    * ``self._attempts_repo`` — :class:`BackupCodeAttemptRepository`
    * ``self._td_repo`` — :class:`TrustedDeviceRepository`

    The repositories are constructed via the corresponding ``get_*``
    factories in :mod:`authglow.repositories.dependencies` so a test
    or alternate deployment can inject a stub / in-memory impl.
    Cross-process concurrency (CAS for trusted-device
    ``last_used`` updates) is surfaced by the repository as
    :class:`ConcurrentWriteError`; the service catches and retries
    inside the in-process lock.
    """

    def __init__(
        self,
        backup_code_repository: Optional["BackupCodeRepository"] = None,
        backup_code_attempt_repository: Optional["BackupCodeAttemptRepository"] = None,
        trusted_device_repository: Optional["TrustedDeviceRepository"] = None,
    ) -> None:
        """Initialize MFA service with settings and repositories.

        All three repository arguments default to ``None`` and are
        resolved lazily via the corresponding FastAPI factory. Tests
        can pass a stub or an in-memory implementation directly.
        """
        from authglow.repositories.dependencies import (
            get_backup_code_attempt_repository,
            get_backup_code_repository,
            get_trusted_device_repository,
        )

        self.settings = get_settings()
        self._bc_repo = backup_code_repository or get_backup_code_repository()
        self._attempts_repo = backup_code_attempt_repository or get_backup_code_attempt_repository()
        self._td_repo = trusted_device_repository or get_trusted_device_repository()
        self._lock = named_lock()
        self.audit_service = AuditService()

    # ------------------------------------------------------------------
    # Pure crypto / QR helpers — no I/O
    # ------------------------------------------------------------------

    def generate_totp_secret(self) -> str:
        """Generate a new TOTP secret using cryptographic randomness."""
        return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")

    def get_totp_uri(self, secret: str, email: str) -> str:
        """Get TOTP provisioning URI for QR code."""
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(name=email, issuer_name=self.settings.app_name)

    def generate_qr_code(self, uri: str) -> str:
        """Generate QR code image as base64 string."""
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")

        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode()

        return f"data:image/png;base64,{img_str}"

    def verify_totp(self, secret: str, code: str) -> bool:
        """Verify a TOTP code."""
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate backup codes (8 characters, alphanumeric)."""
        codes = []
        for _ in range(count):
            code = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)
        return codes

    def hash_backup_code(self, code: str) -> str:
        """Hash a backup code for storage."""
        clean_code = code.replace("-", "")
        return hash_password(clean_code)

    def verify_backup_code(self, code: str, hashed_code: str) -> bool:
        """Verify a backup code against its hash."""
        clean_code = code.replace("-", "").upper()
        from authglow.services.password import verify_password

        return verify_password(clean_code, hashed_code)

    def generate_device_fingerprint(self, user_agent: str, ip: str) -> str:
        """Generate a deterministic device fingerprint using HMAC-SHA256."""
        data = f"{user_agent}:{ip}"
        return hmac.new(
            self.settings.secret_key.encode(),
            data.encode(),
            hashlib.sha256,
        ).hexdigest()

    # ------------------------------------------------------------------
    # Backup codes — persistence
    # ------------------------------------------------------------------

    async def save_backup_codes(self, user_id: str, codes: List[str]):
        """Save hashed backup codes for a user.

        Hashes run concurrently in the thread pool (bcrypt releases the
        GIL), so wall time is one bcrypt cost instead of ``len(codes)``
        sequential costs — and the event loop is never blocked (a sync
        10× bcrypt here made ``/api/mfa/enroll`` take ~3s and stalled
        every other request).
        """
        from authglow.services.password import hash_password_async

        hashed_codes = await asyncio.gather(
            *(hash_password_async(code.replace("-", "")) for code in codes)
        )

        backup_codes = BackupCodes(user_id=user_id, codes=list(hashed_codes))
        await self._bc_repo.save(backup_codes)

    async def get_backup_codes(self, user_id: str) -> Optional[BackupCodes]:
        """Get backup codes for a user."""
        return await self._bc_repo.get(user_id)

    async def delete_backup_codes(self, user_id: str):
        """Delete backup codes for a user."""
        await self._bc_repo.delete(user_id)

    # ------------------------------------------------------------------
    # Backup code verification — guarded by in-process lock
    # ------------------------------------------------------------------

    async def verify_user_backup_code(self, user_id: str, code: str) -> bool:
        """Verify a backup code for a user (single-use).

        Protected by a named lock to prevent concurrent backup code
        verification from corrupting the used_count. Enforces per-user
        brute-force lockout after consecutive failures.

        Raises ``BackupCodeLockedException`` if the user is locked out.
        """
        async with self._lock(f"backup_codes:{user_id}"):
            attempts = await self._attempts_repo.get(user_id)
            if attempts and attempts.locked_until:
                if utcnow() < attempts.locked_until:
                    remaining = max(
                        1,
                        int((attempts.locked_until - utcnow()).total_seconds()),
                    )
                    raise BackupCodeLockedException(user_id, remaining)
                await self._attempts_repo.delete(user_id)
                attempts = None

            backup_codes = await self._bc_repo.get(user_id)
            if not backup_codes:
                return False

            for hashed_code in backup_codes.codes:
                if await asyncio.to_thread(self.verify_backup_code, code, hashed_code):
                    await self._attempts_repo.delete(user_id)
                    await self._bc_repo.use_code(user_id, hashed_code)
                    return True

            await self._record_backup_code_failure(user_id)
            return False

    async def _record_backup_code_failure(self, user_id: str):
        """Record a failed backup code attempt and lock out if threshold reached."""
        existing = await self._attempts_repo.get(user_id)
        if existing is None:
            attempts = BackupCodeAttempt(user_id=user_id, failed_attempts=1)
        else:
            attempts = existing
            attempts.failed_attempts += 1
        attempts.last_attempt_at = utcnow()

        if attempts.failed_attempts >= self.settings.backup_code_max_failed_attempts:
            attempts.locked_until = utcnow() + timedelta(
                seconds=self.settings.backup_code_lockout_seconds
            )

        await self._attempts_repo.save(attempts)

    # ------------------------------------------------------------------
    # Trusted devices — guarded by in-process lock on user
    # ------------------------------------------------------------------

    async def add_trusted_device(
        self, user_id: str, device_fingerprint: str, device_name: Optional[str] = None
    ) -> TrustedDevice:
        """Add a trusted device for a user."""
        device = TrustedDevice(
            user_id=user_id,
            device_fingerprint=device_fingerprint,
            name=device_name,
            expires_at=utcnow() + timedelta(days=30),
        )
        await self._td_repo.add(device)

        # Audit: trusted device added
        await self.audit_service.log_event(
            event_type=AuditEventType.TRUSTED_DEVICE_ADDED,
            user_id=user_id,
            metadata=TrustedDeviceMetadata(
                device_fingerprint=device_fingerprint,
                device_name=device_name,
                expires_at=device.expires_at,
            ),
        )
        return device

    async def is_device_trusted(self, user_id: str, device_fingerprint: str) -> bool:
        """Check if a device is trusted and not expired.

        Protected by a named lock on user_id to prevent concurrent
        last_used updates from clobbering each other. The repository
        ``find_trusted`` already enforces the ``expires_at`` filter
        and matches the (user, fingerprint) pair.
        """
        async with self._lock(f"trusted_devices:{user_id}"):
            for _ in range(5):
                device = await self._td_repo.find_trusted(user_id, device_fingerprint)
                if device is None:
                    return False
                device.last_used = utcnow()
                try:
                    await self._td_repo.update(device)
                    return True
                except ConcurrentWriteError:
                    continue
            return False

    async def list_trusted_devices(self, user_id: str) -> List[TrustedDevice]:
        """List all non-expired trusted devices for a user."""
        return await self._td_repo.list_for_user(user_id)

    async def remove_trusted_device(self, device_id: str) -> bool:
        """Remove a trusted device."""
        # We can't easily get user_id here without fetching the device first
        # The API layer will handle audit logging
        return await self._td_repo.delete(device_id)

    async def cleanup_expired_devices(self):
        """Remove all expired trusted devices."""
        await self._td_repo.cleanup_expired()
