"""MFA (TOTP) service for two-factor authentication."""

import base64
import hashlib
import hmac
import io
import os
import secrets
from datetime import timedelta
from typing import List, Optional

import bcrypt
import fsspec
import pyotp
import qrcode

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import named_lock
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.models.mfa import BackupCodeAttempt, BackupCodes, TrustedDevice


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
    """Service for MFA operations."""

    def __init__(self):
        """Initialize MFA service with settings."""
        self.settings = get_settings()
        self.storage_path = f"{self.settings.storage_path}/mfa"
        self.storage_options = self.settings.get_storage_options()

        # Initialize filesystem
        if self.settings.storage_backend == "file":
            os.makedirs(self.storage_path, exist_ok=True)
            os.makedirs(f"{self.storage_path}/backup_codes", exist_ok=True)
            os.makedirs(f"{self.storage_path}/backup_code_attempts", exist_ok=True)
            os.makedirs(f"{self.storage_path}/trusted_devices", exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(self.settings.storage_backend, **self.storage_options)

        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()

    def generate_totp_secret(self) -> str:
        """Generate a new TOTP secret."""
        return pyotp.random_base32()

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

        # Convert to base64
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        img_str = base64.b64encode(buffer.getvalue()).decode()

        return f"data:image/png;base64,{img_str}"

    def verify_totp(self, secret: str, code: str) -> bool:
        """Verify a TOTP code."""
        totp = pyotp.TOTP(secret)
        # Allow 1 period window (30 seconds before/after) for clock drift
        return totp.verify(code, valid_window=1)

    def generate_backup_codes(self, count: int = 10) -> List[str]:
        """Generate backup codes (8 characters, alphanumeric)."""
        codes = []
        for _ in range(count):
            # Generate 8-character code (easier to type than full random)
            code = "".join(secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8))
            # Format as XXXX-XXXX for readability
            formatted = f"{code[:4]}-{code[4:]}"
            codes.append(formatted)
        return codes

    def hash_backup_code(self, code: str) -> str:
        """Hash a backup code for storage."""
        clean_code = code.replace("-", "")
        code_bytes = clean_code.encode("utf-8")[:72]
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(code_bytes, salt).decode("utf-8")

    def verify_backup_code(self, code: str, hashed_code: str) -> bool:
        """Verify a backup code against its hash."""
        clean_code = code.replace("-", "").upper()
        code_bytes = clean_code.encode("utf-8")[:72]
        return bcrypt.checkpw(code_bytes, hashed_code.encode("utf-8"))

    async def save_backup_codes(self, user_id: str, codes: List[str]):
        """Save hashed backup codes for a user."""
        hashed_codes = [self.hash_backup_code(code) for code in codes]

        backup_codes = BackupCodes(user_id=user_id, codes=hashed_codes)

        path = f"{self.storage_path}/backup_codes/{user_id}.json"
        await self._afs.write_json(path, backup_codes.model_dump(mode="json"), indent=2)

    async def get_backup_codes(self, user_id: str) -> Optional[BackupCodes]:
        """Get backup codes for a user."""
        path = f"{self.storage_path}/backup_codes/{user_id}.json"
        try:
            data = await self._afs.read_json(path)
            return BackupCodes(**data)
        except FileNotFoundError:
            return None

    async def verify_user_backup_code(self, user_id: str, code: str) -> bool:
        """Verify a backup code for a user (multi-use).

        Protected by a named lock to prevent concurrent backup code
        verification from corrupting the used_count. Enforces per-user
        brute-force lockout after consecutive failures.

        Raises ``BackupCodeLockedException`` if the user is locked out.
        """
        async with self._lock(f"backup_codes:{user_id}"):
            # --- Lockout check ---
            attempts = await self._get_backup_code_attempts(user_id)
            if attempts and attempts.locked_until:
                if utcnow() < attempts.locked_until:
                    remaining = max(
                        1,
                        int((attempts.locked_until - utcnow()).total_seconds()),
                    )
                    raise BackupCodeLockedException(user_id, remaining)
                # Lockout expired — reset
                await self._reset_backup_code_attempts(user_id)

            backup_codes = await self.get_backup_codes(user_id)
            if not backup_codes:
                return False

            for hashed_code in backup_codes.codes:
                if self.verify_backup_code(code, hashed_code):
                    await self._reset_backup_code_attempts(user_id)
                    backup_codes.used_count += 1
                    path = f"{self.storage_path}/backup_codes/{user_id}.json"
                    await self._afs.write_json(path, backup_codes.model_dump(mode="json"), indent=2)
                    return True

            # Failure
            await self._record_backup_code_failure(user_id)
            return False

    async def _get_backup_code_attempts(self, user_id: str) -> Optional[BackupCodeAttempt]:
        """Get backup code attempt tracking for a user."""
        path = f"{self.storage_path}/backup_code_attempts/{user_id}.json"
        try:
            data = await self._afs.read_json(path)
            return BackupCodeAttempt(**data)
        except FileNotFoundError:
            return None

    async def _save_backup_code_attempts(self, attempts: BackupCodeAttempt):
        """Save backup code attempt tracking."""
        path = f"{self.storage_path}/backup_code_attempts/{attempts.user_id}.json"
        await self._afs.write_json(path, attempts.model_dump(mode="json"), indent=2)

    async def _record_backup_code_failure(self, user_id: str):
        """Record a failed backup code attempt and lock out if threshold reached."""
        existing = await self._get_backup_code_attempts(user_id)
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

        await self._save_backup_code_attempts(attempts)

    async def _reset_backup_code_attempts(self, user_id: str):
        """Reset backup code attempt tracking (on successful verification)."""
        path = f"{self.storage_path}/backup_code_attempts/{user_id}.json"
        try:
            await self._afs.rm(path)
        except FileNotFoundError:
            pass

    async def delete_backup_codes(self, user_id: str):
        """Delete backup codes for a user."""
        path = f"{self.storage_path}/backup_codes/{user_id}.json"
        try:
            await self._afs.rm(path)
        except FileNotFoundError:
            pass

    # Trusted devices management

    def generate_device_fingerprint(self, user_agent: str, ip: str) -> str:
        """Generate a deterministic device fingerprint using HMAC-SHA256."""
        data = f"{user_agent}:{ip}"
        return hmac.new(
            self.settings.secret_key.encode(),
            data.encode(),
            hashlib.sha256,
        ).hexdigest()

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

        path = f"{self.storage_path}/trusted_devices/{device.id}.json"
        await self._afs.write_json(path, device.model_dump(mode="json"), indent=2)

        return device

    async def is_device_trusted(self, user_id: str, device_fingerprint: str) -> bool:
        """Check if a device is trusted and not expired.

        Protected by a named lock on user_id to prevent concurrent
        last_used updates from clobbering each other.
        """
        async with self._lock(f"trusted_devices:{user_id}"):
            try:
                # List all trusted devices for user
                pattern = f"{self.storage_path}/trusted_devices/*.json"
                files = await self._afs.glob(pattern)

                for file_path in files:
                    data = await self._afs.read_json(file_path)
                    device = TrustedDevice(**data)

                    if (
                        device.user_id == user_id
                        and device.device_fingerprint == device_fingerprint
                        and utcnow() < device.expires_at
                    ):
                        # Update last used
                        device.last_used = utcnow()
                        await self._afs.write_json(
                            file_path, device.model_dump(mode="json"), indent=2
                        )

                        return True

                return False
            except Exception:
                return False

    async def list_trusted_devices(self, user_id: str) -> List[TrustedDevice]:
        """List all trusted devices for a user."""
        devices = []
        try:
            pattern = f"{self.storage_path}/trusted_devices/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                data = await self._afs.read_json(file_path)
                device = TrustedDevice(**data)

                if device.user_id == user_id and utcnow() < device.expires_at:
                    devices.append(device)

            return devices
        except Exception:
            return []

    async def remove_trusted_device(self, device_id: str) -> bool:
        """Remove a trusted device."""
        path = f"{self.storage_path}/trusted_devices/{device_id}.json"
        try:
            await self._afs.rm(path)
            return True
        except FileNotFoundError:
            return False

    async def cleanup_expired_devices(self):
        """Remove all expired trusted devices."""
        try:
            pattern = f"{self.storage_path}/trusted_devices/*.json"
            files = await self._afs.glob(pattern)

            for file_path in files:
                data = await self._afs.read_json(file_path)
                device = TrustedDevice(**data)

                if utcnow() >= device.expires_at:
                    await self._afs.rm(file_path)
        except Exception:
            pass
