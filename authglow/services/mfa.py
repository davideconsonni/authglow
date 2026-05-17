"""MFA (TOTP) service for two-factor authentication."""

import hashlib
import hmac
import io
import json
import os
import secrets
from datetime import datetime, timedelta
from typing import List, Optional, Tuple
import pyotp
import qrcode
import base64
import fsspec
import bcrypt

from authglow.core.config import get_settings
from authglow.models.mfa import BackupCodes, TrustedDevice


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
            os.makedirs(f"{self.storage_path}/trusted_devices", exist_ok=True)
            self.fs = fsspec.filesystem("file")
        else:
            self.fs = fsspec.filesystem(
                self.settings.storage_backend, **self.storage_options
            )

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
            code = "".join(
                secrets.choice("ABCDEFGHJKLMNPQRSTUVWXYZ23456789") for _ in range(8)
            )
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
        with self.fs.open(path, "w") as f:
            json.dump(backup_codes.model_dump(mode="json"), f, indent=2, default=str)

    async def get_backup_codes(self, user_id: str) -> Optional[BackupCodes]:
        """Get backup codes for a user."""
        path = f"{self.storage_path}/backup_codes/{user_id}.json"
        try:
            with self.fs.open(path, "r") as f:
                data = json.load(f)
                return BackupCodes(**data)
        except FileNotFoundError:
            return None

    async def verify_user_backup_code(self, user_id: str, code: str) -> bool:
        """Verify a backup code for a user (multi-use)."""
        backup_codes = await self.get_backup_codes(user_id)
        if not backup_codes:
            return False

        # Check against all codes
        for hashed_code in backup_codes.codes:
            if self.verify_backup_code(code, hashed_code):
                # Increment used count but don't remove (multi-use)
                backup_codes.used_count += 1
                path = f"{self.storage_path}/backup_codes/{user_id}.json"
                with self.fs.open(path, "w") as f:
                    json.dump(
                        backup_codes.model_dump(mode="json"), f, indent=2, default=str
                    )
                return True

        return False

    async def delete_backup_codes(self, user_id: str):
        """Delete backup codes for a user."""
        path = f"{self.storage_path}/backup_codes/{user_id}.json"
        try:
            self.fs.rm(path)
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
            expires_at=datetime.utcnow() + timedelta(days=30),
        )

        path = f"{self.storage_path}/trusted_devices/{device.id}.json"
        with self.fs.open(path, "w") as f:
            json.dump(device.model_dump(mode="json"), f, indent=2, default=str)

        return device

    async def is_device_trusted(self, user_id: str, device_fingerprint: str) -> bool:
        """Check if a device is trusted and not expired."""
        try:
            # List all trusted devices for user
            pattern = f"{self.storage_path}/trusted_devices/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                with self.fs.open(file_path, "r") as f:
                    data = json.load(f)
                    device = TrustedDevice(**data)

                    if (
                        device.user_id == user_id
                        and device.device_fingerprint == device_fingerprint
                        and datetime.utcnow() < device.expires_at
                    ):
                        # Update last used
                        device.last_used = datetime.utcnow()
                        with self.fs.open(file_path, "w") as f:
                            json.dump(
                                device.model_dump(mode="json"), f, indent=2, default=str
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
            files = self.fs.glob(pattern)

            for file_path in files:
                with self.fs.open(file_path, "r") as f:
                    data = json.load(f)
                    device = TrustedDevice(**data)

                    if (
                        device.user_id == user_id
                        and datetime.utcnow() < device.expires_at
                    ):
                        devices.append(device)

            return devices
        except Exception:
            return []

    async def remove_trusted_device(self, device_id: str) -> bool:
        """Remove a trusted device."""
        path = f"{self.storage_path}/trusted_devices/{device_id}.json"
        try:
            self.fs.rm(path)
            return True
        except FileNotFoundError:
            return False

    async def cleanup_expired_devices(self):
        """Remove all expired trusted devices."""
        try:
            pattern = f"{self.storage_path}/trusted_devices/*.json"
            files = self.fs.glob(pattern)

            for file_path in files:
                with self.fs.open(file_path, "r") as f:
                    data = json.load(f)
                    device = TrustedDevice(**data)

                    if datetime.utcnow() >= device.expires_at:
                        self.fs.rm(file_path)
        except Exception:
            pass
