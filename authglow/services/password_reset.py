"""Password reset service for managing reset tokens."""

import secrets
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, List
import fsspec

from authglow.models.password_reset import PasswordResetToken
from authglow.core.config import get_settings


class PasswordResetService:
    """Service for managing password reset tokens."""

    def __init__(self, storage_path: str = None):
        """Initialize the password reset service.

        Args:
            storage_path: Path to storage directory (supports s3://, gcs://, etc.)
        """
        settings = get_settings()
        self.storage_path = storage_path or settings.storage_path
        self.reset_path = f"{self.storage_path}/password_resets"
        self.fs = fsspec.filesystem("file")  # Will auto-detect protocol from path

    def _get_token_path(self, token_id: str) -> str:
        """Get file path for a token."""
        return f"{self.reset_path}/{token_id}.json"

    def _generate_token(self) -> tuple[str, str]:
        """Generate a secure random token.

        Returns:
            tuple: (plaintext_token, hashed_token)
        """
        # Generate 32-byte token (256 bits)
        plaintext = secrets.token_urlsafe(32)

        # Hash the token with bcrypt
        token_hash = bcrypt.hashpw(plaintext.encode(), bcrypt.gensalt()).decode()

        return plaintext, token_hash

    async def create_reset_token(
        self,
        user_id: str,
        email: str,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        expires_in_minutes: int = 30
    ) -> tuple[PasswordResetToken, str]:
        """Create a new password reset token.

        Args:
            user_id: User ID requesting reset
            email: User email
            ip_address: IP address of requester
            user_agent: User agent string
            expires_in_minutes: Token expiration time in minutes

        Returns:
            tuple: (PasswordResetToken, plaintext_token)
        """
        plaintext_token, token_hash = self._generate_token()

        reset_token = PasswordResetToken(
            user_id=user_id,
            email=email,
            token_hash=token_hash,
            expires_at=datetime.utcnow() + timedelta(minutes=expires_in_minutes),
            ip_address=ip_address,
            user_agent=user_agent
        )

        # Save token
        token_path = self._get_token_path(reset_token.token_id)
        self.fs.makedirs(self.reset_path, exist_ok=True)

        with self.fs.open(token_path, "w") as f:
            f.write(reset_token.model_dump_json(indent=2))

        return reset_token, plaintext_token

    async def verify_token(self, plaintext_token: str) -> Optional[PasswordResetToken]:
        """Verify a reset token and return the token object if valid.

        Args:
            plaintext_token: The plaintext token to verify

        Returns:
            PasswordResetToken if valid, None otherwise
        """
        # List all tokens
        tokens = await self.list_all_tokens(active_only=True)

        # Try to match the token
        for token in tokens:
            try:
                if bcrypt.checkpw(plaintext_token.encode(), token.token_hash.encode()):
                    # Token matches - check if expired or used
                    if token.is_used:
                        return None

                    if datetime.utcnow() > token.expires_at:
                        return None

                    return token
            except Exception:
                continue

        return None

    async def mark_token_used(self, token_id: str) -> bool:
        """Mark a token as used.

        Args:
            token_id: Token ID to mark as used

        Returns:
            bool: Success status
        """
        token_path = self._get_token_path(token_id)

        if not self.fs.exists(token_path):
            return False

        with self.fs.open(token_path, "r") as f:
            token = PasswordResetToken.model_validate_json(f.read())

        token.is_used = True
        token.used_at = datetime.utcnow()

        with self.fs.open(token_path, "w") as f:
            f.write(token.model_dump_json(indent=2))

        return True

    async def get_token(self, token_id: str) -> Optional[PasswordResetToken]:
        """Get a token by ID.

        Args:
            token_id: Token ID

        Returns:
            PasswordResetToken if found, None otherwise
        """
        token_path = self._get_token_path(token_id)

        if not self.fs.exists(token_path):
            return None

        with self.fs.open(token_path, "r") as f:
            return PasswordResetToken.model_validate_json(f.read())

    async def list_user_tokens(
        self,
        user_id: str,
        active_only: bool = True
    ) -> List[PasswordResetToken]:
        """List all reset tokens for a user.

        Args:
            user_id: User ID
            active_only: Only return active (unused, unexpired) tokens

        Returns:
            List of PasswordResetToken objects
        """
        if not self.fs.exists(self.reset_path):
            return []

        tokens = []
        for file_path in self.fs.ls(self.reset_path):
            if not file_path.endswith(".json"):
                continue

            with self.fs.open(file_path, "r") as f:
                token = PasswordResetToken.model_validate_json(f.read())

                if token.user_id != user_id:
                    continue

                if active_only:
                    if token.is_used or datetime.utcnow() > token.expires_at:
                        continue

                tokens.append(token)

        return sorted(tokens, key=lambda t: t.created_at, reverse=True)

    async def list_all_tokens(
        self,
        active_only: bool = False,
        limit: int = 100,
        offset: int = 0
    ) -> List[PasswordResetToken]:
        """List all reset tokens (admin).

        Args:
            active_only: Only return active tokens
            limit: Maximum number of tokens to return
            offset: Number of tokens to skip

        Returns:
            List of PasswordResetToken objects
        """
        if not self.fs.exists(self.reset_path):
            return []

        tokens = []
        for file_path in self.fs.ls(self.reset_path):
            if not file_path.endswith(".json"):
                continue

            with self.fs.open(file_path, "r") as f:
                token = PasswordResetToken.model_validate_json(f.read())

                if active_only:
                    if token.is_used or datetime.utcnow() > token.expires_at:
                        continue

                tokens.append(token)

        # Sort by created_at descending
        tokens.sort(key=lambda t: t.created_at, reverse=True)

        # Apply pagination
        return tokens[offset:offset + limit]

    async def revoke_user_tokens(self, user_id: str) -> int:
        """Revoke all active tokens for a user.

        Args:
            user_id: User ID

        Returns:
            Number of tokens revoked
        """
        tokens = await self.list_user_tokens(user_id, active_only=True)
        count = 0

        for token in tokens:
            if await self.mark_token_used(token.token_id):
                count += 1

        return count

    async def cleanup_expired_tokens(self) -> int:
        """Delete all expired and used tokens.

        Returns:
            Number of tokens deleted
        """
        if not self.fs.exists(self.reset_path):
            return 0

        count = 0
        for file_path in self.fs.ls(self.reset_path):
            if not file_path.endswith(".json"):
                continue

            with self.fs.open(file_path, "r") as f:
                token = PasswordResetToken.model_validate_json(f.read())

            # Delete if used or expired (older than 24 hours after expiration)
            should_delete = (
                token.is_used or
                datetime.utcnow() > token.expires_at + timedelta(hours=24)
            )

            if should_delete:
                self.fs.rm(file_path)
                count += 1

        return count

    async def get_stats(self) -> dict:
        """Get statistics about password reset tokens.

        Returns:
            Dictionary with stats
        """
        if not self.fs.exists(self.reset_path):
            return {
                "total": 0,
                "active": 0,
                "expired": 0,
                "used": 0
            }

        total = 0
        active = 0
        expired = 0
        used = 0

        now = datetime.utcnow()

        for file_path in self.fs.ls(self.reset_path):
            if not file_path.endswith(".json"):
                continue

            with self.fs.open(file_path, "r") as f:
                token = PasswordResetToken.model_validate_json(f.read())

            total += 1

            if token.is_used:
                used += 1
            elif now > token.expires_at:
                expired += 1
            else:
                active += 1

        return {
            "total": total,
            "active": active,
            "expired": expired,
            "used": used
        }
