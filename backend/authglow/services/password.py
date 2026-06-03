"""Password validation and hashing service."""

import re
from typing import List, Optional

import bcrypt

from authglow.core.config import get_settings


class PasswordValidator:
    """Validate passwords against configurable policy."""

    def __init__(self):
        """Initialize validator with settings."""
        self.settings = get_settings()

    def validate(self, password: str) -> tuple[bool, Optional[List[str]]]:
        """
        Validate password against policy.

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check minimum length
        if len(password) < self.settings.password_min_length:
            errors.append(
                f"Password must be at least {self.settings.password_min_length} characters long"
            )

        # Check for uppercase
        if self.settings.password_require_uppercase and not re.search(r"[A-Z]", password):
            errors.append("Password must contain at least one uppercase letter")

        # Check for lowercase
        if self.settings.password_require_lowercase and not re.search(r"[a-z]", password):
            errors.append("Password must contain at least one lowercase letter")

        # Check for digits
        if self.settings.password_require_digits and not re.search(r"\d", password):
            errors.append("Password must contain at least one digit")

        # Check for special characters
        if self.settings.password_require_special and not re.search(
            r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>/?]", password
        ):
            errors.append("Password must contain at least one special character")

        return len(errors) == 0, errors if errors else None

    def get_policy_description(self) -> str:
        """Get human-readable password policy description."""
        requirements = [f"At least {self.settings.password_min_length} characters"]

        if self.settings.password_require_uppercase:
            requirements.append("At least one uppercase letter")

        if self.settings.password_require_lowercase:
            requirements.append("At least one lowercase letter")

        if self.settings.password_require_digits:
            requirements.append("At least one digit")

        if self.settings.password_require_special:
            requirements.append("At least one special character")

        return "; ".join(requirements)


def _prepare_password_bytes(password: str, max_bytes: int = 72) -> bytes:
    """Encode password as UTF-8 and truncate to max_bytes without splitting multi-byte sequences.

    If truncation lands inside a multi-byte UTF-8 character, the incomplete character
    is stripped entirely to avoid collisions between different passwords that would
    produce the same truncated byte sequence.
    """
    raw = password.encode("utf-8")
    if len(raw) <= max_bytes:
        return raw
    truncated = raw[:max_bytes]
    while truncated and (truncated[-1] & 0xC0) == 0x80:
        truncated = truncated[:-1]
    if truncated and (truncated[-1] & 0xC0) == 0xC0:
        truncated = truncated[:-1]
    return truncated


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Bcrypt has a maximum password length of 72 bytes.
    Passwords longer than 72 bytes are truncated at UTF-8 boundaries.
    """
    password_bytes = _prepare_password_bytes(password)
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash.

    Bcrypt has a maximum password length of 72 bytes.
    Passwords longer than 72 bytes are truncated at UTF-8 boundaries to match hashing behavior.
    """
    password_bytes = _prepare_password_bytes(plain_password)
    return bcrypt.checkpw(password_bytes, hashed_password.encode("utf-8"))
