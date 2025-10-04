"""Password validation and hashing service."""

import re
from typing import List, Optional
from passlib.context import CryptContext
from authglow.core.config import get_settings


pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto"
)


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
        requirements = [
            f"At least {self.settings.password_min_length} characters"
        ]

        if self.settings.password_require_uppercase:
            requirements.append("At least one uppercase letter")

        if self.settings.password_require_lowercase:
            requirements.append("At least one lowercase letter")

        if self.settings.password_require_digits:
            requirements.append("At least one digit")

        if self.settings.password_require_special:
            requirements.append("At least one special character")

        return "; ".join(requirements)


def hash_password(password: str) -> str:
    """Hash a password using bcrypt.

    Bcrypt has a maximum password length of 72 bytes.
    Passwords longer than 72 bytes are truncated.
    """
    # Truncate to 72 bytes to avoid bcrypt errors
    password_bytes = password.encode('utf-8')[:72]
    truncated_password = password_bytes.decode('utf-8', errors='ignore')
    return pwd_context.hash(truncated_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash.

    Bcrypt has a maximum password length of 72 bytes.
    Passwords longer than 72 bytes are truncated to match hashing behavior.
    """
    # Truncate to 72 bytes to match hash_password behavior
    password_bytes = plain_password.encode('utf-8')[:72]
    truncated_password = password_bytes.decode('utf-8', errors='ignore')
    return pwd_context.verify(truncated_password, hashed_password)
