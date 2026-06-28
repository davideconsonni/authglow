"""Password validation and hashing service."""

import asyncio
import re
from typing import List, Optional

import bcrypt

from authglow.core.config import get_settings

_BCRYPT_HASH_PREFIX = "$2"
_BCRYPT_ROUNDS_MIN = 4
_BCRYPT_ROUNDS_MAX = 16
_BCRYPT_ROUNDS_DEFAULT = 12


def get_bcrypt_rounds() -> int:
    """Return the configured bcrypt cost factor (VAPT-038).

    Reads from :class:`Settings` so operators can raise the cost
    via the ``BCRYPT_ROUNDS`` env var without touching code.
    The validator in :class:`Settings` already enforces
    ``[_BCRYPT_ROUNDS_MIN, _BCRYPT_ROUNDS_MAX]``; this is a
    safe accessor for hot paths.
    """
    return get_settings().bcrypt_rounds


def _extract_bcrypt_rounds(hashed: str) -> Optional[int]:
    """Extract the cost factor from a bcrypt hash string.

    Accepts the standard ``$2a$NN$...``, ``$2b$NN$...`` and
    ``$2y$NN$...`` prefixes. Returns ``None`` for anything
    that does not look like a bcrypt hash so callers can fall
    back to a verify-without-rehash path.
    """
    if not hashed or not hashed.startswith(_BCRYPT_HASH_PREFIX):
        return None
    parts = hashed.split("$")
    # Layout: ["", "2b", "10", "rest..."]
    if len(parts) < 3:
        return None
    try:
        cost = int(parts[2])
    except ValueError:
        return None
    if cost < _BCRYPT_ROUNDS_MIN or cost > _BCRYPT_ROUNDS_MAX:
        return None
    return cost


def bcrypt_needs_rehash(hashed: str) -> bool:
    """Return True if the stored hash is below the configured cost (VAPT-038).

    A login flow that detects a True result should re-hash the
    plaintext against the current setting and persist the
    new hash — the user is already authenticated at that
    point, so the cost is borne by a successful verify.
    """
    target = get_bcrypt_rounds()
    stored = _extract_bcrypt_rounds(hashed)
    if stored is None:
        return False
    return stored < target


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
    The cost factor is read from :func:`get_bcrypt_rounds` so
    operators can raise it via the ``BCRYPT_ROUNDS`` env var
    (VAPT-038). Existing hashes below the current setting are
    migrated transparently on the next successful login.
    """
    password_bytes = _prepare_password_bytes(password)
    salt = bcrypt.gensalt(rounds=get_bcrypt_rounds())
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash.

    Bcrypt has a maximum password length of 72 bytes.
    Passwords longer than 72 bytes are truncated at UTF-8 boundaries to match hashing behavior.
    """
    password_bytes = _prepare_password_bytes(plain_password)
    return bcrypt.checkpw(password_bytes, hashed_password.encode("utf-8"))


def verify_and_maybe_rehash(
    plain_password: str, hashed_password: str
) -> tuple[bool, Optional[str]]:
    """Verify a password and return a fresh hash if re-hash is needed (VAPT-038).

    Returns:
        ``(is_valid, new_hash_or_None)``:

        * ``(True, new_hash)`` when the password matches and the
          stored hash is below the current ``bcrypt_rounds`` —
          the caller is expected to persist ``new_hash`` to
          replace the on-disk credential. The fresh hash is
          already built from the verified plaintext so the
          caller does not need to call :func:`hash_password`
          again.
        * ``(True, None)`` when the password matches and the
          stored hash already meets the current cost factor.
        * ``(False, None)`` on a mismatch — never returns a
          fresh hash on failure (avoids the timing-attack
          shape where a fail/no-fail comparison leaks the
          "stored cost" property).

    The function never raises on a malformed ``hashed_password``
    so login flows can stay linear: a non-bcrypt blob is
    treated as a non-match (returns ``(False, None)``).
    """
    try:
        is_valid = verify_password(plain_password, hashed_password)
    except (ValueError, TypeError):
        # Malformed hash (e.g. legacy plaintext, truncated row).
        # Treat as a non-match — the caller is expected to fail
        # the login and route through the lockout machinery.
        return False, None
    if not is_valid:
        return False, None
    if bcrypt_needs_rehash(hashed_password):
        return True, hash_password(plain_password)
    return True, None


async def hash_password_async(password: str) -> str:
    """Async wrapper around :func:`hash_password` that offloads the bcrypt work
    to the default thread pool via :func:`asyncio.to_thread`.

    Use this in async request handlers to keep the event loop responsive
    during the ~50-300ms bcrypt computation. The sync function is kept
    untouched for CLI scripts and offline jobs.
    """
    return await asyncio.to_thread(hash_password, password)


async def verify_password_async(plain_password: str, hashed_password: str) -> bool:
    """Async wrapper around :func:`verify_password` that offloads the bcrypt
    work to the default thread pool via :func:`asyncio.to_thread`.

    Use this in async request handlers to keep the event loop responsive
    during the ~50-300ms bcrypt computation. The sync function is kept
    untouched for CLI scripts and offline jobs.
    """
    return await asyncio.to_thread(verify_password, plain_password, hashed_password)


async def verify_and_maybe_rehash_async(
    plain_password: str, hashed_password: str
) -> tuple[bool, Optional[str]]:
    """Async wrapper around :func:`verify_and_maybe_rehash` (VAPT-038).

    Used by login flows. The re-hash path is two bcrypt operations
    on the event-loop-blocking side; running both in a single
    ``asyncio.to_thread`` call keeps the loop responsive.
    """
    return await asyncio.to_thread(verify_and_maybe_rehash, plain_password, hashed_password)
