"""Password strength validation utilities."""

import re
from typing import Tuple


def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Validate password strength.

    Requirements:
    - At least 8 characters
    - Contains at least one letter
    - Contains at least one number or special character

    Args:
        password: Password to validate

    Returns:
        Tuple of (is_valid, message)
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"

    if len(password) > 128:
        return False, "Password must be at most 128 characters long"

    # Check for at least one letter
    if not re.search(r'[a-zA-Z]', password):
        return False, "Password must contain at least one letter"

    # Check for at least one number or special character
    if not re.search(r'[\d\W]', password):
        return False, "Password must contain at least one number or special character"

    return True, "Password is strong"


def calculate_password_strength(password: str) -> int:
    """Calculate password strength score (0-5).

    0: Very Weak
    1: Weak
    2: Fair
    3: Good
    4: Strong
    5: Very Strong

    Args:
        password: Password to evaluate

    Returns:
        Strength score from 0 to 5
    """
    score = 0

    # Length score
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if len(password) >= 16:
        score += 1

    # Character variety
    has_lower = bool(re.search(r'[a-z]', password))
    has_upper = bool(re.search(r'[A-Z]', password))
    has_digit = bool(re.search(r'\d', password))
    has_special = bool(re.search(r'[^\w\s]', password))

    char_variety = sum([has_lower, has_upper, has_digit, has_special])

    if char_variety >= 2:
        score += 1
    if char_variety >= 3:
        score += 1

    return min(score, 5)
