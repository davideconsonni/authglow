import pytest
from authglow.core.password import (
    validate_password_strength,
    calculate_password_strength,
)


class TestValidatePasswordStrength:
    def test_valid_password(self):
        valid, msg = validate_password_strength("SecureP@ss1")
        assert valid is True
        assert "strong" in msg.lower()

    def test_too_short(self):
        valid, msg = validate_password_strength("Sh1!")
        assert valid is False
        assert "8 characters" in msg

    def test_too_long(self):
        valid, msg = validate_password_strength("A" * 129 + "1!")
        assert valid is False
        assert "128" in msg

    def test_exactly_8_chars(self):
        valid, msg = validate_password_strength("Aa1!Aa1!")
        assert valid is True

    def test_exactly_128_chars(self):
        pw = "A" * 126 + "1!"
        valid, msg = validate_password_strength(pw)
        assert valid is True

    def test_no_letters(self):
        valid, msg = validate_password_strength("12345678!@")
        assert valid is False
        assert "letter" in msg.lower()

    def test_no_digits_or_special(self):
        valid, msg = validate_password_strength("abcdefghij")
        assert valid is False
        assert "number" in msg.lower() or "special" in msg.lower()

    def test_letters_and_digits_only(self):
        valid, msg = validate_password_strength("Password123")
        assert valid is True

    def test_letters_and_special_only(self):
        valid, msg = validate_password_strength("Password!@#")
        assert valid is True

    def test_empty_string(self):
        valid, msg = validate_password_strength("")
        assert valid is False

    def test_unicode_password(self):
        valid, msg = validate_password_strength("Pàssw0rd!")
        assert valid is True


class TestCalculatePasswordStrength:
    def test_empty_password(self):
        assert calculate_password_strength("") == 0

    def test_very_short(self):
        assert calculate_password_strength("a") == 0

    def test_min_length_only(self):
        score = calculate_password_strength("aaaaaaaa")
        assert score == 1

    def test_12_chars(self):
        score = calculate_password_strength("aaaaaaaaaaaa")
        assert score >= 2

    def test_16_chars(self):
        score = calculate_password_strength("aaaaaaaaaaaaaaaa")
        assert score >= 3

    def test_variety_2(self):
        score = calculate_password_strength("password1")
        assert score >= 2

    def test_variety_3(self):
        score = calculate_password_strength("Password1")
        assert score >= 3

    def test_variety_4(self):
        score = calculate_password_strength("P@ssw0rd12345678")
        assert score >= 4

    def test_strong_password(self):
        score = calculate_password_strength("MyStr0ng!P@ssw0rd2024")
        assert score == 5

    def test_max_is_5(self):
        score = calculate_password_strength("Th1s!Is@V3ry$L0ng&P0w3rfulP@ssw0rd")
        assert score == 5

    def test_only_lowercase(self):
        score = calculate_password_strength("aaaa")
        assert score == 0

    def test_mixed_case(self):
        score = calculate_password_strength("AaAaAaAa1!")
        assert score >= 3
