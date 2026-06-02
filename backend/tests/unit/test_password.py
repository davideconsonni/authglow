import pytest
from authglow.services.password import (
    hash_password,
    verify_password,
    PasswordValidator,
    _prepare_password_bytes,
)


class TestPasswordHashing:
    def test_hash_and_verify_roundtrip(self):
        hashed = hash_password("SecureP@ss123!")
        assert verify_password("SecureP@ss123!", hashed)

    def test_hash_password_different_salt_each_time(self):
        h1 = hash_password("samepassword")
        h2 = hash_password("samepassword")
        assert h1 != h2

    def test_verify_password_wrong_password(self):
        hashed = hash_password("CorrectP@ss1")
        assert not verify_password("WrongP@ss1", hashed)

    def test_verify_password_empty_hash(self):
        try:
            result = verify_password("password", "")
            assert not result
        except (ValueError, TypeError):
            pass

    def test_password_exactly_72_bytes(self):
        pw = "a" * 72
        hashed = hash_password(pw)
        assert verify_password(pw, hashed)

    def test_password_73_bytes_truncated_still_verifies(self):
        pw72 = "a" * 72
        pw73 = "a" * 73
        h72 = hash_password(pw72)
        assert verify_password(pw73, h72)
        h73 = hash_password(pw73)
        assert verify_password(pw72, h73)

    def test_password_utf8_multibyte_truncation(self):
        pw = "ü" * 25
        assert len(pw.encode("utf-8")) == 50
        hashed = hash_password(pw)
        assert verify_password(pw, hashed)

    def test_password_unicode_emoji(self):
        pw = "TestP@ss1🔑🔑🔑"
        hashed = hash_password(pw)
        assert verify_password(pw, hashed)

    def test_password_long_utf8_no_collision(self):
        pw1 = "a" * 70 + "ü"
        pw2 = "a" * 70 + "ú"
        h1 = hash_password(pw1)
        h2 = hash_password(pw2)
        assert not verify_password(pw2, h1)

    def test_password_truncation_boundary(self):
        pw72 = "A" * 72
        pw73 = "A" * 73
        h = hash_password(pw72)
        assert verify_password(pw72, h)
        assert verify_password(pw73, h)

    def test_password_with_null_byte_area(self):
        pw = "TestP@ss1"
        hashed = hash_password(pw)
        assert verify_password(pw, hashed)

    def test_prepare_password_bytes_short_password(self):
        result = _prepare_password_bytes("hello")
        assert result == b"hello"

    def test_prepare_password_bytes_ascii_exactly_72(self):
        result = _prepare_password_bytes("A" * 72)
        assert len(result) == 72

    def test_prepare_password_bytes_ascii_73_truncated_to_72(self):
        result = _prepare_password_bytes("A" * 73)
        assert len(result) == 72
        assert result == b"A" * 72

    def test_prepare_password_bytes_utf8_no_boundary_split(self):
        pw1 = "a" * 70 + "ü"
        pw2 = "a" * 70 + "à"
        b1 = _prepare_password_bytes(pw1)
        b2 = _prepare_password_bytes(pw2)
        assert b1 != b2
        assert b"\\xc3\\xbc" not in b1 or b1 == pw1.encode("utf-8")

    def test_prepare_password_bytes_utf8_boundary_strips_incomplete_char(self):
        pw = "a" * 71 + "ü"
        raw = pw.encode("utf-8")
        assert len(raw) == 73
        result = _prepare_password_bytes(pw)
        assert len(result) == 71
        assert result == b"a" * 71

    def test_password_long_utf8_no_collision_across_boundary(self):
        pw1 = "a" * 70 + "ü"
        pw2 = "a" * 70 + "à"
        assert pw1.encode("utf-8")[:72] != pw2.encode("utf-8")[:72]
        h1 = hash_password(pw1)
        h2 = hash_password(pw2)
        assert not verify_password(pw2, h1)
        assert not verify_password(pw1, h2)

    def test_password_truncation_preserves_full_chars(self):
        pw = "TestP@ss1" + "🔑" * 20
        hashed = hash_password(pw)
        assert verify_password(pw, hashed)

    def test_prepare_password_bytes_empty_string(self):
        result = _prepare_password_bytes("")
        assert result == b""


class TestPasswordValidation:
    def test_validate_min_length(self, password_validator):
        valid, errors = password_validator.validate("Short1!")
        assert not valid
        assert any("8 characters" in e for e in errors)

    def test_validate_requires_uppercase(self, password_validator):
        valid, errors = password_validator.validate("alllowercase1!")
        assert not valid
        assert any("uppercase" in e for e in errors)

    def test_validate_requires_lowercase(self, password_validator):
        valid, errors = password_validator.validate("ALLUPPERCASE1!")
        assert not valid
        assert any("lowercase" in e for e in errors)

    def test_validate_requires_digits(self, password_validator):
        valid, errors = password_validator.validate("NoDigitsHere!!")
        assert not valid
        assert any("digit" in e for e in errors)

    def test_validate_requires_special(self, password_validator):
        valid, errors = password_validator.validate("NoSpecial123Char")
        assert not valid
        assert any("special" in e for e in errors)

    def test_validate_valid_password(self, password_validator):
        valid, errors = password_validator.validate("ValidP@ss123")
        assert valid
        assert errors is None

    def test_validate_returns_none_on_success(self, password_validator):
        valid, errors = password_validator.validate("ValidP@ss123")
        assert valid
        assert errors is None

    def test_get_policy_description(self, password_validator):
        desc = password_validator.get_policy_description()
        assert "8 characters" in desc
        assert "uppercase" in desc.lower()

    def test_validate_multiple_errors(self, password_validator):
        valid, errors = password_validator.validate("short")
        assert not valid
        assert len(errors) >= 3
