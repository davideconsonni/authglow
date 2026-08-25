"""VAPT-039: 72-byte cap is enforced on every Pydantic model
that accepts a NEW password (registration, password change,
password reset confirm, admin set password).

The cap is intentionally NOT applied to the verify-only password
fields (``UserLogin.password``,
``ChangePasswordRequest.current_password``, etc.) so that
legacy accounts with stored long-password hashes (from the
pre-fix silent-truncation era) can still authenticate.
"""

import pytest
from pydantic import ValidationError

from authglow.core.password import BCRYPT_MAX_PASSWORD_BYTES
from authglow.models.admin import SetPasswordRequest
from authglow.models.password_reset import PasswordResetConfirm
from authglow.models.user import RegisterUser, UserCreate
from authglow.models.user_profile import ChangePasswordRequest


def _too_long_ascii_password() -> str:
    return "A" * (BCRYPT_MAX_PASSWORD_BYTES + 1)


def _at_limit_ascii_password() -> str:
    return "A" * BCRYPT_MAX_PASSWORD_BYTES


class TestVapt039NewPasswordCap:
    """All NEW-password fields reject inputs > 72 bytes UTF-8."""

    @pytest.mark.parametrize(
        "model_factory,field_name",
        [
            (lambda pw: UserCreate(email="a@b.com", password=pw), "password"),
            (lambda pw: RegisterUser(email="a@b.com", password=pw), "password"),
            (
                lambda pw: PasswordResetConfirm(reset_code="ABCD-EFGH-JKMN", new_password=pw),
                "new_password",
            ),
            (
                lambda pw: ChangePasswordRequest(current_password="OldP@ss123!", new_password=pw),
                "new_password",
            ),
            (lambda pw: SetPasswordRequest(password=pw), "password"),
        ],
        ids=[
            "UserCreate",
            "RegisterUser",
            "PasswordResetConfirm",
            "ChangePasswordRequest",
            "SetPasswordRequest",
        ],
    )
    def test_too_long_ascii_rejected(self, model_factory, field_name):
        with pytest.raises(ValidationError) as excinfo:
            model_factory(_too_long_ascii_password())
        # The error must mention the field so the client can
        # surface it next to the right input.
        assert field_name in str(excinfo.value)

    @pytest.mark.parametrize(
        "model_factory,field_name",
        [
            (lambda pw: UserCreate(email="a@b.com", password=pw), "password"),
            (lambda pw: RegisterUser(email="a@b.com", password=pw), "password"),
            (
                lambda pw: PasswordResetConfirm(reset_code="ABCD-EFGH-JKMN", new_password=pw),
                "new_password",
            ),
            (
                lambda pw: ChangePasswordRequest(current_password="OldP@ss123!", new_password=pw),
                "new_password",
            ),
            (lambda pw: SetPasswordRequest(password=pw), "password"),
        ],
    )
    def test_at_limit_ascii_accepted(self, model_factory, field_name):
        # No exception: the at-limit password must pass the cap.
        m = model_factory(_at_limit_ascii_password())
        assert getattr(m, field_name) == _at_limit_ascii_password()

    @pytest.mark.parametrize(
        "model_factory",
        [
            lambda pw: UserCreate(email="a@b.com", password=pw),
            lambda pw: RegisterUser(email="a@b.com", password=pw),
            lambda pw: PasswordResetConfirm(reset_code="ABCD-EFGH-JKMN", new_password=pw),
            lambda pw: ChangePasswordRequest(current_password="OldP@ss123!", new_password=pw),
            lambda pw: SetPasswordRequest(password=pw),
        ],
    )
    def test_unicode_over_byte_limit_rejected(self, model_factory):
        # 37 * "ü" = 74 bytes (over 72), even though it's 37 chars.
        over_limit = "ü" * 37
        with pytest.raises(ValidationError):
            model_factory(over_limit)

    def test_error_message_mentions_bcrypt_limit(self):
        # The user-facing message must explain the bcrypt limit so
        # the user understands why their password is rejected.
        with pytest.raises(ValidationError) as excinfo:
            UserCreate(email="a@b.com", password=_too_long_ascii_password())
        # Pydantic wraps the ValueError in a ValidationError; the
        # original message ends up in the str representation.
        assert "72 bytes" in str(excinfo.value)
        assert "bcrypt" in str(excinfo.value)


class TestVapt039VerifyPasswordFieldsNotCapped:
    """Verify-only password fields stay uncapped so legacy
    accounts with pre-fix long-password hashes can still log in."""

    def test_user_login_accepts_long_password(self):
        from authglow.models.user import UserLogin

        long_pw = "A" * 100
        # No exception — the verify path silently truncates to 72
        # bytes (matching the pre-fix behaviour) so existing users
        # are not locked out.
        m = UserLogin(email="a@b.com", password=long_pw)
        assert m.password == long_pw

    def test_change_password_current_uncapped(self):
        long_pw = "A" * 100
        m = ChangePasswordRequest(current_password=long_pw, new_password="NewP@ss123!")
        assert m.current_password == long_pw

    def test_change_email_password_uncapped(self):
        from authglow.models.user_profile import ChangeEmailRequest

        long_pw = "A" * 100
        m = ChangeEmailRequest(new_email="a@b.com", password=long_pw)
        assert m.password == long_pw

    def test_delete_account_password_uncapped(self):
        from authglow.models.user_profile import DeleteAccountRequest

        long_pw = "A" * 100
        m = DeleteAccountRequest(password=long_pw, confirmation="DELETE")
        assert m.password == long_pw
