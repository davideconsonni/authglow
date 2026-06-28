import base64
from unittest.mock import MagicMock, patch

import pytest


class TestPasskeyRegistration:
    def test_exclude_credentials_should_include_existing_passkeys(self):
        from authglow.models.passkey import Passkey
        from authglow.models.user import User
        from authglow.services.passkey import PasskeyService

        user = User(
            id="user-123",
            email="test@example.com",
            hashed_password="irrelevant",
            first_name="Test",
            last_name="User",
        )

        existing = Passkey(
            credential_id="a1B2c3D4e5F6g7H8i9J0",
            public_key="pk123",
            sign_count=0,
            aaguid="00000000-0000-0000-0000-000000000000",
            user_id="user-123",
            name="My Key",
            device_type="security_key",
        )

        with patch.object(PasskeyService, "__init__", lambda self, *a, **kw: None):
            svc = PasskeyService.__new__(PasskeyService)
            svc.rp_id = "localhost"
            svc.rp_name = "AuthGlow"
            svc.origin = "http://localhost:8000"

            with patch("authglow.services.passkey.generate_registration_options") as mock_gen:
                mock_gen.return_value = MagicMock(
                    exclude_credentials=[MagicMock(id=b"\x01\x02")],
                )
                mock_gen.return_value.challenge = b"challenge-bytes"

                with patch(
                    "authglow.services.passkey.options_to_json",
                    return_value='{"challenge":"Y2hhbGxlbmdlLWJ5dGVz"}',
                ):
                    options_dict, challenge_str = svc.generate_registration_options_dict(
                        user, user_passkeys=[existing]
                    )

                    call_kwargs = mock_gen.call_args[1]
                    excl = call_kwargs["exclude_credentials"]
                    assert len(excl) == 1, (
                        "exclude_credentials should contain 1 entry for the existing passkey"
                    )

    def test_exclude_credentials_empty_when_no_passkeys(self):
        from authglow.models.user import User
        from authglow.services.passkey import PasskeyService

        user = User(
            id="user-456",
            email="new@example.com",
            hashed_password="irrelevant",
            first_name="New",
            last_name="User",
        )

        with patch.object(PasskeyService, "__init__", lambda self, *a, **kw: None):
            svc = PasskeyService.__new__(PasskeyService)
            svc.rp_id = "localhost"
            svc.rp_name = "AuthGlow"
            svc.origin = "http://localhost:8000"

            with patch("authglow.services.passkey.generate_registration_options") as mock_gen:
                mock_gen.return_value = MagicMock(exclude_credentials=[])
                mock_gen.return_value.challenge = b"challenge-bytes"

                with patch(
                    "authglow.services.passkey.options_to_json",
                    return_value='{"challenge":"Y2hhbGxlbmdlLWJ5dGVz"}',
                ):
                    svc.generate_registration_options_dict(user)

                    call_kwargs = mock_gen.call_args[1]
                    excl = call_kwargs["exclude_credentials"]
                    assert excl == [], (
                        "exclude_credentials should be empty when no existing passkeys"
                    )

    def test_credential_id_base64url_parsing(self):
        import inspect

        from authglow.services.passkey import PasskeyService

        source = inspect.getsource(PasskeyService.verify_authentication)
        assert "bytes.fromhex" not in source, (
            "verify_authentication should use base64url_to_bytes for credential_id parsing, "
            "not bytes.fromhex which expects hexadecimal encoding"
        )

    def test_credential_id_base64url_encoding(self):
        credential_id_b64url = "a1B2c3D4e5F6g7H8"
        decoded = base64.urlsafe_b64decode(credential_id_b64url + "==")
        assert isinstance(decoded, bytes)
        assert len(decoded) > 0
        with pytest.raises(ValueError):
            bytes.fromhex(credential_id_b64url)


class TestPasskeyAuditCredentialIdTruncation:
    """VAPT-085 — the ``passkey_login_success`` audit log must not
    emit the full ``credential_id`` (stable per-user-device
    fingerprint). Instead, the first 8 characters are enough to
    correlate events without leaking the full identifier.
    """

    def test_passkey_login_audit_truncates_credential_id(self):
        """Read the route source and verify the audit call passes
        a truncated credential_id (≤ 8 chars)."""
        import inspect

        from authglow.api import passkey as passkey_module

        source = inspect.getsource(passkey_module)
        # The fix is in ``complete_authentication``. Look for the
        # exact pattern that proves the truncation.
        assert 'metadata={"credential_id": verification.credential_id[:8]}' in source, (
            "VAPT-085: api/passkey.py must log a truncated "
            "credential_id ([:8]) in the passkey_login_success "
            "audit event. Full credential_id is a per-user-device "
            "fingerprint and must not hit the audit log."
        )

    def test_credential_id_truncation_keeps_first_8_chars(self):
        """Unit check: ``x[:8]`` for a typical 20-char base64url
        credential_id returns the first 8 characters."""
        credential_id = "a1B2c3D4e5F6g7H8i9J0"
        truncated = credential_id[:8]
        assert len(truncated) == 8
        assert truncated == "a1B2c3D4"
