import pytest
import base64
from unittest.mock import MagicMock, patch


class TestPasskeyRegistration:
    def test_exclude_credentials_should_include_existing_passkeys(self):
        from authglow.services.passkey import PasskeyService
        from authglow.models.passkey import Passkey
        from authglow.models.user import User

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

            with patch(
                "authglow.services.passkey.generate_registration_options"
            ) as mock_gen:
                mock_gen.return_value = MagicMock(
                    exclude_credentials=[MagicMock(id=b"\x01\x02")],
                )
                mock_gen.return_value.challenge = b"challenge-bytes"

                with patch(
                    "authglow.services.passkey.options_to_json",
                    return_value='{"challenge":"Y2hhbGxlbmdlLWJ5dGVz"}',
                ):
                    options_dict, challenge_str = (
                        svc.generate_registration_options_dict(
                            user, user_passkeys=[existing]
                        )
                    )

                    call_kwargs = mock_gen.call_args[1]
                    excl = call_kwargs["exclude_credentials"]
                    assert len(excl) == 1, (
                        "exclude_credentials should contain 1 entry for the existing passkey"
                    )

    def test_exclude_credentials_empty_when_no_passkeys(self):
        from authglow.services.passkey import PasskeyService
        from authglow.models.user import User

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

            with patch(
                "authglow.services.passkey.generate_registration_options"
            ) as mock_gen:
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
        from authglow.services.passkey import PasskeyService
        import inspect

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
