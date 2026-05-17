import pytest
import base64


class TestPasskeyRegistration:
    def test_exclude_credentials_should_include_existing_passkeys(self):
        from authglow.services.passkey import PasskeyService
        import inspect

        source = inspect.getsource(PasskeyService.generate_registration_options_dict)
        assert "user_passkeys = []" in source, (
            "Bug H6: generate_registration_options_dict hardcodes user_passkeys = [] "
            "which means existing passkeys are never excluded. After remediation, this "
            "hardcoded empty list should be replaced with the actual user's passkeys."
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
