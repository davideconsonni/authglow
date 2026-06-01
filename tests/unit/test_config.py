import pytest
import warnings
import os
from pathlib import Path
from unittest.mock import patch, MagicMock
from authglow.core.config import Settings


class TestSecretKeyValidation:
    def test_valid_secret_key_no_warning(self):
        key = "a" * 32
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = Settings.validate_secret_key(key)
            assert result == key
            assert len(w) == 0

    def test_placeholder_key_triggers_warning(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = Settings.validate_secret_key(
                "your-secret-key-change-in-production-min-32-chars"
            )
            assert len(w) == 1
            assert issubclass(w[0].category, UserWarning)
            assert "placeholder" in str(w[0].message).lower()
            assert "openssl rand -hex 32" in str(w[0].message)

    def test_your_secret_placeholder_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Settings.validate_secret_key("your-secret-key-is-here-aaaaaaaaaaaa")
            assert len(w) == 1

    def test_your_jwt_placeholder_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Settings.validate_secret_key("your-jwt-secret-key-change-me-aaaaa")
            assert len(w) == 1

    def test_your_prefix_placeholder_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Settings.validate_secret_key("your-custom-key-that-is-32-chars-long!")
            assert len(w) == 1

    def test_too_short_key_raises_value_error(self):
        with pytest.raises(ValueError, match="at least 32 characters"):
            Settings.validate_secret_key("short")

    def test_exactly_32_chars_passes(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = Settings.validate_secret_key("x" * 32)
            assert result == "x" * 32
            assert len(w) == 0

    def test_real_hex_key_no_warning(self):
        hex_key = "a" * 64
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = Settings.validate_secret_key(hex_key)
            assert result == hex_key
            assert len(w) == 0

    def test_case_insensitive_placeholder_detection(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Settings.validate_secret_key("YOUR-SECRET-KEY-CHANGE-IN-PRODUCTION-MIN-32")
            assert len(w) == 1


class TestSettingsInstantiation:
    def test_can_create_settings_with_valid_key(self, tmp_path):
        storage_path = str(tmp_path / "data" / "users")
        import os

        os.makedirs(storage_path, exist_ok=True)
        keys_dir = str(tmp_path / "keys")
        os.makedirs(keys_dir, exist_ok=True)

        settings = Settings(
            secret_key="a" * 32,
            storage_path=storage_path,
            storage_backend="file",
            private_key_path=str(tmp_path / "keys" / "private_key.pem"),
            public_key_path=str(tmp_path / "keys" / "public_key.pem"),
        )
        assert settings.secret_key == "a" * 32
        assert settings.password_min_length == 8
        assert settings.access_token_expire_minutes == 30


class TestRSAKeyEncryption:
    def test_generated_private_key_is_encrypted_on_disk(self, tmp_path):
        priv_path = str(tmp_path / "keys" / "private_key.pem")
        pub_path = str(tmp_path / "keys" / "public_key.pem")
        secret = "k" * 32
        os.makedirs(os.path.dirname(priv_path), exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.secret_key = secret
        with patch("authglow.core.crypto.get_settings", return_value=mock_settings):
            from authglow.core.config import get_or_generate_keys

            get_or_generate_keys(priv_path, pub_path)

        raw = Path(priv_path).read_bytes()
        assert raw.startswith(b"agk1:"), (
            "Private key must be encrypted with agk1: prefix"
        )
        assert b"BEGIN PRIVATE KEY" not in raw, (
            "Private key must NOT contain plaintext PEM"
        )

    def test_public_key_remains_plaintext(self, tmp_path):
        priv_path = str(tmp_path / "keys" / "private_key.pem")
        pub_path = str(tmp_path / "keys" / "public_key.pem")
        secret = "k" * 32
        os.makedirs(os.path.dirname(pub_path), exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.secret_key = secret
        with patch("authglow.core.crypto.get_settings", return_value=mock_settings):
            from authglow.core.config import get_or_generate_keys

            get_or_generate_keys(priv_path, pub_path)

        pub_raw = Path(pub_path).read_bytes()
        assert pub_raw.startswith(b"-----BEGIN PUBLIC KEY-----"), (
            "Public key must remain plain PEM"
        )
        assert b"agk1:" not in pub_raw, "Public key must NOT be encrypted"

    def test_jwt_roundtrip_with_encrypted_key(self, tmp_path):
        priv_path = str(tmp_path / "keys" / "private_key.pem")
        pub_path = str(tmp_path / "keys" / "public_key.pem")
        secret = "r" * 32
        os.makedirs(os.path.dirname(priv_path), exist_ok=True)

        mock_settings = MagicMock()
        mock_settings.secret_key = secret

        with patch("authglow.core.crypto.get_settings", return_value=mock_settings):
            from authglow.core.config import get_or_generate_keys

            get_or_generate_keys(priv_path, pub_path)

        settings = Settings(
            secret_key=secret,
            storage_path=str(tmp_path / "data" / "users"),
            storage_backend="file",
            private_key_path=priv_path,
            public_key_path=pub_path,
        )

        with patch("authglow.core.crypto.get_settings", return_value=mock_settings):
            from authglow.services.jwt import JWTService

            with patch("authglow.services.jwt.get_settings", return_value=settings):
                svc = JWTService()

        token = svc.create_access_token(
            user_id="user-enc", email="enc@example.com", scopes=["read"]
        )
        decoded = svc.decode_token(token)
        assert decoded is not None
        assert decoded.sub == "user-enc"
        assert decoded.email == "enc@example.com"

    def test_encrypted_key_differs_from_plaintext(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.backends import default_backend

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        mock_settings = MagicMock()
        mock_settings.secret_key = "d" * 32

        with patch("authglow.core.crypto.get_settings", return_value=mock_settings):
            from authglow.core.crypto import encrypt_private_key, decrypt_private_key

            encrypted = encrypt_private_key(priv_bytes)
            decrypted = decrypt_private_key(encrypted)

        assert decrypted == priv_bytes, "Roundtrip must restore original PEM bytes"
        assert encrypted != priv_bytes, "Encrypted data must differ from plaintext"
        assert encrypted.startswith(b"agk1:"), "Must have agk1: prefix"
