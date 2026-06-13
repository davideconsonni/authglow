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

    def test_underscore_placeholder_warns_in_development(self):
        # The previous validator missed underscore-separated placeholders
        # like the one shipped in the original .env.example.
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Settings.validate_secret_key("your_super_secret_key_for_sessions_at_least_32_chars")
            assert len(w) == 1
            assert "placeholder" in str(w[0].message).lower()

    def test_change_in_production_underscore_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Settings.validate_secret_key("change_in_production_min_32_chars_aaaa")
            assert len(w) == 1

    def test_replace_me_marker_warns(self):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            Settings.validate_secret_key("replace_me_with_a_real_key_aaaaaaaaaaaa")
            assert len(w) == 1


def _make_settings_with(tmp_path, secret_key, app_env, **kwargs):
    storage_path = str(tmp_path / "data" / "users")
    os.makedirs(storage_path, exist_ok=True)
    keys_dir = str(tmp_path / "keys")
    os.makedirs(keys_dir, exist_ok=True)
    settings_kwargs: dict = {
        "secret_key": secret_key,
        "app_env": app_env,
        "debug": False,
        "storage_path": storage_path,
        "storage_backend": "file",
        "keys_dir": keys_dir,
        "private_key_path": str(tmp_path / "keys" / "private_key.pem"),
        "public_key_path": str(tmp_path / "keys" / "public_key.pem"),
        "jwt_auto_rotate": False,
        "oauth2_client_id": "test-client-id",
        "oauth2_client_secret": "test-client-secret",
    }
    settings_kwargs.update(kwargs)
    return Settings(**settings_kwargs)


class TestSecretKeyHardFailsInProduction:
    """A UserWarning is too easy to miss in production logs. An auth server
    starting with a placeholder SECRET_KEY must hard-fail at boot."""

    def test_placeholder_key_raises_in_production(self, tmp_path):
        with pytest.warns(UserWarning, match="placeholder"):
            with pytest.raises(ValueError, match="placeholder"):
                _make_settings_with(
                    tmp_path,
                    secret_key="your-secret-key-change-me-in-production-min-32-chars!",
                    app_env="production",
                )

    def test_underscore_placeholder_raises_in_production(self, tmp_path):
        with pytest.warns(UserWarning, match="placeholder"):
            with pytest.raises(ValueError, match="placeholder"):
                _make_settings_with(
                    tmp_path,
                    secret_key="your_super_secret_key_for_sessions_at_least_32_chars",
                    app_env="production",
                )

    def test_change_in_production_raises_in_production(self, tmp_path):
        with pytest.warns(UserWarning, match="placeholder"):
            with pytest.raises(ValueError, match="placeholder"):
                _make_settings_with(
                    tmp_path,
                    secret_key="change_in_production_min_32_chars_aaaa",
                    app_env="PRODUCTION",
                )

    def test_real_key_starts_in_production(self, tmp_path):
        # 64 hex chars = 32 bytes = a real cryptographic key
        real_key = "a" * 64
        settings = _make_settings_with(tmp_path, secret_key=real_key, app_env="production")
        assert settings.secret_key == real_key
        assert settings.is_production is True

    def test_placeholder_key_only_warns_in_development(self, tmp_path):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            settings = _make_settings_with(
                tmp_path,
                secret_key="your-secret-key-change-me-in-development-min-32!",
                app_env="development",
            )
            assert settings.app_env == "development"
            assert any("placeholder" in str(x.message).lower() for x in w)


class TestOauth2DefaultsHardFailInProduction:
    """VAPT-014: OAuth2 client credentials using placeholder/default values must
    hard-fail at boot in production."""

    def test_placeholder_oauth2_id_raises_in_production(self, tmp_path):
        with pytest.raises(ValueError, match="OAUTH2_CLIENT_ID"):
            _make_settings_with(
                tmp_path,
                secret_key="k" * 64,
                app_env="production",
                oauth2_client_id="default-client-id",
                oauth2_client_secret="unique-non-placeholder-secret-value",
            )

    def test_placeholder_oauth2_secret_raises_in_production(self, tmp_path):
        with pytest.raises(ValueError, match="OAUTH2_CLIENT_SECRET"):
            _make_settings_with(
                tmp_path,
                secret_key="k" * 64,
                app_env="production",
                oauth2_client_id="custom-client-id-for-production",
                oauth2_client_secret="change-me-in-production",
            )

    def test_custom_oauth2_credentials_ok_in_production(self, tmp_path):
        settings = _make_settings_with(
            tmp_path,
            secret_key="k" * 64,
            app_env="production",
            oauth2_client_id="prod-custom-client-id",
            oauth2_client_secret="prod-custom-client-secret-32chars!!",
        )
        assert settings.is_production is True
        assert settings.oauth2_client_id == "prod-custom-client-id"
        assert (
            settings.oauth2_client_secret.get_secret_value()
            == "prod-custom-client-secret-32chars!!"
        )

    def test_placeholder_oauth2_credentials_ok_in_development(self, tmp_path):
        settings = _make_settings_with(
            tmp_path,
            secret_key="k" * 64,
            app_env="development",
            oauth2_client_id="default-client-id",
            oauth2_client_secret="change-me-in-production",
        )
        assert settings.app_env == "development"
        assert settings.oauth2_client_id == "default-client-id"

    def test_placeholder_change_me_raises_in_production(self, tmp_path):
        with pytest.raises(ValueError, match="OAUTH2_CLIENT_ID"):
            _make_settings_with(
                tmp_path,
                secret_key="k" * 64,
                app_env="PRODUCTION",
                oauth2_client_id="change-me-in-production",
                oauth2_client_secret="unique-non-placeholder-secret-value",
            )

    def test_default_client_secret_patterns_blocked(self, tmp_path):
        blocked_defaults = [
            "default-client-id",
            "replace-me",
            "replace_me",
        ]
        for bad_id in blocked_defaults:
            with pytest.raises(ValueError):
                _make_settings_with(
                    tmp_path,
                    secret_key="k" * 64,
                    app_env="production",
                    oauth2_client_id=bad_id,
                    oauth2_client_secret="good-secret-value-for-testing-ok!",
                )


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
            keys_dir=keys_dir,
            private_key_path=str(tmp_path / "keys" / "private_key.pem"),
            public_key_path=str(tmp_path / "keys" / "public_key.pem"),
            jwt_auto_rotate=False,
        )
        assert settings.secret_key == "a" * 32
        assert settings.password_min_length == 8
        assert settings.access_token_expire_minutes == 30


class TestRSAKeyEncryption:
    def test_generated_private_key_is_encrypted_on_disk(self, tmp_path):
        keys_dir = str(tmp_path / "keys")
        secret = "k" * 32
        os.makedirs(keys_dir, exist_ok=True)

        from authglow.core.config import get_or_generate_keyring

        get_or_generate_keyring(keys_dir, secret_key=secret)

        keyring_path = os.path.join(keys_dir, "keyring.json")
        assert os.path.exists(keyring_path), "keyring.json must exist"

        import json

        with open(keyring_path, "r") as f:
            keyring = json.load(f)

        active_kid = keyring["active_kid"]
        priv_path = os.path.join(keys_dir, active_kid, "private_key.pem")
        raw = Path(priv_path).read_bytes()
        assert raw.startswith(b"agk1:"), "Private key must be encrypted with agk1: prefix"
        assert b"BEGIN PRIVATE KEY" not in raw, "Private key must NOT contain plaintext PEM"

    def test_public_key_remains_plaintext(self, tmp_path):
        keys_dir = str(tmp_path / "keys")
        secret = "k" * 32
        os.makedirs(keys_dir, exist_ok=True)

        from authglow.core.config import get_or_generate_keyring

        get_or_generate_keyring(keys_dir, secret_key=secret)

        import json

        with open(os.path.join(keys_dir, "keyring.json"), "r") as f:
            keyring = json.load(f)

        active_kid = keyring["active_kid"]
        pub_path = os.path.join(keys_dir, active_kid, "public_key.pem")
        pub_raw = Path(pub_path).read_bytes()
        assert pub_raw.startswith(b"-----BEGIN PUBLIC KEY-----"), "Public key must remain plain PEM"
        assert b"agk1:" not in pub_raw, "Public key must NOT be encrypted"

    def test_jwt_roundtrip_with_encrypted_key(self, tmp_path):
        keys_dir = str(tmp_path / "keys")
        secret = "r" * 32
        os.makedirs(keys_dir, exist_ok=True)

        from authglow.core.config import get_or_generate_keyring

        get_or_generate_keyring(keys_dir, secret_key=secret)

        settings = Settings(
            secret_key=secret,
            keys_dir=keys_dir,
            storage_path=str(tmp_path / "data" / "users"),
            storage_backend="file",
            private_key_path=str(tmp_path / "keys" / "private_key.pem"),
            public_key_path=str(tmp_path / "keys" / "public_key.pem"),
            jwt_auto_rotate=False,
        )

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

        secret = "d" * 32

        from authglow.core.crypto import encrypt_private_key, decrypt_private_key

        encrypted = encrypt_private_key(priv_bytes, secret_key=secret)
        decrypted = decrypt_private_key(encrypted, secret_key=secret)

        assert decrypted == priv_bytes, "Roundtrip must restore original PEM bytes"
        assert encrypted != priv_bytes, "Encrypted data must differ from plaintext"
        assert encrypted.startswith(b"agk1:"), "Must have agk1: prefix"
