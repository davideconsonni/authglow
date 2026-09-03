import asyncio
import os
import warnings
from pathlib import Path
from unittest.mock import patch

import pytest

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
            Settings.validate_secret_key("your-secret-key-change-in-production-min-32-chars")
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


class TestCorsWildcardCredentialsGuardrail:
    """F3: CORS wildcard origins + credentials is the most dangerous
    CORS combination — Starlette reflects the request Origin, letting
    any origin make credentialed (httpOnly-cookie) requests. It is a
    hard fail at boot in production and a non-blocking warning
    elsewhere."""

    def test_wildcard_credentials_raise_in_production(self, tmp_path):
        with pytest.raises(ValueError, match="CORS misconfiguration"):
            _make_settings_with(
                tmp_path,
                secret_key="k" * 64,
                app_env="production",
                cors_allowed_origins="*",
                cors_allow_credentials=True,
            )

    def test_explicit_origins_ok_in_production(self, tmp_path):
        settings = _make_settings_with(
            tmp_path,
            secret_key="k" * 64,
            app_env="production",
            cors_allowed_origins="https://app.example.com,https://admin.example.com",
            cors_allow_credentials=True,
        )
        assert settings.cors_allowed_origins != "*"
        assert settings.cors_allow_credentials is True

    def test_wildcard_without_credentials_ok_in_production(self, tmp_path):
        settings = _make_settings_with(
            tmp_path,
            secret_key="k" * 64,
            app_env="production",
            cors_allowed_origins="*",
            cors_allow_credentials=False,
        )
        assert settings.cors_allow_credentials is False

    def test_wildcard_credentials_warn_in_development(self, tmp_path):
        with pytest.warns(UserWarning, match="CORS misconfiguration"):
            settings = _make_settings_with(
                tmp_path,
                secret_key="k" * 64,
                app_env="development",
                cors_allowed_origins="*",
                cors_allow_credentials=True,
            )
        assert settings.cors_allowed_origins == "*"

    def test_wildcard_without_credentials_no_warning_in_development(self, tmp_path):
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            settings = _make_settings_with(
                tmp_path,
                secret_key="k" * 64,
                app_env="development",
                cors_allowed_origins="*",
                cors_allow_credentials=False,
            )
        assert not any("CORS misconfiguration" in str(x.message) for x in caught)
        assert settings.app_env == "development"


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
            svc = asyncio.run(JWTService.new())

        token = svc.create_access_token(
            user_id="user-enc", email="enc@example.com", scopes=["read"]
        )
        decoded = svc.decode_token(token)
        assert decoded is not None
        assert decoded.sub == "user-enc"
        assert decoded.email == "enc@example.com"

    def test_encrypted_key_differs_from_plaintext(self):
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        secret = "d" * 32

        from authglow.core.crypto import decrypt_private_key, encrypt_private_key

        encrypted = encrypt_private_key(priv_bytes, secret_key=secret)
        decrypted = decrypt_private_key(encrypted, secret_key=secret)

        assert decrypted == priv_bytes, "Roundtrip must restore original PEM bytes"
        assert encrypted != priv_bytes, "Encrypted data must differ from plaintext"
        assert encrypted.startswith(b"agk1:"), "Must have agk1: prefix"


class TestSetupTokenPersistence:
    """The setup token must be persisted so that uvicorn's reloader
    subprocess and subsequent boots return the same value instead of
    regenerating one (which would leak a stale token to the logs and
    invalidate anything captured from the worker).
    """

    def test_generates_token_on_first_call(self, tmp_path):
        from authglow.core.config import get_or_generate_setup_token

        keys_dir = tmp_path / "keys"
        token = get_or_generate_setup_token(str(keys_dir))

        assert token, "Token must not be empty"
        assert len(token) >= 32, "Token must be at least 32 bytes of entropy"
        assert (keys_dir / "setup_token").exists(), "Token must be persisted to disk"
        assert (keys_dir / "setup_token").read_text(encoding="utf-8").strip() == token

    def test_returns_same_token_on_subsequent_calls(self, tmp_path):
        from authglow.core.config import get_or_generate_setup_token

        keys_dir = tmp_path / "keys"
        first = get_or_generate_setup_token(str(keys_dir))
        # Second call simulates the uvicorn reloader subprocess re-importing
        # the app: it must observe the persisted value, not regenerate.
        second = get_or_generate_setup_token(str(keys_dir))

        assert first == second, "Subsequent calls must return the same persisted token"
        later = [get_or_generate_setup_token(str(keys_dir)) for _ in range(3)]
        assert later == [second] * 3, "All later calls must return the persisted token"

    def test_existing_token_is_preserved_across_reinits(self, tmp_path):
        """If the operator pre-seeds ``setup_token`` (e.g. restored from
        backup), the helper must NOT overwrite it."""
        from authglow.core.config import get_or_generate_setup_token

        keys_dir = tmp_path / "keys"
        (keys_dir).mkdir(parents=True, exist_ok=True)
        preset = "pre-existing-operator-supplied-token-32bytes!!"
        (keys_dir / "setup_token").write_text(preset, encoding="utf-8")

        result = get_or_generate_setup_token(str(keys_dir))

        assert result == preset, "Pre-existing token must be returned as-is"
        assert (keys_dir / "setup_token").read_text(encoding="utf-8") == preset

    def test_blank_file_is_regenerated(self, tmp_path):
        """A whitespace-only or empty file should trigger regeneration
        rather than returning an empty string."""
        from authglow.core.config import get_or_generate_setup_token

        keys_dir = tmp_path / "keys"
        (keys_dir).mkdir(parents=True, exist_ok=True)
        (keys_dir / "setup_token").write_text("   \n  ", encoding="utf-8")

        result = get_or_generate_setup_token(str(keys_dir))

        assert result, "Blank file must be replaced with a real token"
        assert result.strip(), "Regenerated token must be non-empty"

    def test_unreadable_file_falls_back_to_regeneration(self, tmp_path):
        """If the file exists but can't be read (permission denied,
        I/O error), the helper must regenerate so the operator isn't
        permanently locked out of setup."""
        from unittest.mock import patch

        from authglow.core.config import get_or_generate_setup_token

        keys_dir = tmp_path / "keys"
        keys_dir.mkdir(parents=True, exist_ok=True)
        (keys_dir / "setup_token").write_text("stale", encoding="utf-8")

        with patch.object(Path, "read_text", side_effect=OSError("simulated I/O error")):
            result = get_or_generate_setup_token(str(keys_dir))

        assert result, "Must regenerate when the existing file is unreadable"
        assert result != "stale", "Must NOT return the stale content"
        assert (keys_dir / "setup_token").read_text(encoding="utf-8").strip() == result

    def test_writes_atomically_no_tmp_left_behind(self, tmp_path):
        """``os.replace`` must move the temp file into place, leaving no
        ``.tmp`` artifact on success."""
        from authglow.core.config import get_or_generate_setup_token

        keys_dir = tmp_path / "keys"
        get_or_generate_setup_token(str(keys_dir))

        leftover = list(keys_dir.glob("setup_token.tmp"))
        assert leftover == [], f"No tmp file must remain, found: {leftover}"

    def test_settings_init_persists_token(self, tmp_path):
        """End-to-end: ``Settings(...)`` with no ``SETUP_TOKEN`` env var
        must create a persisted file under ``keys_dir``."""
        keys_dir = str(tmp_path / "keys")
        os.makedirs(keys_dir, exist_ok=True)

        settings = Settings(
            secret_key="a" * 32,
            storage_path=str(tmp_path / "data" / "users"),
            storage_backend="file",
            keys_dir=keys_dir,
            private_key_path=str(tmp_path / "keys" / "private_key.pem"),
            public_key_path=str(tmp_path / "keys" / "public_key.pem"),
            jwt_auto_rotate=False,
        )

        token_path = tmp_path / "keys" / "setup_token"
        assert token_path.exists(), "Settings.__init__ must persist the token"
        assert settings.setup_token == token_path.read_text(encoding="utf-8").strip()

    def test_repeated_settings_init_returns_same_token(self, tmp_path):
        """Two ``Settings(...)`` calls in the same process (the reloader
        scenario) must observe the same persisted token."""
        keys_dir = str(tmp_path / "keys")
        os.makedirs(keys_dir, exist_ok=True)

        first = Settings(
            secret_key="a" * 32,
            storage_path=str(tmp_path / "data" / "users"),
            storage_backend="file",
            keys_dir=keys_dir,
            private_key_path=str(tmp_path / "keys" / "private_key.pem"),
            public_key_path=str(tmp_path / "keys" / "public_key.pem"),
            jwt_auto_rotate=False,
        )
        second = Settings(
            secret_key="a" * 32,
            storage_path=str(tmp_path / "data" / "users"),
            storage_backend="file",
            keys_dir=keys_dir,
            private_key_path=str(tmp_path / "keys" / "private_key.pem"),
            public_key_path=str(tmp_path / "keys" / "public_key.pem"),
            jwt_auto_rotate=False,
        )

        assert first.setup_token == second.setup_token, (
            "Reloader subprocess must see the same persisted token as the parent"
        )


class TestVapt038BcryptRoundsValidation:
    """VAPT-038: bcrypt_rounds is configurable and validated."""

    def _valid_settings(self, **overrides):
        import os
        import tempfile

        keys_dir = overrides.pop("keys_dir", tempfile.mkdtemp(prefix="vapt038_keys_"))
        priv = overrides.pop("private_key_path", os.path.join(keys_dir, "private_key.pem"))
        pub = overrides.pop("public_key_path", os.path.join(keys_dir, "public_key.pem"))
        return Settings(
            secret_key="a" * 32,
            storage_path=overrides.pop("storage_path", tempfile.mkdtemp(prefix="vapt038_users_")),
            storage_backend="file",
            keys_dir=keys_dir,
            private_key_path=priv,
            public_key_path=pub,
            jwt_auto_rotate=False,
            **overrides,
        )

    def test_default_rounds_is_12(self):
        s = self._valid_settings()
        assert s.bcrypt_rounds == 12

    def test_rounds_at_lower_bound_accepted(self):
        s = self._valid_settings(bcrypt_rounds=4)
        assert s.bcrypt_rounds == 4

    def test_rounds_at_upper_bound_accepted(self):
        s = self._valid_settings(bcrypt_rounds=16)
        assert s.bcrypt_rounds == 16

    def test_rounds_below_4_rejected(self):
        with pytest.raises(Exception) as excinfo:
            self._valid_settings(bcrypt_rounds=3)
        assert "bcrypt_rounds" in str(excinfo.value).lower() or "between 4 and 16" in str(
            excinfo.value
        )

    def test_rounds_above_16_rejected(self):
        with pytest.raises(Exception) as excinfo:
            self._valid_settings(bcrypt_rounds=17)
        assert "between 4 and 16" in str(excinfo.value)
