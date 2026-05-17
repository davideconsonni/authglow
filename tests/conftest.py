import os
import sys
import pytest
import tempfile
import shutil
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def _generate_rsa_keys(private_key_path: str, public_key_path: str):
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    priv_path = Path(private_key_path)
    priv_path.parent.mkdir(parents=True, exist_ok=True)
    with open(priv_path, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    with open(public_key_path, "wb") as f:
        f.write(
            private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )


@pytest.fixture(scope="session")
def session_tmp_dir():
    d = tempfile.mkdtemp(prefix="authglow_test_")
    yield d
    shutil.rmtree(d, ignore_errors=True)


@pytest.fixture(scope="session")
def test_keys_dir(session_tmp_dir):
    keys_dir = os.path.join(session_tmp_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = os.path.join(keys_dir, "private_key.pem")
    pub_path = os.path.join(keys_dir, "public_key.pem")
    _generate_rsa_keys(priv_path, pub_path)
    return keys_dir


@pytest.fixture
def test_settings(tmp_path, test_keys_dir):
    from authglow.core.config import Settings

    storage_path = str(tmp_path / "data" / "users")
    os.makedirs(storage_path, exist_ok=True)

    settings = Settings(
        secret_key="test-secret-key-for-authglow-testing-32chars!",
        storage_path=storage_path,
        storage_backend="file",
        private_key_path=os.path.join(test_keys_dir, "private_key.pem"),
        public_key_path=os.path.join(test_keys_dir, "public_key.pem"),
        app_name="AuthGlow Test",
        oauth2_client_id="test-client-id",
        oauth2_client_secret="test-client-secret",
        password_min_length=8,
        password_require_uppercase=True,
        password_require_lowercase=True,
        password_require_digits=True,
        password_require_special=True,
    )
    return settings


@pytest.fixture(autouse=True)
def _override_settings(test_settings):
    with patch("authglow.core.config.get_settings", return_value=test_settings):
        with patch("authglow.core.config.Settings", return_value=test_settings):
            yield


@pytest.fixture
def jwt_service(test_settings):
    from authglow.services.jwt import JWTService

    with patch("authglow.services.jwt.get_settings", return_value=test_settings):
        svc = JWTService()
        return svc


@pytest.fixture
def storage(tmp_path, test_settings):
    from authglow.services.storage import UserStorage

    with patch("authglow.services.storage.get_settings", return_value=test_settings):
        svc = UserStorage()
        return svc


@pytest.fixture
def test_user():
    from authglow.models.user import User
    from authglow.services.password import hash_password

    return User(
        id="test-user-001",
        email="test@example.com",
        hashed_password=hash_password("TestP@ss123!"),
        is_active=True,
        scopes=["read", "write"],
        mfa_enabled=False,
        mfa_verified=False,
        email_verified=True,
    )


@pytest.fixture
def test_admin_user():
    from authglow.models.user import User
    from authglow.services.password import hash_password

    return User(
        id="admin-user-001",
        email="admin@example.com",
        hashed_password=hash_password("AdminP@ss123!"),
        is_active=True,
        scopes=["read", "write", "admin"],
        email_verified=True,
    )


@pytest.fixture
def mfa_service(test_settings):
    from authglow.services.mfa import MFAService

    with patch("authglow.services.mfa.get_settings", return_value=test_settings):
        svc = MFAService()
        return svc


@pytest.fixture
def audit_service(test_settings):
    from authglow.services.audit import AuditService

    with patch("authglow.services.audit.get_settings", return_value=test_settings):
        svc = AuditService()
        return svc


@pytest.fixture
def oauth2_service(test_settings):
    from authglow.services.oauth2 import OAuth2Service

    with patch("authglow.services.oauth2.get_settings", return_value=test_settings):
        with patch(
            "authglow.services.oauth_client.get_settings", return_value=test_settings
        ):
            with patch(
                "authglow.services.password.get_settings", return_value=test_settings
            ):
                svc = OAuth2Service()
                return svc


@pytest.fixture
def api_key_service(test_settings):
    from authglow.services.api_key import APIKeyService

    with patch("authglow.services.api_key.get_settings", return_value=test_settings):
        svc = APIKeyService()
        return svc


@pytest.fixture
def refresh_token_service(test_settings):
    from authglow.services.refresh_token import RefreshTokenService

    with patch(
        "authglow.services.refresh_token.get_settings", return_value=test_settings
    ):
        svc = RefreshTokenService()
        return svc


@pytest.fixture
def password_validator(test_settings):
    from authglow.services.password import PasswordValidator

    with patch("authglow.services.password.get_settings", return_value=test_settings):
        return PasswordValidator()
