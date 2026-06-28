import os
import shutil
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def _generate_rsa_keys(
    private_key_path: str,
    public_key_path: str,
    secret_key: str = "test-secret-key-for-authglow-testing-32chars!",
):
    from authglow.core.crypto import encrypt_private_key

    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    priv_path = Path(private_key_path)
    priv_path.parent.mkdir(parents=True, exist_ok=True)

    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    encrypted_priv = encrypt_private_key(priv_bytes, secret_key=secret_key)
    with open(priv_path, "wb") as f:
        f.write(encrypted_priv)
    with open(public_key_path, "wb") as f:
        f.write(pub_bytes)


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
        keys_dir=test_keys_dir,
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
        # VAPT-038: drop bcrypt cost to the floor for tests so the
        # full suite stays under a few seconds. Production uses
        # the default 12 (see ``Settings.bcrypt_rounds``).
        bcrypt_rounds=4,
        jwt_auto_rotate=False,
    )
    return settings


@pytest.fixture(autouse=True)
def _override_settings(test_settings):
    """Patch ``authglow.core.config.get_settings`` and ``Settings``
    to return the per-test ``test_settings`` instance, and clear the
    ``@lru_cache`` on the module-level ``get_settings`` so cached
    production Settings from a previous test (or test file) does
    not leak into this one.

    Without the ``cache_clear()`` call, the very first test in a
    worker that calls ``get_settings()`` (or any service that does
    so at ``__init__``) populates the cache with a production
    Settings instance. Subsequent tests in the same worker that
    call ``get_settings`` via a local ``from authglow.core.config
    import get_settings`` binding see the cached value — the
    ``with patch`` block does not invalidate an existing cache
    entry, it only intercepts future lookups by name.
    """
    from authglow.core import config as _config

    _config.get_settings.cache_clear()
    with patch("authglow.core.config.get_settings", return_value=test_settings):
        with patch("authglow.core.config.Settings", return_value=test_settings):
            yield


@pytest.fixture(autouse=True)
def _reset_jwt_singleton():
    """Drop the process-wide :func:`authglow.core.jwt_singleton.get_jwt_service`
    cache between tests so each case reloads the keyring against the
    ``test_settings`` patched by :func:`_override_settings`.
    """
    import asyncio

    from authglow.core.jwt_singleton import reset_jwt_singleton

    yield
    asyncio.run(reset_jwt_singleton())


@pytest.fixture(autouse=True)
def _reset_http_client():
    """Close the :func:`authglow.core.http_client.get_http_client` cache
    between tests so the singleton is rebound to the current event
    loop on next call (the httpx client is loop-bound).
    """
    import asyncio

    from authglow.core.http_client import reset_http_client

    yield
    asyncio.run(reset_http_client())


@pytest.fixture(autouse=True)
def _clear_crypto_caches():
    """Drop the process-wide ``lru_cache`` on the four crypto
    primitives between tests so each case reloads the key
    derivation / lookup hashes against the ``test_settings``
    patched by :func:`_override_settings`.

    Without this, a test that calls e.g.
    :func:`authglow.core.crypto.reset_code_lookup_key` with one
    secret will pollute the cache for every other test in the
    same worker — including parallel workers. The pre-existing
    ``test_password_reset_service::TestVapt022ResetCodeFlow``
    tests were failing in ``-n auto`` because the cache was
    populated by an earlier test (e.g. ``test_cache.py`` with
    ``secret_key="a" * 32``) and never reset between workers.
    """
    from authglow.core import crypto

    crypto._derive_key.cache_clear()
    crypto.hash_index_key.cache_clear()
    crypto.reset_code_lookup_key.cache_clear()
    crypto.verification_code_lookup_key.cache_clear()


@pytest.fixture
def jwt_service(test_settings):
    import asyncio

    from authglow.services.jwt import JWTService

    with patch("authglow.services.jwt.get_settings", return_value=test_settings):
        svc = asyncio.run(JWTService.new())
        return svc


@pytest.fixture
def storage(tmp_path, test_settings):
    from authglow.services.user import UserService as UserStorage

    with patch("authglow.services.user.get_settings", return_value=test_settings):
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
        yield MFAService()


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
        with patch("authglow.services.oauth_client.get_settings", return_value=test_settings):
            with patch("authglow.services.password.get_settings", return_value=test_settings):
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

    with patch("authglow.services.refresh_token.get_settings", return_value=test_settings):
        svc = RefreshTokenService()
        return svc


@pytest.fixture
def password_validator(test_settings):
    from authglow.services.password import PasswordValidator

    with patch("authglow.services.password.get_settings", return_value=test_settings):
        return PasswordValidator()


@pytest.fixture
def session_service(test_settings):
    from authglow.services.session import SessionService

    with patch("authglow.services.session.get_settings", return_value=test_settings):
        return SessionService()


@pytest.fixture
def password_reset_service(test_settings):
    """Fixture for ``PasswordResetService``.

    VAPT-022 cleanup: must use ``yield`` (not ``return``) so the
    ``patch`` on ``authglow.services.password_reset.get_settings``
    stays active for the whole test. ``password_reset.py:47``
    imports ``get_settings`` at module level, so the function
    ``_reset_code_lookup_key`` binds to the local name. The
    ``_override_settings`` autouse fixture patches
    ``authglow.core.config.get_settings`` but does NOT reach
    the per-service local binding — without this yield-based
    patch, the test fails with ``found is None`` because the
    HMAC is computed with the production ``SECRET_KEY``.
    """
    from authglow.services.password_reset import PasswordResetService

    with patch("authglow.services.password_reset.get_settings", return_value=test_settings):
        yield PasswordResetService()


@pytest.fixture
def oauth_client_storage(test_settings):
    from authglow.services.oauth_client import OAuth2ClientStorage

    with patch("authglow.services.oauth_client.get_settings", return_value=test_settings):
        with patch("authglow.services.password.get_settings", return_value=test_settings):
            return OAuth2ClientStorage()


@pytest.fixture
def oauth_consent_service(test_settings):
    from authglow.services.oauth_consent import OAuth2ConsentService

    with patch("authglow.services.oauth_consent.get_settings", return_value=test_settings):
        yield OAuth2ConsentService()


@pytest.fixture
def email_verification_service(test_settings):
    from authglow.services.email_verification import EmailVerificationService

    with patch("authglow.services.email_verification.get_settings", return_value=test_settings):
        with patch("authglow.services.email_verification.UserStorage"):
            svc = EmailVerificationService()
            svc.user_storage = MagicMock()
            yield svc


@pytest.fixture
def rbac_service(test_settings):
    from authglow.services.rbac import RBACService

    with patch("authglow.services.rbac.get_settings", return_value=test_settings):
        yield RBACService()


@pytest.fixture
def user_profile_service(test_settings):
    from authglow.services.user_profile import UserProfileService

    with patch("authglow.services.user_profile.get_settings", return_value=test_settings):
        with patch("authglow.services.user_profile.EmailVerificationService"):
            with patch("authglow.services.user_profile.SecurityNotificationService"):
                svc = UserProfileService()
                svc.user_storage = MagicMock()
                svc.email_service = MagicMock()
                svc.security_service = MagicMock()
                return svc


@pytest.fixture
def oidc_service():
    from authglow.services.oidc import OIDCService

    with patch("authglow.services.oidc.UserStorage"):
        return OIDCService()


@pytest.fixture
def security_notification_service(test_settings):
    from authglow.services.security_notifications import SecurityNotificationService

    with patch(
        "authglow.services.security_notifications.get_settings",
        return_value=test_settings,
    ):
        with patch("authglow.services.security_notifications.get_email_service") as mock:
            mock_email = MagicMock()
            mock.return_value = mock_email
            svc = SecurityNotificationService()
            return svc


@pytest.fixture(autouse=True)
def _ensure_event_loop(request):
    """Ensure an event loop exists for each sync test (Python 3.12+ compat).

    Creates a fresh loop per sync test function.  Async tests are skipped
    because pytest-asyncio manages their loops.
    """
    import asyncio
    import inspect

    if inspect.iscoroutinefunction(request.node.function):
        yield
        return

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    yield
    loop.close()
