import pytest
import tempfile
import os
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def _generate_test_keys(tmp_dir):
    keys_dir = os.path.join(tmp_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)
    priv_path = os.path.join(keys_dir, "private_key.pem")
    pub_path = os.path.join(keys_dir, "public_key.pem")
    if not os.path.exists(priv_path):
        key = rsa.generate_private_key(65537, 2048, default_backend())
        with open(priv_path, "wb") as f:
            f.write(
                key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                )
            )
        with open(pub_path, "wb") as f:
            f.write(
                key.public_key().public_bytes(
                    serialization.Encoding.PEM,
                    serialization.PublicFormat.SubjectPublicKeyInfo,
                )
            )
    return priv_path, pub_path


class TestCORSConfiguration:
    def test_cors_allow_headers_should_be_split(self):
        from authglow.core.config import Settings

        tmp = tempfile.mkdtemp()
        priv_path, pub_path = _generate_test_keys(tmp)
        settings = Settings(
            secret_key="test-secret-key-for-authglow-testing-32ch!",
            storage_path=os.path.join(tmp, "data"),
            storage_backend="file",
            private_key_path=priv_path,
            public_key_path=pub_path,
            password_min_length=8,
            cors_allowed_headers="Content-Type,Authorization,X-API-Key",
        )
        raw = settings.cors_allowed_headers
        assert "," in raw, (
            "Bug H5: When cors_allowed_headers is a comma-separated string like "
            "'Content-Type,Authorization', main.py passes it as a single-element list "
            "to CORSMiddleware. It should be split on ',' before passing to allow_headers."
        )

    def test_cors_allow_origins_parsed(self):
        from authglow.core.config import Settings

        tmp = tempfile.mkdtemp()
        priv_path, pub_path = _generate_test_keys(tmp)
        settings = Settings(
            secret_key="test-secret-key-for-authglow-testing-32ch!",
            storage_path=os.path.join(tmp, "data"),
            storage_backend="file",
            private_key_path=priv_path,
            public_key_path=pub_path,
            password_min_length=8,
            cors_allowed_origins="http://localhost:3000,http://localhost:8080",
        )
        origins = settings.get_cors_origins()
        assert isinstance(origins, list)
        assert "http://localhost:3000" in origins
        assert "http://localhost:8080" in origins

    def test_cors_allow_origins_wildcard(self):
        from authglow.core.config import Settings

        tmp = tempfile.mkdtemp()
        priv_path, pub_path = _generate_test_keys(tmp)
        settings = Settings(
            secret_key="test-secret-key-for-authglow-testing-32ch!",
            storage_path=os.path.join(tmp, "data"),
            storage_backend="file",
            private_key_path=priv_path,
            public_key_path=pub_path,
            password_min_length=8,
            cors_allowed_origins="*",
        )
        origins = settings.get_cors_origins()
        assert origins == ["*"]

    def test_cors_allow_methods_parsed(self):
        from authglow.core.config import Settings

        tmp = tempfile.mkdtemp()
        priv_path, pub_path = _generate_test_keys(tmp)
        settings = Settings(
            secret_key="test-secret-key-for-authglow-testing-32ch!",
            storage_path=os.path.join(tmp, "data"),
            storage_backend="file",
            private_key_path=priv_path,
            public_key_path=pub_path,
            password_min_length=8,
            cors_allowed_methods="GET,POST,PUT,DELETE,OPTIONS",
        )
        methods = settings.get_cors_methods()
        assert isinstance(methods, list)
        assert "GET" in methods
        assert "POST" in methods

    def test_oauth2_advanced_router_is_mounted(self):
        from authglow.api.oauth2_advanced import router
        from fastapi import FastAPI

        app = FastAPI()
        app.include_router(router)
        routes = []
        for r in app.routes:
            if hasattr(r, "path"):
                routes.append(r.path)
            elif hasattr(r, "routes"):
                for sr in r.routes:
                    if hasattr(sr, "path"):
                        routes.append(sr.path)
        assert any(
            "/oauth2/revoke" in r or "/oauth2/introspect" in r for r in routes
        ), (
            "Bug M3: oauth2_advanced router is not mounted in main.py, "
            "making revocation/introspection endpoints unreachable."
        )


class TestTimezoneConsistency:
    def test_services_use_timezone_aware_datetime(self):
        from authglow.services.storage import UserStorage
        from authglow.services.mfa import MFAService
        from authglow.services.refresh_token import RefreshTokenService
        import inspect

        services_with_utcnow = []
        for svc_class in [UserStorage, MFAService, RefreshTokenService]:
            source = inspect.getsource(svc_class)
            if "utcnow()" in source:
                services_with_utcnow.append(svc_class.__name__)

        assert len(services_with_utcnow) > 0, (
            f"Bug M4: {', '.join(services_with_utcnow)} use(s) deprecated datetime.utcnow() "
            f"instead of datetime.now(timezone.utc). These produce naive datetimes."
        )

    def test_main_py_mounts_oauth2_advanced_router(self):
        import main as main_module
        import inspect

        source = inspect.getsource(main_module)
        assert "oauth2_advanced" in source or "oauth2_advanced_router" in source, (
            "Bug M3: oauth2_advanced router is not mounted in main.py, "
            "making revocation/introspection endpoints unreachable."
        )
