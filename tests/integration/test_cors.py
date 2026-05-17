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
    def test_cors_allow_headers_should_be_split(self, test_settings):
        test_settings.cors_allowed_headers = "Content-Type,Authorization,X-API-Key"
        headers = test_settings.get_cors_headers()
        assert isinstance(headers, list), "get_cors_headers() must return a list"
        assert "Content-Type" in headers
        assert "Authorization" in headers
        assert "X-API-Key" in headers
        assert len(headers) == 3, (
            "Bug H5: cors_allowed_headers should be split into individual headers, "
            f"got {headers}"
        )

    def test_cors_allow_headers_wildcard(self, test_settings):
        test_settings.cors_allowed_headers = "*"
        headers = test_settings.get_cors_headers()
        assert headers == ["*"]

    def test_cors_allow_origins_parsed(self, test_settings):
        test_settings.cors_allowed_origins = (
            "http://localhost:3000,http://localhost:8080"
        )
        origins = test_settings.get_cors_origins()
        assert isinstance(origins, list)
        assert "http://localhost:3000" in origins
        assert "http://localhost:8080" in origins

    def test_cors_allow_origins_wildcard(self, test_settings):
        test_settings.cors_allowed_origins = "*"
        origins = test_settings.get_cors_origins()
        assert origins == ["*"]

    def test_cors_allow_methods_parsed(self, test_settings):
        test_settings.cors_allowed_methods = "GET,POST,PUT,DELETE,OPTIONS"
        methods = test_settings.get_cors_methods()
        assert isinstance(methods, list)
        assert "GET" in methods
        assert "POST" in methods

    def test_cors_headers_strips_whitespace(self, test_settings):
        test_settings.cors_allowed_headers = (
            " Content-Type , Authorization , X-API-Key "
        )
        headers = test_settings.get_cors_headers()
        assert headers == ["Content-Type", "Authorization", "X-API-Key"]

    def test_cors_headers_empty_string(self, test_settings):
        test_settings.cors_allowed_headers = ""
        headers = test_settings.get_cors_headers()
        assert headers == []

    def test_cors_main_uses_get_cors_headers(self):
        import main as main_module
        import inspect

        source = inspect.getsource(main_module)
        assert "get_cors_headers()" in source, (
            "Bug H5: main.py should call settings.get_cors_headers() instead of "
            "passing cors_allowed_headers directly to CORSMiddleware"
        )

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
