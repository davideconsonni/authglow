import pytest
import tempfile
import os
import warnings
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from authglow.core.config import Settings as _RealSettings


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
    def test_credentials_wildcard_headers_triggers_warning(
        self, test_keys_dir, tmp_path
    ):
        storage_path = str(tmp_path / "data" / "users")
        os.makedirs(storage_path, exist_ok=True)

        with pytest.warns(UserWarning, match="CORS misconfiguration"):
            _RealSettings(
                secret_key="test-secret-key-for-authglow-testing-32chars!",
                storage_path=storage_path,
                storage_backend="file",
                private_key_path=os.path.join(test_keys_dir, "private_key.pem"),
                public_key_path=os.path.join(test_keys_dir, "public_key.pem"),
                cors_allow_credentials=True,
                cors_allowed_headers="*",
            )

    def test_credentials_explicit_headers_no_warning(self, test_keys_dir, tmp_path):
        storage_path = str(tmp_path / "data" / "users")
        os.makedirs(storage_path, exist_ok=True)

        with warnings.catch_warnings(record=True) as record:
            warnings.simplefilter("always")
            _RealSettings(
                secret_key="test-secret-key-for-authglow-testing-32chars!",
                storage_path=storage_path,
                storage_backend="file",
                private_key_path=os.path.join(test_keys_dir, "private_key.pem"),
                public_key_path=os.path.join(test_keys_dir, "public_key.pem"),
                cors_allow_credentials=True,
                cors_allowed_headers="Authorization, Content-Type, X-Requested-With",
            )
        cors_warnings = [w for w in record if "CORS misconfiguration" in str(w.message)]
        assert len(cors_warnings) == 0, (
            f"Bug S4: CORS warning emitted despite explicit headers. "
            f"Got warnings: {[str(w.message) for w in cors_warnings]}"
        )

    def test_no_credentials_wildcard_no_warning(self, test_keys_dir, tmp_path):
        storage_path = str(tmp_path / "data" / "users")
        os.makedirs(storage_path, exist_ok=True)

        with warnings.catch_warnings(record=True) as record:
            warnings.simplefilter("always")
            _RealSettings(
                secret_key="test-secret-key-for-authglow-testing-32chars!",
                storage_path=storage_path,
                storage_backend="file",
                private_key_path=os.path.join(test_keys_dir, "private_key.pem"),
                public_key_path=os.path.join(test_keys_dir, "public_key.pem"),
                cors_allow_credentials=False,
                cors_allowed_headers="*",
            )
        cors_warnings = [w for w in record if "CORS misconfiguration" in str(w.message)]
        assert len(cors_warnings) == 0, (
            f"Bug S4: CORS warning emitted despite credentials=false. "
            f"Got warnings: {[str(w.message) for w in cors_warnings]}"
        )

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
        import main as main_module

        app = main_module.app
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
    def test_services_do_not_use_deprecated_utcnow(self):
        import inspect
        import pkgutil
        import authglow.services as svc_pkg
        import authglow.models as mdl_pkg
        import authglow.api as api_pkg

        offenders = []
        for pkg in (svc_pkg, mdl_pkg, api_pkg):
            for _importer, modname, _ispkg in pkgutil.iter_modules(pkg.__path__):
                mod = __import__(f"{pkg.__name__}.{modname}", fromlist=[""])
                source = inspect.getsource(mod)
                if "datetime.utcnow()" in source:
                    offenders.append(f"{pkg.__name__}.{modname}")

        assert len(offenders) == 0, (
            f"Bug M4: the following modules still use deprecated datetime.utcnow() "
            f"instead of authglow.core.datetime.utcnow(): {', '.join(offenders)}"
        )

    def test_main_py_mounts_oauth2_advanced_router(self):
        import main as main_module
        import inspect

        source = inspect.getsource(main_module)
        assert "oauth2_advanced" in source or "oauth2_advanced_router" in source, (
            "Bug M3: oauth2_advanced router is not mounted in main.py, "
            "making revocation/introspection endpoints unreachable."
        )
