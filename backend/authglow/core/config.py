"""Configuration management for AuthGlow."""

import asyncio
import os
import secrets
import warnings
from functools import lru_cache
from pathlib import Path
from typing import Any, Optional

import structlog
from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

# Re-exports for tests / external code that imports these
# helpers from ``authglow.core.config``. The implementation
# lives in ``authglow.repositories.file.keystore``; we re-export
# via module-level ``__getattr__`` to avoid the circular import
# (the repository imports from ``authglow.repositories.file.base``
# which imports from this module).
__all__ = [  # noqa: F822
    "Settings",
    "get_settings",
    "get_or_generate_keyring",
    "get_or_generate_setup_token",
    "_KEYRING_FILENAME",
    "_generate_key_pair",
    "_new_kid",
]


def __getattr__(name: str) -> Any:
    if name in {"_KEYRING_FILENAME", "_generate_key_pair", "_new_kid"}:
        from authglow.repositories.file.keystore import (
            _KEYRING_FILENAME as _kr_filename,
        )
        from authglow.repositories.file.keystore import (
            _generate_key_pair as _kr_gen,
        )
        from authglow.repositories.file.keystore import (
            _new_kid as _kr_new_kid,
        )

        globals()["_KEYRING_FILENAME"] = _kr_filename
        globals()["_generate_key_pair"] = _kr_gen
        globals()["_new_kid"] = _kr_new_kid
        return globals()[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def get_or_generate_keyring(
    keys_dir: str,
    secret_key: str,
    rotation_days: int = 90,
    auto_rotate: bool = True,
    key_size: int = 2048,
) -> None:
    """Ensure the RSA keyring exists on the fsspec backend.

    Delegates every I/O operation to
    :class:`FileKeyStoreRepository`:

    1. If the keyring is missing, bootstrap it (migrate the
       legacy single-key layout if present, otherwise generate
       a fresh key).
    2. If ``auto_rotate`` is set, rotate the active key when
       it's older than ``rotation_days``.

    This is a startup-only function: it runs once when
    :class:`Settings` is first instantiated.

    Implementation: the repository is built with the fsspec
    **sync** filesystem (the same fsspec layer every other
    entity uses, selected by ``Settings.storage_backend``).
    The bootstrap / auto-rotate paths are executed through a
    private synchronous driver that uses ``asyncio.run`` in a
    way that saves and restores the calling thread's current
    event loop — so calling this from a sync test fixture
    (e.g. :func:`tests.conftest.test_settings`) does not break
    subsequent ``asyncio.get_event_loop()`` calls in the same
    thread.
    """
    from authglow.repositories.file.keystore import (
        FileKeyStoreRepository,
    )

    repo = FileKeyStoreRepository.for_keys_dir(
        keys_dir=keys_dir, secret_key=secret_key, key_size=key_size
    )

    # Save the calling thread's current event loop (if any)
    # and restore it after ``asyncio.run`` returns. Without
    # this, callers that already had a loop set (e.g. the
    # ``_ensure_event_loop`` autouse fixture in tests/conftest)
    # would silently lose it after the first ``Settings``
    # instantiation, breaking the next ``asyncio.get_event_loop()``
    # call in the same thread.
    try:
        previous_loop = asyncio.get_event_loop()
    except RuntimeError:
        previous_loop = None

    async def _run() -> None:
        await repo.bootstrap_if_missing(secret_key=secret_key, key_size=key_size)
        if auto_rotate:
            await repo.auto_rotate_if_needed(
                secret_key=secret_key,
                rotation_days=rotation_days,
                key_size=key_size,
            )

    try:
        asyncio.run(_run())
    finally:
        if previous_loop is not None:
            try:
                asyncio.set_event_loop(previous_loop)
            except RuntimeError:
                # The previous loop is already closed (e.g. the
                # conftest's ``_ensure_event_loop`` created and
                # closed it in the same test). Nothing to
                # restore.
                pass


def get_or_generate_setup_token(keys_dir: str) -> str:
    """Return the one-time setup token, persisting it on first call.

    The token is stored at ``<keys_dir>/setup_token`` so that every
    subsequent boot (notably uvicorn's reloader subprocess, which
    re-imports ``main.py`` and rebuilds ``Settings``) returns the
    same value instead of regenerating one. This prevents the
    reloader parent from leaking a stale token to the logs while
    the worker uses a different one.

    The file is written atomically via ``os.replace`` (POSIX and
    Windows both guarantee rename-atomicity at the filesystem
    level). On the very first boot the new token is emitted once
    via ``structlog`` at WARNING level so the operator can copy
    it; later boots are silent.

    Security: the file is written in plaintext inside ``keys_dir``
    alongside the encrypted keyring. The directory is expected to
    be protected at the OS level (same as the keyring itself). For
    CI/CD, prefer setting ``SETUP_TOKEN`` in the environment
    instead of relying on auto-generation.
    """
    keys_path = Path(keys_dir)
    token_file = keys_path / "setup_token"

    if token_file.exists():
        try:
            existing = token_file.read_text(encoding="utf-8").strip()
            if existing:
                return existing
        except OSError:
            # Corrupt / unreadable file: fall through to regenerate
            # so the operator isn't permanently locked out of setup.
            pass

    keys_path.mkdir(parents=True, exist_ok=True)
    new_token = secrets.token_urlsafe(32)

    tmp_file = token_file.with_name(token_file.name + ".tmp")
    try:
        tmp_file.write_text(new_token, encoding="utf-8")
        os.replace(tmp_file, token_file)
    except OSError:
        try:
            tmp_file.unlink()
        except OSError:
            pass
        raise

    structlog.get_logger("authglow.setup").warning(
        "setup_token_generated",
        token=new_token,
    )
    return new_token


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False, extra="ignore"
    )

    # Application Settings
    app_name: str = "AuthGlow"
    app_env: str = "development"
    debug: bool = False
    enable_docs: bool = True
    secret_key: str = Field(..., min_length=32)
    jwt_algorithm: str = "RS256"
    keys_dir: str = "data/keys"
    private_key_path: str = "data/keys/private_key.pem"
    public_key_path: str = "data/keys/public_key.pem"
    jwt_key_rotation_days: int = 90
    jwt_auto_rotate: bool = True
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    def __init__(self, **values):
        super().__init__(**values)
        get_or_generate_keyring(
            self.keys_dir,
            self.secret_key,
            self.jwt_key_rotation_days,
            self.jwt_auto_rotate,
        )
        if not self.setup_token:
            self.setup_token = get_or_generate_setup_token(self.keys_dir)
        if self.cors_allow_credentials and self.cors_allowed_headers == "*":
            warnings.warn(
                "CORS misconfiguration: cors_allow_credentials=true combined with "
                "cors_allowed_headers='*' (wildcard). Browsers reject this combination "
                "per the Fetch standard — the wildcard is ignored when credentials=true. "
                "Set cors_allowed_headers to explicit comma-separated headers such as "
                "'Authorization, Content-Type, X-Requested-With, Accept'.",
                UserWarning,
            )

    # Server Settings
    host: str = "0.0.0.0"
    port: int = 8000

    # Storage Settings
    storage_backend: str = "file"
    storage_path: str = "./data/users"

    # Cloud provider credentials (optional)
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: Optional[str] = None
    google_application_credentials: Optional[str] = None
    azure_storage_account_name: Optional[str] = None
    azure_storage_account_key: Optional[str] = None

    # Password Policy
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_digits: bool = True
    password_require_special: bool = True

    # Registration
    allow_public_registration: bool = True

    # OAuth2 Settings
    oauth2_authorization_code_expire_minutes: int = 10
    oauth2_client_id: str = Field(
        default="change-me-in-production",
        description="OAuth2 client ID. Must be overridden in production.",
    )
    oauth2_client_secret: SecretStr = Field(
        default=SecretStr("change-me-in-production"),
        description="OAuth2 client secret. Must be overridden in production.",
    )
    oauth2_reject_unknown_scopes: bool = False
    enforce_pkce: bool = True
    blacklist_backend: str = "persistent"

    # Device Authorization Grant (RFC 8628)
    device_code_expire_seconds: int = 600  # 10 minutes
    device_poll_interval_seconds: int = 5

    # CORS Security Settings
    cors_allowed_origins: str = (
        "http://localhost:3000,http://localhost:5173,http://localhost:6060,http://localhost:8080"
    )
    cors_allow_credentials: bool = True
    cors_allowed_methods: str = "GET,POST,PUT,PATCH,DELETE,OPTIONS"  # Comma-separated list
    cors_allowed_headers: str = "Authorization, Content-Type, X-Requested-With, Accept"

    # OpenID Connect Settings
    issuer: str = "http://localhost:8000"  # Must match the actual server URL

    # OIDC Discovery customization (None = use built-in defaults)
    oidc_claims_supported: Optional[str] = None  # Comma-separated, e.g. "sub,email,name"
    oidc_scopes_supported: Optional[str] = None  # Comma-separated, e.g. "openid,profile,email"
    oidc_grant_types_supported: Optional[str] = None  # Comma-separated
    oidc_response_types_supported: Optional[str] = None  # Comma-separated
    oidc_service_documentation: Optional[str] = None
    oidc_op_policy_uri: Optional[str] = None
    oidc_op_tos_uri: Optional[str] = None

    # Request Body Size Limit
    max_request_body_size_mb: int = 10

    # Timing Side-Channel Protection
    timing_leak_protection: bool = True

    # Audit Log Settings
    audit_email_log_level: str = "mask"  # "mask", "hash", "none"

    # Security Headers Settings
    csp_header: str = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "frame-ancestors 'none'; "
        "object-src 'none'; "
        "base-uri 'self'"
    )
    x_frame_options: str = "DENY"
    x_content_type_options: str = "nosniff"
    referrer_policy: str = "strict-origin-when-cross-origin"
    x_permitted_cross_domain_policies: str = "none"
    permissions_policy: str = ""
    hsts_max_age: int = 31536000
    hsts_include_subdomains: bool = True
    enforce_hsts: bool = True

    # API Key Brute-Force Lockout
    api_key_max_failed_attempts: int = 5
    api_key_lockout_minutes: int = 15

    # Backup Code Brute-Force Lockout
    backup_code_max_failed_attempts: int = 3
    backup_code_lockout_seconds: int = 30

    # Auth cookie settings (httpOnly cookies for secure token storage)
    auth_cookie_access_name: str = "access_token"
    auth_cookie_refresh_name: str = "refresh_token"
    auth_cookie_path: str = "/api"
    auth_cookie_samesite: str = "lax"
    auth_cookie_domain: Optional[str] = None

    @property
    def auth_cookie_secure(self) -> bool:
        """Secure flag: True in production (HTTPS), False for local dev (HTTP)."""
        return self.is_production

    # HTTPS Enforcement
    enforce_https: bool = True
    https_redirect_status: int = 301
    trusted_proxies: str = ""  # Comma-separated IPs/CIDR ranges of trusted reverse proxies

    # Cache Settings
    cache_refresh_token_maxsize: int = 5000
    cache_refresh_token_ttl: int = 60
    cache_user_maxsize: int = 2000
    cache_user_ttl: int = 300
    # JTI replay-protection cache for client_assertion JWTs (T.2). Bounds
    # the in-process state of recently-seen ``jti`` claims — entries evict
    # automatically when the JWT expires.
    cache_jti_maxsize: int = 10000
    cache_jti_ttl: int = 3600

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"

    # Passkey/WebAuthn Settings
    passkey_rp_id: str = "localhost"
    passkey_rp_name: str = "AuthGlow"
    passkey_origin: str = "http://localhost:8000"

    # Email settings
    email_backend: str = "console"  # console, file_storage
    email_provider: Optional[str] = None  # For future use with real email services
    email_from_address: str = "noreply@authglow.example.com"
    email_from_name: str = "AuthGlow"
    email_storage_path: str = "data/users/emails"

    # SMTP Settings (if email_provider = "smtp")
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True

    # SendGrid Settings (if email_provider = "sendgrid")
    sendgrid_api_key: Optional[str] = None

    # Mailgun Settings (if email_provider = "mailgun")
    mailgun_api_key: Optional[str] = None
    mailgun_domain: Optional[str] = None

    # Base URL for links in emails
    base_url: str = "http://localhost:8000"
    frontend_base_url: str = "http://localhost:5173"
    company_name: str = "AuthGlow"

    # UI Customization
    logo_url: Optional[str] = None
    favicon_url: Optional[str] = None

    # Setup / Bootstrap
    # One-time token required to call POST /api/setup/create-admin (RFC 7591 Initial Access Token pattern).
    # If not set via environment variable, a token is generated on the first
    # boot, persisted to ``<keys_dir>/setup_token`` and logged once. Subsequent
    # boots (including uvicorn's reloader subprocess) read the same value
    # instead of regenerating. Set SETUP_TOKEN=<value> in your .env to supply
    # a fixed token (e.g. for CI/CD or to reset the persisted one).
    setup_token: Optional[str] = None

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("Key must be at least 32 characters long")
        placeholder_markers = [
            "change-in-production",
            "change_in_production",
            "change-me",
            "change_me",
            "your-secret",
            "your_secret",
            "your-jwt",
            "your_jwt",
            "your-",
            "your_",
            "placeholder",
            "example",
            "replace-me",
            "replace_me",
        ]
        if any(marker in v.lower() for marker in placeholder_markers):
            warnings.warn(
                "SECRET_KEY appears to be a placeholder (e.g. 'change-in-production'). "
                "Generate a real cryptographic key with: openssl rand -hex 32",
                UserWarning,
            )
        return v

    @model_validator(mode="after")
    def _validate_debug_not_enabled_in_production(self):
        if self.is_production and self.debug:
            raise ValueError(
                "DEBUG must be 'false' when app_env is 'production'. "
                "Debug mode enables auto-reload and may leak tracebacks "
                "via HTTP responses."
            )
        return self

    @model_validator(mode="after")
    def _validate_secret_key_for_environment(self):
        """Hard-fail in production if SECRET_KEY is a known placeholder.

        A UserWarning is too easy to miss in production logs — for an
        auth server this is a deploy-blocker, not a footnote.
        """
        if not self.app_env or self.app_env.lower() != "production":
            return self
        placeholder_markers = [
            "change-in-production",
            "change_in_production",
            "change-me",
            "change_me",
            "your-secret",
            "your_secret",
            "your-jwt",
            "your_jwt",
            "your-",
            "your_",
            "placeholder",
            "example",
            "replace-me",
            "replace_me",
        ]
        if any(marker in self.secret_key.lower() for marker in placeholder_markers):
            raise ValueError(
                "SECRET_KEY appears to be a placeholder value but app_env is "
                f"'{self.app_env}'. Generate a real cryptographic key with "
                "openssl rand -hex 32 and set it in the environment before "
                "starting the service."
            )
        return self

    @model_validator(mode="after")
    def _validate_oauth2_defaults_for_production(self):
        """Hard-fail in production if OAuth2 client credentials use known defaults.

        The default client-id / client-secret are public knowledge. In production,
        an operator must override them with unique, generated values.
        """
        if not self.app_env or self.app_env.lower() != "production":
            return self

        known_defaults = (
            "default-client-id",
            "default-client-secret",
            "change-me",
            "change_me",
            "change-me-in-production",
            "change_me_in_production",
            "replace-me",
            "replace_me",
        )
        client_id_lower = self.oauth2_client_id.lower()
        client_secret_val = self.oauth2_client_secret.get_secret_value()
        client_secret_lower = client_secret_val.lower()
        if any(d in client_id_lower for d in known_defaults):
            raise ValueError(
                "OAUTH2_CLIENT_ID appears to be a placeholder or default value "
                f"('{self.oauth2_client_id}') but app_env is "
                f"'{self.app_env}'. Generate unique OAuth2 credentials with "
                'python -c "import secrets; print(secrets.token_urlsafe(16))" '
                "and set OAUTH2_CLIENT_ID / OAUTH2_CLIENT_SECRET."
            )
        if any(d in client_secret_lower for d in known_defaults):
            raise ValueError(
                "OAUTH2_CLIENT_SECRET appears to be a placeholder or default value "
                f"(matches a known default pattern) but app_env is "
                f"'{self.app_env}'. Generate unique OAuth2 credentials with "
                'python -c "import secrets; print(secrets.token_urlsafe(32))" '
                "and set OAUTH2_CLIENT_ID / OAUTH2_CLIENT_SECRET."
            )
        return self

    def get_storage_options(self) -> dict:
        """Get storage options based on backend."""
        options: dict[str, object] = {}

        if self.storage_backend == "s3":
            if self.aws_access_key_id and self.aws_secret_access_key:
                options = {
                    "key": self.aws_access_key_id,
                    "secret": self.aws_secret_access_key,
                }
                if self.aws_region:
                    options["client_kwargs"] = {"region_name": self.aws_region}

        elif self.storage_backend == "gcs":
            if self.google_application_credentials:
                options = {"token": self.google_application_credentials}

        elif self.storage_backend == "abfs":
            if self.azure_storage_account_name and self.azure_storage_account_key:
                options = {
                    "account_name": self.azure_storage_account_name,
                    "account_key": self.azure_storage_account_key,
                }

        return options

    def get_cors_origins(self) -> list:
        """Get CORS allowed origins as a list."""
        if self.cors_allowed_origins == "*":
            return ["*"]
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

    def get_cors_methods(self) -> list:
        """Get CORS allowed methods as a list."""
        return [method.strip() for method in self.cors_allowed_methods.split(",") if method.strip()]

    def get_cors_headers(self) -> list:
        """Get CORS allowed headers as a list."""
        if self.cors_allowed_headers == "*":
            return ["*"]
        return [header.strip() for header in self.cors_allowed_headers.split(",") if header.strip()]

    def get_trusted_proxies(self) -> list:
        """Get trusted proxy IPs/CIDR ranges as a list."""
        if not self.trusted_proxies:
            return []
        return [addr.strip() for addr in self.trusted_proxies.split(",") if addr.strip()]


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
