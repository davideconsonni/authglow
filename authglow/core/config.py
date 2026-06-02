"""Configuration management for AuthGlow."""

import json
import os
import warnings
from datetime import datetime, timedelta, timezone
from functools import cached_property, lru_cache
from typing import Any, Dict, Optional

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_KEYRING_FILENAME = "keyring.json"
_LEGACY_KID = "klegacy"


def _generate_key_pair(key_size: int = 2048):
    """Generate a fresh RSA key pair and return (private_bytes, public_bytes)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )
    priv_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return priv_bytes, pub_bytes


def _new_kid() -> str:
    """Generate a unique sortable key ID with timestamp + random suffix."""
    import secrets

    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    suffix = secrets.token_hex(2)
    return f"k{ts}{suffix}"


def _load_keyring(keyring_path: str) -> Optional[Dict[str, Any]]:
    """Load keyring.json, return None if missing."""
    if not os.path.exists(keyring_path):
        return None
    with open(keyring_path, "r", encoding="utf-8") as f:
        data: Dict[str, Any] = json.load(f)
        return data


def _save_keyring(keyring_path: str, keyring: Dict[str, Any]):
    """Atomically save keyring.json."""
    tmp = keyring_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(keyring, f, indent=2)
    os.replace(tmp, keyring_path)


def get_or_generate_keyring(
    keys_dir: str,
    secret_key: str,
    rotation_days: int = 90,
    auto_rotate: bool = True,
    key_size: int = 2048,
):
    """
    Ensure the RSA keyring exists on disk with at least one active key.

    1. Migrate legacy single-key format to keyring if needed.
    2. Generate new keys if no keys exist.
    3. Auto-rotate if the active key is older than *rotation_days*.

    Backward compat: the active key is also written to
    ``{keys_dir}/private_key.pem`` / ``{keys_dir}/public_key.pem``.
    """
    from authglow.core.crypto import encrypt_private_key

    os.makedirs(keys_dir, exist_ok=True)
    keyring_path = os.path.join(keys_dir, _KEYRING_FILENAME)
    legacy_priv_path = os.path.join(keys_dir, "private_key.pem")
    legacy_pub_path = os.path.join(keys_dir, "public_key.pem")

    keyring = _load_keyring(keyring_path)

    # --- Migration from legacy single-key format ---
    if keyring is None and os.path.exists(legacy_priv_path) and os.path.exists(legacy_pub_path):
        print("Migrating legacy RSA keys to keyring...")
        kid = _LEGACY_KID
        kid_dir = os.path.join(keys_dir, kid)
        os.makedirs(kid_dir, exist_ok=True)
        os.rename(legacy_priv_path, os.path.join(kid_dir, "private_key.pem"))
        os.rename(legacy_pub_path, os.path.join(kid_dir, "public_key.pem"))
        keyring = {
            "active_kid": kid,
            "keys": {
                kid: {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "status": "active",
                    "algorithm": "RS256",
                    "key_size": key_size,
                }
            },
        }
        _save_keyring(keyring_path, keyring)
        _write_active_symlinks(keys_dir, keyring)

    # --- Fresh generation ---
    if keyring is None:
        print("Generating new RSA keyring...")
        kid = _new_kid()
        kid_dir = os.path.join(keys_dir, kid)
        os.makedirs(kid_dir, exist_ok=True)

        priv_bytes, pub_bytes = _generate_key_pair(key_size)
        encrypted_priv = encrypt_private_key(priv_bytes, secret_key=secret_key)
        with open(os.path.join(kid_dir, "private_key.pem"), "wb") as f:
            f.write(encrypted_priv)
        with open(os.path.join(kid_dir, "public_key.pem"), "wb") as f:
            f.write(pub_bytes)

        keyring = {
            "active_kid": kid,
            "keys": {
                kid: {
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "status": "active",
                    "algorithm": "RS256",
                    "key_size": key_size,
                }
            },
        }
        _save_keyring(keyring_path, keyring)
        _write_active_symlinks(keys_dir, keyring)
        print(f"RSA keyring initialised — active kid={kid}")
        return

    # --- Auto-rotate ---
    if auto_rotate:
        active_kid = keyring["active_kid"]
        active_meta = keyring["keys"].get(active_kid, {})
        created_str = active_meta.get("created_at", "")
        if created_str:
            created_dt = datetime.fromisoformat(created_str)
            age = datetime.now(timezone.utc) - created_dt
            if age > timedelta(days=rotation_days):
                print(
                    f"Active key {active_kid} is {age.days} days old "
                    f"(> {rotation_days} days). Auto-rotating..."
                )
                _perform_rotation(keys_dir, keyring_path, keyring, secret_key, active_kid, key_size)


def _write_active_symlinks(keys_dir: str, keyring: Dict[str, Any]):
    """Copy the active key to the legacy flat paths for backward compatibility."""
    active_kid = keyring["active_kid"]
    src_priv = os.path.join(keys_dir, active_kid, "private_key.pem")
    src_pub = os.path.join(keys_dir, active_kid, "public_key.pem")
    dst_priv = os.path.join(keys_dir, "private_key.pem")
    dst_pub = os.path.join(keys_dir, "public_key.pem")

    try:
        os.remove(dst_priv)
    except FileNotFoundError:
        pass
    try:
        os.remove(dst_pub)
    except FileNotFoundError:
        pass

    import shutil

    shutil.copy2(src_priv, dst_priv)
    shutil.copy2(src_pub, dst_pub)


def _perform_rotation(
    keys_dir: str,
    keyring_path: str,
    keyring: Dict[str, Any],
    secret_key: str,
    old_kid: str,
    key_size: int,
):
    """Generate a new key pair, mark old active as verifying, save."""
    from authglow.core.crypto import encrypt_private_key

    kid = _new_kid()
    kid_dir = os.path.join(keys_dir, kid)
    os.makedirs(kid_dir, exist_ok=True)

    priv_bytes, pub_bytes = _generate_key_pair(key_size)
    encrypted_priv = encrypt_private_key(priv_bytes, secret_key=secret_key)
    with open(os.path.join(kid_dir, "private_key.pem"), "wb") as f:
        f.write(encrypted_priv)
    with open(os.path.join(kid_dir, "public_key.pem"), "wb") as f:
        f.write(pub_bytes)

    now_str = datetime.now(timezone.utc).isoformat()
    keyring["keys"][kid] = {
        "created_at": now_str,
        "status": "active",
        "algorithm": "RS256",
        "key_size": key_size,
    }
    keyring["keys"][old_kid]["status"] = "verifying"
    keyring["keys"][old_kid]["retired_at"] = now_str
    keyring["active_kid"] = kid

    _save_keyring(keyring_path, keyring)
    _write_active_symlinks(keys_dir, keyring)
    print(f"Key rotated: {old_kid} -> {kid} (new active, old is now verifying)")


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

    # UI Customization
    ui_logo_url: Optional[str] = (
        "/static/images/authglow_full_dark.png"  # Dark logo for light backgrounds
    )
    ui_logo_dark_url: Optional[str] = (
        "/static/images/authglow_full_light.png"  # Light logo for dark backgrounds
    )
    ui_primary_color: str = "#3498DB"
    ui_secondary_color: str = "#FF3366"
    ui_background_color: str = "#F8F8F8"
    ui_background_dark: str = "#1A1A1A"
    ui_text_color: str = "#2C3E50"
    ui_text_dark: str = "#F0F0F0"
    ui_company_name: str = "AuthGlow"
    ui_support_email: str = "support@example.com"
    ui_privacy_policy_url: Optional[str] = None
    ui_terms_of_service_url: Optional[str] = None

    # OAuth2 Settings
    oauth2_authorization_code_expire_minutes: int = 10
    oauth2_client_id: str = "default-client-id"
    oauth2_client_secret: str = "default-client-secret"
    oauth2_reject_unknown_scopes: bool = False

    # CORS Security Settings
    cors_allowed_origins: str = (
        "http://localhost:3000,http://localhost:6060,http://localhost:8080"  # Comma-separated list
    )
    cors_allow_credentials: bool = True
    cors_allowed_methods: str = "GET,POST,PUT,DELETE,OPTIONS"  # Comma-separated list
    cors_allowed_headers: str = "Authorization, Content-Type, X-Requested-With, Accept"

    # OpenID Connect Settings
    issuer: str = "http://localhost:8000"  # Must match the actual server URL

    # Request Body Size Limit
    max_request_body_size_mb: int = 10

    # Timing Side-Channel Protection
    timing_leak_protection: bool = True

    # Audit Log Settings
    audit_email_log_level: str = "mask"  # "mask", "hash", "none"

    # Security Headers Settings
    csp_header: str = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "script-src 'self' 'unsafe-inline'"
    )
    x_frame_options: str = "DENY"
    x_content_type_options: str = "nosniff"
    referrer_policy: str = "strict-origin-when-cross-origin"
    x_permitted_cross_domain_policies: str = "none"
    permissions_policy: str = ""
    hsts_max_age: int = 31536000
    hsts_include_subdomains: bool = True

    # API Key Brute-Force Lockout
    api_key_max_failed_attempts: int = 5
    api_key_lockout_minutes: int = 15

    # Backup Code Brute-Force Lockout
    backup_code_max_failed_attempts: int = 3
    backup_code_lockout_seconds: int = 30

    # HTTPS Enforcement
    enforce_https: bool = True
    https_redirect_status: int = 301

    # Cache Settings
    cache_refresh_token_maxsize: int = 5000
    cache_refresh_token_ttl: int = 60
    cache_user_maxsize: int = 2000
    cache_user_ttl: int = 300

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
    company_name: str = "AuthGlow"

    # UI Customization
    logo_url: Optional[str] = None
    favicon_url: Optional[str] = None

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        if len(v) < 32:
            raise ValueError("Key must be at least 32 characters long")
        placeholder_markers = [
            "change-in-production",
            "your-secret",
            "your-jwt",
            "your-",
        ]
        if any(marker in v.lower() for marker in placeholder_markers):
            warnings.warn(
                "SECRET_KEY appears to be a placeholder (e.g. 'change-in-production'). "
                "Generate a real cryptographic key with: openssl rand -hex 32",
                UserWarning,
            )
        return v

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

    @cached_property
    def ui_context(self) -> dict:
        """Get UI customization context for templates.

        Computed once per Settings instance (singleton via get_settings()),
        so the same dict object is returned on every access, avoiding
        repeated allocations across the 27+ call sites.
        """
        return {
            "app_name": self.app_name,
            "logo_url": self.ui_logo_url,
            "logo_dark_url": self.ui_logo_dark_url,
            "primary_color": self.ui_primary_color,
            "secondary_color": self.ui_secondary_color,
            "background_color": self.ui_background_color,
            "background_dark": self.ui_background_dark,
            "text_color": self.ui_text_color,
            "text_dark": self.ui_text_dark,
            "company_name": self.ui_company_name,
            "support_email": self.ui_support_email,
            "privacy_policy_url": self.ui_privacy_policy_url,
            "terms_of_service_url": self.ui_terms_of_service_url,
        }


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
