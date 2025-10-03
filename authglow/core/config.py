"""Configuration management for AuthGlow."""

from functools import lru_cache
from typing import Optional
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )

    # Application Settings
    app_name: str = "AuthGlow"
    app_env: str = "development"
    debug: bool = False
    secret_key: str = Field(..., min_length=32)
    jwt_secret_key: str = Field(..., min_length=32)
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

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

    # UI Customization
    ui_logo_url: Optional[str] = "/static/images/authglow_full_dark.png"  # Dark logo for light backgrounds
    ui_logo_dark_url: Optional[str] = "/static/images/authglow_full_light.png"  # Light logo for dark backgrounds
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

    # OpenID Connect Settings
    issuer: str = "http://localhost:8000"  # Must match the actual server URL

    # Passkey/WebAuthn Settings
    passkey_rp_id: str = "localhost"
    passkey_rp_name: str = "AuthGlow"
    passkey_origin: str = "http://localhost:8000"

    # Email settings
    email_backend: str = "console"  # console, file_storage
    email_provider: Optional[str] = None # For future use with real email services
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

    @field_validator("secret_key", "jwt_secret_key")
    @classmethod
    def validate_keys(cls, v: str) -> str:
        """Validate that keys are at least 32 characters."""
        if len(v) < 32:
            raise ValueError("Key must be at least 32 characters long")
        return v

    def get_storage_options(self) -> dict:
        """Get storage options based on backend."""
        options = {}

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

    def get_ui_context(self) -> dict:
        """Get UI customization context for templates."""
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
