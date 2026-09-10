"""FastAPI dependency-injection factories for repositories.

One ``get_<entity>_repository()`` factory per entity. Each factory is a
thin wrapper over :func:`_resolve`, which selects the concrete
implementation from :data:`_REGISTRY` based on
``Settings.repository_backend`` (env ``REPOSITORY_BACKEND``).

A new storage backend only adds a new ``repositories/<backend>/``
implementation plus one :func:`register_backend` call — zero changes
to services or API.

``storage_backend`` (``Settings.storage_backend``) is unrelated: it
selects the fsspec object store (file/s3/gcs/abfs) underneath the
``file`` repository backend.
"""

import importlib
from typing import TYPE_CHECKING, Any, Callable, Dict, TypeVar

from fastapi import Depends, params

from authglow.core.config import Settings, get_settings

if TYPE_CHECKING:
    from authglow.repositories.protocols import (
        AdminActionRepository,
        APIKeyClaimPolicyRepository,
        APIKeyRepository,
        AuthorizationCodeRepository,
        BackupCodeAttemptRepository,
        BackupCodeRepository,
        ClientClaimPolicyRepository,
        CSRFTokenRepository,
        DeviceAuthorizationRepository,
        EmailIndexRepository,
        EmailVerificationRepository,
        FederatedIdentityRepository,
        FederationProviderRepository,
        KeyStoreRepository,
        LoginHistoryRepository,
        OAuth2ClientRepository,
        OAuth2ConsentRepository,
        PasskeyRepository,
        PasswordResetRepository,
        PermissionRepository,
        PhoneVerificationRepository,
        RateLimitConfigRepository,
        RefreshTokenRepository,
        RoleRepository,
        SecurityEventRepository,
        SessionRepository,
        SettingsOverrideRepository,
        TokenBlacklistRepository,
        TrustedDeviceRepository,
        UserPreferencesRepository,
        UserRepository,
        UserRoleRepository,
        WebAuthnChallengeRepository,
        WebhookDeliveryRepository,
        WebhookRepository,
    )

# A factory takes an already-resolved Settings (or None) and returns a
# repository instance. Factories lazy-import the concrete class so this
# module never creates import cycles at startup.
_Factory = Callable[[Any], Any]
_BackendMap = Dict[str, _Factory]
_T = TypeVar("_T")

_REGISTRY: Dict[str, _BackendMap] = {}


def _file_factory(module: str, class_name: str) -> _Factory:
    """Build a lazy factory for a ``File*Repository`` class."""

    def _make(settings: Any = None) -> Any:
        mod = importlib.import_module(module)
        cls = getattr(mod, class_name)
        return cls(settings=settings)

    _make.__name__ = f"file_{class_name}"
    return _make


def register_backend(name: str, mapping: _BackendMap) -> None:
    """Register (or replace) a named repository backend.

    ``mapping`` keys are entity names (e.g. ``"user"``,
    ``"refresh_token"``); values are factories taking ``settings``.
    """
    _REGISTRY[name] = dict(mapping)


def _resolve_backend_name(settings: Any = None) -> str:
    """Return the configured backend name, resolving Settings lazily.

    Non-string values (e.g. ``MagicMock``-mocked Settings in tests,
    which auto-create attributes) fall back to ``"file"`` — fail-fast
    applies to real (string) misconfigurations only.
    """
    if settings is None:
        from authglow.core.config import get_settings

        settings = get_settings()
    backend = getattr(settings, "repository_backend", "file")
    if not isinstance(backend, str):
        return "file"
    return backend


def _resolve(entity: str, settings: Any = None, _expect: "type[_T] | None" = None) -> _T:
    """Instantiate the repository for *entity* on the configured backend.

    Fail-fast: unknown backends or entities raise ``ValueError`` with
    the available names — never a silent fallback to ``file``.
    The passed ``settings`` object is always forwarded to the
    concrete constructor (``lru_cache`` bypass); only backend-name
    lookup tolerates non-string values (see
    :func:`_resolve_backend_name`).
    """
    backend = _resolve_backend_name(settings)
    try:
        mapping = _REGISTRY[backend]
    except KeyError:
        raise ValueError(
            f"Unknown repository_backend={backend!r} for entity {entity!r}. "
            f"Available backends: {sorted(_REGISTRY)}"
        ) from None
    try:
        factory = mapping[entity]
    except KeyError:
        raise ValueError(
            f"Backend {backend!r} has no repository for entity {entity!r}. "
            f"Available entities: {sorted(mapping)}"
        ) from None
    if settings is None:
        from authglow.core.config import get_settings

        settings = get_settings()
    return factory(settings)  # type: ignore[no-any-return]


_FILE_BACKEND: _BackendMap = {
    "token_blacklist": _file_factory(
        "authglow.repositories.file.token_blacklist", "FileTokenBlacklistRepository"
    ),
    "csrf_token": _file_factory("authglow.repositories.file.csrf", "FileCSRFTokenRepository"),
    "session": _file_factory("authglow.repositories.file.session", "FileSessionRepository"),
    "email_verification": _file_factory(
        "authglow.repositories.file.email_verification",
        "FileEmailVerificationRepository",
    ),
    "password_reset": _file_factory(
        "authglow.repositories.file.password_reset", "FilePasswordResetRepository"
    ),
    "phone_verification": _file_factory(
        "authglow.repositories.file.phone_verification",
        "FilePhoneVerificationRepository",
    ),
    "authorization_code": _file_factory(
        "authglow.repositories.file.authorization_code",
        "FileAuthorizationCodeRepository",
    ),
    "oauth2_client": _file_factory(
        "authglow.repositories.file.oauth_client", "FileOAuth2ClientRepository"
    ),
    "oauth2_consent": _file_factory(
        "authglow.repositories.file.oauth_consent", "FileOAuth2ConsentRepository"
    ),
    "backup_code": _file_factory("authglow.repositories.file.mfa", "FileBackupCodeRepository"),
    "backup_code_attempt": _file_factory(
        "authglow.repositories.file.mfa", "FileBackupCodeAttemptRepository"
    ),
    "trusted_device": _file_factory(
        "authglow.repositories.file.mfa", "FileTrustedDeviceRepository"
    ),
    "passkey": _file_factory("authglow.repositories.file.passkey", "FilePasskeyRepository"),
    "webauthn_challenge": _file_factory(
        "authglow.repositories.file.passkey", "FileWebAuthnChallengeRepository"
    ),
    "api_key": _file_factory("authglow.repositories.file.api_key", "FileAPIKeyRepository"),
    "refresh_token": _file_factory(
        "authglow.repositories.file.refresh_token", "FileRefreshTokenRepository"
    ),
    "permission": _file_factory("authglow.repositories.file.rbac", "FilePermissionRepository"),
    "role": _file_factory("authglow.repositories.file.rbac", "FileRoleRepository"),
    "user_role": _file_factory("authglow.repositories.file.rbac", "FileUserRoleRepository"),
    "login_history": _file_factory(
        "authglow.repositories.file.login_history", "FileLoginHistoryRepository"
    ),
    "admin_action": _file_factory(
        "authglow.repositories.file.admin_action", "FileAdminActionRepository"
    ),
    "security_event": _file_factory(
        "authglow.repositories.file.security_event", "FileSecurityEventRepository"
    ),
    "email_index": _file_factory(
        "authglow.repositories.file.email_index", "FileEmailIndexRepository"
    ),
    "federated_identity": _file_factory(
        "authglow.repositories.file.federated_identity",
        "FileFederatedIdentityRepository",
    ),
    "user": _file_factory("authglow.repositories.file.user", "FileUserRepository"),
    "user_preferences": _file_factory(
        "authglow.repositories.file.user_preferences", "FileUserPreferencesRepository"
    ),
    "federation_provider": _file_factory(
        "authglow.repositories.file.federation", "FileFederationProviderRepository"
    ),
    "keystore": _file_factory("authglow.repositories.file.keystore", "FileKeyStoreRepository"),
    "device_authorization": _file_factory(
        "authglow.repositories.file.device_authorization",
        "FileDeviceAuthorizationRepository",
    ),
    "claim_policy": _file_factory(
        "authglow.repositories.file.claim_policy", "FileClientClaimPolicyRepository"
    ),
    "api_key_claim_policy": _file_factory(
        "authglow.repositories.file.api_key_claim_policy",
        "FileAPIKeyClaimPolicyRepository",
    ),
    "webhook": _file_factory("authglow.repositories.file.webhook", "FileWebhookRepository"),
    "webhook_delivery": _file_factory(
        "authglow.repositories.file.webhook", "FileWebhookDeliveryRepository"
    ),
    "rate_limit_config": _file_factory(
        "authglow.repositories.file.rate_limit_config",
        "FileRateLimitConfigRepository",
    ),
    "settings_override": _file_factory(
        "authglow.repositories.file.settings_override",
        "FileSettingsOverrideRepository",
    ),
}

register_backend("file", _FILE_BACKEND)

__all__ = [
    "register_backend",
    "get_token_blacklist_repository",
    "get_csrf_token_repository",
    "get_session_repository",
    "get_email_verification_repository",
    "get_password_reset_repository",
    "get_phone_verification_repository",
    "get_authorization_code_repository",
    "get_oauth2_client_repository",
    "get_oauth2_consent_repository",
    "get_backup_code_repository",
    "get_backup_code_attempt_repository",
    "get_trusted_device_repository",
    "get_passkey_repository",
    "get_webauthn_challenge_repository",
    "get_api_key_repository",
    "get_refresh_token_repository",
    "get_permission_repository",
    "get_role_repository",
    "get_user_role_repository",
    "get_login_history_repository",
    "get_admin_action_repository",
    "get_security_event_repository",
    "get_email_index_repository",
    "get_federated_identity_repository",
    "get_user_repository",
    "get_user_preferences_repository",
    "get_federation_provider_repository",
    "get_keystore_repository",
    "get_device_authorization_repository",
    "get_claim_policy_repository",
    "get_api_key_claim_policy_repository",
    "get_webhook_repository",
    "get_webhook_delivery_repository",
    "get_rate_limit_config_repository",
    "get_settings_override_repository",
]


def get_token_blacklist_repository(
    settings: "Settings | None" = None,
) -> "TokenBlacklistRepository":
    """FastAPI factory for the token-blacklist repository."""
    return _resolve("token_blacklist", settings)


def get_csrf_token_repository(
    settings: "Settings | None" = None,
) -> "CSRFTokenRepository":
    """FastAPI factory for the CSRF-token repository."""
    return _resolve("csrf_token", settings)


def get_session_repository(
    settings: "Settings | None" = None,
) -> "SessionRepository":
    """FastAPI factory for the MFA + consent-session repository."""
    return _resolve("session", settings)


def get_email_verification_repository(
    settings: "Settings | None" = None,
) -> "EmailVerificationRepository":
    """FastAPI factory for the email-verification-token repository."""
    return _resolve("email_verification", settings)


def get_password_reset_repository(
    settings: "Settings | None" = None,
) -> "PasswordResetRepository":
    """FastAPI factory for the password-reset-token repository."""
    return _resolve("password_reset", settings)


def get_phone_verification_repository(
    settings: "Settings | None" = None,
) -> "PhoneVerificationRepository":
    """FastAPI factory for the phone-verification-token repository."""
    return _resolve("phone_verification", settings)


def get_authorization_code_repository(
    settings: "Settings | None" = None,
) -> "AuthorizationCodeRepository":
    """FastAPI factory for the OAuth2 authorization-code repository."""
    return _resolve("authorization_code", settings)


def get_oauth2_client_repository(
    settings: "Settings | None" = None,
) -> "OAuth2ClientRepository":
    """FastAPI factory for the OAuth2-client repository."""
    return _resolve("oauth2_client", settings)


def get_oauth2_consent_repository(
    settings: "Settings | None" = None,
) -> "OAuth2ConsentRepository":
    """FastAPI factory for the OAuth2-consent repository."""
    return _resolve("oauth2_consent", settings)


def get_backup_code_repository(
    settings: "Settings | None" = None,
) -> "BackupCodeRepository":
    """FastAPI factory for the MFA backup-codes repository."""
    return _resolve("backup_code", settings)


def get_backup_code_attempt_repository(
    settings: "Settings | None" = None,
) -> "BackupCodeAttemptRepository":
    """FastAPI factory for the MFA backup-code-attempt counter."""
    return _resolve("backup_code_attempt", settings)


def get_trusted_device_repository(
    settings: "Settings | None" = None,
) -> "TrustedDeviceRepository":
    """FastAPI factory for the trusted-device repository."""
    return _resolve("trusted_device", settings)


def get_passkey_repository(
    settings: "Settings | None" = None,
) -> "PasskeyRepository":
    """FastAPI factory for the WebAuthn passkey repository."""
    return _resolve("passkey", settings)


def get_webauthn_challenge_repository(
    settings: "Settings | None" = None,
) -> "WebAuthnChallengeRepository":
    """FastAPI factory for the WebAuthn challenge repository."""
    return _resolve("webauthn_challenge", settings)


def get_api_key_repository(
    settings: "Settings | None" = None,
) -> "APIKeyRepository":
    """FastAPI factory for the API-key repository."""
    return _resolve("api_key", settings)


def get_refresh_token_repository(
    settings: "Settings | None" = None,
) -> "RefreshTokenRepository":
    """FastAPI factory for the refresh-token repository.

    The optional ``settings`` argument lets the caller (typically
    the service constructor) propagate an already-resolved
    ``Settings`` instance — this is needed when the service
    resolves ``get_settings()`` against a patched binding and the
    repository must read from the same ``Settings`` (the
    ``BaseFileRepository`` default would otherwise hit the
    ``lru_cache``'d global ``get_settings``).
    """
    return _resolve("refresh_token", settings)


def get_permission_repository(
    settings: "Settings | None" = None,
) -> "PermissionRepository":
    """FastAPI factory for the RBAC permission repository."""
    return _resolve("permission", settings)


def get_role_repository(
    settings: "Settings | None" = None,
) -> "RoleRepository":
    """FastAPI factory for the RBAC role repository."""
    return _resolve("role", settings)


def get_user_role_repository(
    settings: "Settings | None" = None,
) -> "UserRoleRepository":
    """FastAPI factory for the RBAC user-role assignment repository."""
    return _resolve("user_role", settings)


def get_login_history_repository(
    settings: "Settings | None" = None,
) -> "LoginHistoryRepository":
    """FastAPI factory for the login-history repository."""
    return _resolve("login_history", settings)


def get_admin_action_repository(
    settings: "Settings | None" = None,
) -> "AdminActionRepository":
    """FastAPI factory for the admin-action repository."""
    return _resolve("admin_action", settings)


def get_security_event_repository(
    settings: "Settings | None" = None,
) -> "SecurityEventRepository":
    """FastAPI factory for the security-event repository."""
    return _resolve("security_event", settings)


def get_email_index_repository(
    settings: "Settings | None" = None,
) -> "EmailIndexRepository":
    """FastAPI factory for the email-index repository."""
    return _resolve("email_index", settings)


def get_federated_identity_repository(
    settings: "Settings | None" = None,
) -> "FederatedIdentityRepository":
    """FastAPI factory for the federated-identity repository."""
    return _resolve("federated_identity", settings)


def get_user_repository(
    settings: "Settings | None" = None,
) -> "UserRepository":
    """FastAPI factory for the user repository."""
    return _resolve("user", settings)


def get_user_preferences_repository(
    settings: "Settings | None" = None,
) -> "UserPreferencesRepository":
    """FastAPI factory for the user-preferences repository."""
    return _resolve("user_preferences", settings)


def get_federation_provider_repository(
    settings: "Settings | None" = None,
) -> "FederationProviderRepository":
    """FastAPI factory for the federation-provider repository."""
    return _resolve("federation_provider", settings)


def get_keystore_repository(
    settings: "Settings | None" = None,
) -> "KeyStoreRepository":
    """FastAPI factory for the keyring repository."""
    return _resolve("keystore", settings)


def get_device_authorization_repository(
    settings: "Settings | None" = None,
) -> "DeviceAuthorizationRepository":
    """FastAPI factory for the device-authorization repository."""
    return _resolve("device_authorization", settings)


def get_claim_policy_repository(
    settings: "Settings | None" = None,
) -> "ClientClaimPolicyRepository":
    """FastAPI factory for the per-client claim policy repository."""
    return _resolve("claim_policy", settings)


def get_api_key_claim_policy_repository(
    settings: "Settings | None" = None,
) -> "APIKeyClaimPolicyRepository":
    """FastAPI factory for the per-API-key claim policy repository."""
    return _resolve("api_key_claim_policy", settings)


def get_webhook_repository(
    settings: Settings | None = Depends(get_settings),
) -> "WebhookRepository":
    """FastAPI factory for the webhook-endpoint repository.

    ``settings`` is injected by FastAPI via ``Depends(get_settings)`` so
    the function can be used directly as a dependency without the
    parameter leaking into the request schema. Direct callers (e.g.
    ``WebhookDispatcher``) invoke it with no arguments, in which case the
    ``Depends`` sentinel is normalized to ``None`` and :func:`_resolve`
    falls back to ``get_settings()``.
    """
    if isinstance(settings, params.Depends):
        settings = None
    return _resolve("webhook", settings)


def get_webhook_delivery_repository(
    settings: Settings | None = Depends(get_settings),
) -> "WebhookDeliveryRepository":
    """FastAPI factory for the webhook-delivery repository.

    See :func:`get_webhook_repository` for the ``Depends`` normalization
    rationale.
    """
    if isinstance(settings, params.Depends):
        settings = None
    return _resolve("webhook_delivery", settings)


def get_rate_limit_config_repository(
    settings: "Settings | None" = None,
) -> "RateLimitConfigRepository":
    """FastAPI factory for the admin rate-limit config repository."""
    return _resolve("rate_limit_config", settings)


def get_settings_override_repository(
    settings: "Settings | None" = None,
) -> "SettingsOverrideRepository":
    """FastAPI factory for the settings-override repository."""
    return _resolve("settings_override", settings)
