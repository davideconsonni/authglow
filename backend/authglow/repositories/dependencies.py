"""FastAPI dependency-injection factories for repositories.

Per-entity factory functions are added here as each storage service
is migrated to the repository pattern (see
``docs/REFACTOR_REPOSITORY_PLAN.md`` §5.1 for the full schedule).
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from authglow.core.config import Settings
    from authglow.repositories.protocols import (
        AdminActionRepository,
        APIKeyRepository,
        AuthorizationCodeRepository,
        BackupCodeAttemptRepository,
        BackupCodeRepository,
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
        RefreshTokenRepository,
        RoleRepository,
        SecurityEventRepository,
        SessionRepository,
        TokenBlacklistRepository,
        TrustedDeviceRepository,
        UserPreferencesRepository,
        UserRepository,
        UserRoleRepository,
        WebAuthnChallengeRepository,
    )


def get_token_blacklist_repository() -> "TokenBlacklistRepository":
    """FastAPI factory for the token-blacklist repository.

    Returns a fresh ``FileTokenBlacklistRepository`` per request — the
    repository holds no mutable state, only fsspec handles, so this is
    cheap. The service layer in ``services/auth/token_blacklist.py``
    wraps the repository in a process-singleton, but FastAPI route
    handlers that need direct access (none today, but added in case
    of future admin / introspection endpoints) can inject this
    factory.
    """
    from authglow.repositories.file.token_blacklist import (
        FileTokenBlacklistRepository,
    )

    return FileTokenBlacklistRepository()


def get_csrf_token_repository() -> "CSRFTokenRepository":
    """FastAPI factory for the CSRF-token repository.

    Returns a fresh ``FileCSRFTokenRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``CSRFTokenService`` (in ``services/csrf.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.csrf import FileCSRFTokenRepository

    return FileCSRFTokenRepository()


def get_session_repository() -> "SessionRepository":
    """FastAPI factory for the MFA + consent-session repository.

    Returns a fresh ``FileSessionRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``SessionService`` (in ``services/session.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.session import FileSessionRepository

    return FileSessionRepository()


def get_email_verification_repository() -> "EmailVerificationRepository":
    """FastAPI factory for the email-verification-token repository.

    Returns a fresh ``FileEmailVerificationRepository`` per request —
    the repository holds no mutable state, only fsspec handles. The
    ``EmailVerificationService`` (in
    ``services/email_verification.py``) creates its own default
    repository by default; this factory is exposed for FastAPI
    route handlers or tests that want to inject the repository
    directly.
    """
    from authglow.repositories.file.email_verification import (
        FileEmailVerificationRepository,
    )

    return FileEmailVerificationRepository()


def get_password_reset_repository() -> "PasswordResetRepository":
    """FastAPI factory for the password-reset-token repository.

    Returns a fresh ``FilePasswordResetRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``PasswordResetService`` (in ``services/password_reset.py``)
    creates its own default repository by default; this factory
    is exposed for FastAPI route handlers or tests that want to
    inject the repository directly.
    """
    from authglow.repositories.file.password_reset import (
        FilePasswordResetRepository,
    )

    return FilePasswordResetRepository()


def get_authorization_code_repository() -> "AuthorizationCodeRepository":
    """FastAPI factory for the OAuth2 authorization-code repository.

    Returns a fresh ``FileAuthorizationCodeRepository`` per request —
    the repository holds no mutable state, only fsspec handles. The
    ``OAuth2Service`` (in ``services/oauth2.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.authorization_code import (
        FileAuthorizationCodeRepository,
    )

    return FileAuthorizationCodeRepository()


def get_oauth2_client_repository() -> "OAuth2ClientRepository":
    """FastAPI factory for the OAuth2-client repository.

    Returns a fresh ``FileOAuth2ClientRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``OAuth2ClientStorage`` (in ``services/oauth_client.py``) creates
    its own default repository by default; this factory is exposed
    for FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.oauth_client import (
        FileOAuth2ClientRepository,
    )

    return FileOAuth2ClientRepository()


def get_oauth2_consent_repository() -> "OAuth2ConsentRepository":
    """FastAPI factory for the OAuth2-consent repository.

    Returns a fresh ``FileOAuth2ConsentRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``OAuth2ConsentService`` (in ``services/oauth_consent.py``)
    creates its own default repository by default; this factory
    is exposed for FastAPI route handlers or tests that want to
    inject the repository directly.
    """
    from authglow.repositories.file.oauth_consent import (
        FileOAuth2ConsentRepository,
    )

    return FileOAuth2ConsentRepository()


def get_backup_code_repository() -> "BackupCodeRepository":
    """FastAPI factory for the MFA backup-codes repository.

    Returns a fresh ``FileBackupCodeRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``MFAService`` (in ``services/mfa.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.mfa import FileBackupCodeRepository

    return FileBackupCodeRepository()


def get_backup_code_attempt_repository() -> "BackupCodeAttemptRepository":
    """FastAPI factory for the MFA backup-code-attempt counter.

    Returns a fresh ``FileBackupCodeAttemptRepository`` per request —
    the repository holds no mutable state, only fsspec handles. The
    ``MFAService`` (in ``services/mfa.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.mfa import FileBackupCodeAttemptRepository

    return FileBackupCodeAttemptRepository()


def get_trusted_device_repository() -> "TrustedDeviceRepository":
    """FastAPI factory for the trusted-device repository.

    Returns a fresh ``FileTrustedDeviceRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``MFAService`` (in ``services/mfa.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.mfa import FileTrustedDeviceRepository

    return FileTrustedDeviceRepository()


def get_passkey_repository() -> "PasskeyRepository":
    """FastAPI factory for the WebAuthn passkey repository.

    Returns a fresh ``FilePasskeyRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``PasskeyService`` (in ``services/passkey.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.passkey import FilePasskeyRepository

    return FilePasskeyRepository()


def get_webauthn_challenge_repository() -> "WebAuthnChallengeRepository":
    """FastAPI factory for the WebAuthn challenge repository.

    Returns a fresh ``FileWebAuthnChallengeRepository`` per request —
    the repository holds no mutable state, only fsspec handles. The
    ``PasskeyService`` (in ``services/passkey.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.passkey import (
        FileWebAuthnChallengeRepository,
    )

    return FileWebAuthnChallengeRepository()


def get_api_key_repository() -> "APIKeyRepository":
    """FastAPI factory for the API-key repository.

    Returns a fresh ``FileAPIKeyRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``APIKeyService`` (in ``services/api_key.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.api_key import FileAPIKeyRepository

    return FileAPIKeyRepository()


def get_refresh_token_repository(
    settings: "Settings | None" = None,
) -> "RefreshTokenRepository":
    """FastAPI factory for the refresh-token repository.

    Returns a fresh ``FileRefreshTokenRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``RefreshTokenService`` (in ``services/refresh_token.py``)
    creates its own default repository by default; this factory
    is exposed for FastAPI route handlers or tests that want to
    inject the repository directly.

    The optional ``settings`` argument lets the caller (typically
    the service constructor) propagate an already-resolved
    ``Settings`` instance — this is needed when the service
    resolves ``get_settings()`` against a patched binding and the
    repository must read from the same ``Settings`` (the
    ``BaseFileRepository`` default would otherwise hit the
    ``lru_cache``'d global ``get_settings``, which is a
    process-cached singleton that ignores per-test patches).
    """
    from authglow.repositories.file.refresh_token import (
        FileRefreshTokenRepository,
    )

    return FileRefreshTokenRepository(settings=settings)


def get_permission_repository() -> "PermissionRepository":
    """FastAPI factory for the RBAC permission repository.

    Returns a fresh ``FilePermissionRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``RBACService`` (in ``services/rbac.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.rbac import FilePermissionRepository

    return FilePermissionRepository()


def get_role_repository() -> "RoleRepository":
    """FastAPI factory for the RBAC role repository.

    Returns a fresh ``FileRoleRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``RBACService`` (in ``services/rbac.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.rbac import FileRoleRepository

    return FileRoleRepository()


def get_user_role_repository() -> "UserRoleRepository":
    """FastAPI factory for the RBAC user-role assignment repository.

    Returns a fresh ``FileUserRoleRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``RBACService`` (in ``services/rbac.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.rbac import FileUserRoleRepository

    return FileUserRoleRepository()


def get_login_history_repository(
    settings: "Settings | None" = None,
) -> "LoginHistoryRepository":
    """FastAPI factory for the login-history repository.

    Returns a fresh ``FileLoginHistoryRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``LoginHistoryService`` (in ``services/login_history.py``)
    creates its own default repository by default; this factory
    is exposed for FastAPI route handlers or tests that want to
    inject the repository directly.

    The optional ``settings`` argument lets the caller (typically
    the service constructor) propagate an already-resolved
    ``Settings`` instance — same ``lru_cache`` bypass rationale as
    :func:`get_refresh_token_repository`.
    """
    from authglow.repositories.file.login_history import (
        FileLoginHistoryRepository,
    )

    return FileLoginHistoryRepository(settings=settings)


def get_admin_action_repository() -> "AdminActionRepository":
    """FastAPI factory for the admin-action repository.

    Returns a fresh ``FileAdminActionRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``AdminActionService`` (in ``services/admin_action.py``)
    creates its own default repository by default; this factory
    is exposed for FastAPI route handlers or tests that want to
    inject the repository directly.
    """
    from authglow.repositories.file.admin_action import (
        FileAdminActionRepository,
    )

    return FileAdminActionRepository()


def get_security_event_repository() -> "SecurityEventRepository":
    """FastAPI factory for the security-event repository.

    Returns a fresh ``FileSecurityEventRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``SecurityEventService`` (in ``services/security_event.py``)
    creates its own default repository by default; this factory
    is exposed for FastAPI route handlers or tests that want to
    inject the repository directly.
    """
    from authglow.repositories.file.security_event import (
        FileSecurityEventRepository,
    )

    return FileSecurityEventRepository()


def get_email_index_repository(
    settings: "Settings | None" = None,
) -> "EmailIndexRepository":
    """FastAPI factory for the email-index repository.

    Returns a fresh ``FileEmailIndexRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``UserStorage`` (in ``services/storage.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.

    The optional ``settings`` argument lets the caller (typically
    the service constructor) propagate an already-resolved
    ``Settings`` instance — same ``lru_cache`` bypass rationale as
    :func:`get_refresh_token_repository` /
    :func:`get_login_history_repository`.
    """
    from authglow.repositories.file.email_index import (
        FileEmailIndexRepository,
    )

    return FileEmailIndexRepository(settings=settings)


def get_federated_identity_repository(
    settings: "Settings | None" = None,
) -> "FederatedIdentityRepository":
    """FastAPI factory for the federated-identity repository.

    Returns a fresh ``FileFederatedIdentityRepository`` per
    request — the repository holds no mutable state, only fsspec
    handles. The ``UserStorage`` (in ``services/storage.py``)
    creates its own default repository by default; this factory
    is exposed for FastAPI route handlers or tests that want to
    inject the repository directly.

    The optional ``settings`` argument lets the caller (typically
    the service constructor) propagate an already-resolved
    ``Settings`` instance — same ``lru_cache`` bypass rationale as
    :func:`get_refresh_token_repository` /
    :func:`get_login_history_repository`.
    """
    from authglow.repositories.file.federated_identity import (
        FileFederatedIdentityRepository,
    )

    return FileFederatedIdentityRepository(settings=settings)


def get_user_repository(
    settings: "Settings | None" = None,
) -> "UserRepository":
    """FastAPI factory for the user repository.

    Returns a fresh ``FileUserRepository`` per request — the
    repository holds no mutable state, only fsspec handles. The
    ``UserStorage`` (in ``services/storage.py``) creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.

    The optional ``settings`` argument lets the caller (typically
    the service constructor) propagate an already-resolved
    ``Settings`` instance — same ``lru_cache`` bypass rationale as
    :func:`get_refresh_token_repository` /
    :func:`get_login_history_repository`.
    """
    from authglow.repositories.file.user import FileUserRepository

    return FileUserRepository(settings=settings)


def get_user_preferences_repository(
    settings: "Settings | None" = None,
) -> "UserPreferencesRepository":
    """FastAPI factory for the user-preferences repository.

    Returns a fresh ``FileUserPreferencesRepository`` per
    request — the repository holds no mutable state, only fsspec
    handles. The ``UserProfileService`` (in
    ``services/user_profile.py``) creates its own default
    repository by default; this factory is exposed for FastAPI
    route handlers or tests that want to inject the repository
    directly.

    The optional ``settings`` argument lets the caller (typically
    the service constructor) propagate an already-resolved
    ``Settings`` instance — same ``lru_cache`` bypass rationale as
    :func:`get_refresh_token_repository` /
    :func:`get_login_history_repository`.
    """
    from authglow.repositories.file.user_preferences import (
        FileUserPreferencesRepository,
    )

    return FileUserPreferencesRepository(settings=settings)


def get_federation_provider_repository(
    settings: "Settings | None" = None,
) -> "FederationProviderRepository":
    """FastAPI factory for the federation-provider repository.

    Returns a fresh ``FileFederationProviderRepository`` per
    request — the repository holds no mutable state, only fsspec
    handles. The ``FederationService`` (in
    ``services/federation.py``) creates its own default
    repository by default; this factory is exposed for FastAPI
    route handlers or tests that want to inject the repository
    directly.

    The optional ``settings`` argument lets the caller (typically
    the service constructor) propagate an already-resolved
    ``Settings`` instance — same ``lru_cache`` bypass rationale as
    :func:`get_refresh_token_repository` /
    :func:`get_login_history_repository`.
    """
    from authglow.repositories.file.federation import (
        FileFederationProviderRepository,
    )

    return FileFederationProviderRepository(settings=settings)


def get_keystore_repository() -> "KeyStoreRepository":
    """FastAPI factory for the keyring repository.

    Returns a fresh ``FileKeyStoreRepository`` per request —
    the repository holds the keyring state in-memory after
    first load (subsequent calls are cheap, but the keyring
    is small: typically 1-3 key pairs).

    The ``JWTService`` (in ``services/jwt.py``) creates its
    own default repository by default; this factory is
    exposed for FastAPI route handlers or tests that want to
    inject the repository directly.

    Note: this factory does NOT accept a ``settings`` argument
    because the keyring repository reads from
    ``settings.keys_dir`` (which is a *directory*, not a
    single file). Tests use the autouse ``_override_settings``
    fixture + the ``test_keys_dir`` session-scoped fixture to
    control the keyring location.
    """
    from authglow.repositories.file.keystore import (
        FileKeyStoreRepository,
    )

    return FileKeyStoreRepository()


def get_device_authorization_repository(
    settings: "Settings | None" = None,
) -> "DeviceAuthorizationRepository":
    """FastAPI factory for the device-authorization repository.

    Returns a fresh ``FileDeviceAuthorizationRepository`` per
    request. The ``DeviceAuthorizationService`` creates its own
    default repository by default; this factory is exposed for
    FastAPI route handlers or tests that want to inject the
    repository directly.
    """
    from authglow.repositories.file.device_authorization import (
        FileDeviceAuthorizationRepository,
    )

    return FileDeviceAuthorizationRepository(settings=settings)
