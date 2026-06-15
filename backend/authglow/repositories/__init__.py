"""Repository layer for AuthGlow.

This package provides the **Repository pattern** abstraction over the
underlying storage layer. The goal is to allow swapping the storage
backend (fsspec + JSON files today, possibly Postgres / Firestore /
Redis in the future) without modifying any business-logic service.

Layered architecture::

    API layer (FastAPI routes)
        │  Depends(get_<entity>_repository)
        ▼
    services/                # Business logic — no I/O knowledge
        │  uses Repository Protocols
        ▼
    repositories/
        ├── protocols.py     # Abstract contracts (Protocol classes)
        ├── exceptions.py    # Domain-specific errors
        ├── dependencies.py  # FastAPI factory functions
        ├── base.py          # Cross-cutting repository helpers (placeholder)
        └── file/            # File-system implementations
            ├── base.py      # BaseFileRepository (fsspec + AsyncFileSystem)
            └── <entity>.py  # File<Entity>Repository

Two-layer migration is in progress:

* ``repositories/protocols.py`` declares the contracts.
* ``repositories/file/<entity>.py`` provides the file-system
  implementations. The existing services in ``authglow.services`` are
  migrated one at a time (strangler pattern) to call these
  repositories instead of using ``fsspec`` / ``AsyncFileSystem`` directly.

Until a service is migrated, the corresponding ``File<Entity>Repository``
may not exist yet — see ``docs/REFACTOR_REPOSITORY_PLAN.md`` for the
full migration roadmap.
"""

from authglow.repositories.exceptions import (
    EntityAlreadyExistsError,
    EntityNotFoundError,
)
from authglow.repositories.protocols import (
    AdminActionRepository,
    APIKeyRepository,
    AuthorizationCodeRepository,
    BackupCodeAttemptRepository,
    BackupCodeRepository,
    CSRFTokenRepository,
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
    TrustedDeviceRepository,
    UserPreferencesRepository,
    UserRepository,
    WebAuthnChallengeRepository,
)

__all__ = [
    # Protocols
    "APIKeyRepository",
    "AdminActionRepository",
    "AuthorizationCodeRepository",
    "BackupCodeAttemptRepository",
    "BackupCodeRepository",
    "CSRFTokenRepository",
    "EmailIndexRepository",
    "EmailVerificationRepository",
    "FederatedIdentityRepository",
    "FederationProviderRepository",
    "KeyStoreRepository",
    "LoginHistoryRepository",
    "OAuth2ClientRepository",
    "OAuth2ConsentRepository",
    "PasswordResetRepository",
    "PasskeyRepository",
    "PermissionRepository",
    "RefreshTokenRepository",
    "RoleRepository",
    "SecurityEventRepository",
    "SessionRepository",
    "TrustedDeviceRepository",
    "UserPreferencesRepository",
    "UserRepository",
    "WebAuthnChallengeRepository",
    # Exceptions
    "EntityAlreadyExistsError",
    "EntityNotFoundError",
]
