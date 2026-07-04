"""Protocol conformance tests for the Repository pattern.

This test parametrizes a small "smoke-test" of the repository
Protocols against every concrete implementation in
``authglow/repositories/file/``. Adding a new backend (e.g.
``SqlUserRepository``) is a 1-line addition to ``IMPL_MAP``
below — the conformance test then runs against it
automatically, asserting that the new impl honours the
Protocol contract.

Why this matters
----------------

The point of the Repository pattern is that a service can
take *any* impl of the Protocol without knowing the backend.
This file is the proof: a single set of tests drives the
contract check across every impl, so adding a new backend
forces you to either:

1. Implement the Protocol correctly (the tests pass), or
2. Watch the tests fail loudly at the contract boundary.

The tests here are intentionally minimal — a handful of
happy-path / round-trip / no-clobber checks per entity, plus
an ``isinstance`` check against the Protocol. Full coverage
of every edge case lives in the per-impl
``tests/unit/repositories/file/test_<entity>.py``.
"""

from __future__ import annotations

import pytest
from authglow.models.user import User
from authglow.models.user_profile import UserPreferences
from authglow.repositories.file.api_key import FileAPIKeyRepository
from authglow.repositories.file.api_key_claim_policy import (
    FileAPIKeyClaimPolicyRepository,
)
from authglow.repositories.file.authorization_code import (
    FileAuthorizationCodeRepository,
)
from authglow.repositories.file.claim_policy import (
    FileClientClaimPolicyRepository,
)
from authglow.repositories.file.csrf import FileCSRFTokenRepository
from authglow.repositories.file.email_index import (
    FileEmailIndexRepository,
)
from authglow.repositories.file.email_verification import (
    FileEmailVerificationRepository,
)
from authglow.repositories.file.federated_identity import (
    FileFederatedIdentityRepository,
)
from authglow.repositories.file.federation import (
    FileFederationProviderRepository,
)
from authglow.repositories.file.login_history import (
    FileLoginHistoryRepository,
)
from authglow.repositories.file.oauth_client import (
    FileOAuth2ClientRepository,
)
from authglow.repositories.file.oauth_consent import (
    FileOAuth2ConsentRepository,
)
from authglow.repositories.file.password_reset import (
    FilePasswordResetRepository,
)
from authglow.repositories.file.rbac import (
    FilePermissionRepository,
    FileRoleRepository,
    FileUserRoleRepository,
)
from authglow.repositories.file.refresh_token import (
    FileRefreshTokenRepository,
)
from authglow.repositories.file.session import FileSessionRepository
from authglow.repositories.file.token_blacklist import (
    FileTokenBlacklistRepository,
)
from authglow.repositories.file.user_preferences import (
    FileUserPreferencesRepository,
)
from authglow.repositories.protocols import (
    APIKeyRepository,
    APIKeyClaimPolicyRepository,
    AuthorizationCodeRepository,
    ClientClaimPolicyRepository,
    CSRFTokenRepository,
    EmailIndexRepository,
    EmailVerificationRepository,
    FederatedIdentityRepository,
    FederationProviderRepository,
    LoginHistoryRepository,
    OAuth2ClientRepository,
    OAuth2ConsentRepository,
    PasswordResetRepository,
    PermissionRepository,
    RefreshTokenRepository,
    RoleRepository,
    SessionRepository,
    TokenBlacklistRepository,
    UserPreferencesRepository,
    UserRoleRepository,
)


# (impl class, Protocol, kwargs_to_ctor, friendly_name)
_IMPL_TABLE = [
    (
        FileTokenBlacklistRepository,
        TokenBlacklistRepository,
        "TokenBlacklist",
    ),
    (
        FileCSRFTokenRepository,
        CSRFTokenRepository,
        "CSRFToken",
    ),
    (
        FileSessionRepository,
        SessionRepository,
        "Session",
    ),
    (
        FileEmailVerificationRepository,
        EmailVerificationRepository,
        "EmailVerification",
    ),
    (
        FilePasswordResetRepository,
        PasswordResetRepository,
        "PasswordReset",
    ),
    (
        FileAuthorizationCodeRepository,
        AuthorizationCodeRepository,
        "AuthorizationCode",
    ),
    (
        FileClientClaimPolicyRepository,
        ClientClaimPolicyRepository,
        "ClientClaimPolicy",
    ),
    (
        FileAPIKeyClaimPolicyRepository,
        APIKeyClaimPolicyRepository,
        "APIKeyClaimPolicy",
    ),
    (
        FileOAuth2ClientRepository,
        OAuth2ClientRepository,
        "OAuth2Client",
    ),
    (
        FileOAuth2ConsentRepository,
        OAuth2ConsentRepository,
        "OAuth2Consent",
    ),
    (
        FileAPIKeyRepository,
        APIKeyRepository,
        "APIKey",
    ),
    (
        FileRefreshTokenRepository,
        RefreshTokenRepository,
        "RefreshToken",
    ),
    (
        FilePermissionRepository,
        PermissionRepository,
        "Permission",
    ),
    (
        FileRoleRepository,
        RoleRepository,
        "Role",
    ),
    (
        FileUserRoleRepository,
        UserRoleRepository,
        "UserRole",
    ),
    (
        FileLoginHistoryRepository,
        LoginHistoryRepository,
        "LoginHistory",
    ),
    (
        FileEmailIndexRepository,
        EmailIndexRepository,
        "EmailIndex",
    ),
    (
        FileFederatedIdentityRepository,
        FederatedIdentityRepository,
        "FederatedIdentity",
    ),
    (
        FileFederationProviderRepository,
        FederationProviderRepository,
        "FederationProvider",
    ),
    (
        FileUserPreferencesRepository,
        UserPreferencesRepository,
        "UserPreferences",
    ),
]


# UserRepository and KeyStoreRepository are tested separately
# below because they have richer setup (PII encryption, keyring
# directory that does not use the standard
# ``storage_path/<subdir>`` layout) that does not fit the simple
# ``FileXxxRepository(test_settings)`` pattern.


@pytest.mark.parametrize(
    "impl_cls,protocol_cls,name",
    _IMPL_TABLE,
    ids=[t[2] for t in _IMPL_TABLE],
)
class TestFileRepositoryConformance:
    """Each File implementation MUST satisfy its Protocol."""

    def test_subclass_declares_protocol(
        self, impl_cls, protocol_cls, name
    ):
        assert issubclass(impl_cls, protocol_cls), (
            f"{name}: {impl_cls.__name__} does not declare "
            f"{protocol_cls.__name__} as a base class. "
            f"Add it to the class definition so isinstance() "
            f"checks at runtime succeed."
        )

    def test_satisfies_protocol_at_runtime(
        self, test_settings, impl_cls, protocol_cls, name
    ):
        repo = impl_cls(settings=test_settings)
        assert isinstance(repo, protocol_cls), (
            f"{name}: {type(repo).__name__} does not satisfy "
            f"{protocol_cls.__name__} at runtime (missing method?)"
        )


# ---------------------------------------------------------------------------
# UserRepository — separate because it has special PII encryption
# ---------------------------------------------------------------------------


class TestFileUserRepositoryConformance:
    def test_satisfies_protocol(self, test_settings):
        from authglow.repositories.file.user import FileUserRepository
        from authglow.repositories.protocols import UserRepository

        repo = FileUserRepository(settings=test_settings)
        assert isinstance(repo, UserRepository)

    async def test_create_then_get_by_id_round_trip(self, test_settings):
        from authglow.repositories.file.user import FileUserRepository
        from authglow.repositories.protocols import UserRepository
        from authglow.services.password import hash_password

        repo = FileUserRepository(settings=test_settings)
        user = User(
            id="conf-user-1",
            email="conf@example.com",
            hashed_password=hash_password("ConfP@ss123!"),
            is_active=True,
            scopes=["read"],
        )
        await repo.create(user)
        fetched = await repo.get_by_id("conf-user-1")
        assert fetched is not None
        assert fetched.email == "conf@example.com"
        assert isinstance(repo, UserRepository)


# ---------------------------------------------------------------------------
# UserPreferences — separate because it's a Pydantic round-trip
# ---------------------------------------------------------------------------


class TestFileUserPreferencesRepositoryConformance:
    async def test_save_then_get_round_trip(self, test_settings):
        from authglow.repositories.file.user_preferences import (
            FileUserPreferencesRepository,
        )
        from authglow.repositories.protocols import UserPreferencesRepository

        repo = FileUserPreferencesRepository(settings=test_settings)
        prefs = UserPreferences(
            user_id="conf-prefs",
            theme="dark",
            language="it",
        )
        await repo.save(prefs)
        fetched = await repo.get("conf-prefs")
        assert fetched is not None
        assert fetched.theme == "dark"
        assert fetched.language == "it"
        assert isinstance(repo, UserPreferencesRepository)


# ---------------------------------------------------------------------------
# KeyStoreRepository — separate because it has a custom root_dir
# (settings.keys_dir, not settings.storage_path/<subdir>)
# ---------------------------------------------------------------------------


class TestFileKeyStoreRepositoryConformance:
    """The keyring repository is a BaseFileRepository
    subclass with a custom root_dir pointing at
    ``settings.keys_dir``. It honours the
    ``KeyStoreRepository`` Protocol — this test proves the
    contract still holds after the fsspec refactor (Fase 22)."""

    def test_subclass_declares_protocol(self):
        from authglow.repositories.file.keystore import (
            FileKeyStoreRepository,
        )
        from authglow.repositories.protocols import KeyStoreRepository

        assert issubclass(FileKeyStoreRepository, KeyStoreRepository)

    def test_satisfies_protocol_at_runtime(self, test_settings):
        from authglow.repositories.file.keystore import (
            FileKeyStoreRepository,
        )
        from authglow.repositories.protocols import KeyStoreRepository

        repo = FileKeyStoreRepository(settings=test_settings)
        assert isinstance(repo, KeyStoreRepository)

    async def test_create_then_rotate_then_get_round_trip(
        self, test_settings, tmp_path
    ):
        """Smoke test: generate a keyring, rotate, then read
        the new active keypair. Exercises every Protocol
        method on the happy path."""
        from authglow.repositories.file.keystore import (
            FileKeyStoreRepository,
        )
        from authglow.repositories.protocols import KeyStoreRepository

        # Override keys_dir with a per-test path so the
        # lru_cache'd test_keys_dir is not touched.
        class _Stub:
            storage_backend = "file"

            def __init__(self, kd: str) -> None:
                self.keys_dir = kd

            def get_storage_options(self) -> dict:
                return {}

        keys_dir = tmp_path / "conformance_keys"
        keys_dir.mkdir()
        repo = FileKeyStoreRepository(settings=_Stub(str(keys_dir)))

        # Empty keyring
        assert await repo.get_active_keypair() is None
        assert await repo.get_public_keys() == []

        # Bootstrap a fresh keyring (the repository's
        # startup path — same code that
        # ``core.config.get_or_generate_keyring`` runs).
        await repo.bootstrap_if_missing(secret_key="test-secret")
        first_active = await repo.get_active_keypair()
        assert first_active is not None
        assert first_active.meta.status == "active"

        # Rotate the active key
        new_keypair = await repo.rotate(secret_key="test-secret")
        assert new_keypair.kid != first_active.kid
        assert new_keypair.meta.status == "active"

        # The new key must be visible via get_active_keypair
        active = await repo.get_active_keypair()
        assert active is not None
        assert active.kid == new_keypair.kid

        # And via get_public_keys
        pub = await repo.get_public_keys()
        kids = {k.kid for k in pub}
        assert new_keypair.kid in kids
        assert first_active.kid in kids  # the old (now verifying) key is still listed

        assert isinstance(repo, KeyStoreRepository)
