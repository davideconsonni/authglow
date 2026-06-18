"""OAuth2 authorization service.

Authorization codes are persisted via the
``AuthorizationCodeRepository`` Protocol. The service owns:

* the in-process ``named_lock`` that serialises cross-coroutine
  ``mark_code_as_used`` calls;
* the ``AuthorizationCode`` model construction (``code`` default
  factory, ``expires_at`` calculation);
* the cross-process CAS retry loop (defensive — the repository's
  ``mark_used`` already retries internally, so this is a safety
  net for the future);
* the client / scope / redirect-uri / grant-type verification
  methods, which use ``client_storage`` (a peer service, not a
  repository) and ``settings`` — these are **not** part of the
  refactor and stay where they were.

The repository is responsible for the file layout, JSON
serialisation, the absent / corrupt / expired / already-used
``get_by_code`` policy, and the CAS-protected ``mark_used``. A
default ``FileAuthorizationCodeRepository`` is constructed when
no repository is injected — FastAPI's ``Depends(get_oauth2_service)``
factory uses the default.
"""

import secrets
from datetime import timedelta
from typing import List, Optional

from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import Settings, get_settings
from authglow.core.datetime import utcnow
from authglow.models.token import AuthorizationCode
from authglow.repositories.protocols import AuthorizationCodeRepository
from authglow.services.oauth_client import OAuth2ClientStorage


class OAuth2Service:
    """Service for OAuth2 authorization codes (stateless).

    The ``mark_code_as_used`` operation is protected by a named lock
    (in-process) and optimistic-concurrency versioning (cross-process)
    to prevent authorization code reuse.
    """

    MAX_CAS_RETRIES = 3

    def __init__(
        self,
        repository: Optional[AuthorizationCodeRepository] = None,
        *,
        settings: Optional[Settings] = None,
    ) -> None:
        """Initialize OAuth2 service with settings."""
        self.settings: Settings = settings or get_settings()
        self._repository: AuthorizationCodeRepository = (
            repository if repository is not None else _default_repository(self.settings)
        )
        self._lock = named_lock()

        # Peer service — used by verify_client / verify_redirect_uri /
        # verify_scopes / process_scopes / verify_grant_type. Kept as
        # a public attribute for backward compatibility with the
        # existing test mocks (see tests/integration/test_auth_api.py).
        self.client_storage = OAuth2ClientStorage()

    @property
    def repository(self) -> AuthorizationCodeRepository:
        """The underlying repository (exposed for tests / admin tools)."""
        return self._repository

    # ------------------------------------------------------------------
    # Authorization code lifecycle
    # ------------------------------------------------------------------

    async def create_authorization_code(
        self,
        client_id: str,
        user_id: str,
        redirect_uri: str,
        scope: str,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        nonce: Optional[str] = None,
        acr: Optional[str] = None,
        amr: Optional[List[str]] = None,
        state: Optional[str] = None,
    ) -> AuthorizationCode:
        """Create a new authorization code."""
        expires_at = utcnow() + timedelta(
            minutes=self.settings.oauth2_authorization_code_expire_minutes
        )

        auth_code = AuthorizationCode(
            client_id=client_id,
            user_id=user_id,
            redirect_uri=redirect_uri,
            scope=scope,
            expires_at=expires_at,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            acr=acr,
            amr=amr,
            state=state,
        )

        await self._repository.create(auth_code)
        return auth_code

    async def get_authorization_code(self, code: str) -> Optional[AuthorizationCode]:
        """Get and validate an authorization code.

        The repository handles the absent / corrupt / expired (and
        auto-deleted) / already-used policy.
        """
        return await self._repository.get_by_code(code)

    async def mark_code_as_used(self, code: str) -> bool:
        """Mark an authorization code as used.

        Protected by a named lock on the code (in-process) and the
        repository's CAS retry loop (cross-process).
        """
        async with self._lock(f"auth_code:{code}"):
            for _ in range(self.MAX_CAS_RETRIES):
                try:
                    return await self._repository.mark_used(code)
                except ConcurrentWriteError:
                    continue
            return False

    async def delete_authorization_code(self, code: str) -> None:
        """Delete an authorization code."""
        await self._repository.delete(code)

    # ------------------------------------------------------------------
    # Client / scope / redirect-uri / grant-type verification
    # (unchanged from pre-refactor — these delegate to client_storage
    # and settings, not to a repository)
    # ------------------------------------------------------------------

    async def verify_client(self, client_id: str, client_secret: Optional[str] = None) -> bool:
        """
        Verify client credentials using dynamic client storage.

        The settings-based fallback client is only available in non-production
        environments.  In production, operators must provision dynamic OAuth2
        clients through the admin API and the fallback is always rejected.
        """
        # Try dynamic client storage first
        client = await self.client_storage.get_client(client_id)

        if client:
            if not client.is_active:
                return False
            await self.client_storage.update_last_used(client_id)
            if client_secret:
                return await self.client_storage.verify_client_secret(client, client_secret)
            return True

        # Settings-based fallback client — disabled in production (VAPT-014)
        if self.settings.is_production:
            return False

        if client_id != self.settings.oauth2_client_id:
            return False

        if client_secret:
            if not secrets.compare_digest(
                client_secret, self.settings.oauth2_client_secret.get_secret_value()
            ):
                return False

        return True

    async def verify_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Verify if redirect_uri is allowed for the client."""
        client = await self.client_storage.get_client(client_id)

        if client:
            return await self.client_storage.verify_redirect_uri(client_id, redirect_uri)

        if self.settings.is_production:
            return False

        if client_id == self.settings.oauth2_client_id:
            return redirect_uri == "http://localhost:8000/callback"

        return False

    async def verify_scopes(self, client_id: str, requested_scopes: list[str]) -> bool:
        """Verify if client is allowed to request these scopes."""
        client = await self.client_storage.get_client(client_id)

        if client:
            return await self.client_storage.is_scope_allowed(client_id, requested_scopes)

        if self.settings.is_production:
            return False

        return client_id == self.settings.oauth2_client_id

    async def process_scopes(self, client_id: str, requested_scopes: List[str]) -> List[str]:
        """
        Process and validate scopes based on client configuration and application settings.

        Security: Always validates that requested scopes are authorized for the client.
        OIDC standard scopes (openid, profile, email, phone, address, offline_access)
        are always allowed as per OIDC spec.
        """
        OIDC_STANDARD_SCOPES = {
            "openid",
            "profile",
            "email",
            "phone",
            "address",
            "offline_access",
        }

        client = await self.client_storage.get_client(client_id)
        allowed_scopes = list(client.allowed_scopes) if client else []

        # Settings-based fallback client — only permissible in non-production
        if not client and client_id == self.settings.oauth2_client_id:
            if not self.settings.is_production:
                if not self.settings.oauth2_reject_unknown_scopes:
                    return requested_scopes
                allowed_scopes = []

        # Always include OIDC standard scopes in allowed list
        allowed_scopes_set = set(allowed_scopes) | OIDC_STANDARD_SCOPES

        # Check for unauthorized scopes
        unknown_scopes = set(requested_scopes) - allowed_scopes_set

        if unknown_scopes:
            if self.settings.oauth2_reject_unknown_scopes:
                raise ValueError(
                    f"Unauthorized scopes: {', '.join(sorted(unknown_scopes))}. "
                    f"Allowed: {', '.join(sorted(allowed_scopes_set))}"
                )
            else:
                filtered_scopes = [s for s in requested_scopes if s in allowed_scopes_set]
                return filtered_scopes

        return requested_scopes

    async def verify_grant_type(self, client_id: str, grant_type: str) -> bool:
        """Verify if client is allowed to use this grant type."""
        client = await self.client_storage.get_client(client_id)

        if client:
            return await self.client_storage.is_grant_type_allowed(client_id, grant_type)

        if self.settings.is_production:
            return False

        return client_id == self.settings.oauth2_client_id


def _default_repository(settings: Settings) -> AuthorizationCodeRepository:
    from authglow.repositories.file.authorization_code import (
        FileAuthorizationCodeRepository,
    )

    return FileAuthorizationCodeRepository(settings)
