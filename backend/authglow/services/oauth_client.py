"""OAuth2 Client storage and management service.

Clients are persisted via the ``OAuth2ClientRepository``
Protocol. The service owns:

* the bcrypt-hashing of the plaintext client secret (via
  ``hash_password``) at creation and rotation;
* the in-process ``named_lock`` that serialises cross-coroutine
  ``update_last_used`` and ``rotate_secret`` calls;
* the CAS retry loop (defensive — the repository's ``update``
  raises ``ConcurrentWriteError`` on a stale version, and the
  service catches + retries);
* the verification methods (``verify_client_secret``,
  ``verify_redirect_uri``, ``is_scope_allowed``,
  ``is_grant_type_allowed``) — these are business rules and
  stay in the service;
* the secret-generation helper (``generate_client_secret``).

The repository is responsible for the file layout, JSON
serialisation, versioned-write CAS, and bulk ``list`` operations.
A default ``FileOAuth2ClientRepository`` is constructed when no
repository is injected — FastAPI's ``Depends(get_client_storage)``
factory uses the default.
"""

import secrets
from typing import List, Optional

from authglow.core.cache import oauth_client_cache
from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.config import Settings, get_settings
from authglow.core.datetime import utcnow
from authglow.models.oauth_client import OAuth2Client
from authglow.repositories.protocols import OAuth2ClientRepository
from authglow.services.client_jwt_auth import (
    encrypt_client_jwt_key_value,
    generate_client_jwt_symmetric_key,
)
from authglow.services.password import hash_password_async, verify_password_async


class OAuth2ClientStorage:
    """Storage for OAuth2 clients."""

    MAX_CAS_RETRIES = 3

    def __init__(
        self,
        repository: Optional[OAuth2ClientRepository] = None,
        *,
        settings: Optional[Settings] = None,
    ) -> None:
        """Initialize client storage."""
        self.settings: Settings = settings or get_settings()
        self._repository: OAuth2ClientRepository = (
            repository if repository is not None else _default_repository(self.settings)
        )
        self._lock = named_lock()

    @property
    def repository(self) -> OAuth2ClientRepository:
        """The underlying repository (exposed for tests / admin tools)."""
        return self._repository

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create_client(self, client: OAuth2Client, plaintext_secret: str) -> OAuth2Client:
        """Create a new OAuth2 client.

        The plaintext secret is bcrypt-hashed in place on the model
        before persistence; the caller never sees the hash
        (use ``generate_client_secret`` to obtain a plaintext
        secret for the API response).
        """
        client.client_secret = await hash_password_async(plaintext_secret)
        await self._repository.create(client)
        return client

    async def get_client(self, client_id: str) -> Optional[OAuth2Client]:
        """Get a client by client_id with cross-request caching.

        In the OAuth2 authorize + token-exchange flow the same
        client can be read 5+ times per request (verify_* /
        process_scopes methods). The per-request ContextVar in
        _get_client_cached covers that, but across requests the
        same client was re-read from disk every time. This
        cross-request cache eliminates those redundant reads.
        """
        cached: OAuth2Client | None = await oauth_client_cache.get(client_id)
        if cached is not None:
            return cached

        client = await self._repository.get_by_id(client_id)
        if client is not None:
            await oauth_client_cache.set(client_id, client)
        return client

    async def update_client(self, client: OAuth2Client) -> OAuth2Client:
        """Update an existing client (CAS-protected)."""
        await self._repository.update(client)
        await oauth_client_cache.delete(client.client_id)
        return client

    async def delete_client(self, client_id: str) -> bool:
        """Delete a client. Returns ``True`` on success."""
        result = await self._repository.delete(client_id)
        if result:
            await oauth_client_cache.delete(client_id)
        return result

    async def list_clients(
        self, limit: int = 100, offset: int = 0, active_only: bool = False
    ) -> List[OAuth2Client]:
        """List all OAuth2 clients with pagination."""
        return await self._repository.list(limit=limit, offset=offset, active_only=active_only)

    # ------------------------------------------------------------------
    # Verification (business rules, stay in the service)
    # ------------------------------------------------------------------

    async def verify_client_secret(self, client: OAuth2Client, client_secret: str) -> bool:
        """Verify client credentials."""
        if not client or not client.is_active:
            return False
        return await verify_password_async(client_secret, client.client_secret)

    async def verify_redirect_uri(self, client_id: str, redirect_uri: str) -> bool:
        """Verify if redirect_uri is allowed for the client."""
        client = await self.get_client(client_id)
        if not client or not client.is_active:
            return False
        return redirect_uri in client.redirect_uris

    async def is_scope_allowed(self, client_id: str, requested_scopes: List[str]) -> bool:
        """Check if client is allowed to request these scopes."""
        client = await self.get_client(client_id)
        if not client or not client.is_active:
            return False
        return all(scope in client.allowed_scopes for scope in requested_scopes)

    async def is_grant_type_allowed(self, client_id: str, grant_type: str) -> bool:
        """Check if client is allowed to use this grant type."""
        client = await self.get_client(client_id)
        if not client or not client.is_active:
            return False
        return grant_type in client.grant_types

    # ------------------------------------------------------------------
    # CAS-protected mutators
    # ------------------------------------------------------------------

    async def update_last_used(self, client_id: str) -> None:
        """Update last used timestamp with CAS protection.

        Re-raises the final ``ConcurrentWriteError`` after
        ``MAX_CAS_RETRIES`` unsuccessful CAS attempts.
        """
        async with self._lock(f"oauth_client:{client_id}"):
            for attempt in range(self.MAX_CAS_RETRIES):
                client = await self._repository.get_by_id(client_id)
                if client is None:
                    return
                client.last_used_at = utcnow()
                try:
                    await self._repository.update(client)
                    return
                except ConcurrentWriteError:
                    if attempt == self.MAX_CAS_RETRIES - 1:
                        raise
                    continue

    async def rotate_secret(self, client_id: str) -> str:
        """Rotate client secret with CAS protection.

        Returns the new plaintext secret. Raises ``ValueError``
        if the client is not found.
        """
        async with self._lock(f"oauth_client:{client_id}"):
            for attempt in range(self.MAX_CAS_RETRIES):
                client = await self._repository.get_by_id(client_id)
                if client is None:
                    raise ValueError("Client not found")
                new_secret = secrets.token_urlsafe(32)
                client.client_secret = await hash_password_async(new_secret)
                try:
                    await self._repository.update(client)
                    await oauth_client_cache.delete(client_id)
                    return new_secret
                except ConcurrentWriteError:
                    if attempt == self.MAX_CAS_RETRIES - 1:
                        raise
                    continue
        # Unreachable: the loop either returns (success), raises
        # ValueError (not found), or raises ConcurrentWriteError.
        raise ConcurrentWriteError(
            f"Failed to rotate secret for {client_id} after {self.MAX_CAS_RETRIES} attempts"
        )

    async def rotate_client_jwt_key(self, client_id: str) -> str:
        """Rotate the symmetric key used for ``client_secret_jwt`` (T.2).

        Returns the new **plaintext** key (shown to the admin once,
        like the regular ``rotate_secret``). The encrypted copy is
        persisted; the plaintext is never stored. Raises
        ``ValueError`` if the client does not exist.
        """
        async with self._lock(f"oauth_client:{client_id}"):
            for attempt in range(self.MAX_CAS_RETRIES):
                client = await self._repository.get_by_id(client_id)
                if client is None:
                    raise ValueError("Client not found")
                plaintext = generate_client_jwt_symmetric_key()
                client.client_secret_jwt_key = encrypt_client_jwt_key_value(plaintext)
                try:
                    await self._repository.update(client)
                    await oauth_client_cache.delete(client_id)
                    return plaintext
                except ConcurrentWriteError:
                    if attempt == self.MAX_CAS_RETRIES - 1:
                        raise
                    continue
        raise ConcurrentWriteError(
            f"Failed to rotate JWT key for {client_id} after {self.MAX_CAS_RETRIES} attempts"
        )

    def generate_client_secret(self) -> str:
        """Generate a secure random client secret."""
        return secrets.token_urlsafe(32)


def _default_repository(settings: Settings) -> OAuth2ClientRepository:
    from authglow.repositories.file.oauth_client import (
        FileOAuth2ClientRepository,
    )

    return FileOAuth2ClientRepository(settings)


# ``offline_access`` keeps the dashboard's browser session backed by a
# refresh token once the OIDC §11 gate on third-party code/device flows
# is in effect (see the token endpoint).
FIRST_PARTY_OAUTH_SCOPES = "openid profile email read write admin offline_access"


def first_party_oauth_client(settings: Settings) -> OAuth2Client:
    """Build the configured public client used by the AuthGlow dashboard."""
    return OAuth2Client(
        client_id=settings.oauth2_client_id,
        client_secret="first-party-public-client",
        client_name="AuthGlow Dashboard",
        redirect_uris=[settings.oauth2_first_party_redirect_uri],
        allowed_scopes=FIRST_PARTY_OAUTH_SCOPES.split(),
        grant_types=["authorization_code", "refresh_token"],
        is_confidential=False,
        require_pkce=True,
        require_consent=False,
        token_endpoint_auth_method="none",
    )


async def ensure_first_party_client(settings: Optional[Settings] = None) -> bool:
    """Persist the first-party dashboard client if it is not on disk yet.

    The dashboard client used to exist only as a settings-derived
    in-memory fallback scattered across endpoints, so any endpoint doing
    a strict repository lookup (e.g. ``verify_oauth_mfa_login``) failed
    with "Invalid or inactive OAuth client" on a deployment where the
    client had never been created. The client is a normal, persisted
    client — just auto-created at startup, like the demo user.

    Idempotent: returns ``True`` when the client was created now,
    ``False`` when it already existed (admin-configured state is left
    untouched — no re-activation, no secret rotation).
    """
    settings = settings or get_settings()
    storage = OAuth2ClientStorage(settings=settings)
    existing = await storage.get_client(settings.oauth2_client_id)
    if existing is not None:
        return False
    await storage.create_client(first_party_oauth_client(settings), "first-party-public-client")
    return True
