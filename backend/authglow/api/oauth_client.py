"""OAuth2 Client Management API endpoints."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status

from authglow.api.auth import get_current_user
from authglow.core.rate_limit import limiter
from authglow.core.safeword_store import (
    SafewordPurpose,
    consume_challenge,
    issue_challenge,
)
from authglow.models.oauth_client import (
    OAuth2Client,
    OAuth2ClientCreate,
    OAuth2ClientResponse,
    OAuth2ClientSecretRotation,
    OAuth2ClientUpdate,
    OAuth2ClientWithSecret,
    RotateSecretChallenge,
    RotateSecretConfirm,
    _client_response_from_model,
)
from authglow.models.user import User
from authglow.services.audit import AuditService
from authglow.services.client_jwt_auth import (
    encrypt_client_jwt_key_value,
    generate_client_jwt_symmetric_key,
)
from authglow.services.oauth_client import OAuth2ClientStorage

router = APIRouter(prefix="/api/oauth-clients")


# ---------------------------------------------------------------------------
# Safeword challenge gate
# ---------------------------------------------------------------------------
#
# Destructive OAuth-client admin actions (rotate-secret,
# rotate-jwt-key) require the operator to type a server-issued
# safeword before the call is accepted. The challenge store and
# helpers live in :mod:`authglow.core.safeword_store`; this module
# only orchestrates the two-call handshake.


def get_client_storage() -> OAuth2ClientStorage:
    """Get OAuth2 client storage instance."""
    return OAuth2ClientStorage()


def get_audit_service() -> AuditService:
    """Get audit service instance."""
    return AuditService()


def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Require admin scope."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return current_user


@router.post("", response_model=OAuth2ClientWithSecret, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")  # Max 10 client creations per hour
async def create_oauth_client(
    request: Request,
    client_data: OAuth2ClientCreate,
    current_user: User = Depends(require_admin),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """
    Create a new OAuth2 client (admin only).

    The client secret is only shown once at creation time.
    Store it securely as it cannot be retrieved later.
    """
    # Generate client secret
    plaintext_secret = storage.generate_client_secret()

    # T.2: if the admin picked ``client_secret_jwt``, mint a fresh
    # symmetric key and show it **once** in the response, exactly like
    # the regular ``client_secret``. The encrypted copy is persisted
    # via ``client_secret_jwt_key``; the plaintext is never stored.
    plaintext_jwt_key: Optional[str] = None
    if client_data.token_endpoint_auth_method == "client_secret_jwt":
        plaintext_jwt_key = generate_client_jwt_symmetric_key()

    # Create client
    client = OAuth2Client(
        client_name=client_data.client_name,
        client_secret=plaintext_secret,  # Will be hashed in storage
        redirect_uris=client_data.redirect_uris,
        allowed_post_logout_redirect_uris=client_data.allowed_post_logout_redirect_uris,
        allowed_scopes=client_data.allowed_scopes,
        grant_types=client_data.grant_types,
        is_confidential=client_data.is_confidential,
        require_pkce=client_data.require_pkce,
        require_consent=client_data.require_consent,
        description=client_data.description,
        logo_uri=client_data.logo_uri,
        homepage_uri=client_data.homepage_uri,
        terms_uri=client_data.terms_uri,
        privacy_uri=client_data.privacy_uri,
        branding=client_data.branding,
        access_token_lifetime=client_data.access_token_lifetime,
        refresh_token_lifetime=client_data.refresh_token_lifetime,
        created_by=current_user.id,
        token_endpoint_auth_method=client_data.token_endpoint_auth_method or "client_secret_basic",
        public_jwk=client_data.public_jwk,
        client_secret_jwt_key=(
            encrypt_client_jwt_key_value(plaintext_jwt_key)
            if plaintext_jwt_key is not None
            else None
        ),
    )

    await storage.create_client(client, plaintext_secret)

    # Audit log
    await audit_service.log_event(
        event_type="oauth_client_created",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "client_id": client.client_id,
            "client_name": client.client_name,
            "token_endpoint_auth_method": client.token_endpoint_auth_method,
        },
    )

    # Return client with plaintext secret (only shown once). The JWT key
    # is returned in the same envelope when applicable so the admin
    # can hand it to the client operator through the established
    # "show-once" UI flow. ``client_secret_jwt_key`` is excluded
    # from the dump because the response model re-receives the
    # PLAINTEXT key below (the dump carries the encrypted copy).
    response_kwargs = client.model_dump(
        exclude={"client_secret", "client_secret_jwt_key"}
    )
    response = OAuth2ClientWithSecret(
        **response_kwargs,
        client_secret=plaintext_secret,
        client_secret_jwt_key=plaintext_jwt_key,
    )

    return response


@router.get("", response_model=List[OAuth2ClientResponse])
async def list_oauth_clients(
    limit: int = 100,
    offset: int = 0,
    active_only: bool = False,
    current_user: User = Depends(require_admin),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
):
    """List all OAuth2 clients (admin only)."""
    clients = await storage.list_clients(limit=limit, offset=offset, active_only=active_only)

    return [_client_response_from_model(client) for client in clients]


@router.get("/{client_id}", response_model=OAuth2ClientResponse)
async def get_oauth_client(
    client_id: str,
    current_user: User = Depends(require_admin),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
):
    """Get a specific OAuth2 client (admin only)."""
    client = await storage.get_client(client_id)

    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2 client not found")

    return _client_response_from_model(client)


@router.put("/{client_id}", response_model=OAuth2ClientResponse)
@limiter.limit("30/hour")  # Max 30 client updates per hour
async def update_oauth_client(
    request: Request,
    client_id: str,
    update_data: OAuth2ClientUpdate,
    current_user: User = Depends(require_admin),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Update an OAuth2 client (admin only)."""
    client = await storage.get_client(client_id)

    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2 client not found")

    # Update fields
    update_dict = update_data.model_dump(exclude_unset=True)
    for field, value in update_dict.items():
        setattr(client, field, value)

    await storage.update_client(client)

    # Audit log
    await audit_service.log_event(
        event_type="oauth_client_updated",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"client_id": client_id, "updated_fields": list(update_dict.keys())},
    )

    return _client_response_from_model(client)


@router.delete("/{client_id}")
@limiter.limit("20/hour")  # Max 20 client deletions per hour
async def delete_oauth_client(
    request: Request,
    client_id: str,
    current_user: User = Depends(require_admin),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Delete an OAuth2 client (admin only)."""
    client = await storage.get_client(client_id)

    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2 client not found")

    success = await storage.delete_client(client_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete OAuth2 client",
        )

    # Audit log
    await audit_service.log_event(
        event_type="oauth_client_deleted",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"client_id": client_id, "client_name": client.client_name},
        severity="warning",
    )

    return {"message": "OAuth2 client deleted successfully"}


@router.post(
    "/{client_id}/rotate-secret/challenge", response_model=RotateSecretChallenge
)
@limiter.limit("60/hour")
async def request_rotate_secret_challenge(
    request: Request,
    client_id: str,
    current_user: User = Depends(require_admin),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """
    Issue a single-use safeword challenge for ``rotate-secret``.

    The admin must echo the returned ``word`` back in the body of
    the subsequent ``POST /api/oauth-clients/{id}/rotate-secret``
    call. The challenge expires after 60 seconds and is bound to
    this ``client_id`` and to the ``secret`` purpose (a challenge
    minted here cannot be used to rotate a JWT key, and vice versa).
    """
    client = await storage.get_client(client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2 client not found"
        )

    issued = issue_challenge(client_id, SafewordPurpose.OAUTH_CLIENT_SECRET)

    await audit_service.log_event(
        event_type="oauth_client_rotate_challenge_issued",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "client_id": client_id,
            "client_name": client.client_name,
            "purpose": "secret",
        },
        severity="info",
    )

    return RotateSecretChallenge(
        challenge_id=issued["challenge_id"],
        word=issued["word"],
        expires_at=issued["expires_at"],
    )


@router.post(
    "/{client_id}/rotate-jwt-key/challenge", response_model=RotateSecretChallenge
)
@limiter.limit("60/hour")
async def request_rotate_jwt_key_challenge(
    request: Request,
    client_id: str,
    current_user: User = Depends(require_admin),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """
    Issue a single-use safeword challenge for ``rotate-jwt-key``.

    Same semantics as the secret-rotation challenge, but the
    challenge is bound to the ``jwt_key`` purpose so it cannot be
    redeemed against the secret-rotation endpoint.
    """
    client = await storage.get_client(client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2 client not found"
        )
    if client.token_endpoint_auth_method != "client_secret_jwt":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "rotate-jwt-key is only valid for clients with "
                "token_endpoint_auth_method='client_secret_jwt'."
            ),
        )

    issued = issue_challenge(client_id, SafewordPurpose.OAUTH_CLIENT_JWT_KEY)

    await audit_service.log_event(
        event_type="oauth_client_rotate_challenge_issued",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "client_id": client_id,
            "client_name": client.client_name,
            "purpose": "jwt_key",
        },
        severity="info",
    )

    return RotateSecretChallenge(
        challenge_id=issued["challenge_id"],
        word=issued["word"],
        expires_at=issued["expires_at"],
    )


@router.post("/{client_id}/rotate-secret", response_model=OAuth2ClientSecretRotation)
@limiter.limit("10/day")  # Max 10 secret rotations per day
async def rotate_client_secret(
    request: Request,
    client_id: str,
    body: RotateSecretConfirm,
    current_user: User = Depends(require_admin),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """
    Rotate OAuth2 client secret (admin only).

    Requires a valid safeword challenge obtained from
    ``/{client_id}/rotate-secret/challenge``. The new secret is only
    shown once — store it securely.
    """
    consume_challenge(
        body.challenge_id, client_id, body.word, SafewordPurpose.OAUTH_CLIENT_SECRET
    )

    client = await storage.get_client(client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2 client not found"
        )

    new_secret = await storage.rotate_secret(client_id)

    await audit_service.log_event(
        event_type="oauth_client_secret_rotated",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"client_id": client_id, "client_name": client.client_name},
        severity="high",
    )

    return OAuth2ClientSecretRotation(
        client_id=client_id, new_client_secret=new_secret
    )


@router.post("/{client_id}/rotate-jwt-key", response_model=OAuth2ClientSecretRotation)
@limiter.limit("10/day")
async def rotate_client_jwt_key(
    request: Request,
    client_id: str,
    body: RotateSecretConfirm,
    current_user: User = Depends(require_admin),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """
    Rotate the symmetric key used by ``token_endpoint_auth_method=client_secret_jwt``.

    T.2 + safeword: requires a valid challenge from
    ``/{client_id}/rotate-jwt-key/challenge``. The new key is shown
    only once. The encrypted copy is persisted, the plaintext is
    returned for handoff to the client operator.
    """
    consume_challenge(
        body.challenge_id, client_id, body.word, SafewordPurpose.OAUTH_CLIENT_JWT_KEY
    )

    client = await storage.get_client(client_id)
    if not client:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2 client not found"
        )
    if client.token_endpoint_auth_method != "client_secret_jwt":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "rotate-jwt-key is only valid for clients with "
                "token_endpoint_auth_method='client_secret_jwt'."
            ),
        )

    new_key = await storage.rotate_client_jwt_key(client_id)

    await audit_service.log_event(
        event_type="oauth_client_jwt_key_rotated",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"client_id": client_id, "client_name": client.client_name},
        severity="high",
    )

    # Reuse the secret-rotation response envelope but the field
    # semantic is "new JWT key". The OpenAPI response_model documents
    # the actual field meaning through the description in the admin UI.
    return OAuth2ClientSecretRotation(
        client_id=client_id, new_client_secret=new_key
    )


@router.post("/{client_id}/activate")
async def activate_oauth_client(
    client_id: str,
    current_user: User = Depends(require_admin),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Activate an OAuth2 client (admin only)."""
    client = await storage.get_client(client_id)

    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2 client not found")

    client.is_active = True
    await storage.update_client(client)

    # Audit log
    await audit_service.log_event(
        event_type="oauth_client_activated",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"client_id": client_id},
    )

    return {"message": "OAuth2 client activated"}


@router.post("/{client_id}/deactivate")
async def deactivate_oauth_client(
    client_id: str,
    current_user: User = Depends(require_admin),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Deactivate an OAuth2 client (admin only)."""
    client = await storage.get_client(client_id)

    if not client:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="OAuth2 client not found")

    client.is_active = False
    await storage.update_client(client)

    # Audit log
    await audit_service.log_event(
        event_type="oauth_client_deactivated",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"client_id": client_id},
        severity="warning",
    )

    return {"message": "OAuth2 client deactivated"}
