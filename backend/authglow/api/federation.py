"""External Identity Provider federation API.

Provides admin CRUD for external IdP configurations, and the public-facing
login/callback endpoints for federated authentication flows.
"""

import secrets
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.core.rate_limit import limiter
from authglow.models.federation import (
    ExternalIdpConfig,
    ExternalIdpConfigCreate,
    ExternalIdpConfigResponse,
    ExternalIdpConfigUpdate,
)
from authglow.services.audit import AuditService
from authglow.services.federation import FederationService
from authglow.services.federation_state import FederationStateError, FederationStateToken
from authglow.services.federation_storage import FederationStorage
from authglow.services.jwt import JWTService
from authglow.services.login_history import LoginHistoryService
from authglow.services.storage import UserStorage

router = APIRouter()


# ---------------------------------------------------------------------------
# Public endpoints — used by the OAuth authorize / login page
# ---------------------------------------------------------------------------


@router.get("/api/federation/providers")
async def list_public_providers(
    storage: FederationStorage = Depends(lambda: FederationStorage()),
):
    """Return the list of enabled external IdPs for the login UI."""
    service = FederationService()
    return await service.get_providers_for_ui()


@router.get("/api/federation/login/{provider_id}")
async def federation_login(
    provider_id: str,
    redirect_uri: str = Query(default="/auth/callback"),
    acr_values: Optional[str] = Query(default=None),
    storage: FederationStorage = Depends(lambda: FederationStorage()),
):
    """Initiate federated login — redirect user to the external IdP.

    The CSRF protection for the OAuth2/OIDC authorization code flow
    (RFC 6749 §10.12) is provided by a signed JWT state token: all
    callback context (provider_id, redirect_uri, nonce, expiry) is
    embedded in the token claims and protected by a signature. This
    keeps the flow stateless — no shared store, no session cookie —
    which is required for serverless deployments.
    """
    provider = await storage.get_provider(provider_id)
    if not provider or not provider.enabled:
        raise HTTPException(status_code=404, detail="Provider not found or disabled")
    if not provider.issuer.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400, detail="Provider issuer must start with http:// or https://"
        )

    callback_uri = f"{get_settings().base_url.rstrip('/')}/api/federation/callback"
    state_token = FederationStateToken()
    signed = state_token.sign(
        provider_id=provider.id,
        redirect_uri=callback_uri,
    )

    try:
        service = FederationService()
        auth_url, _state, _nonce = await service.get_authorization_url(
            provider,
            redirect_uri=callback_uri,
            state=signed["state"],
            nonce=signed["nonce"],
            acr_values=acr_values,
        )
        return RedirectResponse(url=auth_url, status_code=302)
    except Exception as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to reach external provider: {str(e)}",
        )


@router.get("/api/federation/callback")
async def federation_callback(
    code: str,
    state: str,
    provider_id: str,
    storage: FederationStorage = Depends(lambda: FederationStorage()),
    user_storage: UserStorage = Depends(lambda: UserStorage()),
    audit_service: AuditService = Depends(lambda: AuditService()),
):
    """Handle the redirect callback from the external IdP.

    Security (RFC 6749 §10.12, OIDC Core §3.1.2.1 / §15.5.2):
        * ``state`` is a signed JWT generated at ``/api/federation/login``.
          Any tampering, expiry, or signature failure aborts the flow.
        * The ``provider_id`` claim in the state must match the query
          parameter, so a state from one provider cannot be replayed
          against another.
        * When the IdP returns an ``id_token`` (OIDC), the ``nonce``
          claim is verified against the value bound to the state.
    """
    state_claims: dict = {}
    try:
        state_claims = FederationStateToken().verify(state)
    except FederationStateError as e:
        await audit_service.log_event(
            event_type="federation_login_failed",
            email="unknown",
            metadata={"provider_id": provider_id, "error": f"state_invalid: {e}"},
        )
        raise HTTPException(status_code=400, detail=f"Invalid state: {e}") from e

    if state_claims.get("provider_id") != provider_id:
        await audit_service.log_event(
            event_type="federation_login_failed",
            email="unknown",
            metadata={
                "provider_id": provider_id,
                "error": "provider_mismatch",
                "state_provider_id": state_claims.get("provider_id"),
            },
        )
        raise HTTPException(status_code=400, detail="State provider does not match request")

    provider = await storage.get_provider(provider_id)
    if not provider or not provider.enabled:
        raise HTTPException(status_code=404, detail="Provider not found or disabled")

    service = FederationService()
    redirect_uri = state_claims["redirect_uri"]

    try:
        token_response = await service.exchange_code(provider, code, redirect_uri)
        access_token = token_response.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token in response")

        id_token = token_response.get("id_token")
        if id_token:
            try:
                import jwt as _jwt

                _unverified = _jwt.decode(id_token, options={"verify_signature": False})
                if _unverified.get("nonce") != state_claims.get("nonce"):
                    raise ValueError("nonce mismatch")
            except (ValueError, TypeError) as e:
                raise HTTPException(
                    status_code=400, detail=f"ID token nonce validation failed: {e}"
                ) from e

        claims = await service.fetch_userinfo(provider, access_token)
        mapped = await service.map_claims_to_user(provider, claims)

        external_id = mapped.get("external_id", "")
        email = mapped.get("email", "")

        existing_user = (
            await user_storage.get_by_external_id(provider.id, external_id)
            if hasattr(user_storage, "get_by_external_id")
            else None
        )

        if not existing_user and email:
            existing_user = await user_storage.get_by_email(email)

        if existing_user:
            user = existing_user
        else:
            from authglow.models.user import UserCreate
            from authglow.services.password import hash_password

            new_user = UserCreate(
                email=email or f"{external_id}@federated.local",
                password=hash_password(secrets.token_urlsafe(32)),
                name=mapped.get("name", email or external_id),
            )
            user = await user_storage.create_user(new_user)

        # Check if account is suspended
        if user.suspended_until and utcnow() < user.suspended_until:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account suspended until {user.suspended_until.isoformat()}",
            )

        jwt_service = JWTService()
        tokens = await jwt_service.create_user_tokens(user)

        await audit_service.log_event(
            event_type="federation_login_success",
            user_id=user.id,
            email=user.email,
            metadata={
                "provider_id": provider_id,
                "provider_label": provider.label,
                "external_id": external_id,
                "state_jti": state_claims.get("jti"),
            },
        )

        login_svc = LoginHistoryService()
        await login_svc.record_login(
            user_id=user.id,
            email=user.email,
            success=True,
        )

        return {
            "access_token": tokens["access_token"],
            "refresh_token": tokens.get("refresh_token"),
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "email": user.email,
                "name": user.name,
            },
        }

    except HTTPException:
        raise
    except Exception as e:
        await audit_service.log_event(
            event_type="federation_login_failed",
            email="unknown",
            metadata={
                "provider_id": provider_id,
                "provider_label": provider.label,
                "error": str(e),
            },
        )
        raise HTTPException(status_code=400, detail=f"Federation login failed: {str(e)}")


# ---------------------------------------------------------------------------
# Admin CRUD
# ---------------------------------------------------------------------------


@router.post("/api/federation/providers", response_model=ExternalIdpConfigResponse)
@limiter.limit("10/minute")
async def create_provider(
    request: Request,
    provider_data: ExternalIdpConfigCreate,
    storage: FederationStorage = Depends(lambda: FederationStorage()),
):
    """Admin: create a new external IdP provider."""

    if not provider_data.issuer.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Issuer must start with http:// or https://")

    provider = ExternalIdpConfig(
        label=provider_data.label,
        description=provider_data.description,
        issuer=provider_data.issuer,
        client_id=provider_data.client_id,
        client_secret=provider_data.client_secret,
        scopes=provider_data.scopes,
        icon_uri=provider_data.icon_uri,
        logo_uri=provider_data.logo_uri,
        enabled=provider_data.enabled,
        auth_levels=provider_data.auth_levels,
        claims_mapping=provider_data.claims_mapping
        or ExternalIdpConfig.model_fields["claims_mapping"].default,
    )
    created = await storage.create_provider(provider)
    return created


@router.get("/api/federation/admin/providers", response_model=List[ExternalIdpConfigResponse])
async def list_all_providers(
    storage: FederationStorage = Depends(lambda: FederationStorage()),
):
    """Admin: list all providers (including disabled)."""
    return await storage.list_providers(enabled_only=False)


@router.get(
    "/api/federation/admin/providers/{provider_id}", response_model=ExternalIdpConfigResponse
)
async def get_provider(
    provider_id: str,
    storage: FederationStorage = Depends(lambda: FederationStorage()),
):
    """Admin: get a single provider."""
    provider = await storage.get_provider(provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    return provider


@router.put(
    "/api/federation/admin/providers/{provider_id}", response_model=ExternalIdpConfigResponse
)
@limiter.limit("30/minute")
async def update_provider(
    request: Request,
    provider_id: str,
    updates: ExternalIdpConfigUpdate,
    storage: FederationStorage = Depends(lambda: FederationStorage()),
):
    """Admin: update a provider."""
    update_data = updates.model_dump(exclude_unset=True)
    updated = await storage.update_provider(provider_id, update_data)
    if not updated:
        raise HTTPException(status_code=404, detail="Provider not found")
    return updated


@router.delete("/api/federation/admin/providers/{provider_id}")
@limiter.limit("20/minute")
async def delete_provider(
    request: Request,
    provider_id: str,
    storage: FederationStorage = Depends(lambda: FederationStorage()),
):
    """Admin: delete a provider."""
    deleted = await storage.delete_provider(provider_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Provider not found")
    return {"status": "deleted", "provider_id": provider_id}


@router.patch("/api/federation/admin/providers/{provider_id}/toggle")
async def toggle_provider(
    provider_id: str,
    storage: FederationStorage = Depends(lambda: FederationStorage()),
):
    """Admin: toggle provider enabled/disabled."""
    provider = await storage.get_provider(provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    updated = await storage.update_provider(provider_id, {"enabled": not provider.enabled})
    return updated
