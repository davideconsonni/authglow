"""Device Authorization Grant (RFC 8628) API endpoints.

Exposes the client-facing device authorization endpoint and
the user-facing verification endpoints for browser-based approval.
"""

from typing import Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from pydantic import BaseModel

from authglow.api.auth import get_current_user  # noqa: E402
from authglow.api.oauth_errors import (
    INVALID_CLIENT,
    INVALID_SCOPE,
    UNAUTHORIZED_CLIENT,
    OAuth2Error,
)
from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.models.user import User
from authglow.services.device_auth import DeviceAuthorizationService
from authglow.services.oauth2 import OAuth2Service

DEVICE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

router = APIRouter(tags=["Device Authorization"])


class DeviceAuthorizationResponse(BaseModel):
    """Response for POST /oauth2/device/authorize (RFC 8628 §3.2)."""

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str
    expires_in: int
    interval: int


class DeviceVerifyRequest(BaseModel):
    """Request body for POST /api/oauth2/device/verify."""

    user_code: str


class DeviceVerifyResponse(BaseModel):
    """Response with device info shown to the user for approval."""

    client_id: str
    scopes: list[str]
    expires_at: str  # ISO-8601


@router.post("/oauth2/device/authorize", response_model=DeviceAuthorizationResponse)
@limiter.limit("10/minute")
async def device_authorize(
    request: Request,
    client_id: str = Form(...),
    scope: str = Form("read"),
    # A2: confidential clients SHOULD authenticate here (RFC 8628 §3.1);
    # the secret also lets the server bind the authorization to a
    # verified client instead of an arbitrary ``client_id`` string.
    client_secret: Optional[str] = Form(None),
):
    """Device Authorization endpoint (RFC 8628 §3.1).

    Called by the device (CLI, IoT, TV) to initiate the flow.
    Returns a ``device_code`` for polling and a ``user_code``
    for the user to enter on a secondary device.

    A2 hardening (previously this endpoint accepted ANY client_id):

    * the client must exist and be active → else ``invalid_client``;
    * confidential clients must present their secret;
    * the client registration must include the device grant
      → else ``unauthorized_client``;
    * the requested scope is processed against the client's
      ``allowed_scopes`` → unknown scopes raise ``invalid_scope``.
    """
    settings = get_settings()

    oauth2_service = OAuth2Service()
    client = await oauth2_service.client_storage.get_client(client_id)
    if client is None and client_id == settings.oauth2_client_id:
        from authglow.api.auth import _first_party_oauth_client

        client = _first_party_oauth_client(settings)
    if not client or not getattr(client, "is_active", True):
        raise OAuth2Error(INVALID_CLIENT, "Unknown or inactive client", status_code=401)

    if bool(getattr(client, "is_confidential", True)):
        if not client_secret:
            raise OAuth2Error(
                INVALID_CLIENT,
                "Client authentication required for confidential clients",
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="OAuth2"'},
            )
        if not await oauth2_service.verify_client(client_id, client_secret):
            raise OAuth2Error(INVALID_CLIENT, "Invalid client credentials", status_code=401)

    if DEVICE_GRANT not in set(client.grant_types):
        raise OAuth2Error(
            UNAUTHORIZED_CLIENT,
            f"Client is not authorized to use the {DEVICE_GRANT} grant",
            status_code=400,
        )

    try:
        processed_scopes = await oauth2_service.process_scopes(client_id, scope.split())
    except ValueError as exc:
        raise OAuth2Error(INVALID_SCOPE, str(exc), status_code=400) from exc

    base_url = settings.frontend_base_url or str(request.base_url).rstrip("/")
    verification_uri = f"{base_url}/oauth2/device/verify"

    service = DeviceAuthorizationService()
    auth = await service.create_device_authorization(
        client_id, " ".join(processed_scopes), verification_uri
    )

    return DeviceAuthorizationResponse(
        device_code=auth.device_code,
        user_code=auth.user_code,
        verification_uri=verification_uri,
        verification_uri_complete=f"{verification_uri}?user_code={auth.user_code}",
        expires_in=settings.device_code_expire_seconds,
        interval=auth.interval,
    )


@router.post("/api/oauth2/device/verify", response_model=DeviceVerifyResponse)
@limiter.limit("10/minute")
async def device_verify(
    request: Request,
    body: DeviceVerifyRequest,
    current_user: User = Depends(get_current_user),
):
    """User-facing endpoint: lookup a user_code.

    Requires authentication. Returns the client info and
    requested scopes so the user can decide whether to approve.
    """
    service = DeviceAuthorizationService()
    auth = await service.verify_user_code(body.user_code)

    if auth is None:
        raise HTTPException(status_code=404, detail="Invalid or expired user code")

    if auth.status != "pending":
        raise HTTPException(
            status_code=400, detail="This device authorization is no longer pending"
        )

    return DeviceVerifyResponse(
        client_id=auth.client_id,
        scopes=auth.scope.split(),
        expires_at=auth.expires_at.isoformat(),
    )


@router.post("/api/oauth2/device/approve")
@limiter.limit("10/minute")
async def device_approve(
    request: Request,
    body: DeviceVerifyRequest,
    current_user: User = Depends(get_current_user),
):
    """User-facing endpoint: approve a device authorization."""
    service = DeviceAuthorizationService()
    success = await service.approve(body.user_code, current_user.id)

    if not success:
        raise HTTPException(status_code=400, detail="Invalid or expired user code")

    return {"status": "approved"}


@router.post("/api/oauth2/device/deny")
@limiter.limit("10/minute")
async def device_deny(
    request: Request,
    body: DeviceVerifyRequest,
    current_user: User = Depends(get_current_user),
):
    """User-facing endpoint: deny a device authorization."""
    service = DeviceAuthorizationService()
    success = await service.deny(body.user_code)

    if not success:
        raise HTTPException(status_code=400, detail="Invalid or expired user code")

    return {"status": "denied"}


@router.get("/api/oauth2/device/authorizations")
@limiter.limit("30/minute")
async def my_device_authorizations(
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """User-facing endpoint: list own device authorizations."""
    service = DeviceAuthorizationService()
    auths = await service.list_by_user(current_user.id)

    return {
        "device_authorizations": [
            {
                "device_code": a.device_code[:12] + "...",
                "user_code": a.user_code,
                "client_id": a.client_id,
                "scope": a.scope,
                "status": a.status,
                "created_at": a.created_at.isoformat(),
                "expires_at": a.expires_at.isoformat(),
            }
            for a in auths
        ],
        "total": len(auths),
    }


@router.post("/api/oauth2/device/authorizations/{user_code}/revoke")
@limiter.limit("10/minute")
async def revoke_my_device_authorization(
    user_code: str,
    request: Request,
    current_user: User = Depends(get_current_user),
):
    """User-facing endpoint: revoke own device authorization by user_code."""
    service = DeviceAuthorizationService()
    auth = await service.verify_user_code(user_code)

    if auth is None or auth.user_id != current_user.id:
        raise HTTPException(status_code=404, detail="Device authorization not found")

    success = await service.revoke(auth.device_code)
    if not success:
        raise HTTPException(status_code=400, detail="Cannot revoke this device authorization")

    return {"status": "revoked"}
