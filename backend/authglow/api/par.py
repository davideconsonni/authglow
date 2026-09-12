"""Pushed Authorization Requests (PAR, RFC 9126, OA-501).

``POST /oauth2/par`` stores the authorization parameters pushed by an
authenticated client and returns an opaque ``request_uri``. The later
authorize call carries only ``client_id`` + ``request_uri`` instead of
the full parameter set (see ``authorize_post``).
"""

from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Form, Request, status

from authglow.api.auth import (
    _authenticate_client_at_token_endpoint,
    _enforce_grant_allowed,
    _extract_basic_auth,
)
from authglow.api.oauth_errors import (
    INVALID_CLIENT,
    INVALID_REQUEST,
    INVALID_SCOPE,
    OAuth2Error,
)
from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.models.par import PushedAuthorizationResponse
from authglow.services.audit import AuditService
from authglow.services.oauth2 import OAuth2Service
from authglow.services.par import PushedAuthorizationService

router = APIRouter(tags=["Pushed Authorization"])


def get_oauth2_service() -> OAuth2Service:
    """Get OAuth2 service instance (overridable in tests)."""
    return OAuth2Service()


def get_par_service() -> PushedAuthorizationService:
    """Get PAR service instance (overridable in tests)."""
    return PushedAuthorizationService()


def get_audit_service() -> AuditService:
    """Get audit service instance (overridable in tests)."""
    return AuditService()


@router.post("/oauth2/par", response_model=PushedAuthorizationResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("60/minute")
async def pushed_authorization_request(
    request: Request,
    redirect_uri: Annotated[str, Form()],
    client_id: Annotated[Optional[str], Form()] = None,
    client_secret: Annotated[Optional[str], Form()] = None,
    response_type: Annotated[Optional[str], Form()] = None,
    scope: Annotated[str, Form()] = "read",
    state: Annotated[Optional[str], Form()] = None,
    code_challenge: Annotated[Optional[str], Form()] = None,
    code_challenge_method: Annotated[Optional[str], Form()] = None,
    nonce: Annotated[Optional[str], Form()] = None,
    prompt: Annotated[Optional[str], Form()] = None,
    max_age: Annotated[Optional[int], Form()] = None,
    claims: Annotated[Optional[str], Form()] = None,
    client_assertion_type: Annotated[Optional[str], Form()] = None,
    client_assertion: Annotated[Optional[str], Form()] = None,
    oauth2_service: OAuth2Service = Depends(get_oauth2_service),
    par_service: PushedAuthorizationService = Depends(get_par_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Push authorization parameters (RFC 9126 §2).

    Errors are direct RFC 6749 §5.2 bodies (no redirect — the client
    has not been sent anywhere yet). The response carries the
    single-use ``request_uri`` plus its lifetime in seconds.
    """
    settings = get_settings()

    basic_client_id, basic_client_secret = _extract_basic_auth(request)
    resolved_client_id = client_id or basic_client_id
    resolved_client_secret = client_secret or basic_client_secret
    if not resolved_client_id:
        raise OAuth2Error(INVALID_REQUEST, "Missing client_id", status_code=400)

    # RFC 9126 §2: the pushed request is authenticated like a token
    # request (same helper, same methods). Unknown clients fail here.
    oauth_client = await _authenticate_client_at_token_endpoint(
        request,
        oauth2_service,
        resolved_client_id=resolved_client_id,
        resolved_client_secret=resolved_client_secret,
        client_assertion_type=client_assertion_type,
        client_assertion=client_assertion,
    )
    if not oauth_client:
        raise OAuth2Error(INVALID_CLIENT, "Invalid client credentials", status_code=401)

    if not redirect_uri or not await oauth2_service.verify_redirect_uri(
        resolved_client_id, redirect_uri
    ):
        raise OAuth2Error(INVALID_REQUEST, "Invalid redirect_uri", status_code=400)

    # Only the code flow exists here — implicit/hybrid never had a
    # handler, so there is nothing to push for them.
    if response_type and response_type != "code":
        raise OAuth2Error(
            INVALID_REQUEST,
            "Only the 'code' response_type is supported (implicit flow disabled).",
            status_code=400,
        )

    if settings.enforce_pkce and not code_challenge:
        raise OAuth2Error(
            INVALID_REQUEST,
            "PKCE is required for all OAuth 2.0 clients (RFC 7636, Security BCP).",
            status_code=400,
        )
    if oauth_client.require_pkce and not code_challenge:
        raise OAuth2Error(
            INVALID_REQUEST,
            "PKCE is required for this client, but code_challenge was not provided.",
            status_code=400,
        )

    await _enforce_grant_allowed(
        oauth2_service,
        client_id=resolved_client_id,
        grant_type="authorization_code",
    )

    requested_scopes = scope.split() if scope else []
    try:
        validated = await oauth2_service.process_scopes(resolved_client_id, requested_scopes)
    except ValueError:
        raise OAuth2Error(INVALID_SCOPE, "Invalid scope", status_code=400)

    par = await par_service.create_request(
        client_id=resolved_client_id,
        redirect_uri=redirect_uri,
        scope=" ".join(validated),
        response_type="code",
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
        prompt=prompt,
        max_age=max_age,
        claims=claims,
    )

    try:
        await audit_service.log_event(
            event_type="par_request_created",
            user_id=None,
            client_id=resolved_client_id,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            metadata={
                "client_id": resolved_client_id,
                "request_id": par.request_id,
                "scopes": validated,
            },
        )
    except Exception:
        pass

    return PushedAuthorizationResponse(
        request_uri=par.request_uri,
        expires_in=settings.par_request_uri_ttl_seconds,
    )
