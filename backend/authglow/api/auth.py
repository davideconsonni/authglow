"""Authentication API endpoints."""

import base64
import hashlib
import inspect
import re
from datetime import timedelta
from typing import Annotated, Any, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlencode

import jwt
import structlog
from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer

from authglow.api.oauth_errors import (
    INVALID_CLIENT,
    INVALID_GRANT,
    INVALID_REQUEST,
    INVALID_SCOPE,
    UNAUTHORIZED_CLIENT,
    UNSUPPORTED_GRANT_TYPE,
    OAuth2Error,
)
from authglow.core.config import Settings, get_settings
from authglow.core.crypto import decrypt_totp_secret
from authglow.core.datetime import utcnow
from authglow.core.jwt_singleton import get_jwt_service
from authglow.core.rate_limit import limiter
from authglow.models.claim_policy import ClaimTarget
from authglow.models.oauth_client import OAuth2Client
from authglow.models.token import Token
from authglow.models.user import (
    InviteUser,
    RegisterUser,
    User,
    UserResponse,
)
from authglow.services.api_key import APIKeyLockedException, APIKeyService
from authglow.services.audit import AuditService
from authglow.services.claim_policy import ClaimPolicyService
from authglow.services.email.factory import get_email_service
from authglow.services.email_verification import EmailVerificationService
from authglow.services.jwt import JWTService
from authglow.services.mfa import BackupCodeLockedException, MFAService
from authglow.services.oauth2 import OAuth2Service
from authglow.services.oidc_claims import (
    ClaimsParameterError,
    parse_claims_parameter,
)
from authglow.services.password import (
    PasswordValidator,
    hash_password_async,
)
from authglow.services.password_reset import PasswordResetService
from authglow.services.refresh_token import RefreshTokenService
from authglow.services.session import SessionService
from authglow.services.user import UserService

# Back-compat alias for Fase 21 transition window
UserStorage = UserService

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/oauth2/token", auto_error=False)
FIRST_PARTY_BROWSER_CLIENT_ID = "password_grant"
FIRST_PARTY_OAUTH_SCOPES = "openid profile email read write admin"


def _first_party_oauth_client(settings: Settings) -> OAuth2Client:
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


def _cookie_kwargs(settings: Settings) -> dict:
    """Build standard kwargs for httpOnly auth cookies."""
    kw: dict = {
        "httponly": True,
        "secure": settings.auth_cookie_secure,
        "samesite": settings.auth_cookie_samesite,
        "path": settings.auth_cookie_path,
    }
    if settings.auth_cookie_domain:
        kw["domain"] = settings.auth_cookie_domain
    return kw


def _set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: Optional[str],
    settings: Settings,
) -> None:
    """Set httpOnly auth cookies on the response."""
    kw = _cookie_kwargs(settings)
    response.set_cookie(
        key=settings.auth_cookie_access_name,
        value=access_token,
        max_age=settings.access_token_expire_minutes * 60,
        **kw,
    )
    if refresh_token:
        response.set_cookie(
            key=settings.auth_cookie_refresh_name,
            value=refresh_token,
            max_age=settings.refresh_token_expire_days * 86400,
            **kw,
        )


def _clear_auth_cookies(response: Response, settings: Settings) -> None:
    """Clear all auth cookies on every known path."""
    for path in ("/", settings.auth_cookie_path):
        kw = _cookie_kwargs(settings) | {"path": path}
        response.delete_cookie(settings.auth_cookie_access_name, **kw)
        response.delete_cookie(settings.auth_cookie_refresh_name, **kw)


def _extract_basic_auth(request: Request) -> Tuple[Optional[str], Optional[str]]:
    """Extract client_id and client_secret from HTTP Basic Auth header.

    Per RFC 6749 Section 2.3.1, clients MAY use HTTP Basic authentication.
    Format: Authorization: Basic base64(client_id:client_secret)
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Basic "):
        return None, None

    try:
        decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
        if ":" not in decoded:
            return None, None
        cid, csec = decoded.split(":", 1)
        # RFC 6749 §2.3.1: client_id and client_secret are
        # ``application/x-www-form-urlencoded`` before being combined
        # into the Basic credentials — decode both sides before use.
        return unquote(cid), unquote(csec)
    except Exception:
        return None, None


def _extract_bearer_auth(request: Request) -> Optional[str]:
    """Extract a Bearer token from the ``Authorization`` header.

    Used by T.2 to support ``client_assertion`` JWTs on the
    DCR Management endpoints (RFC 7521 §2.2 — the JWT can travel
    in a ``Bearer`` header for HTTP transports that lack a request
    body, e.g. ``GET /oauth2/register/{client_id}``).
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer ") :].strip()
    return token or None


# VAPT-044: minimum length + character set for the OAuth 2.0
# ``state`` parameter. RFC 6819 §4.4.1.8 + RFC 9700 (OAuth 2.0
# Security BCP, July 2025) require the server to validate
# ``state`` is high-entropy to defend against CSRF on the
# authorization-code flow. A short or predictable state is the
# classic Mix-Up / authorization-code-injection vector.
#
# Constants:
#   * ``_MIN_STATE_LEN`` — 16 printable chars. The OAuth 2.0
#     Security BCP recommends ≥ 128 bits of entropy; a 16-char
#     base64url nonce already provides 96 bits and the
#     recommended implementation pattern is a 32-byte
#     ``secrets.token_urlsafe(32)`` which produces 43 chars
#     (192 bits). 16 is the floor — anything shorter is almost
#     certainly a misconfiguration.
#   * ``_MAX_STATE_LEN`` — 512 chars. Defensive cap to prevent
#     a malicious client from forcing the server to
#     URL-encode megabytes of state into the redirect.
#   * ``_STATE_OK`` — printable ASCII excluding whitespace
#     and shell metacharacters. The character set is a
#     superset of "anything a UUID, hex digest, base64url, or
#     ULID might look like" so legitimate clients are never
#     blocked, while the no-whitespace rule protects the
#     audit log + redirect URL from log-injection attacks.
_MIN_STATE_LEN = 16
_MAX_STATE_LEN = 512
_STATE_OK = re.compile(r"^[A-Za-z0-9_\-.:~+/=]{16,512}\Z")


def _validate_state(state: Optional[str]) -> Optional[str]:
    """VAPT-044: enforce minimum length + character set on ``state``.

    Returns the state unchanged when it is a valid opaque nonce
    (16-512 chars, safe character set). Returns ``None`` when
    the state is missing, too short, too long, or contains
    characters that could break the redirect URL or the audit
    log (whitespace, control chars, shell metacharacters).

    The function never raises — callers are expected to map
    ``None`` to a 400 response with a clear error message
    (the redirect-URL echo path is the public surface, so
    refusing to echo a tainted state is the secure default).
    """
    if not state:
        return None
    if not _STATE_OK.match(state):
        return None
    return state


def _build_oauth_redirect(redirect_uri: str, **parameters: Optional[str]) -> str:
    """Append OAuth response parameters without changing their values."""
    values = {key: value for key, value in parameters.items() if value is not None}
    if not values:
        return redirect_uri
    separator = "&" if "?" in redirect_uri else "?"
    return f"{redirect_uri}{separator}{urlencode(values)}"


def _oauth_error_redirect(
    redirect_uri: str,
    error: str,
    description: Optional[str] = None,
    state: Optional[str] = None,
):
    """RFC 6749 §4.1.2.1 error redirect (302 with ``error`` params).

    Used once ``client_id`` + ``redirect_uri`` are validated — every
    later authorization-request failure MUST be reported by
    redirecting back to the client rather than a bare JSON 400.
    A tainted/absent ``state`` is simply not echoed.
    """
    from fastapi.responses import RedirectResponse

    return RedirectResponse(
        url=_build_oauth_redirect(
            redirect_uri,
            error=error,
            error_description=description,
            state=state,
        ),
        status_code=302,
    )


async def _enforce_grant_allowed(
    oauth2_service: OAuth2Service,
    *,
    client_id: str,
    grant_type: str,
) -> None:
    """RFC 6749 §5.2 ``unauthorized_client`` guard (workstream A4).

    A registered client may only exercise the grant types listed in
    its ``grant_types`` registration. The check existed in
    :meth:`OAuth2Service.verify_grant_type` but was never invoked from
    production code, so any active client could mint tokens through
    any supported grant.     A registration that does not include the grant raises the §5.2
    ``unauthorized_client`` protocol error.
    """
    # ``inspect.isawaitable`` mirrors the MagicMock-tolerant pattern used
    # by ``_require_dpop_proof_if_bound``: unit-test doubles often stub
    # ``verify_grant_type`` with a plain MagicMock (sync, truthy).
    result = oauth2_service.verify_grant_type(client_id, grant_type)
    if inspect.isawaitable(result):
        result = await result
    if result:
        return
    raise OAuth2Error(
        UNAUTHORIZED_CLIENT,
        f"Client is not authorized to use the {grant_type} grant",
        status_code=400,
    )


async def _require_dpop_proof_if_bound(
    request: Request,
    client: OAuth2Client,
    expected_htm: str,
) -> Optional[Dict[str, Any]]:
    """Return a ``cnf`` claim if the client is DPoP-bound, else ``None``.

    T.3 / RFC 9449: when ``client.dpop_bound`` is ``True`` the
    caller MUST have supplied a valid DPoP proof JWT in the
    ``DPoP`` header. The function verifies the proof and returns
    the resulting ``cnf`` claim (``{"jkt": "<thumbprint>"}``) so
    the caller can embed it in the access token.

    Raises ``HTTPException(400|401)`` when the client is
    DPoP-bound but the proof is missing or invalid. The
    ``WWW-Authenticate`` header advertises DPoP to the client.
    """
    # ``is True`` (not truthy) so MagicMock-based unit tests that
    # do not set ``dpop_bound`` explicitly default to "off".
    if getattr(client, "dpop_bound", None) is not True:
        return None
    from authglow.services.dpop import (
        build_cnf_claim,
        extract_dpop_proof,
        verify_dpop_proof,
    )

    proof = extract_dpop_proof(request)
    if not proof:
        raise OAuth2Error(
            INVALID_REQUEST,
            "DPoP proof is required for this client "
            "(token_endpoint_auth_method is DPoP-bound).",
            status_code=400,
            error_code="missing_dpop_proof",
            headers={"WWW-Authenticate": 'DPoP algs="ES256"'},
        )

    # The token endpoint URL is the target the proof declares
    # — RFC 9449 §4.2 htu claim.
    settings_ = get_settings()
    expected_htu = f"{settings_.issuer.rstrip('/')}/oauth2/token"

    claims = await verify_dpop_proof(
        proof,
        expected_htm=expected_htm,
        expected_htu=expected_htu,
    )
    jwk = claims.get("jwk") or jwt.get_unverified_header(proof).get("jwk")
    if not jwk:
        # Should not happen — verify_dpop_proof already enforces
        # the jwk header — defensive fallback.
        raise OAuth2Error(
            INVALID_REQUEST,
            "DPoP proof is missing the jwk header.",
            status_code=401,
            error_code="missing_jwk",
        )
    return build_cnf_claim(jwk)


async def _authenticate_client_at_token_endpoint(
    request: Request,
    oauth2_service: OAuth2Service,
    *,
    resolved_client_id: Optional[str],
    resolved_client_secret: Optional[str],
    client_assertion_type: Optional[str],
    client_assertion: Optional[str],
) -> Optional["OAuth2Client"]:
    """Authenticate a client on the token endpoint, dispatching on method.

    T.2: when ``client_assertion_type`` is present we delegate to
    :func:`authglow.services.client_jwt_auth.verify_client_assertion`,
    which picks the verifier based on the client's registered
    ``token_endpoint_auth_method``. Otherwise we fall back to the
    legacy secret-based path (``oauth2_service.verify_client``).

    For the legacy path the helper preserves the pre-T.2 error
    contract, expressed as RFC 6749 §5.2 bodies: a confidential
    client with a missing secret is rejected with
    ``invalid_client`` (401) and a public client with a bad
    ``client_id`` is rejected with ``invalid_client`` (400).

    Returns the authenticated :class:`OAuth2Client` when one can be
    located, otherwise ``None``. The caller is responsible for the
    subsequent 401 if the result is ``None``.
    """
    # Lazy import — circular-deps safe.
    from authglow.models.oauth_client import OAuth2Client  # noqa: F401  (type)

    if client_assertion_type or client_assertion:
        if not resolved_client_id:
            # JWT-Bearer needs a registered client to find the key.
            raise OAuth2Error(INVALID_REQUEST, "Missing client_id", status_code=400)
        client = await oauth2_service.client_storage.get_client(resolved_client_id)
        if not client or not client.is_active:
            raise OAuth2Error(
                INVALID_CLIENT,
                "Client authentication failed (unknown or inactive client).",
                status_code=401,
            )
        from authglow.services.client_jwt_auth import (
            verify_client_assertion,
        )

        await verify_client_assertion(
            request,
            client,
            client_assertion_type=client_assertion_type,
            client_assertion=client_assertion,
        )
        # Update last_used asynchronously — same as legacy path.
        await oauth2_service.client_storage.update_last_used(client.client_id)
        return client

    # Legacy secret-based path. We need to know whether the client is
    # confidential before deciding which error to raise — load it
    # first, then either return the client (legacy verify_client
    # path) or raise the legacy 401/400 errors. Public clients with
    # ``is_confidential=False`` do not need a secret.
    if not resolved_client_id:
        return None
    client = await oauth2_service.client_storage.get_client(resolved_client_id)
    settings = get_settings()
    if client is None and resolved_client_id == settings.oauth2_client_id:
        client = _first_party_oauth_client(settings)
    is_confidential = (
        bool(getattr(client, "is_confidential", True))
        if client
        else resolved_client_id != settings.oauth2_client_id
    )

    if is_confidential:
        if not resolved_client_secret:
            raise OAuth2Error(
                INVALID_CLIENT,
                "Client authentication required for confidential clients",
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="OAuth2"'},
            )
        if not await oauth2_service.verify_client(resolved_client_id, resolved_client_secret):
            raise OAuth2Error(INVALID_CLIENT, "Invalid client credentials", status_code=401)
    else:
        if not await oauth2_service.verify_client(resolved_client_id):
            raise OAuth2Error(INVALID_CLIENT, "Invalid client_id", status_code=400)
    return client


# Dependency injection
def get_user_storage():
    """Get user storage instance."""
    return UserStorage()


def get_oauth2_service():
    """Get OAuth2 service instance."""
    return OAuth2Service()


def get_password_validator():
    """Get password validator instance."""
    return PasswordValidator()


def get_mfa_service():
    """Get MFA service instance."""
    return MFAService()


def get_session_service():
    """Get session service instance."""
    return SessionService()


def get_audit_service():
    """Get audit service instance."""
    return AuditService()


def get_api_key_service():
    """Get API key service instance."""
    return APIKeyService()


async def get_current_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    storage: UserStorage = Depends(get_user_storage),
    jwt_service: JWTService = Depends(get_jwt_service),
    api_key_service: APIKeyService = Depends(get_api_key_service),
    audit_service: AuditService = Depends(get_audit_service),
    oauth2_service: OAuth2Service = Depends(get_oauth2_service),
) -> User:
    """Get current authenticated user (supports both JWT and API Key)."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    # Try API Key authentication first (from X-API-Key header or Bearer token)
    api_key = request.headers.get("X-API-Key")
    auth_header = request.headers.get("Authorization")
    bearer_token = None

    if auth_header and auth_header.startswith("Bearer "):
        bearer_token = auth_header[7:]

    # If the bearer token is an API key (e.g., starts with "ak_"), use it.
    if bearer_token and bearer_token.startswith("ak_"):
        api_key = bearer_token
    elif not api_key:
        # If no API key in header or as bearer token, try JWT from header or cookie
        if not bearer_token:
            settings = get_settings()
            bearer_token = request.cookies.get(settings.auth_cookie_access_name)
        if not bearer_token:
            raise credentials_exception
        token = bearer_token

    if api_key:
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")
        api_key_obj = await api_key_service.validate_and_track(
            api_key, ip_address=client_ip, user_agent=user_agent
        )
        if api_key_obj:
            await audit_service.log_event(
                event_type="api_key_used",
                user_id=api_key_obj.user_id,
                metadata={"key_id": api_key_obj.key_id, "key_name": api_key_obj.name},
                ip_address=client_ip,
            )

            user = await storage.get_user(api_key_obj.user_id)
            if user and user.is_active:
                user.api_key_scopes = api_key_obj.scopes
                return user

        raise credentials_exception

    # Fall back to JWT authentication if no valid API key was processed
    if not token:
        raise credentials_exception

    token_data = jwt_service.decode_token(token)
    if token_data is None or token_data.token_type != "access":
        raise credentials_exception

    user = await storage.get_user(token_data.sub)
    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    # Override user scopes with those from the JWT token
    # This ensures the user only has the permissions authorized in this specific token
    user.scopes = token_data.scopes

    return user


async def get_optional_user(
    request: Request,
    token: Optional[str] = Depends(oauth2_scheme),
    storage: UserStorage = Depends(get_user_storage),
    jwt_service: JWTService = Depends(get_jwt_service),
    api_key_service: APIKeyService = Depends(get_api_key_service),
    audit_service: AuditService = Depends(get_audit_service),
    oauth2_service: OAuth2Service = Depends(get_oauth2_service),
) -> Optional[User]:
    """Get current user if authenticated, otherwise return None.

    Used by endpoints that behave differently for authenticated vs
    anonymous users (e.g. resend verification email).
    """
    try:
        return await get_current_user(
            request, token, storage, jwt_service, api_key_service, audit_service, oauth2_service
        )
    except HTTPException:
        return None


# OAuth2 Authorization Code Flow Endpoints


@router.get("/api/oauth2/csrf-token")
async def csrf_token_endpoint(request: Request):
    """Issue a CSRF token bound to a ``csrf_session_id`` cookie."""
    from authglow.core.config import get_settings
    from authglow.services.csrf import (
        SESSION_ID_COOKIE,
        CSRFTokenService,
        get_or_create_session_id,
    )

    settings = get_settings()
    session_id = get_or_create_session_id(request)
    csrf_service = CSRFTokenService(settings=settings)
    token = await csrf_service.generate_token(session_id)

    from fastapi.responses import JSONResponse

    response = JSONResponse(content={"csrf_token": token})
    response.set_cookie(
        key=SESSION_ID_COOKIE,
        value=session_id,
        httponly=True,
        samesite=settings.auth_cookie_samesite,
        secure=settings.auth_cookie_secure,
        domain=settings.auth_cookie_domain,
        path="/",
        max_age=1800,
    )
    return response


@router.post("/api/oauth2/authorize")
@limiter.limit("10/minute")
async def authorize_post(
    request: Request,
    email: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    # A5: ``response_type`` was historically not accepted at all — the
    # SPA validated it client-side, so direct API calls could skip
    # implicit-rejection. It is now a first-class server-side param.
    response_type: Optional[str] = Form(None),
    scope: str = Form("read"),
    state: Optional[str] = Form(None),
    code_challenge: Optional[str] = Form(None),
    code_challenge_method: Optional[str] = Form(None),
    nonce: Optional[str] = Form(None),
    csrf_token: Optional[str] = Form(None),
    prompt: Optional[str] = Form(None),
    max_age: Optional[int] = Form(None),
    id_token_hint: Optional[str] = Form(None),
    # OIDC Core §5.5 — ``claims`` request parameter, JSON-encoded
    # string. When present, the token endpoint applies the
    # ``id_token`` sub-dict to filter the ID token, and the
    # UserInfo endpoint applies the ``userinfo`` sub-dict to
    # filter the UserInfo response.
    claims: Optional[str] = Form(None),
    storage: UserStorage = Depends(get_user_storage),
    oauth2_service: OAuth2Service = Depends(get_oauth2_service),
    mfa_service: MFAService = Depends(get_mfa_service),
    session_service: SessionService = Depends(get_session_service),
):
    """Process login and create authorization code (or MFA challenge).

    Accepts either email+password credentials OR an existing session cookie.
    """
    # Verify client and redirect_uri before processing login
    settings = get_settings()
    client = await oauth2_service.client_storage.get_client(client_id)
    if client is None and client_id == settings.oauth2_client_id:
        client = _first_party_oauth_client(settings)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    if settings.enforce_pkce and not code_challenge:
        raise HTTPException(
            status_code=400,
            detail="PKCE is required for all OAuth 2.0 clients (RFC 7636, Security BCP).",
        )
    if client.require_pkce and not code_challenge:
        raise HTTPException(
            status_code=400,
            detail="PKCE is required for this client, but code_challenge was not provided.",
        )

    if not await oauth2_service.verify_redirect_uri(client_id, redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    # A5 / RFC 6749 §4.1.2.1 + OIDC Core §3.1.2.1: with client_id and
    # redirect_uri validated, further request errors are reported by
    # redirecting back with ``error``/``error_description``.
    # An ABSENT ``response_type`` defaults to ``code`` — the first-party
    # SPA form contract predates the parameter; any explicit non-``code``
    # value (implicit, hybrid) is rejected server-side.
    if response_type and response_type != "code":
        return _oauth_error_redirect(
            redirect_uri,
            error="unsupported_response_type",
            description=(
                "Only the 'code' response_type is supported (implicit flow disabled)."
            ),
            state=_validate_state(state),
        )

    # VAPT-044: validate the ``state`` parameter. A short or
    # predictable state loses CSRF protection on the
    # authorization-code flow (RFC 6819 §4.4.1.8, RFC 9700
    # OAuth 2.0 Security BCP). The check happens after the
    # client_id + redirect_uri + PKCE validation so the error
    # goes back to the legitimate caller (rather than a
    # crafted redirect).
    if _validate_state(state) is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "state parameter is required and must be an opaque nonce of "
                f"at least {_MIN_STATE_LEN} characters (RFC 6819 §4.4.1.8, "
                "RFC 9700 OAuth 2.0 Security BCP). Generate a fresh value "
                "with secrets.token_urlsafe(32) and retry."
            ),
        )

    requested_scopes = scope.split() if scope else []
    try:
        processed_scopes = await oauth2_service.process_scopes(client_id, requested_scopes)
        validated_scope = " ".join(processed_scopes)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scope")

    # --- id_token_hint pre-identification (OIDC Core §3.1.2.1) ---
    hint_user: Optional[User] = None
    if id_token_hint:
        try:
            jwt_svc = await get_jwt_service()
            hint_token = jwt_svc.decode_id_token(id_token_hint, expected_aud=client_id)
            if hint_token and not email:
                hint_user = await storage.get_user(hint_token.sub)
                if hint_user:
                    email = hint_user.email
        except Exception:
            pass

    # --- OIDC prompt parameter (OIDC Core §3.1.2) ---
    _VALID_PROMPT_VALUES = {"none", "login", "consent", "select_account"}
    parsed_prompts: set[str] = set()

    if prompt:
        parsed_prompts = set(prompt.split())
        invalid = parsed_prompts - _VALID_PROMPT_VALUES
        if invalid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid prompt value(s): {', '.join(sorted(invalid))}. "
                "Allowed: none, login, consent, select_account.",
            )
        if "none" in parsed_prompts and len(parsed_prompts) > 1:
            raise HTTPException(
                status_code=400,
                detail="'none' cannot be combined with other prompt values.",
            )

    # --- OIDC Core §5.5 — ``claims`` request parameter ---
    # JSON-encoded object the client uses to ask for specific
    # claims in the ID token / UserInfo response. Parsed once
    # here and stored on the AuthorizationCode so the token
    # endpoint + UserInfo endpoint can apply the filter.
    try:
        parsed_claims = parse_claims_parameter(claims)
    except ClaimsParameterError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    # --- Security: state parameter validation (VAPT-044) ---
    # The earlier ``_validate_state`` call rejects weak or
    # absent state outright (RFC 6819 §4.4.1.8, RFC 9700 OAuth
    # 2.0 Security BCP). The legacy "warn and continue" path
    # was removed because it left the deployment exposed to
    # CSRF on the authorization-code flow.

    # --- Authentication (cookie-first, then email/password) ---
    user = None
    auth_acr: Optional[str] = None
    auth_amr: Optional[List[str]] = None

    access_token = request.cookies.get(settings.auth_cookie_access_name)
    if access_token and "login" not in parsed_prompts:
        try:
            jwt_svc = await get_jwt_service()
            token_data = jwt_svc.decode_token(access_token)
            if token_data:
                user = await storage.get_user(token_data.sub)
        except Exception:
            pass

    # --- Prompt parameter handling (OIDC Core §3.1.2) ---
    if "none" in parsed_prompts and not user:
        error_redirect = _build_oauth_redirect(
            redirect_uri,
            error="login_required",
            error_description="User is not authenticated",
            state=state,
        )
        from fastapi.responses import RedirectResponse

        return RedirectResponse(url=error_redirect, status_code=302)

    if "none" in parsed_prompts and user:
        if not user.is_active:
            raise HTTPException(status_code=400, detail="Inactive user")
        if user.suspended_until and utcnow() < user.suspended_until:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account suspended until {user.suspended_until.isoformat()}",
            )
        # A3 / OIDC Core §3.1.2.1: ``prompt=none`` permits NO
        # interaction — including the consent screen. A code may only
        # be minted silently when the client does not require consent
        # or a covering consent is already on record; otherwise the
        # request fails with ``error=consent_required``.
        if client.require_consent:
            from authglow.services.oauth_consent import OAuth2ConsentService

            has_consent, _ = await OAuth2ConsentService().check_consent(
                user_id=user.id,
                client_id=client_id,
                required_scopes=validated_scope.split() if validated_scope else ["read"],
            )
            if not has_consent:
                return _oauth_error_redirect(
                    redirect_uri,
                    error="consent_required",
                    description="Consent has not been granted for this client and scope",
                    state=state,
                )
        auth_code = await oauth2_service.create_authorization_code(
            client_id=client_id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            scope=validated_scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            state=state,
            requested_claims=parsed_claims,
        )
        redirect_url = _build_oauth_redirect(redirect_uri, code=auth_code.code, state=state)
        from fastapi.responses import RedirectResponse

        return RedirectResponse(url=redirect_url, status_code=302)

    # --- max_age enforcement (OIDC Core §3.1.2.1) ---
    if user and max_age is not None:
        if max_age == 0 or (
            user.last_login is not None and utcnow() > user.last_login + timedelta(seconds=max_age)
        ):
            user = None

    if user:
        from authglow.services.csrf import CSRFTokenService, get_or_create_session_id

        session_id = get_or_create_session_id(request)
        csrf_service = CSRFTokenService()
        if csrf_token is None:
            await AuditService().log_event(
                event_type="csrf_token_mismatch",
                user_id=user.id,
                email=user.email,
                ip_address=request.client.host if request.client else None,
                metadata={"reason": "csrf_token_missing"},
                severity="high",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token required when authenticated via session cookie.",
            )

        csrf_valid = await csrf_service.validate_token(session_id, csrf_token)
        if not csrf_valid:
            await AuditService().log_event(
                event_type="csrf_token_mismatch",
                user_id=user.id,
                email=user.email,
                ip_address=request.client.host if request.client else None,
                metadata={"reason": "csrf_token_invalid"},
                severity="high",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or expired CSRF token.",
            )

        if not user.is_active:
            raise HTTPException(status_code=400, detail="Inactive user")
        if user.suspended_until and utcnow() < user.suspended_until:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account suspended until {user.suspended_until.isoformat()}",
            )
    else:
        if not email or not password:
            raise HTTPException(
                status_code=400,
                detail="Credentials required. Sign in with email and password, or use an active session.",
            )

        user = await storage.get_user_by_email(email)
        if not user:
            # VAPT-050 will add a dummy bcrypt here to equalize
            # timing for non-existent users. For now, the response
            # shape is unchanged from the original implementation.
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # VAPT-048: check account lockout BEFORE the bcrypt compare
        # to prevent CPU DoS amplification. An attacker hammering
        # a locked account would otherwise pay one full bcrypt
        # cost (~100ms at rounds=12) per request, capped only by
        # the per-IP rate limiter. The lockout check is a single
        # file read with no crypto, so the per-request cost on
        # a locked account drops from ~100ms to <1ms.
        if await storage.is_account_locked(user.id):
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is temporarily locked due to too many failed login attempts. Please try again later.",
            )

        # VAPT-038: verify_and_maybe_rehash_password transparently
        # re-hashes the stored hash to the configured bcrypt cost
        # on a successful verify. The user is already authenticated
        # at that point, so the re-hash is a benign side effect.
        is_valid, _ = await storage.verify_and_maybe_rehash_password(user, password)
        if not is_valid:
            await storage.record_failed_login(user.id)

            # B3: main-path failed logins bypass LoginHistoryService entirely
            # (pre-existing gap — they only bump the lockout counter), so the
            # webhook emission hooks here rather than in the history service.
            from authglow.models.webhook_events import LOGIN_FAILED
            from authglow.services.webhook_dispatcher import emit_webhook_event

            emit_webhook_event(
                LOGIN_FAILED,
                {
                    "user_id": user.id,
                    "email": user.email,
                    "ip_address": request.client.host if request.client else None,
                },
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if not user.is_active:
            raise HTTPException(status_code=400, detail="Inactive user")

        await storage.reset_failed_login_attempts(user.id)

        if user.suspended_until and utcnow() < user.suspended_until:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account suspended until {user.suspended_until.isoformat()}",
            )

        # Forced credential rotation: an admin-flagged expired password must
        # complete a password change before any session or authorization code
        # is issued. The credentials were verified above, so this is NOT a
        # failed login — return early without ``record_login``,
        # ``update_last_login``, an MFA challenge, or an auth code. The SPA
        # routes to the forced-change screen on this response shape.
        if user.password_expired:
            return {"password_expired": True, "email": user.email}

        from authglow.services.login_history import LoginHistoryService

        login_svc = LoginHistoryService()
        await login_svc.record_login(
            user_id=user.id,
            email=user.email,
            success=True,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        if user.mfa_enabled and user.mfa_verified:
            req_user_agent = request.headers.get("user-agent", "")
            client_host = request.client.host if request.client else ""
            device_fingerprint = mfa_service.generate_device_fingerprint(
                req_user_agent, client_host
            )
            is_trusted = await mfa_service.is_device_trusted(user.id, device_fingerprint)

            if not is_trusted:
                mfa_session = await session_service.create_mfa_session(
                    user_id=user.id,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    scope=validated_scope,
                    state=state,
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                    nonce=nonce,
                )

                return {
                    "mfa_required": True,
                    "session_token": mfa_session.session_token,
                }

        await storage.update_last_login(user.id)
        auth_acr = "1"
        auth_amr = ["pwd"]

    if "consent" not in parsed_prompts:
        if not client.require_consent:
            auth_code = await oauth2_service.create_authorization_code(
                client_id=client_id,
                user_id=user.id,
                redirect_uri=redirect_uri,
                scope=validated_scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                nonce=nonce,
                acr=auth_acr,
                amr=auth_amr,
                state=state,
                requested_claims=parsed_claims,
            )
            redirect_url = _build_oauth_redirect(redirect_uri, code=auth_code.code, state=state)
            return {"redirect_url": redirect_url}

        from authglow.services.oauth_consent import OAuth2ConsentService

        consent_svc = OAuth2ConsentService()
        has_consent, _ = await consent_svc.check_consent(
            user_id=user.id,
            client_id=client_id,
            required_scopes=validated_scope.split() if validated_scope else ["read"],
        )

        if has_consent:
            auth_code = await oauth2_service.create_authorization_code(
                client_id=client_id,
                user_id=user.id,
                redirect_uri=redirect_uri,
                scope=validated_scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                nonce=nonce,
                acr=auth_acr,
                amr=auth_amr,
                state=state,
                requested_claims=parsed_claims,
            )
            redirect_url = _build_oauth_redirect(redirect_uri, code=auth_code.code, state=state)
            return {"redirect_url": redirect_url}

    # Show consent screen (forced by prompt=consent, or no prior consent)
    consent_session = await session_service.create_consent_session(
        user_id=user.id,
        client_id=client_id,
        redirect_uri=redirect_uri,
        scope=validated_scope,
        state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        nonce=nonce,
    )

    scope_labels: Dict[str, str] = {
        "openid": "Verify your identity",
        "profile": "Access your profile information (name, picture)",
        "email": "Access your email address",
        "offline_access": "Allow offline access (refresh tokens)",
        "read": "Read access to your data",
        "write": "Write access to your data",
    }
    scope_items = [
        {"name": s, "description": scope_labels.get(s, f"Access to {s}")}
        for s in (validated_scope.split() if validated_scope else ["read"])
    ]

    return {
        "consent_required": True,
        "session_token": consent_session["session_token"],
        "redirect_uri": redirect_uri,
        "client_name": client.client_name,
        "client_description": client.description,
        "client_logo_uri": client.logo_uri,
        "client_homepage_uri": client.homepage_uri,
        "client_terms_uri": client.terms_uri,
        "client_privacy_uri": client.privacy_uri,
        "branding": client.branding.model_dump() if client.branding else None,
        "scopes": scope_items,
    }


@router.get("/api/auth/oidc/config")
async def first_party_oidc_config():
    """Return public OIDC configuration for the AuthGlow dashboard client."""
    settings = get_settings()
    return {
        "client_id": settings.oauth2_client_id,
        "redirect_uri": settings.oauth2_first_party_redirect_uri,
        "scopes": FIRST_PARTY_OAUTH_SCOPES,
        "authorization_endpoint": f"{settings.issuer}/oauth2/authorize",
        "token_endpoint": f"{settings.issuer}/oauth2/token",
    }


@router.post("/oauth2/token", response_model=Token)
@limiter.limit("30/minute")
async def token_endpoint(
    request: Request,
    response: Response,
    grant_type: str = Form(...),
    # T.2: ``Annotated[Optional[str], Form()] = None`` is used
    # instead of ``Optional[str] = Form(None)`` because the latter
    # evaluates the default to a truthy ``Form(None)`` object when
    # the function is called directly (e.g. from unit tests). The
    # ``Annotated`` form keeps the default at ``None`` for Python
    # while still being recognised as a form parameter by FastAPI.
    code: Annotated[Optional[str], Form()] = None,
    redirect_uri: Annotated[Optional[str], Form()] = None,
    client_id: Annotated[Optional[str], Form()] = None,
    client_secret: Annotated[Optional[str], Form()] = None,
    refresh_token: Annotated[Optional[str], Form()] = None,
    scope: Annotated[Optional[str], Form()] = None,
    code_verifier: Annotated[Optional[str], Form()] = None,
    # T.2: client_assertion (RFC 7521) — the JWT-Bearer alternative
    # to ``client_secret_basic``/``client_secret_post``. Accepted on
    # every grant_type that requires client authentication.
    client_assertion_type: Annotated[Optional[str], Form()] = None,
    client_assertion: Annotated[Optional[str], Form()] = None,
    storage: UserStorage = Depends(get_user_storage),
    jwt_service: JWTService = Depends(get_jwt_service),
    oauth2_service: OAuth2Service = Depends(get_oauth2_service),
    refresh_token_service: RefreshTokenService = Depends(lambda: RefreshTokenService()),
):
    """OAuth2 token endpoint - exchanges code for tokens."""
    settings = get_settings()

    if grant_type == "authorization_code":
        # Validate authorization code
        if not code or not redirect_uri:
            raise OAuth2Error(INVALID_REQUEST, "Missing required parameters", status_code=400)

        auth_code = await oauth2_service.get_authorization_code(code)
        if not auth_code:
            raise OAuth2Error(
                INVALID_GRANT,
                "Invalid or expired authorization code",
                status_code=400,
            )

        # --- Client Authentication (RFC 6749 Section 4.1.3) ---
        # Extract client credentials from HTTP Basic Auth (client_secret_basic)
        basic_client_id, basic_client_secret = _extract_basic_auth(request)

        # Resolve client_id/client_secret: form params take precedence over Basic auth
        resolved_client_id = client_id or basic_client_id
        resolved_client_secret = client_secret or basic_client_secret

        # client_id is required and must match the authorization code
        if not resolved_client_id:
            raise OAuth2Error(INVALID_REQUEST, "Missing client_id", status_code=400)

        if resolved_client_id != auth_code.client_id:
            raise OAuth2Error(INVALID_GRANT, "Client ID mismatch", status_code=400)

        # T.2: when client_assertion is present, the helper routes to
        # the JWT-Bearer verifier (HS256 or RS256 depending on the
        # registered method). Otherwise, fall back to the legacy
        # secret-based path.
        oauth_client = await _authenticate_client_at_token_endpoint(
            request,
            oauth2_service,
            resolved_client_id=resolved_client_id,
            resolved_client_secret=resolved_client_secret,
            client_assertion_type=client_assertion_type,
            client_assertion=client_assertion,
        )
        if not oauth_client:
            # Determine is_confidential for the public-client branch
            # of the legacy path.
            is_confidential = resolved_client_id != settings.oauth2_client_id
            stored = await oauth2_service.client_storage.get_client(resolved_client_id)
            if stored:
                is_confidential = stored.is_confidential
            if is_confidential:
                raise OAuth2Error(
                    INVALID_CLIENT,
                    "Client authentication required for confidential clients",
                    status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="OAuth2"'},
                )
            raise OAuth2Error(INVALID_CLIENT, "Invalid client_id", status_code=400)
        # --- End Client Authentication ---

        # A4: the client must be registered for the authorization_code grant.
        await _enforce_grant_allowed(
            oauth2_service,
            client_id=resolved_client_id,
            grant_type="authorization_code",
        )

        # T.3: DPoP-bound clients must supply a fresh DPoP proof
        # JWT. The check sits between client authentication and
        # PKCE validation: it is a second client-auth factor
        # (proof-of-possession) so it logically belongs with the
        # auth checks, before the user-facing PKCE / scope work.
        dpop_cnf = await _require_dpop_proof_if_bound(request, oauth_client, "POST")

        if auth_code.redirect_uri != redirect_uri:
            raise OAuth2Error(INVALID_GRANT, "Redirect URI mismatch", status_code=400)

        # --- PKCE Validation ---
        if auth_code.code_challenge:
            if not code_verifier:
                raise OAuth2Error(
                    INVALID_REQUEST,
                    "Missing code_verifier for PKCE flow",
                    status_code=400,
                )

            # Validate S256 method
            if auth_code.code_challenge_method == "S256":
                hashed_verifier = hashlib.sha256(code_verifier.encode("utf-8")).digest()
                recreated_challenge = (
                    base64.urlsafe_b64encode(hashed_verifier).decode("utf-8").rstrip("=")
                )
            else:
                # Per RFC 7636, plain is not recommended. We only support S256.
                raise OAuth2Error(
                    INVALID_REQUEST,
                    "Unsupported code_challenge_method",
                    status_code=400,
                )

            if recreated_challenge != auth_code.code_challenge:
                raise OAuth2Error(INVALID_GRANT, "Invalid code_verifier", status_code=401)
        else:
            raise OAuth2Error(
                INVALID_REQUEST,
                "PKCE is required for all clients (RFC 7636, Security BCP).",
                status_code=400,
            )
        # --- End PKCE Validation ---

        # Mark code as used
        await oauth2_service.mark_code_as_used(code)

        # Get user
        user = await storage.get_user(auth_code.user_id)
        if not user:
            raise OAuth2Error(INVALID_GRANT, "User not found", status_code=400)

        # Parse and process scopes from the authorization code
        requested_scopes = auth_code.scope.split() if auth_code.scope else []
        try:
            # Validate requested scopes against what the client is allowed to request
            processed_scopes = await oauth2_service.process_scopes(
                auth_code.client_id, requested_scopes
            )
        except ValueError:
            raise OAuth2Error(INVALID_SCOPE, "Invalid scope", status_code=400)

        # Final check: ensure the user has the scopes that were approved and are valid for the client
        # OIDC standard scopes (openid, profile, email, phone, address) are always allowed
        oidc_standard_scopes = {"openid", "profile", "email", "phone", "address"}
        scopes = [s for s in processed_scopes if s in user.scopes or s in oidc_standard_scopes]

        # Generate JWT access token. The claim policy for this
        # client (or the default first-party policy if the
        # client has none) is consulted to build the extra
        # claims — see ``services/claim_policy.py`` for the
        # namespacing rules per OIDC §5.1.2.
        claim_policy_service = ClaimPolicyService()
        extra_claims = await claim_policy_service.build_claims(
            user,
            client_id=auth_code.client_id,
            scopes=scopes,
            target=ClaimTarget.ACCESS_TOKEN,
        )
        access_token_response = jwt_service.create_token_response(
            user.id,
            user.email,
            scopes,
            include_refresh=False,
            audience=auth_code.client_id,
            azp=auth_code.client_id,
            cnf=dpop_cnf,
            token_type="DPoP" if dpop_cnf else "Bearer",
            extra_claims=extra_claims,
        )

        # Create persistent refresh token with rotation
        rt = await refresh_token_service.create_refresh_token(
            user_id=user.id,
            client_id=auth_code.client_id,
            scopes=scopes,
            issued_ip=request.client.host if request.client else None,
            expires_in_days=30,
        )

        # Add refresh token to response
        access_token_response.refresh_token = rt.token

        # The dashboard is a public OAuth client. Set the browser session
        # cookies as a same-origin convenience; the OAuth response remains
        # standards-compatible JSON for every other client.
        if (
            resolved_client_id == settings.oauth2_client_id
            and redirect_uri == settings.oauth2_first_party_redirect_uri
        ):
            _set_auth_cookies(response, access_token_response.access_token, rt.token, settings)

        # Add ID token if OpenID Connect flow (openid scope requested)
        if "openid" in scopes:
            from authglow.services.oidc import OIDCService
            from authglow.services.oidc_claims import (
                ClaimsEssentialMissingError,
                apply_claims_request,
            )

            oidc_service = OIDCService()

            # Build user claims for ID token
            user_claims = oidc_service.build_user_claims(user, scopes)

            # Namespaced custom claims for the ID token (RBAC,
            # tenant, etc.) — only the rules with
            # ``include_in=[ID_TOKEN]`` apply.
            id_extra_claims = await claim_policy_service.build_claims(
                user,
                client_id=auth_code.client_id,
                scopes=scopes,
                target=ClaimTarget.ID_TOKEN,
            )

            # OIDC §5.5 — apply the ``id_token`` portion of the
            # ``claims`` request parameter the client sent on
            # the authorization request. The standard claims
            # come from ``user_claims``; the namespaced custom
            # claims come from ``id_extra_claims``. The two
            # dicts are merged, then filtered to the
            # intersection of what the client asked for and
            # what the server can provide.
            try:
                available_id_token_claims = {**user_claims, **id_extra_claims}
                filtered, missing_essential = apply_claims_request(
                    "id_token",
                    getattr(auth_code, "requested_claims", None),
                    available_id_token_claims,
                )
                user_claims = {
                    k: v for k, v in user_claims.items() if k in filtered
                }
                id_extra_claims = {
                    k: v for k, v in id_extra_claims.items() if k in filtered
                }
                if missing_essential:
                    # OIDC §5.5: the server MUST refuse when an
                    # essential claim cannot be provided.
                    from fastapi.responses import JSONResponse

                    return JSONResponse(
                        status_code=400,
                        content={
                            "error": "claims_request_invalid",
                            "error_description": (
                                "Essential claims requested by the client "
                                "are not available: "
                                + ", ".join(sorted(missing_essential))
                            ),
                        },
                    )
            except ClaimsEssentialMissingError as exc:
                from fastapi.responses import JSONResponse

                return JSONResponse(
                    status_code=400,
                    content={
                        "error": "claims_request_invalid",
                        "error_description": str(exc),
                    },
                )

            # Create ID token
            id_token = jwt_service.create_id_token(
                user_id=user.id,
                client_id=auth_code.client_id,
                scopes=scopes,
                user_claims=user_claims,
                nonce=getattr(auth_code, "nonce", None),
                auth_time=user.last_login,
                acr=auth_code.acr,
                amr=auth_code.amr,
                access_token=access_token_response.access_token,
                extra_claims=id_extra_claims,
            )

            # Add to response
            access_token_response.id_token = id_token

        if (
            resolved_client_id == settings.oauth2_client_id
            and redirect_uri == settings.oauth2_first_party_redirect_uri
        ):
            from fastapi.responses import JSONResponse

            first_party_response = JSONResponse(content={"ok": True})
            _set_auth_cookies(
                first_party_response,
                access_token_response.access_token,
                rt.token,
                settings,
            )
            return first_party_response
        return access_token_response

    elif grant_type == "client_credentials":
        # Client credentials flow (RFC 6749 §4.4)
        basic_client_id, basic_client_secret = _extract_basic_auth(request)
        resolved_client_id = client_id or basic_client_id
        resolved_client_secret = client_secret or basic_client_secret

        if not resolved_client_id:
            raise OAuth2Error(INVALID_CLIENT, "Missing client credentials", status_code=400)

        # T.2: JWT-Bearer auth is acceptable for client_credentials
        # (FAPI 2.0 §5.2.2) when ``client_assertion`` is supplied.
        # The legacy secret path still applies when the assertion is
        # absent.
        if client_assertion:
            oauth_client = await _authenticate_client_at_token_endpoint(
                request,
                oauth2_service,
                resolved_client_id=resolved_client_id,
                resolved_client_secret=None,
                client_assertion_type=client_assertion_type,
                client_assertion=client_assertion,
            )
            if not oauth_client:
                raise OAuth2Error(INVALID_CLIENT, "Invalid client credentials", status_code=401)
        else:
            if not resolved_client_secret:
                raise OAuth2Error(
                    INVALID_CLIENT, "Missing client credentials", status_code=400
                )
            if not await oauth2_service.verify_client(resolved_client_id, resolved_client_secret):
                raise OAuth2Error(INVALID_CLIENT, "Invalid client credentials", status_code=401)

        # A4: the client must be registered for the client_credentials grant.
        await _enforce_grant_allowed(
            oauth2_service,
            client_id=resolved_client_id,
            grant_type="client_credentials",
        )

        # Process and validate scopes
        requested_scopes = scope.split() if scope else []
        try:
            validated_scopes = await oauth2_service.process_scopes(
                resolved_client_id, requested_scopes
            )
        except ValueError:
            raise OAuth2Error(INVALID_SCOPE, "Invalid scope", status_code=400)

        # T.3: DPoP-bound clients must supply a fresh DPoP proof.
        # We re-load the client from storage to check the flag —
        # ``verify_client`` only returns a boolean.
        dpop_bound_client = await oauth2_service.client_storage.get_client(resolved_client_id)
        cc_dpop_cnf: Optional[Dict[str, Any]] = None
        if dpop_bound_client is not None and getattr(dpop_bound_client, "dpop_bound", None) is True:
            cc_dpop_cnf = await _require_dpop_proof_if_bound(request, dpop_bound_client, "POST")

        # Create token for client (no specific user). The claim
        # policy is consulted with ``user=None`` so RBAC and
        # USER_FIELD rules produce no value (no subject to look
        # up) — only STATIC and JWT_META rules can contribute.
        claim_policy_service = ClaimPolicyService()
        extra_claims = await claim_policy_service.build_claims(
            user=None,
            client_id=resolved_client_id,
            scopes=validated_scopes,
            target=ClaimTarget.ACCESS_TOKEN,
        )

        return jwt_service.create_token_response(
            user_id=resolved_client_id,
            email=f"{resolved_client_id}@client.internal",
            scopes=validated_scopes,
            include_refresh=False,
            cnf=cc_dpop_cnf,
            token_type="DPoP" if cc_dpop_cnf else "Bearer",
            extra_claims=extra_claims,
        )

    elif grant_type == "refresh_token":
        # Refresh token flow with rotation (supports body + cookie)
        if not refresh_token:
            refresh_token = request.cookies.get(settings.auth_cookie_refresh_name)
        basic_client_id, basic_client_secret = _extract_basic_auth(request)
        resolved_client_id = client_id or basic_client_id
        resolved_client_secret = client_secret or basic_client_secret
        if basic_client_id and client_id and basic_client_id != client_id:
            raise OAuth2Error(INVALID_REQUEST, "Client ID mismatch", status_code=400)
        if not refresh_token or not resolved_client_id:
            raise OAuth2Error(
                INVALID_REQUEST,
                "Missing refresh_token or client_id",
                status_code=400,
            )

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

        # A4: the client must be registered for the refresh_token grant.
        await _enforce_grant_allowed(
            oauth2_service,
            client_id=resolved_client_id,
            grant_type="refresh_token",
        )

        # A6 / RFC 9449 §5: DPoP-bound clients must prove key
        # possession on EVERY token-endpoint request, including refresh.
        dpop_cnf = await _require_dpop_proof_if_bound(request, oauth_client, "POST")

        # Validate and rotate refresh token
        new_rt, error = await refresh_token_service.validate_and_rotate(
            token=refresh_token,
            client_id=resolved_client_id,
            ip_address=request.client.host if request.client else None,
        )

        if error:
            raise OAuth2Error(INVALID_GRANT, error, status_code=401)
        assert new_rt is not None  # help mypy narrow after error check

        # Get user
        user = await storage.get_user(new_rt.user_id)
        if not user or not user.is_active:
            raise OAuth2Error(INVALID_GRANT, "Invalid user", status_code=401)
        assert user is not None  # help mypy narrow after raise

        # Generate new JWT access token — the claim policy for
        # the originating OAuth client (or the default
        # first-party policy if the refresh token was issued on
        # a first-party flow) decides which custom claims are
        # embedded.
        claim_policy_service = ClaimPolicyService()
        extra_claims = await claim_policy_service.build_claims(
            user,
            client_id=client_id,
            scopes=list(new_rt.scopes),
            target=ClaimTarget.ACCESS_TOKEN,
        )
        access_token_response = jwt_service.create_token_response(
            user.id,
            user.email,
            new_rt.scopes,
            include_refresh=False,
            audience=resolved_client_id,
            azp=resolved_client_id,
            cnf=dpop_cnf,
            token_type="DPoP" if dpop_cnf else "Bearer",
            extra_claims=extra_claims,
        )

        # Add new refresh token to response
        access_token_response.refresh_token = new_rt.token

        # Set httpOnly auth cookies
        _set_auth_cookies(response, access_token_response.access_token, new_rt.token, settings)

        return access_token_response

    elif grant_type == "urn:ietf:params:oauth:grant-type:device_code":
        # Device Authorization Grant (RFC 8628 §3.4) — A2 hardening:
        # client authentication, grant registration, ownership check,
        # scope processing and opaque rotated refresh tokens now match
        # every other grant branch.
        if not code or not client_id:
            raise OAuth2Error(INVALID_REQUEST, "Missing device_code or client_id", status_code=400)
        device_code = code  # reuse the `code` param for device_code

        # --- Client Authentication (same contract as other grants) ---
        basic_client_id, basic_client_secret = _extract_basic_auth(request)
        resolved_device_client_id = client_id or basic_client_id
        resolved_device_client_secret = client_secret or basic_client_secret

        oauth_client = await _authenticate_client_at_token_endpoint(
            request,
            oauth2_service,
            resolved_client_id=resolved_device_client_id,
            resolved_client_secret=resolved_device_client_secret,
            client_assertion_type=client_assertion_type,
            client_assertion=client_assertion,
        )
        if not oauth_client:
            raise OAuth2Error(INVALID_CLIENT, "Invalid client credentials", status_code=401)

        await _enforce_grant_allowed(
            oauth2_service, client_id=resolved_device_client_id, grant_type=grant_type
        )

        # A6 / RFC 9449 §5: DPoP proof required for bound clients here too.
        device_dpop_cnf = await _require_dpop_proof_if_bound(request, oauth_client, "POST")

        from authglow.services.device_auth import DeviceAuthorizationService

        device_service = DeviceAuthorizationService()
        auth = await device_service.poll(device_code)

        if auth is None:
            raise OAuth2Error(
                "expired_token",
                "The device code has expired.",
                status_code=400,
            )

        # Ownership: a polled authorization may only be redeemed by
        # the client it was issued to.
        if auth.client_id != resolved_device_client_id:
            raise OAuth2Error(
                INVALID_GRANT,
                "device_code was issued to a different client",
                status_code=400,
            )

        if auth.status == "pending":
            now_time = utcnow()
            if auth.last_poll_at and (now_time - auth.last_poll_at).total_seconds() < auth.interval:
                # RFC 8628 §3.5: escalate the polling interval by 5s.
                new_interval = await device_service.escalate_interval(device_code)
                raise OAuth2Error(
                    "slow_down",
                    f"Polling too fast; retry in {new_interval} seconds.",
                    status_code=400,
                )
            raise OAuth2Error(
                "authorization_pending",
                "User has not yet authorized.",
                status_code=400,
            )

        if auth.status == "denied":
            raise OAuth2Error(
                "access_denied",
                "The user denied the request.",
                status_code=400,
            )

        if auth.status == "authorized" and auth.user_id:
            user = await storage.get_user(auth.user_id)
            if not user or not user.is_active:
                raise OAuth2Error(INVALID_GRANT, "Invalid user", status_code=401)

            # Scope processing — previously raw scopes from the stored
            # request were minted verbatim.
            try:
                scopes_list = await oauth2_service.process_scopes(
                    resolved_device_client_id, auth.scope.split()
                )
            except ValueError as exc:
                raise OAuth2Error(INVALID_SCOPE, str(exc), status_code=400) from exc

            claim_policy_service = ClaimPolicyService()
            extra_claims = await claim_policy_service.build_claims(
                user,
                client_id=resolved_device_client_id,
                scopes=scopes_list,
                target=ClaimTarget.ACCESS_TOKEN,
            )
            access_token_response = jwt_service.create_token_response(
                user.id,
                user.email,
                scopes_list,
                include_refresh=False,
                audience=resolved_device_client_id,
                azp=resolved_device_client_id,
                cnf=device_dpop_cnf,
                token_type="DPoP" if device_dpop_cnf else "Bearer",
                extra_claims=extra_claims,
            )

            # Opaque persisted refresh token with rotation + theft
            # detection — previously a JWT the refresh endpoint could
            # never accept.
            rt = await refresh_token_service.create_refresh_token(
                user_id=user.id,
                client_id=resolved_device_client_id,
                scopes=scopes_list,
                issued_ip=request.client.host if request.client else None,
                expires_in_days=30,
            )
            access_token_response.refresh_token = rt.token

            await device_service.cleanup_expired()
            return access_token_response

        raise OAuth2Error(INVALID_REQUEST, "Unexpected device authorization state", status_code=400)

    else:
        # CONFORMANCE T.1: AuthGlow explicitly rejects `grant_type=password`
        # (Resource Owner Password Credentials, RFC 6749 §4.3). Only the
        # following grants are accepted on the standard OAuth2 token endpoint:
        #   - authorization_code (with PKCE mandatory)
        #   - client_credentials
        #   - refresh_token
        #   - urn:ietf:params:oauth:grant-type:device_code
        # Password grant is not supported. Browser login uses the same
        # Authorization Code + PKCE flow as every public client.
        raise OAuth2Error(
            UNSUPPORTED_GRANT_TYPE,
            "Unsupported grant_type",
            status_code=400,
        )

@router.post("/api/token/api-key")
@limiter.limit("20/minute")
async def exchange_api_key_for_token(
    request: Request,
    api_key_service: APIKeyService = Depends(get_api_key_service),
    storage: UserStorage = Depends(get_user_storage),
    jwt_service: JWTService = Depends(get_jwt_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Exchange an API key for an access token.

    Send the API key in the Authorization header as: Authorization: Bearer <api_key>
    """
    # Get API key from Authorization header
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header. Use: Authorization: Bearer <api_key>",
        )

    api_key = auth_header.replace("Bearer ", "")

    # Validate and get API key data
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    try:
        key_data = await api_key_service.validate_and_track(
            api_key, ip_address=client_ip, user_agent=user_agent
        )
    except APIKeyLockedException as e:
        await audit_service.log_event(
            event_type="api_key_locked",
            ip_address=client_ip,
            severity="warning",
            metadata={"key_id": e.key_id},
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="API key temporarily locked due to too many failed attempts. Try again later.",
        )
    if not key_data:
        await audit_service.log_event(
            event_type="api_key_invalid",
            ip_address=client_ip,
            severity="warning",
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
        )

    # Get user
    user = await storage.get_user(key_data.user_id)
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    # Log successful authentication
    await audit_service.log_event(
        event_type="api_key_auth_success",
        user_id=user.id,
        email=user.email,
        ip_address=request.client.host if request.client else None,
        metadata={"api_key_name": key_data.name},
    )

    # Return access token with API key scopes
    # VAPT-046: tag the access token with the internal-flow
    # audience so a future resource server that wants to
    # accept only federated OAuth2 traffic can reject tokens
    # minted by the first-party API-key exchange. Claim policy
    # is consulted with ``api_key_id=key_data.key_id`` so a
    # saved API key claim policy is applied. The service
    # merges the saved policy on top of the default first-party
    # rule set (RBAC roles + permissions) — the merge is the
    # whole point of the API key policy.
    from authglow.services.jwt import INTERNAL_AUDIENCE

    claim_policy_service = ClaimPolicyService()
    extra_claims = await claim_policy_service.build_claims(
        user,
        api_key_id=key_data.key_id,
        api_key=key_data,
        scopes=list(key_data.scopes),
        target=ClaimTarget.ACCESS_TOKEN,
    )

    return jwt_service.create_token_response(
        user.id,
        user.email,
        key_data.scopes,
        audience=INTERNAL_AUDIENCE,
        extra_claims=extra_claims,
    )


# Cookie-based auth endpoints for browser clients


@router.post("/api/auth/refresh")
@limiter.limit("10/minute")
async def cookie_refresh(
    request: Request,
    response: Response,
    storage: UserStorage = Depends(get_user_storage),
    jwt_service: JWTService = Depends(get_jwt_service),
    refresh_token_service: RefreshTokenService = Depends(lambda: RefreshTokenService()),
):
    """Refresh tokens using httpOnly cookie (no request body needed).

    Reads the refresh_token cookie, rotates it, and sets new cookies.
    The client must send `credentials: include` so the cookie is sent.
    """
    settings = get_settings()
    rt_cookie = request.cookies.get(settings.auth_cookie_refresh_name)
    if not rt_cookie:
        raise HTTPException(status_code=401, detail="No refresh token cookie")

    new_rt, error = await refresh_token_service.validate_and_rotate(
        token=rt_cookie,
        client_id=settings.oauth2_client_id,
        ip_address=request.client.host if request.client else None,
    )

    if error or not new_rt:
        _clear_auth_cookies(response, settings)
        raise HTTPException(status_code=401, detail=error or "Invalid refresh token")

    user = await storage.get_user(new_rt.user_id)
    if not user or not user.is_active:
        _clear_auth_cookies(response, settings)
        raise HTTPException(status_code=401, detail="Invalid user")

    # VAPT-046: tag the rotated access token with the
    # internal-flow audience (same convention as the password
    # login + API-key paths). The claim policy is consulted
    # with ``client_id=None`` so the default first-party rule
    # set (namespaced RBAC roles + permissions) is applied.
    from authglow.services.jwt import INTERNAL_AUDIENCE

    claim_policy_service = ClaimPolicyService()
    extra_claims = await claim_policy_service.build_claims(
        user,
        client_id=None,  # first-party cookie-based flow
        scopes=list(new_rt.scopes),
        target=ClaimTarget.ACCESS_TOKEN,
    )

    access_token = jwt_service.create_access_token(
        user.id,
        user.email,
        new_rt.scopes,
        audience=INTERNAL_AUDIENCE,
        extra_claims=extra_claims,
    )
    _set_auth_cookies(response, access_token, new_rt.token, settings)

    return {"ok": True}


@router.post("/api/auth/logout")
async def cookie_logout(
    request: Request,
    response: Response,
    jwt_service: JWTService = Depends(get_jwt_service),
    refresh_token_service: RefreshTokenService = Depends(lambda: RefreshTokenService()),
):
    """Logout — clears auth cookies, blacklists access/refresh JWT jti, revokes refresh tokens."""
    from authglow.services.auth.token_blacklist import token_blacklist as get_blacklist

    settings = get_settings()

    # Decode access token before revocation so we can extract its jti
    access_token = request.cookies.get(settings.auth_cookie_access_name)
    access_jti: Optional[str] = None
    access_exp: Optional[float] = None
    if access_token:
        at_data = jwt_service.decode_token(access_token)
        if at_data and at_data.jti:
            access_jti = at_data.jti
            access_exp = at_data.exp.timestamp()

    # Revoke disk-based refresh token and decode JWT refresh token for jti
    rt_cookie = request.cookies.get(settings.auth_cookie_refresh_name)
    rt_jti: Optional[str] = None
    rt_exp: Optional[float] = None
    if rt_cookie:
        try:
            await refresh_token_service.revoke_token(rt_cookie, reason="logout")
        except Exception:
            pass
        # Also attempt JWT decode — JWT-based refresh tokens carry jti for blacklisting
        rt_data = jwt_service.decode_token(rt_cookie)
        if rt_data and rt_data.jti:
            rt_jti = rt_data.jti
            rt_exp = rt_data.exp.timestamp()

    # Blacklist access token JWT id so it cannot be replayed
    if access_jti and access_exp:
        await get_blacklist().revoke(access_jti, access_exp)

    # Blacklist refresh token JWT id if it was a JWT-based refresh token
    if rt_jti and rt_exp:
        await get_blacklist().revoke(rt_jti, rt_exp)

    _clear_auth_cookies(response, settings)
    return {"ok": True}


# User management endpoints
@router.post(
    "/api/users/invite",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def invite_user(
    invite: InviteUser,
    current_user: User = Depends(get_current_user),
    storage: UserStorage = Depends(get_user_storage),
    password_validator: PasswordValidator = Depends(get_password_validator),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Invite a new user (admin only - requires 'admin' scope)."""
    settings = get_settings()

    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Admin access required")

    # Check if user already exists
    existing_user = await storage.get_user_by_email(invite.email)
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")

    # Generate temporary password (user should change it)
    import secrets

    temp_password = secrets.token_urlsafe(16)

    # Create user
    user = User(
        email=invite.email,
        hashed_password=await hash_password_async(temp_password),
        first_name=invite.first_name,
        last_name=invite.last_name,
        scopes=invite.scopes,
        is_invited=True,
        email_verified=False,  # Require email verification
    )

    user = await storage.create_user(user)

    # Create verification token
    verification_service = EmailVerificationService()
    token = await verification_service.create_verification_token(user)

    # Create password reset token so the invited user can set their own password
    reset_service = PasswordResetService()
    reset_token, _reset_plaintext, reset_code = await reset_service.create_reset_token(
        user_id=user.id,
        email=user.email,
        expires_in_minutes=1440,  # 24 hours for invitation
    )

    # Send welcome email with verification link and set-password link
    email_service = get_email_service()
    try:
        # VAPT-022: never embed the plaintext bearer token in a URL.
        # The ``set_password_url`` points to a clean page; the human-
        # friendly ``reset_code`` is rendered in the email body.
        context = {
            "user_name": user.first_name or user.email.split("@")[0],
            "email": user.email,
            "created_at": user.created_at.strftime("%Y-%m-%d %H:%M"),
            "login_url": f"{settings.frontend_base_url}/auth/login",
            "docs_url": f"{settings.base_url}/docs",
            "company_name": settings.company_name,
            "set_password_url": f"{settings.frontend_base_url}/auth/reset-password",
            "reset_code": reset_code,
        }

        await email_service.send_template(
            to=[user.email],
            subject=f"Welcome to {settings.company_name} - Verify your email",
            template_name="welcome",
            context=context,
        )

        # Also send verification email
        await verification_service.send_verification_email(user, token.verification_code)

    except Exception:
        # VAPT-083: route email-send failures through structlog so
        # the JSON audit stream is not polluted with plaintext
        # Python ``print()``.
        structlog.get_logger("authglow.email").warning(
            "send_email_failed",
            template="welcome_email",
            user_id=user.id if user else None,
            exc_info=True,
        )

    # Log user creation
    await audit_service.log_event(
        event_type="user_invited",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"invited_user_id": user.id, "invited_email": user.email},
    )

    return UserResponse(**user.model_dump())


@router.post("/oauth2/mfa-verify")
@limiter.limit("3/minute")
async def oauth2_mfa_verify(
    request: Request,
    session_token: str = Form(...),
    code: str = Form(...),
    trust_device: bool = Form(False),
    storage: UserStorage = Depends(get_user_storage),
    oauth2_service: OAuth2Service = Depends(get_oauth2_service),
    mfa_service: MFAService = Depends(get_mfa_service),
    session_service: SessionService = Depends(get_session_service),
):
    """Verify MFA code and complete OAuth2 authorization."""
    mfa_session = await session_service.get_mfa_session(session_token)
    if not mfa_session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    user = await storage.get_user(mfa_session.user_id)
    if not user or not user.mfa_enabled or not user.mfa_verified:
        raise HTTPException(status_code=400, detail="MFA not properly configured")

    is_valid = False

    if user.mfa_secret and len(code) == 6:
        is_valid = mfa_service.verify_totp(decrypt_totp_secret(user.mfa_secret), code)

    if not is_valid and len(code) >= 8:
        try:
            is_valid = await mfa_service.verify_user_backup_code(user.id, code)
        except BackupCodeLockedException as e:
            raise HTTPException(
                status_code=429,
                detail=f"Too many backup code attempts. Retry after {e.retry_after_seconds} seconds.",
                headers={"Retry-After": str(e.retry_after_seconds)},
            )

    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    await storage.update_last_login(user.id)

    if trust_device:
        user_agent = request.headers.get("user-agent", "")
        client_host = request.client.host if request.client else ""
        device_fingerprint = mfa_service.generate_device_fingerprint(user_agent, client_host)
        await mfa_service.add_trusted_device(user.id, device_fingerprint, "Browser")

    await session_service.delete_mfa_session(session_token)

    requested_scopes = mfa_session.scope.split() if mfa_session.scope else []
    try:
        processed_scopes = await oauth2_service.process_scopes(
            mfa_session.client_id, requested_scopes
        )
        validated_scope = " ".join(processed_scopes)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scope")

    auth_code = await oauth2_service.create_authorization_code(
        client_id=mfa_session.client_id,
        user_id=user.id,
        redirect_uri=mfa_session.redirect_uri,
        scope=validated_scope,
        code_challenge=mfa_session.code_challenge,
        code_challenge_method=mfa_session.code_challenge_method,
        nonce=mfa_session.nonce,
        acr="2",
        amr=["pwd", "mfa"],
        state=mfa_session.state,
        requested_claims=getattr(mfa_session, "requested_claims", None),
    )

    redirect_url = f"{mfa_session.redirect_uri}?code={auth_code.code}"
    if mfa_session.state:
        redirect_url += f"&state={mfa_session.state}"

    return {
        "authorization_code": auth_code.code,
        "redirect_url": redirect_url,
    }


@router.get("/api/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return UserResponse(**current_user.model_dump())


@router.get("/api/auth/my-token")
async def get_my_token(request: Request, current_user: User = Depends(get_current_user)):
    """Return the current access token (reads httpOnly cookie server-side)."""
    settings = get_settings()
    token = request.cookies.get(settings.auth_cookie_access_name, "")
    return {"access_token": token}


@router.post("/api/users", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
async def register_user(
    request: Request,
    user_data: RegisterUser,
    storage: UserStorage = Depends(get_user_storage),
    password_validator: PasswordValidator = Depends(get_password_validator),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Public self-registration endpoint."""
    settings = get_settings()

    if not settings.allow_public_registration:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Public registration is disabled",
        )

    errors = password_validator.validate(user_data.password)
    if not errors[0]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Password validation failed: {'; '.join(errors[1] or [])}",
        )

    existing_user = await storage.get_user_by_email(user_data.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with this email already exists",
        )

    user = User(
        email=user_data.email,
        hashed_password=await hash_password_async(user_data.password),
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        scopes=["read"],
        is_active=True,
        is_invited=False,
        email_verified=False,
    )

    user = await storage.create_user(user)

    verification_service = EmailVerificationService()
    token = await verification_service.create_verification_token(user)
    await verification_service.send_verification_email(user, token.verification_code)

    email_service = get_email_service()
    try:
        context = {
            "user_name": user.first_name or user.email.split("@")[0],
            "email": user.email,
            "created_at": user.created_at.strftime("%Y-%m-%d %H:%M"),
            "login_url": f"{settings.frontend_base_url}/auth/login",
            "company_name": settings.company_name,
        }
        await email_service.send_template(
            to=[user.email],
            subject=f"Welcome to {settings.company_name} - Verify your email",
            template_name="welcome",
            context=context,
        )
    except Exception:
        pass

    await audit_service.log_event(
        event_type="user_registered",
        user_id=user.id,
        email=user.email,
        ip_address=request.client.host if request.client else None,
    )

    return UserResponse(**user.model_dump())


# NOTE: the legacy admin-scoped ``GET /api/users`` list endpoint was removed
# (Fase 7 cleanup) — ``GET /api/admin/users`` supersedes it with filtering
# and pagination. The path now 404s like any unknown route.
