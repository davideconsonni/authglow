"""Authentication API endpoints."""

import base64
import hashlib
from typing import Dict, NoReturn, Optional, Tuple

from fastapi import APIRouter, Depends, Form, HTTPException, Request, Response, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from authglow.core.config import Settings, get_settings
from authglow.core.crypto import decrypt_totp_secret
from authglow.core.datetime import utcnow
from authglow.core.rate_limit import limiter
from authglow.models.token import Token
from authglow.models.user import (
    InviteUser,
    RegisterUser,
    User,
    UserResponse,
)
from authglow.services.api_key import APIKeyLockedException, APIKeyService
from authglow.services.audit import AuditService
from authglow.services.email.factory import get_email_service
from authglow.services.email_verification import EmailVerificationService
from authglow.services.jwt import JWTService
from authglow.services.jwt import resolve_rbac_permissions
from authglow.services.mfa import BackupCodeLockedException, MFAService
from authglow.services.oauth2 import OAuth2Service
from authglow.services.password import PasswordValidator, hash_password, verify_password
from authglow.services.password_reset import PasswordResetService
from authglow.services.refresh_token import RefreshTokenService
from authglow.services.session import SessionService
from authglow.services.storage import UserStorage

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token", auto_error=False)


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
        return cid, csec
    except Exception:
        return None, None


# Dependency injection
def get_user_storage():
    """Get user storage instance."""
    return UserStorage()


def get_jwt_service():
    """Get JWT service instance."""
    return JWTService()


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
        api_key_obj = await api_key_service.validate_key(api_key)
        if api_key_obj:
            # Track usage
            client_ip = request.client.host if request.client else None
            await api_key_service.record_usage(
                key_id=api_key_obj.key_id,
                ip_address=client_ip,
                user_agent=request.headers.get("user-agent"),
            )

            # Log API key usage
            await audit_service.log_event(
                event_type="api_key_used",
                user_id=api_key_obj.user_id,
                metadata={"key_id": api_key_obj.key_id, "key_name": api_key_obj.name},
                ip_address=client_ip,
            )

            # Get user
            user = await storage.get_user(api_key_obj.user_id)
            if user and user.is_active:
                # Attach API key info to user for scope checking
                user.api_key_scopes = api_key_obj.scopes
                return user

        # If API key is provided but invalid, raise an error
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


# OAuth2 Authorization Code Flow Endpoints


@router.post("/api/oauth2/authorize")
@limiter.limit("10/minute")
async def authorize_post(
    request: Request,
    email: Optional[str] = Form(None),
    password: Optional[str] = Form(None),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form("read"),
    state: Optional[str] = Form(None),
    code_challenge: Optional[str] = Form(None),
    code_challenge_method: Optional[str] = Form(None),
    nonce: Optional[str] = Form(None),
    storage: UserStorage = Depends(get_user_storage),
    oauth2_service: OAuth2Service = Depends(get_oauth2_service),
    mfa_service: MFAService = Depends(get_mfa_service),
    session_service: SessionService = Depends(get_session_service),
):
    """Process login and create authorization code (or MFA challenge).

    Accepts either email+password credentials OR an existing session cookie.
    """
    # Verify client and redirect_uri before processing login
    client = await oauth2_service.client_storage.get_client(client_id)
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client_id")

    if client.require_pkce and not code_challenge:
        raise HTTPException(
            status_code=400,
            detail="PKCE is required for this client, but code_challenge was not provided.",
        )

    if not await oauth2_service.verify_redirect_uri(client_id, redirect_uri):
        raise HTTPException(status_code=400, detail="Invalid redirect_uri")

    requested_scopes = scope.split() if scope else []
    try:
        processed_scopes = await oauth2_service.process_scopes(client_id, requested_scopes)
        validated_scope = " ".join(processed_scopes)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scope")

    # --- Authentication (cookie-first, then email/password) ---
    user = None

    settings = get_settings()
    access_token = request.cookies.get(settings.auth_cookie_access_name)
    if access_token:
        try:
            jwt_svc = JWTService()
            token_data = jwt_svc.decode_token(access_token)
            if token_data:
                user = await storage.get_user(token_data.sub)
        except Exception:
            pass

    if user:
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
        if not user or not verify_password(password, user.hashed_password):
            if user:
                await storage.record_failed_login(user.id)
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if await storage.is_account_locked(user.id):
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Account is temporarily locked due to too many failed login attempts. Please try again later.",
            )

        if not user.is_active:
            raise HTTPException(status_code=400, detail="Inactive user")

        await storage.reset_failed_login_attempts(user.id)

        if user.suspended_until and utcnow() < user.suspended_until:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account suspended until {user.suspended_until.isoformat()}",
            )

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

    if not client.require_consent:
        auth_code = await oauth2_service.create_authorization_code(
            client_id=client_id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            scope=validated_scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
        )
        redirect_url = f"{redirect_uri}?code={auth_code.code}"
        if state:
            redirect_url += f"&state={state}"
        return {"redirect_url": redirect_url}

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
        "client_name": client.client_name,
        "client_description": client.description,
        "client_logo_uri": client.logo_uri,
        "client_homepage_uri": client.homepage_uri,
        "client_terms_uri": client.terms_uri,
        "client_privacy_uri": client.privacy_uri,
        "custom_css": client.custom_css,
        "scopes": scope_items,
    }


@router.post("/oauth2/token", response_model=Token)
async def token_endpoint(
    request: Request,
    response: Response,
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
    code_verifier: Optional[str] = Form(None),
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
            raise HTTPException(status_code=400, detail="Missing required parameters")

        auth_code = await oauth2_service.get_authorization_code(code)
        if not auth_code:
            raise HTTPException(status_code=400, detail="Invalid or expired authorization code")

        # --- Client Authentication (RFC 6749 Section 4.1.3) ---
        # Extract client credentials from HTTP Basic Auth (client_secret_basic)
        basic_client_id, basic_client_secret = _extract_basic_auth(request)

        # Resolve client_id/client_secret: form params take precedence over Basic auth
        resolved_client_id = client_id or basic_client_id
        resolved_client_secret = client_secret or basic_client_secret

        # client_id is required and must match the authorization code
        if not resolved_client_id:
            raise HTTPException(status_code=400, detail="Missing client_id")

        if resolved_client_id != auth_code.client_id:
            raise HTTPException(status_code=400, detail="Client ID mismatch")

        # Determine if client is confidential or public
        oauth_client = await oauth2_service.client_storage.get_client(resolved_client_id)
        is_confidential = True  # Default for settings-based fallback client

        if oauth_client:
            is_confidential = oauth_client.is_confidential

        if is_confidential:
            # Confidential clients MUST authenticate with client_secret
            if not resolved_client_secret:
                raise HTTPException(
                    status_code=401,
                    detail="Client authentication required for confidential clients",
                    headers={"WWW-Authenticate": 'Basic realm="OAuth2"'},
                )
            if not await oauth2_service.verify_client(resolved_client_id, resolved_client_secret):
                raise HTTPException(status_code=401, detail="Invalid client credentials")
        else:
            # Public client: validate client_id exists but don't require secret
            if not await oauth2_service.verify_client(resolved_client_id):
                raise HTTPException(status_code=400, detail="Invalid client_id")
        # --- End Client Authentication ---

        if auth_code.redirect_uri != redirect_uri:
            raise HTTPException(status_code=400, detail="Redirect URI mismatch")

        # --- PKCE Validation ---
        if auth_code.code_challenge:
            if not code_verifier:
                raise HTTPException(status_code=400, detail="Missing code_verifier for PKCE flow")

            # Validate S256 method
            if auth_code.code_challenge_method == "S256":
                hashed_verifier = hashlib.sha256(code_verifier.encode("utf-8")).digest()
                recreated_challenge = (
                    base64.urlsafe_b64encode(hashed_verifier).decode("utf-8").rstrip("=")
                )
            else:
                # Per RFC 7636, plain is not recommended. We only support S256.
                raise HTTPException(status_code=400, detail="Unsupported code_challenge_method")

            if recreated_challenge != auth_code.code_challenge:
                raise HTTPException(status_code=401, detail="Invalid code_verifier")
        elif not is_confidential:
            # Public clients without PKCE are insecure; reject the token exchange
            raise HTTPException(
                status_code=400,
                detail="Public clients must use PKCE (code_challenge required)",
            )
        # --- End PKCE Validation ---

        # Mark code as used
        await oauth2_service.mark_code_as_used(code)

        # Get user
        user = await storage.get_user(auth_code.user_id)
        if not user:
            raise HTTPException(status_code=400, detail="User not found")

        # Parse and process scopes from the authorization code
        requested_scopes = auth_code.scope.split() if auth_code.scope else []
        try:
            # Validate requested scopes against what the client is allowed to request
            processed_scopes = await oauth2_service.process_scopes(
                auth_code.client_id, requested_scopes
            )
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scope")

        # Final check: ensure the user has the scopes that were approved and are valid for the client
        # OIDC standard scopes (openid, profile, email, phone, address) are always allowed
        oidc_standard_scopes = {"openid", "profile", "email", "phone", "address"}
        scopes = [s for s in processed_scopes if s in user.scopes or s in oidc_standard_scopes]

        # Generate JWT access token
        rbac_perms, rbac_roles = await resolve_rbac_permissions(user.id)
        access_token_response = jwt_service.create_token_response(
            user.id,
            user.email,
            scopes,
            include_refresh=False,
            permissions=rbac_perms,
            roles=rbac_roles,
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

        # Add ID token if OpenID Connect flow (openid scope requested)
        if "openid" in scopes:
            from authglow.services.oidc import OIDCService

            oidc_service = OIDCService()

            # Build user claims for ID token
            user_claims = oidc_service.build_user_claims(user, scopes)

            # Create ID token
            id_token = jwt_service.create_id_token(
                user_id=user.id,
                client_id=auth_code.client_id,
                scopes=scopes,
                user_claims=user_claims,
                nonce=getattr(auth_code, "nonce", None),  # If nonce was stored
                auth_time=user.last_login,
            )

            # Add to response
            access_token_response.id_token = id_token

        return access_token_response

    elif grant_type == "client_credentials":
        # Client credentials flow
        if not client_id or not client_secret:
            raise HTTPException(status_code=400, detail="Missing client credentials")

        if not await oauth2_service.verify_client(client_id, client_secret):
            raise HTTPException(status_code=401, detail="Invalid client credentials")

        # Process and validate scopes
        requested_scopes = scope.split() if scope else []
        try:
            validated_scopes = await oauth2_service.process_scopes(client_id, requested_scopes)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scope")

        # Create token for client (no specific user)
        return jwt_service.create_token_response(
            user_id=client_id,
            email=f"{client_id}@client.internal",
            scopes=validated_scopes,
            include_refresh=False,
        )

    elif grant_type == "refresh_token":
        # Refresh token flow with rotation (supports body + cookie)
        if not refresh_token:
            refresh_token = request.cookies.get(settings.auth_cookie_refresh_name)
        if not refresh_token or not client_id:
            raise HTTPException(status_code=400, detail="Missing refresh_token or client_id")

        # Validate and rotate refresh token
        new_rt, error = await refresh_token_service.validate_and_rotate(
            token=refresh_token,
            client_id=client_id,
            ip_address=request.client.host if request.client else None,
        )

        if error:
            raise HTTPException(status_code=401, detail=error)
        assert new_rt is not None  # help mypy narrow after error check

        # Get user
        user = await storage.get_user(new_rt.user_id)
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="Invalid user")
        assert user is not None  # help mypy narrow after raise

        # Generate new JWT access token
        rbac_perms, rbac_roles = await resolve_rbac_permissions(user.id)
        access_token_response = jwt_service.create_token_response(
            user.id,
            user.email,
            new_rt.scopes,
            include_refresh=False,
            permissions=rbac_perms,
            roles=rbac_roles,
        )

        # Add new refresh token to response
        access_token_response.refresh_token = new_rt.token

        # Set httpOnly auth cookies
        _set_auth_cookies(response, access_token_response.access_token, new_rt.token, settings)

        return access_token_response

    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")


# Traditional token endpoint (for browser login)
@router.post("/api/token")
@limiter.limit("5/minute")  # Max 5 login attempts per minute per IP
async def login_for_access_token(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    storage: UserStorage = Depends(get_user_storage),
    jwt_service: JWTService = Depends(get_jwt_service),
    audit_service: AuditService = Depends(get_audit_service),
    refresh_token_service: RefreshTokenService = Depends(lambda: RefreshTokenService()),
):
    """Direct token endpoint (username/password). Sets httpOnly auth cookies."""
    settings = get_settings()
    user = await storage.get_user_by_email(form_data.username)

    # Unified failure handling to prevent user enumeration
    async def handle_failed_login() -> NoReturn:
        await audit_service.log_event(
            event_type="login_failed",
            email=form_data.username,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            severity="warning",
        )
        # Record login history for existing users
        if user:
            from authglow.services.login_history import LoginHistoryService

            login_svc = LoginHistoryService()
            await login_svc.record_login(
                user_id=user.id,
                email=user.email,
                success=False,
                ip_address=request.client.host if request.client else None,
                user_agent=request.headers.get("user-agent"),
                failure_reason="invalid_password",
            )
            locked_until = await storage.record_failed_login(user.id)
            if locked_until:
                await audit_service.log_event(
                    event_type="account_locked",
                    user_id=user.id,
                    email=user.email,
                    ip_address=request.client.host if request.client else None,
                    user_agent=request.headers.get("user-agent"),
                    severity="high",
                )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Check if user exists and verify password
    if not user or not verify_password(form_data.password, user.hashed_password):
        await handle_failed_login()
    assert user is not None  # help mypy narrow after NoReturn handler

    # Check if account is suspended
    if user.suspended_until and utcnow() < user.suspended_until:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"Account suspended until {user.suspended_until.isoformat()}",
        )

    # Check if account is locked
    if await storage.is_account_locked(user.id):
        await audit_service.log_event(
            event_type="login_attempt_while_locked",
            user_id=user.id,
            email=user.email,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            severity="high",
        )
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked due to too many failed login attempts. Please try again later.",
        )

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    # Reset failed login attempts on successful login
    await storage.reset_failed_login_attempts(user.id)

    # Check if MFA is required
    if user.mfa_enabled and user.mfa_verified:
        # Create temporary session token for MFA verification
        session_token = jwt_service.create_mfa_session_token(user.id, user.email)

        await audit_service.log_event(
            event_type="login_mfa_required",
            user_id=user.id,
            email=user.email,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        return {
            "mfa_required": True,
            "session_token": session_token,
            "message": "MFA verification required",
        }

    # Update last login
    await storage.update_last_login(user.id)

    # Log successful login
    await audit_service.log_event(
        event_type="login_success",
        user_id=user.id,
        email=user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    from authglow.services.login_history import LoginHistoryService

    login_svc = LoginHistoryService()
    await login_svc.record_login(
        user_id=user.id,
        email=user.email,
        success=True,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    # Generate JWT token response (without refresh token from JWT service)
    rbac_perms, rbac_roles = await resolve_rbac_permissions(user.id)
    token_response = jwt_service.create_token_response(
        user.id,
        user.email,
        user.scopes,
        include_refresh=False,
        permissions=rbac_perms,
        roles=rbac_roles,
    )

    # Check if password is expired
    if user.password_expired:
        token_response.password_expired = True

    # Create persistent refresh token in storage so sessions are tracked
    rt = await refresh_token_service.create_refresh_token(
        user_id=user.id,
        client_id="password_grant",
        scopes=user.scopes,
        issued_ip=request.client.host if request.client else None,
        expires_in_days=30,
    )

    token_response.refresh_token = rt.token

    # Set httpOnly auth cookies for browser-based clients
    _set_auth_cookies(response, token_response.access_token, rt.token, settings)

    return token_response


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
    try:
        key_data = await api_key_service.validate_key(api_key)
    except APIKeyLockedException as e:
        await audit_service.log_event(
            event_type="api_key_locked",
            ip_address=request.client.host if request.client else None,
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
            ip_address=request.client.host if request.client else None,
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

    # Record usage
    await api_key_service.record_usage(
        key_id=key_data.key_id,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
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
    rbac_perms, rbac_roles = await resolve_rbac_permissions(user.id)
    return jwt_service.create_token_response(
        user.id,
        user.email,
        key_data.scopes,
        permissions=rbac_perms,
        roles=rbac_roles,
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
        client_id="cookie_grant",
        ip_address=request.client.host if request.client else None,
    )

    if error or not new_rt:
        _clear_auth_cookies(response, settings)
        raise HTTPException(status_code=401, detail=error or "Invalid refresh token")

    user = await storage.get_user(new_rt.user_id)
    if not user or not user.is_active:
        _clear_auth_cookies(response, settings)
        raise HTTPException(status_code=401, detail="Invalid user")

    access_token = jwt_service.create_access_token(user.id, user.email, new_rt.scopes)
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
    from authglow.core.token_blacklist import token_blacklist as get_blacklist

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
        hashed_password=hash_password(temp_password),
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
    reset_token, reset_plaintext = await reset_service.create_reset_token(
        user_id=user.id,
        email=user.email,
        expires_in_minutes=1440,  # 24 hours for invitation
    )

    # Send welcome email with verification link and set-password link
    email_service = get_email_service()
    try:
        context = {
            "user_name": user.first_name or user.email.split("@")[0],
            "email": user.email,
            "created_at": user.created_at.strftime("%Y-%m-%d %H:%M"),
            "login_url": f"{settings.base_url}/login",
            "docs_url": f"{settings.base_url}/docs",
            "company_name": settings.company_name,
            "set_password_url": f"{settings.base_url}/set-password?token={reset_plaintext}",
        }

        await email_service.send_template(
            to=[user.email],
            subject=f"Welcome to {settings.company_name} - Verify your email",
            template_name="welcome",
            context=context,
        )

        # Also send verification email
        await verification_service.send_verification_email(user, token.token)

    except Exception as e:
        print(f"Failed to send welcome email: {e}")

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
        hashed_password=hash_password(user_data.password),
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
    await verification_service.send_verification_email(user, token.token)

    email_service = get_email_service()
    try:
        context = {
            "user_name": user.first_name or user.email.split("@")[0],
            "email": user.email,
            "created_at": user.created_at.strftime("%Y-%m-%d %H:%M"),
            "login_url": f"{settings.base_url}/login",
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


@router.get("/api/users", response_model=list[UserResponse])
async def list_users(
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    storage: UserStorage = Depends(get_user_storage),
):
    """List all users (admin only)."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Admin access required")

    users, _ = await storage.list_users(limit=limit, offset=offset)
    return [UserResponse(**user.model_dump()) for user in users]
