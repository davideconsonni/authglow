"""Authentication API endpoints."""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Form, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, HTMLResponse
from fastapi.templating import Jinja2Templates

from authglow.models.user import User, UserCreate, UserLogin, InviteUser, UserResponse
from authglow.models.token import Token, OAuth2AuthorizationRequest, OAuth2TokenRequest
from authglow.models.mfa import MFALoginRequest
from authglow.services.storage import UserStorage
from authglow.services.password import hash_password, verify_password, PasswordValidator
from authglow.services.jwt import JWTService
from authglow.services.oauth2 import OAuth2Service
from authglow.services.mfa import MFAService
from authglow.services.session import SessionService
from authglow.services.audit import AuditService
from authglow.core.config import get_settings

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/token")
templates = Jinja2Templates(directory="authglow/templates")


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


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    storage: UserStorage = Depends(get_user_storage),
    jwt_service: JWTService = Depends(get_jwt_service)
) -> User:
    """Get current authenticated user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    token_data = jwt_service.decode_token(token)
    if token_data is None or token_data.token_type != "access":
        raise credentials_exception

    user = await storage.get_user(token_data.sub)
    if user is None:
        raise credentials_exception

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    return user


# OAuth2 Authorization Code Flow Endpoints

@router.get("/oauth2/authorize", response_class=HTMLResponse)
async def authorize(
    request: Request,
    response_type: str,
    client_id: str,
    redirect_uri: str,
    scope: Optional[str] = "read",
    state: Optional[str] = None,
    oauth2_service: OAuth2Service = Depends(get_oauth2_service)
):
    """OAuth2 authorization endpoint - shows login page."""
    settings = get_settings()

    # Verify client
    if not oauth2_service.verify_client(client_id):
        raise HTTPException(status_code=400, detail="Invalid client_id")

    if response_type != "code":
        raise HTTPException(status_code=400, detail="Unsupported response_type")

    # Render login page with OAuth2 parameters
    ui_context = settings.get_ui_context()
    return templates.TemplateResponse(
        "login.html",
        {
            "request": request,
            **ui_context,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "state": state,
            "password_policy": PasswordValidator().get_policy_description()
        }
    )


@router.post("/oauth2/authorize")
async def authorize_post(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    client_id: str = Form(...),
    redirect_uri: str = Form(...),
    scope: str = Form("read"),
    state: Optional[str] = Form(None),
    storage: UserStorage = Depends(get_user_storage),
    oauth2_service: OAuth2Service = Depends(get_oauth2_service),
    mfa_service: MFAService = Depends(get_mfa_service),
    session_service: SessionService = Depends(get_session_service)
):
    """Process login and create authorization code (or MFA challenge)."""
    # Authenticate user
    user = await storage.get_user_by_email(email)
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    # Check if MFA is required
    if user.mfa_enabled and user.mfa_verified:
        # Check if device is trusted
        user_agent = request.headers.get("user-agent", "")
        client_host = request.client.host if request.client else ""
        device_fingerprint = mfa_service.generate_device_fingerprint(user_agent, client_host)

        is_trusted = await mfa_service.is_device_trusted(user.id, device_fingerprint)

        if not is_trusted:
            # Require MFA - create temporary session
            mfa_session = await session_service.create_mfa_session(
                user_id=user.id,
                client_id=client_id,
                redirect_uri=redirect_uri,
                scope=scope,
                state=state
            )

            # Show MFA verification page
            settings = get_settings()
            ui_context = settings.get_ui_context()
            return templates.TemplateResponse(
                "mfa_verify.html",
                {
                    "request": request,
                    **ui_context,
                    "session_token": mfa_session.session_token
                }
            )

    # No MFA required or device trusted - proceed with authorization
    await storage.update_last_login(user.id)

    # Create authorization code
    auth_code = await oauth2_service.create_authorization_code(
        client_id=client_id,
        user_id=user.id,
        redirect_uri=redirect_uri,
        scope=scope
    )

    # Redirect with authorization code
    redirect_url = f"{redirect_uri}?code={auth_code.code}"
    if state:
        redirect_url += f"&state={state}"

    return RedirectResponse(url=redirect_url, status_code=303)


@router.post("/oauth2/token", response_model=Token)
async def token_endpoint(
    grant_type: str = Form(...),
    code: Optional[str] = Form(None),
    redirect_uri: Optional[str] = Form(None),
    client_id: Optional[str] = Form(None),
    client_secret: Optional[str] = Form(None),
    refresh_token: Optional[str] = Form(None),
    scope: Optional[str] = Form(None),
    storage: UserStorage = Depends(get_user_storage),
    jwt_service: JWTService = Depends(get_jwt_service),
    oauth2_service: OAuth2Service = Depends(get_oauth2_service)
):
    """OAuth2 token endpoint - exchanges code for tokens."""

    if grant_type == "authorization_code":
        # Validate authorization code
        if not code or not redirect_uri:
            raise HTTPException(status_code=400, detail="Missing required parameters")

        auth_code = await oauth2_service.get_authorization_code(code)
        if not auth_code:
            raise HTTPException(status_code=400, detail="Invalid or expired authorization code")

        if auth_code.redirect_uri != redirect_uri:
            raise HTTPException(status_code=400, detail="Redirect URI mismatch")

        # Mark code as used
        await oauth2_service.mark_code_as_used(code)

        # Get user
        user = await storage.get_user(auth_code.user_id)
        if not user:
            raise HTTPException(status_code=400, detail="User not found")

        # Generate tokens
        return jwt_service.create_token_response(user.id, user.email, user.scopes)

    elif grant_type == "client_credentials":
        # Client credentials flow
        if not client_id or not client_secret:
            raise HTTPException(status_code=400, detail="Missing client credentials")

        if not oauth2_service.verify_client(client_id, client_secret):
            raise HTTPException(status_code=401, detail="Invalid client credentials")

        # Create token for client (no specific user)
        scopes = scope.split() if scope else ["read"]
        return jwt_service.create_token_response(
            user_id=client_id,
            email=f"{client_id}@client.local",
            scopes=scopes,
            include_refresh=False
        )

    elif grant_type == "refresh_token":
        # Refresh token flow
        if not refresh_token:
            raise HTTPException(status_code=400, detail="Missing refresh_token")

        token_data = jwt_service.decode_token(refresh_token)
        if not token_data or token_data.token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")

        # Get user
        user = await storage.get_user(token_data.sub)
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="Invalid user")

        # Generate new tokens
        return jwt_service.create_token_response(user.id, user.email, user.scopes)

    else:
        raise HTTPException(status_code=400, detail="Unsupported grant_type")


# Traditional token endpoint (for testing)
@router.post("/api/token", response_model=Token)
async def login_for_access_token(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    storage: UserStorage = Depends(get_user_storage),
    jwt_service: JWTService = Depends(get_jwt_service),
    audit_service: AuditService = Depends(get_audit_service)
):
    """Direct token endpoint (username/password)."""
    user = await storage.get_user_by_email(form_data.username)

    # Log failed login
    if not user or not verify_password(form_data.password, user.hashed_password):
        await audit_service.log_event(
            event_type="login_failed",
            email=form_data.username,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            severity="warning"
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")

    # Update last login
    await storage.update_last_login(user.id)

    # Log successful login
    await audit_service.log_event(
        event_type="login_success",
        user_id=user.id,
        email=user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )

    return jwt_service.create_token_response(user.id, user.email, user.scopes)


# User management endpoints
@router.post("/api/users/invite", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def invite_user(
    invite: InviteUser,
    current_user: User = Depends(get_current_user),
    storage: UserStorage = Depends(get_user_storage),
    password_validator: PasswordValidator = Depends(get_password_validator)
):
    """Invite a new user (admin only - requires 'admin' scope)."""
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
        is_invited=True
    )

    user = await storage.create_user(user)

    # In production, send email with temp_password
    # For now, just return it (this is insecure - implement email service)

    return UserResponse(**user.model_dump())


@router.post("/oauth2/mfa-verify")
async def oauth2_mfa_verify(
    request: Request,
    session_token: str = Form(...),
    code: str = Form(...),
    trust_device: bool = Form(False),
    storage: UserStorage = Depends(get_user_storage),
    oauth2_service: OAuth2Service = Depends(get_oauth2_service),
    mfa_service: MFAService = Depends(get_mfa_service),
    session_service: SessionService = Depends(get_session_service)
):
    """Verify MFA code and complete OAuth2 authorization."""
    # Get MFA session
    mfa_session = await session_service.get_mfa_session(session_token)
    if not mfa_session:
        raise HTTPException(status_code=401, detail="Invalid or expired session")

    # Get user
    user = await storage.get_user(mfa_session.user_id)
    if not user or not user.mfa_enabled or not user.mfa_verified:
        raise HTTPException(status_code=400, detail="MFA not properly configured")

    # Verify code (try TOTP first, then backup code)
    is_valid = False

    # Try TOTP
    if user.mfa_secret and len(code) == 6:
        is_valid = mfa_service.verify_totp(user.mfa_secret, code)

    # Try backup code if TOTP failed
    if not is_valid and len(code) >= 8:
        is_valid = await mfa_service.verify_user_backup_code(user.id, code)

    if not is_valid:
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    # MFA verified successfully
    await storage.update_last_login(user.id)

    # Trust device if requested
    if trust_device:
        user_agent = request.headers.get("user-agent", "")
        client_host = request.client.host if request.client else ""
        device_fingerprint = mfa_service.generate_device_fingerprint(user_agent, client_host)
        await mfa_service.add_trusted_device(user.id, device_fingerprint, "Browser")

    # Delete MFA session
    await session_service.delete_mfa_session(session_token)

    # Create authorization code
    auth_code = await oauth2_service.create_authorization_code(
        client_id=mfa_session.client_id,
        user_id=user.id,
        redirect_uri=mfa_session.redirect_uri,
        scope=mfa_session.scope
    )

    # Redirect with authorization code
    redirect_url = f"{mfa_session.redirect_uri}?code={auth_code.code}"
    if mfa_session.state:
        redirect_url += f"&state={mfa_session.state}"

    return RedirectResponse(url=redirect_url, status_code=303)


@router.get("/api/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_user)):
    """Get current user info."""
    return UserResponse(**current_user.model_dump())


@router.get("/api/users", response_model=list[UserResponse])
async def list_users(
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user),
    storage: UserStorage = Depends(get_user_storage)
):
    """List all users (admin only)."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Admin access required")

    users = await storage.list_users(limit=limit, offset=offset)
    return [UserResponse(**user.model_dump()) for user in users]


# OAuth2 Callback endpoint (for testing)
@router.get("/callback", response_class=HTMLResponse)
async def oauth2_callback(
    request: Request,
    code: Optional[str] = None,
    state: Optional[str] = None,
    error: Optional[str] = None
):
    """OAuth2 callback endpoint - displays authorization code for testing."""
    settings = get_settings()
    ui_context = settings.get_ui_context()

    return templates.TemplateResponse(
        "callback.html",
        {
            "request": request,
            **ui_context,
            "code": code,
            "state": state,
            "error": error
        }
    )
