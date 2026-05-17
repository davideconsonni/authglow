"""OAuth2 Consent Handler - integrates consent into authorization flow."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from authglow.core.rate_limit import limiter

from authglow.services.oauth_consent import OAuth2ConsentService
from authglow.services.oauth2 import OAuth2Service
from authglow.services.oauth_client import OAuth2ClientStorage
from authglow.services.session import SessionService
from authglow.services.storage import UserStorage
from authglow.services.audit import AuditService
from authglow.core.config import get_settings

router = APIRouter()
templates = Jinja2Templates(directory="authglow/templates")


# Scope descriptions for consent screen
SCOPE_DESCRIPTIONS = {
    "read": "View your profile information and read access to your data",
    "write": "Create and modify data on your behalf",
    "admin": "Full administrative access to your account",
    "email": "Access to your email address",
    "profile": "Access to your profile information (name, avatar, etc.)",
    "openid": "Verify your identity",
}


@router.get("/oauth2/consent", response_class=HTMLResponse)
async def show_consent_screen(
    request: Request,
    session_token: str,
    session_service: SessionService = Depends(lambda: SessionService()),
    client_storage: OAuth2ClientStorage = Depends(lambda: OAuth2ClientStorage()),
    user_storage: UserStorage = Depends(lambda: UserStorage()),
    consent_service: OAuth2ConsentService = Depends(lambda: OAuth2ConsentService()),
):
    """Show OAuth2 consent screen."""
    settings = get_settings()

    # Get the session (contains OAuth2 params and user_id)
    session = await session_service.get_consent_session(session_token)
    if not session:
        raise HTTPException(status_code=400, detail="Invalid or expired session")

    # Get client info
    client = await client_storage.get_client(session["client_id"])
    if not client:
        raise HTTPException(status_code=400, detail="Invalid client")

    # Get user
    user = await user_storage.get_user(session["user_id"])
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    # Parse requested scopes
    requested_scopes = session["scope"].split() if session["scope"] else ["read"]

    # Check if user has already consented
    has_consent, existing_consent = await consent_service.check_consent(
        user_id=user.id, client_id=client.client_id, required_scopes=requested_scopes
    )

    # If already consented, skip consent screen
    if has_consent:
        # Create authorization code directly
        oauth2_service = OAuth2Service()
        auth_code = await oauth2_service.create_authorization_code(
            client_id=client.client_id,
            user_id=user.id,
            redirect_uri=session["redirect_uri"],
            scope=session["scope"],
            code_challenge=session.get("code_challenge"),
            code_challenge_method=session.get("code_challenge_method"),
            nonce=session.get("nonce"),
        )

        # Build redirect URL
        redirect_url = f"{session['redirect_uri']}?code={auth_code.code}"
        if session.get("state"):
            redirect_url += f"&state={session['state']}"

        return RedirectResponse(url=redirect_url)

    # Show consent screen
    ui_context = settings.get_ui_context()

    # Build scope descriptions
    scope_descriptions = {}
    for scope in requested_scopes:
        scope_descriptions[scope] = SCOPE_DESCRIPTIONS.get(
            scope, f"Access {scope} resources"
        )

    return templates.TemplateResponse(
        request,
        "oauth_consent.html",
        context={
            **ui_context,
            "client_id": client.client_id,
            "client_name": client.client_name,
            "client_description": client.description,
            "client_logo_url": client.logo_uri,
            "user_email": user.email,
            "requested_scopes": requested_scopes,
            "scope_descriptions": scope_descriptions,
            "redirect_uri": session["redirect_uri"],
            "state": session.get("state"),
            "session_token": session_token,
        },
    )


@router.post("/oauth2/consent")
@limiter.limit("10/minute")
async def process_consent(
    request: Request,
    session_token: str = Form(...),
    approved: str = Form(...),
    remember: str = Form("false"),
    session_service: SessionService = Depends(lambda: SessionService()),
    consent_service: OAuth2ConsentService = Depends(lambda: OAuth2ConsentService()),
    oauth2_service: OAuth2Service = Depends(lambda: OAuth2Service()),
    audit_service: AuditService = Depends(lambda: AuditService()),
):
    """Process user's consent decision."""
    # Get session
    session = await session_service.get_consent_session(session_token)
    if not session:
        raise HTTPException(status_code=400, detail="Invalid or expired session")

    # Parse form data
    is_approved = approved.lower() == "true"
    should_remember = remember.lower() == "true"

    # Handle denial
    if not is_approved:
        # Log denial
        await audit_service.log_event(
            event_type="oauth2_consent_denied",
            user_id=session["user_id"],
            metadata={"client_id": session["client_id"], "scopes": session["scope"]},
            severity="info",
            ip_address=request.client.host if request.client else None,
        )

        # Redirect with error
        redirect_url = f"{session['redirect_uri']}?error=access_denied"
        if session.get("state"):
            redirect_url += f"&state={session['state']}"

        return RedirectResponse(url=redirect_url, status_code=303)

    # Handle approval
    requested_scopes = session["scope"].split() if session["scope"] else ["read"]

    # Save consent if "remember" was checked
    if should_remember:
        await consent_service.create_consent(
            user_id=session["user_id"],
            client_id=session["client_id"],
            scopes=requested_scopes,
            expires_at=None,  # Never expires
        )

    # Log consent
    await audit_service.log_event(
        event_type="oauth2_consent_granted",
        user_id=session["user_id"],
        metadata={
            "client_id": session["client_id"],
            "scopes": requested_scopes,
            "remembered": should_remember,
        },
        severity="info",
        ip_address=request.client.host if request.client else None,
    )

    # Create authorization code
    print(f"DEBUG consent - Creating auth code with scope: {session['scope']}")
    auth_code = await oauth2_service.create_authorization_code(
        client_id=session["client_id"],
        user_id=session["user_id"],
        redirect_uri=session["redirect_uri"],
        scope=session["scope"],
        code_challenge=session.get("code_challenge"),
        code_challenge_method=session.get("code_challenge_method"),
        nonce=session.get("nonce"),
    )
    print(
        f"DEBUG consent - Auth code created: {auth_code.code}, scope: {auth_code.scope}"
    )

    # Delete the consent session
    await session_service.delete_consent_session(session_token)

    # Build redirect URL with authorization code
    redirect_url = f"{session['redirect_uri']}?code={auth_code.code}"
    if session.get("state"):
        redirect_url += f"&state={session['state']}"

    return RedirectResponse(url=redirect_url, status_code=303)
