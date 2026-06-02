"""OAuth2 Consent Handler - integrates consent into authorization flow."""

from fastapi import APIRouter, Depends, Form, HTTPException, Request

from authglow.core.rate_limit import limiter
from authglow.services.audit import AuditService
from authglow.services.oauth2 import OAuth2Service
from authglow.services.oauth_consent import OAuth2ConsentService
from authglow.services.session import SessionService
from authglow.services.storage import UserStorage

router = APIRouter()


@router.get("/api/oauth2/consent/check")
async def check_consent_auto(
    session_token: str,
    session_service: SessionService = Depends(lambda: SessionService()),
    consent_service: OAuth2ConsentService = Depends(lambda: OAuth2ConsentService()),
    user_storage: UserStorage = Depends(lambda: UserStorage()),
):
    """Check if user has already consented and auto-create auth code if so."""
    session = await session_service.get_consent_session(session_token)
    if not session:
        raise HTTPException(status_code=400, detail="Invalid or expired session")

    user = await user_storage.get_user(session["user_id"])
    if not user:
        raise HTTPException(status_code=400, detail="User not found")

    requested_scopes = session["scope"].split() if session["scope"] else ["read"]

    has_consent, _ = await consent_service.check_consent(
        user_id=user.id,
        client_id=session["client_id"],
        required_scopes=requested_scopes,
    )

    if has_consent:
        oauth2_service = OAuth2Service()
        auth_code = await oauth2_service.create_authorization_code(
            client_id=session["client_id"],
            user_id=user.id,
            redirect_uri=session["redirect_uri"],
            scope=session["scope"],
            code_challenge=session.get("code_challenge"),
            code_challenge_method=session.get("code_challenge_method"),
            nonce=session.get("nonce"),
        )

        redirect_url = f"{session['redirect_uri']}?code={auth_code.code}"
        if session.get("state"):
            redirect_url += f"&state={session['state']}"

        return {
            "consent_required": False,
            "authorization_code": auth_code.code,
            "redirect_url": redirect_url,
        }

    return {"consent_required": True, "session_token": session_token}


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
    session = await session_service.get_consent_session(session_token)
    if not session:
        raise HTTPException(status_code=400, detail="Invalid or expired session")

    is_approved = approved.lower() == "true"
    should_remember = remember.lower() == "true"

    if not is_approved:
        await audit_service.log_event(
            event_type="oauth2_consent_denied",
            user_id=session["user_id"],
            metadata={"client_id": session["client_id"], "scopes": session["scope"]},
            severity="info",
            ip_address=request.client.host if request.client else None,
        )

        redirect_url = f"{session['redirect_uri']}?error=access_denied"
        if session.get("state"):
            redirect_url += f"&state={session['state']}"

        return {"approved": False, "redirect_url": redirect_url}

    requested_scopes = session["scope"].split() if session["scope"] else ["read"]

    if should_remember:
        await consent_service.create_consent(
            user_id=session["user_id"],
            client_id=session["client_id"],
            scopes=requested_scopes,
            expires_at=None,
        )

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

    auth_code = await oauth2_service.create_authorization_code(
        client_id=session["client_id"],
        user_id=session["user_id"],
        redirect_uri=session["redirect_uri"],
        scope=session["scope"],
        code_challenge=session.get("code_challenge"),
        code_challenge_method=session.get("code_challenge_method"),
        nonce=session.get("nonce"),
    )

    await session_service.delete_consent_session(session_token)

    redirect_url = f"{session['redirect_uri']}?code={auth_code.code}"
    if session.get("state"):
        redirect_url += f"&state={session['state']}"

    return {"approved": True, "authorization_code": auth_code.code, "redirect_url": redirect_url}
