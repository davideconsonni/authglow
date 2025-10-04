"""Email verification API endpoints."""

from typing import Optional
from fastapi import APIRouter, HTTPException, status, Request, Depends
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.util import get_remote_address

from authglow.models.email_verification import (
    EmailVerificationRequest,
    ResendVerificationRequest
)
from authglow.models.user import User
from authglow.services.email_verification import EmailVerificationService
from authglow.services.audit import AuditService
from authglow.core.config import get_settings
from authglow.api.auth import get_current_user

router = APIRouter()
templates = Jinja2Templates(directory="authglow/templates")
limiter = Limiter(key_func=get_remote_address)


def get_verification_service():
    """Get email verification service instance."""
    return EmailVerificationService()


def get_audit_service():
    """Get audit service instance."""
    return AuditService()


@router.get("/verify-email", response_class=HTMLResponse)
async def verify_email_page(
    request: Request,
    token: str
):
    """Email verification page (verify via GET for easy email links)."""
    settings = get_settings()
    verification_service = get_verification_service()
    audit_service = get_audit_service()

    # Verify email
    success, error = await verification_service.verify_email(token)

    if success:
        # Get the token to find user
        verification_token = await verification_service.get_token(token)
        if verification_token:
            # Log the verification
            await audit_service.log_event(
                event_type="email_verified",
                user_id=verification_token.user_id,
                email=verification_token.email,
                metadata={"token": token},
                ip_address=request.client.host if request.client else None
            )

        return templates.TemplateResponse(
            "email_verified.html",
            {
                "request": request,
                "success": True,
                "message": "Email verified successfully! You can now login.",
                "login_url": f"{settings.base_url}/login",
                **settings.get_ui_context()
            }
        )
    else:
        return templates.TemplateResponse(
            "email_verified.html",
            {
                "request": request,
                "success": False,
                "error": error,
                "resend_url": f"{settings.base_url}/resend-verification",
                **settings.get_ui_context()
            }
        )


@router.post("/api/email/verify")
@limiter.limit("10/hour")
async def verify_email_api(
    request: Request,
    verification_request: EmailVerificationRequest
):
    """Verify email via API (POST with token in body)."""
    verification_service = get_verification_service()
    audit_service = get_audit_service()

    # Verify email
    success, error = await verification_service.verify_email(verification_request.token)

    if not success:
        # Log failed verification attempt
        await audit_service.log_event(
            event_type="email_verification_failed",
            email="unknown",
            metadata={"token": verification_request.token, "error": error},
            severity="warning",
            ip_address=request.client.host if request.client else None
        )
        raise HTTPException(status_code=400, detail=error)

    # Get the token to find user
    verification_token = await verification_service.get_token(verification_request.token)
    if verification_token:
        # Log the verification
        await audit_service.log_event(
            event_type="email_verified",
            user_id=verification_token.user_id,
            email=verification_token.email,
            metadata={"token": verification_request.token},
            ip_address=request.client.host if request.client else None
        )

    return {"message": "Email verified successfully"}


@router.post("/api/email/resend-verification")
@limiter.limit("5/hour")
async def resend_verification_email(
    request: Request,
    current_user: User = Depends(get_current_user)
):
    """Resend verification email for authenticated user."""
    verification_service = get_verification_service()
    audit_service = get_audit_service()

    # Use current user's email
    email = current_user.email

    # Resend verification email
    success, error = await verification_service.resend_verification_email(email)

    if not success:
        # Log failed resend attempt
        await audit_service.log_event(
            event_type="email_verification_resend_failed",
            email=email,
            metadata={"error": error},
            severity="warning",
            ip_address=request.client.host if request.client else None
        )
        raise HTTPException(status_code=400, detail=error)

    # Log successful resend
    await audit_service.log_event(
        event_type="email_verification_resent",
        email=email,
        ip_address=request.client.host if request.client else None
    )

    return {"message": "Verification email sent successfully"}


@router.get("/resend-verification", response_class=HTMLResponse)
async def resend_verification_page(request: Request):
    """Resend verification email page."""
    settings = get_settings()
    return templates.TemplateResponse(
        "resend_verification.html",
        {
            "request": request,
            **settings.get_ui_context()
        }
    )
