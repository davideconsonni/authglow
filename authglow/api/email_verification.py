"""Email verification API endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request

from authglow.api.auth import get_current_user
from authglow.core.rate_limit import limiter
from authglow.models.email_verification import (
    EmailVerificationRequest,
)
from authglow.models.user import User
from authglow.services.audit import AuditService
from authglow.services.email_verification import EmailVerificationService

router = APIRouter()


def get_verification_service():
    """Get email verification service instance."""
    return EmailVerificationService()


def get_audit_service():
    """Get audit service instance."""
    return AuditService()


@router.post("/api/email/verify")
@limiter.limit("10/hour")
async def verify_email_api(request: Request, verification_request: EmailVerificationRequest):
    """Verify email via API (POST with token in body)."""
    verification_service = get_verification_service()
    audit_service = get_audit_service()

    success, error = await verification_service.verify_email(verification_request.token)

    if not success:
        await audit_service.log_event(
            event_type="email_verification_failed",
            email="unknown",
            metadata={"token": verification_request.token, "error": error},
            severity="warning",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(status_code=400, detail=error)

    verification_token = await verification_service.get_token(verification_request.token)
    if verification_token:
        await audit_service.log_event(
            event_type="email_verified",
            user_id=verification_token.user_id,
            email=verification_token.email,
            metadata={"token": verification_request.token},
            ip_address=request.client.host if request.client else None,
        )

    return {"message": "Email verified successfully"}


@router.post("/api/email/resend-verification")
@limiter.limit("5/hour")
async def resend_verification_email(
    request: Request, current_user: User = Depends(get_current_user)
):
    """Resend verification email for authenticated user."""
    verification_service = get_verification_service()
    audit_service = get_audit_service()

    email = current_user.email

    success, error = await verification_service.resend_verification_email(email)

    if not success:
        await audit_service.log_event(
            event_type="email_verification_resend_failed",
            email=email,
            metadata={"error": error},
            severity="warning",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(status_code=400, detail=error)

    await audit_service.log_event(
        event_type="email_verification_resent",
        email=email,
        ip_address=request.client.host if request.client else None,
    )

    return {"message": "Verification email sent successfully"}
