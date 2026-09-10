"""Phone verification API endpoints (OTP via pluggable provider)."""

from fastapi import APIRouter, Depends, HTTPException, Request

from authglow.api.auth import get_current_user
from authglow.core.rate_limit import limiter
from authglow.models.audit_events import AuditEventType
from authglow.models.phone_verification import PhoneCodeRequest, PhoneVerifyRequest
from authglow.models.user import User
from authglow.services.audit import AuditService
from authglow.services.phone_verification import PhoneVerificationService

router = APIRouter()


def get_phone_verification_service() -> PhoneVerificationService:
    """Get phone verification service instance."""
    return PhoneVerificationService()


def get_audit_service() -> AuditService:
    """Get audit service instance."""
    return AuditService()


@router.post("/api/phone/request")
@limiter.limit("5/hour")
async def request_phone_code(
    request: Request,
    body: PhoneCodeRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Generate and send a verification code to a phone number.

    The number is stored on the user (unverified) so a subsequent
    ``/api/phone/verify`` call can prove ownership of it.
    """
    service = get_phone_verification_service()
    audit_service = get_audit_service()

    success, error = await service.request_code(current_user.id, body.phone)

    if not success:
        await audit_service.log_event(
            event_type=AuditEventType.PHONE_VERIFICATION_FAILED,
            user_id=current_user.id,
            email=current_user.email,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            metadata={"phone": body.phone, "error": error},
            severity="warning",
        )
        raise HTTPException(status_code=400, detail=error)

    await audit_service.log_event(
        event_type=AuditEventType.PHONE_VERIFICATION_SENT,
        user_id=current_user.id,
        email=current_user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={"phone": body.phone, "provider": service.provider.get_provider_name()},
    )

    return {"message": "Verification code sent"}


@router.post("/api/phone/verify")
@limiter.limit("10/hour")
async def verify_phone_code(
    request: Request,
    body: PhoneVerifyRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Verify a phone number with the received code.

    On success the user's ``phone_verified`` flag is set, which feeds
    the OIDC ``phone_number_verified`` claim.
    """
    service = get_phone_verification_service()
    audit_service = get_audit_service()

    success, error = await service.verify_code(current_user.id, body.phone, body.code)

    if not success:
        await audit_service.log_event(
            event_type=AuditEventType.PHONE_VERIFICATION_FAILED,
            user_id=current_user.id,
            email=current_user.email,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
            metadata={"phone": body.phone, "error": error},
            severity="warning",
        )
        raise HTTPException(status_code=400, detail=error)

    await audit_service.log_event(
        event_type=AuditEventType.PHONE_VERIFIED,
        user_id=current_user.id,
        email=current_user.email,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        metadata={"phone": body.phone},
    )

    return {"message": "Phone number verified successfully"}
