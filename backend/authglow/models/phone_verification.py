"""Phone verification models."""

import re
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from authglow.core.datetime import utcnow

_PHONE_REGEX = re.compile(r"^\+[1-9]\d{7,14}$")
_CODE_REGEX = re.compile(r"^\d{6}$")


class PhoneVerificationToken(BaseModel):
    """One-time phone verification code.

    The record is indexed by ``code_lookup`` (HMAC of ``phone:code``)
    and the plaintext ``code`` is stored in the JSON body for O(1)
    lookup and constant-time comparison, mirroring the
    email-verification flow. Codes are numeric, single-use, and
    short-lived (10 minutes by default).
    """

    token_id: str = Field(default_factory=lambda: str(uuid4()))
    code_lookup: str = ""
    code: str = ""
    user_id: str
    phone: str
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(default_factory=lambda: utcnow() + timedelta(minutes=10))
    attempts: int = 0
    used: bool = False
    used_at: Optional[datetime] = None


class PhoneCodeRequest(BaseModel):
    """Request a verification code for a phone number (E.164)."""

    phone: str = Field(..., min_length=8, max_length=16)

    @field_validator("phone")
    @classmethod
    def _validate_phone(cls, value: str) -> str:
        normalised = value.strip().replace(" ", "").replace("-", "")
        if not _PHONE_REGEX.match(normalised):
            raise ValueError("Phone number must be in E.164 format (e.g. +15551234567)")
        return normalised


class PhoneVerifyRequest(BaseModel):
    """Verify a phone number with the received code."""

    phone: str = Field(..., min_length=8, max_length=16)
    code: str = Field(..., min_length=6, max_length=6)

    @field_validator("phone")
    @classmethod
    def _validate_phone(cls, value: str) -> str:
        normalised = value.strip().replace(" ", "").replace("-", "")
        if not _PHONE_REGEX.match(normalised):
            raise ValueError("Phone number must be in E.164 format (e.g. +15551234567)")
        return normalised

    @field_validator("code")
    @classmethod
    def _validate_code(cls, value: str) -> str:
        normalised = value.strip()
        if not _CODE_REGEX.match(normalised):
            raise ValueError("Verification code must be 6 digits")
        return normalised
