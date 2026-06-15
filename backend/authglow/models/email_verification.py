"""Email verification models."""

import re
from datetime import datetime, timedelta
from typing import Any, Dict, Optional
from uuid import uuid4

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator

from authglow.core.datetime import utcnow

_VERIFICATION_CODE_REGEX = re.compile(r"^[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}$")
_LEGACY_LONG_TOKEN_MAX = 64


class EmailVerificationToken(BaseModel):
    """Email verification token model.

    VAPT-022 alignment: the record is indexed by ``code_lookup``
    (HMAC of the human-friendly ``verification_code``) and the
    plaintext ``verification_code`` is stored in the JSON body for
    O(1) lookups. The single-use, 24h-window, HMAC-as-filename model
    matches the password-reset flow.
    """

    token_id: str = Field(default_factory=lambda: str(uuid4()))
    code_lookup: str = ""
    verification_code: str = ""
    user_id: str
    email: EmailStr
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime = Field(default_factory=lambda: utcnow() + timedelta(hours=24))
    used: bool = False
    used_at: Optional[datetime] = None


class EmailVerificationRequest(BaseModel):
    """Request to verify email.

    Accepts the human-friendly verification code (``XXXX-XXXX-XXXX``,
    14 chars) or, for one deploy-cycle of backward compatibility, a
    legacy long opaque token (e.g. 43-char base64url from the
    pre-VAPT-022 code path). The service normalises whitespace and
    case for the human-friendly path.
    """

    token: str = Field(min_length=14, max_length=_LEGACY_LONG_TOKEN_MAX)

    @field_validator("token")
    @classmethod
    def _validate_code_shape(cls, value: str) -> str:
        normalised = value.strip()
        if len(normalised) == 14 and normalised[4] == "-" and normalised[9] == "-":
            if _VERIFICATION_CODE_REGEX.match(normalised.upper()):
                return normalised.upper()
        if 14 <= len(normalised) <= _LEGACY_LONG_TOKEN_MAX:
            return normalised
        raise ValueError("Verification code must be 14 characters in the format XXXX-XXXX-XXXX")

    @model_validator(mode="before")
    @classmethod
    def _accept_legacy_field_names(cls, data: Any) -> Any:
        if isinstance(data, Dict):
            if "token" not in data and "verification_code" in data:
                data = {**data, "token": data["verification_code"]}
        return data


class ResendVerificationRequest(BaseModel):
    """Request to resend verification email."""

    email: EmailStr
