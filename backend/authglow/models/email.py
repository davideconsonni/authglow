"""Email models and data structures."""

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr


class EmailPriority(str, Enum):
    """Email priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"


class EmailAttachment(BaseModel):
    """Email attachment."""
    filename: str
    content: bytes
    content_type: str = "application/octet-stream"


class EmailMessage(BaseModel):
    """Email message structure."""
    to: List[EmailStr]
    subject: str
    body_text: Optional[str] = None  # Plain text version
    body_html: Optional[str] = None  # HTML version
    from_email: Optional[EmailStr] = None  # If None, use default from config
    from_name: Optional[str] = None
    reply_to: Optional[EmailStr] = None
    cc: Optional[List[EmailStr]] = None
    bcc: Optional[List[EmailStr]] = None
    attachments: Optional[List[EmailAttachment]] = None
    priority: EmailPriority = EmailPriority.NORMAL
    headers: Optional[Dict[str, str]] = None

    # Template context (if rendering from template)
    template_name: Optional[str] = None
    template_context: Optional[Dict[str, Any]] = None


class EmailSendResult(BaseModel):
    """Result of email send operation."""
    success: bool
    message_id: Optional[str] = None
    error: Optional[str] = None
    provider: Optional[str] = None  # Which provider sent it
