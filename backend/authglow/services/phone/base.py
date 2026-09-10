"""Base phone verification provider interface and result model."""

from abc import ABC, abstractmethod
from typing import Optional

from pydantic import BaseModel


class PhoneSendResult(BaseModel):
    """Result of a verification-code send operation."""

    success: bool
    message_id: Optional[str] = None
    error: Optional[str] = None
    provider: Optional[str] = None  # Which provider sent it
    channel: Optional[str] = None  # sms, whatsapp, voice, ...


class PhoneVerificationProvider(ABC):
    """Abstract base class for phone verification code senders.

    Every provider (always-allow, Infobip SMS, Infobip WhatsApp, future
    voice vendors, ...) implements this interface. OTP generation,
    storage, expiry, and verification live in
    ``PhoneVerificationService`` — providers only transport the code.
    """

    @abstractmethod
    async def send_code(self, to: str, code: str, message: str) -> PhoneSendResult:
        """Send a verification code to a phone number.

        Args:
            to: Destination phone number in E.164 format.
            code: The numeric verification code.
            message: Rendered human-readable message (already templated).

        Returns:
            PhoneSendResult with success status and optional message_id.
        """
        pass

    @abstractmethod
    def validate_config(self) -> bool:
        """Validate provider configuration.

        Returns:
            True if configuration is valid, False otherwise.
        """
        pass

    @abstractmethod
    def get_provider_name(self) -> str:
        """Get the name of this provider.

        Returns:
            Provider name (e.g. "always_allow", "infobip_sms").
        """
        pass

    @abstractmethod
    def get_channel(self) -> str:
        """Get the channel this provider sends on.

        Returns:
            Channel name (e.g. "sms", "whatsapp", "voice").
        """
        pass
