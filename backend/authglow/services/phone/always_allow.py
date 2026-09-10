"""Always-allow phone verification provider (development default)."""

from uuid import uuid4

from authglow.services.phone.base import PhoneSendResult, PhoneVerificationProvider


class AlwaysAllowPhoneProvider(PhoneVerificationProvider):
    """Provider that accepts every verification without sending anything.

    Useful for development and testing: no external dependency, no cost.
    Must never be used when real phone ownership proof is required.
    """

    async def send_code(self, to: str, code: str, message: str) -> PhoneSendResult:
        """Pretend to send the code (no-op, always succeeds)."""
        return PhoneSendResult(
            success=True,
            message_id=f"always-allow-{uuid4()}",
            provider="always_allow",
            channel="none",
        )

    def validate_config(self) -> bool:
        """Always valid — no configuration required."""
        return True

    def get_provider_name(self) -> str:
        """Return the provider identifier."""
        return "always_allow"

    def get_channel(self) -> str:
        """No real channel is used."""
        return "none"
