"""Phone provider factory for creating configured senders."""

from functools import lru_cache
from typing import Optional

from authglow.core.config import Settings, get_settings
from authglow.services.phone.always_allow import AlwaysAllowPhoneProvider
from authglow.services.phone.base import PhoneVerificationProvider


def create_phone_provider(
    provider_name: Optional[str] = None,
    *,
    settings: Optional[Settings] = None,
) -> PhoneVerificationProvider:
    """Create a phone verification provider based on settings."""
    resolved = settings or get_settings()
    backend = provider_name or resolved.phone_verification_backend

    if backend == "always_allow":
        return AlwaysAllowPhoneProvider()

    if backend == "infobip_sms":
        from authglow.services.phone.infobip_sms import InfobipSmsProvider

        return InfobipSmsProvider(
            api_key=resolved.infobip_api_key,
            base_url=resolved.infobip_base_url,
            sender=resolved.infobip_sms_sender,
            timeout=resolved.infobip_timeout,
        )

    if backend == "infobip_whatsapp":
        from authglow.services.phone.infobip_whatsapp import InfobipWhatsappProvider

        return InfobipWhatsappProvider(
            api_key=resolved.infobip_api_key,
            base_url=resolved.infobip_base_url,
            sender=resolved.infobip_whatsapp_sender,
            template_name=resolved.infobip_whatsapp_template_name,
            template_lang=resolved.infobip_whatsapp_template_lang,
            timeout=resolved.infobip_timeout,
        )

    raise ValueError(
        f"Unsupported PHONE_VERIFICATION_BACKEND '{backend}'. "
        "Choose always_allow, infobip_sms, or infobip_whatsapp."
    )


@lru_cache
def get_phone_service() -> PhoneVerificationProvider:
    """Get the cached phone provider instance.

    Returns:
        Configured PhoneVerificationProvider ready to use.
    """
    return create_phone_provider()
