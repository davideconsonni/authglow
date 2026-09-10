"""Infobip SMS phone verification provider.

Sends the OTP via ``POST {base}/sms/3/messages`` (SMS API V3)::

    {"messages": [{"sender": "...", "destinations": [{"to": "..."}],
                   "content": {"text": "..."}}]}

Authentication uses the API-key header (``Authorization: App <key>``).
HTTP 200 means the message was queued; the per-message
``status.groupName`` (PENDING / DELIVERED / ...) carries the outcome.
See https://www.infobip.com/docs/api/channels/sms/outbound-sms/send-message/send-sms-messages
"""

from typing import Optional
from uuid import uuid4

from authglow.core.http_client import get_http_client
from authglow.services.phone.base import PhoneSendResult, PhoneVerificationProvider
from authglow.services.phone.infobip_base import auth_header, is_accepted, normalize_base_url


class InfobipSmsProvider(PhoneVerificationProvider):
    """Send verification codes through the Infobip SMS API."""

    def __init__(
        self,
        api_key: Optional[str],
        base_url: Optional[str],
        sender: Optional[str] = None,
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key
        self.base_url = normalize_base_url(base_url)
        self.sender = sender or "InfoSMS"
        self.timeout = timeout

    async def send_code(self, to: str, code: str, message: str) -> PhoneSendResult:
        """Send the rendered message to ``to`` via Infobip SMS."""
        try:
            if not self.validate_config():
                raise ValueError("INFOBIP_API_KEY, INFOBIP_BASE_URL and sender are required")
            client = await get_http_client()
            response = await client.post(
                f"{self.base_url}/sms/3/messages",
                headers={**auth_header(self.api_key), "Content-Type": "application/json"},
                json={
                    "messages": [
                        {
                            "sender": self.sender,
                            "destinations": [{"to": to}],
                            "content": {"text": message},
                        }
                    ]
                },
                timeout=self.timeout,
            )
            if response.status_code != 200:
                raise RuntimeError(
                    f"Infobip SMS returned HTTP {response.status_code}: {response.text[:500]}"
                )
            payload = response.json()
            messages = payload.get("messages", [])
            if not messages:
                raise RuntimeError("Infobip SMS response contained no messages")
            first = messages[0]
            if not is_accepted(first.get("status")):
                status = first.get("status", {})
                raise RuntimeError(
                    f"Infobip SMS rejected the message: "
                    f"{status.get('name', 'UNKNOWN')} - "
                    f"{status.get('description', 'no description')}"
                )
            return PhoneSendResult(
                success=True,
                message_id=str(first.get("messageId") or f"infobip-sms-{uuid4()}"),
                provider="infobip_sms",
                channel="sms",
            )
        except Exception as exc:
            return PhoneSendResult(
                success=False, error=str(exc), provider="infobip_sms", channel="sms"
            )

    def validate_config(self) -> bool:
        """Return whether API key, base URL and sender are configured."""
        return bool(self.api_key and self.base_url and self.sender)

    def get_provider_name(self) -> str:
        """Return the provider identifier."""
        return "infobip_sms"

    def get_channel(self) -> str:
        """Return the channel identifier."""
        return "sms"
