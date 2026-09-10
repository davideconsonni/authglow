"""Infobip WhatsApp phone verification provider.

Template-first delivery: the OTP is sent via
``POST {base}/whatsapp/1/message/template`` with an ``AUTHENTICATION``
template (``COPY_CODE`` button recommended)::

    {"messages": [{"from": "...", "to": "...",
                   "content": {"templateName": "...",
                               "templateData": {"body": {"placeholders": ["<code>"]}},
                               "language": "en_GB"}}]}

Template messages are delivered at any time — this is the exception
to the provider-agnostic text rule: WhatsApp free-form text
(``POST {base}/whatsapp/1/message/text``) is only a fallback used
when no template is configured, and it is delivered solely inside
the 24-hour customer-service window. The AuthGlow message template
(``PHONE_MESSAGE_TEMPLATE``) is still used for SMS and every other
channel.
See https://www.infobip.com/docs/api/channels/whatsapp/whatsapp-outbound-messages/whatsapp-template-message/send-whatsapp-template-message
"""

from typing import Optional
from uuid import uuid4

from authglow.core.http_client import get_http_client
from authglow.services.phone.base import PhoneSendResult, PhoneVerificationProvider
from authglow.services.phone.infobip_base import auth_header, is_accepted, normalize_base_url


class InfobipWhatsappProvider(PhoneVerificationProvider):
    """Send verification codes through the Infobip WhatsApp API."""

    def __init__(
        self,
        api_key: Optional[str],
        base_url: Optional[str],
        sender: Optional[str] = None,
        template_name: Optional[str] = None,
        template_lang: str = "en_GB",
        timeout: float = 30.0,
    ) -> None:
        self.api_key = api_key
        self.base_url = normalize_base_url(base_url)
        self.sender = sender
        self.template_name = template_name
        self.template_lang = template_lang or "en_GB"
        self.timeout = timeout

    async def send_code(self, to: str, code: str, message: str) -> PhoneSendResult:
        """Send the code via template message (or free-form fallback)."""
        try:
            if not self.validate_config():
                raise ValueError("INFOBIP_API_KEY, INFOBIP_BASE_URL and sender are required")
            if self.template_name:
                return await self._send_template(to, code)
            return await self._send_text(to, message)
        except Exception as exc:
            return PhoneSendResult(
                success=False, error=str(exc), provider="infobip_whatsapp", channel="whatsapp"
            )

    async def _send_template(self, to: str, code: str) -> PhoneSendResult:
        # AUTHENTICATION templates carry the code twice: once as the
        # body placeholder and once as the URL-button parameter (the
        # "Copy code" button URL ends with ``code=otp{{1}}``). Omitting
        # the button parameter yields EC_INVALID_TEMPLATE_ARGS
        # ("Failed to match template parameters") with the message
        # accepted (HTTP 200) but never delivered.
        client = await get_http_client()
        response = await client.post(
            f"{self.base_url}/whatsapp/1/message/template",
            headers={**auth_header(self.api_key), "Content-Type": "application/json"},
            json={
                "messages": [
                    {
                        "from": self.sender,
                        "to": to,
                        "content": {
                            "templateName": self.template_name,
                            "templateData": {
                                "body": {"placeholders": [code]},
                                "buttons": [{"type": "URL", "parameter": code}],
                            },
                            "language": self.template_lang,
                        },
                    }
                ]
            },
            timeout=self.timeout,
        )
        return self._result(response.status_code, response.text, _first_template_message)

    async def _send_text(self, to: str, message: str) -> PhoneSendResult:
        client = await get_http_client()
        response = await client.post(
            f"{self.base_url}/whatsapp/1/message/text",
            headers={**auth_header(self.api_key), "Content-Type": "application/json"},
            json={"from": self.sender, "to": to, "content": {"text": message}},
            timeout=self.timeout,
        )
        return self._result(response.status_code, response.text, _first_text_message)

    def _result(self, status_code: int, body: str, extract) -> PhoneSendResult:
        import json

        if status_code != 200:
            raise RuntimeError(f"Infobip WhatsApp returned HTTP {status_code}: {body[:500]}")
        try:
            payload = json.loads(body)
        except ValueError:
            raise RuntimeError(f"Infobip WhatsApp returned non-JSON body: {body[:500]}")
        first = extract(payload)
        if first is None:
            raise RuntimeError("Infobip WhatsApp response contained no message status")
        if not is_accepted(first.get("status")):
            status = first.get("status", {})
            raise RuntimeError(
                f"Infobip WhatsApp rejected the message: "
                f"{status.get('name', 'UNKNOWN')} - "
                f"{status.get('description', status.get('text', 'no description'))}"
            )
        return PhoneSendResult(
            success=True,
            message_id=str(first.get("messageId") or f"infobip-whatsapp-{uuid4()}"),
            provider="infobip_whatsapp",
            channel="whatsapp",
        )

    def validate_config(self) -> bool:
        """Return whether API key, base URL and sender are configured."""
        return bool(self.api_key and self.base_url and self.sender)

    def get_provider_name(self) -> str:
        """Return the provider identifier."""
        return "infobip_whatsapp"

    def get_channel(self) -> str:
        """Return the channel identifier."""
        return "whatsapp"


def _first_template_message(payload: dict) -> Optional[dict]:
    messages = payload.get("messages", [])
    return messages[0] if messages else None


def _first_text_message(payload: dict) -> Optional[dict]:
    if "status" in payload:
        return payload
    return None
