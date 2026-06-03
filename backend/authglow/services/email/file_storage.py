"""File storage email provider - saves emails to JSON files for development."""

import asyncio
import json
from pathlib import Path
from uuid import uuid4

from authglow.core.datetime import utcnow
from authglow.models.email import EmailMessage, EmailSendResult
from authglow.services.email.base import EmailProvider


class FileStorageEmailProvider(EmailProvider):
    """Email provider that saves emails as JSON files.

    Useful for development and testing. Emails are saved in the
    data/emails directory as JSON files with timestamp and ID.
    """

    def __init__(self, storage_path: str = "data/emails"):
        """Initialize file storage email provider.

        Args:
            storage_path: Directory to save emails (default: data/emails)
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def _write_email(self, file_path: Path, email_data: dict) -> None:
        """Write email data to a file (sync helper)."""
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(email_data, f, indent=2, ensure_ascii=False)

    async def send(self, message: EmailMessage) -> EmailSendResult:
        """Send email by saving to file.

        Args:
            message: EmailMessage to "send"

        Returns:
            EmailSendResult with success=True and generated message_id
        """
        try:
            # Generate unique message ID
            timestamp = utcnow()
            message_id = f"file-{uuid4()}"

            # Create filename with timestamp and ID
            filename = f"{timestamp.strftime('%Y%m%d_%H%M%S')}_{message_id.split('-')[1]}.json"
            file_path = self.storage_path / filename

            # Prepare email data
            email_data = {
                "message_id": message_id,
                "timestamp": timestamp.isoformat() + "Z",
                "provider": "file_storage",
                "from": {
                    "email": message.from_email or "noreply@authglow.local",
                    "name": message.from_name,
                },
                "to": message.to,
                "cc": message.cc or [],
                "bcc": message.bcc or [],
                "reply_to": message.reply_to,
                "subject": message.subject,
                "body_text": message.body_text,
                "body_html": message.body_html,
                "priority": message.priority.value,
                "headers": message.headers or {},
                "attachments": [
                    {
                        "filename": att.filename,
                        "content_type": att.content_type,
                        "size_bytes": len(att.content),
                    }
                    for att in (message.attachments or [])
                ],
            }

            # Save to file (async to avoid blocking event loop)
            await asyncio.to_thread(self._write_email, file_path, email_data)

            return EmailSendResult(success=True, message_id=message_id, provider="file_storage")

        except Exception as e:
            return EmailSendResult(success=False, error=str(e), provider="file_storage")

    def validate_config(self) -> bool:
        """Validate file storage provider configuration.

        Checks if storage directory is writable.

        Returns:
            True if directory exists and is writable
        """
        try:
            # Check if directory exists and is writable
            if not self.storage_path.exists():
                self.storage_path.mkdir(parents=True, exist_ok=True)

            # Try to create a test file
            test_file = self.storage_path / ".write_test"
            test_file.touch()
            test_file.unlink()

            return True
        except Exception:
            return False

    def get_provider_name(self) -> str:
        """Get provider name.

        Returns:
            "file_storage"
        """
        return "file_storage"
