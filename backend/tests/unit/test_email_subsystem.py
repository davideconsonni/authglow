import pytest
from io import StringIO
from unittest.mock import patch, MagicMock, AsyncMock
from authglow.models.email import EmailMessage, EmailSendResult, EmailPriority


class TestConsoleEmailProvider:
    def test_send_email(self):
        from authglow.services.email.console import ConsoleEmailProvider

        output = StringIO()
        provider = ConsoleEmailProvider(output_stream=output, colorize=False)
        message = EmailMessage(
            to=["test@example.com"],
            subject="Test Email",
            body_text="Hello World",
        )

        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(provider.send(message))
        assert result.success is True
        assert result.provider == "console"
        assert result.message_id.startswith("console-")
        output_str = output.getvalue()
        assert "Test Email" in output_str
        assert "test@example.com" in output_str

    def test_validate_config_always_true(self):
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider()
        assert provider.validate_config() is True

    def test_get_provider_name(self):
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider()
        assert provider.get_provider_name() == "console"

    def test_send_with_html_body(self):
        from authglow.services.email.console import ConsoleEmailProvider

        output = StringIO()
        provider = ConsoleEmailProvider(output_stream=output, colorize=False)
        message = EmailMessage(
            to=["html@example.com"],
            subject="HTML Email",
            body_html="<h1>Hello</h1>",
        )

        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(provider.send(message))
        assert result.success is True
        output_str = output.getvalue()
        assert "<h1>Hello</h1>" in output_str

    def test_colorize_disabled(self):
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider(colorize=False)
        assert provider._colorize("test", "\033[31m") == "test"


class TestFileStorageEmailProvider:
    def test_send_email(self, tmp_path):
        from authglow.services.email.file_storage import FileStorageEmailProvider

        storage_path = str(tmp_path / "emails")
        provider = FileStorageEmailProvider(storage_path=storage_path)
        message = EmailMessage(
            to=["file@example.com"],
            subject="File Test",
            body_text="File content",
        )

        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(provider.send(message))
        assert result.success is True
        assert result.provider == "file_storage"
        assert result.message_id.startswith("file-")

    def test_validate_config(self, tmp_path):
        from authglow.services.email.file_storage import FileStorageEmailProvider

        storage_path = str(tmp_path / "emails_val")
        provider = FileStorageEmailProvider(storage_path=storage_path)
        assert provider.validate_config() is True

    def test_get_provider_name(self, tmp_path):
        from authglow.services.email.file_storage import FileStorageEmailProvider

        provider = FileStorageEmailProvider(storage_path=str(tmp_path / "emails_name"))
        assert provider.get_provider_name() == "file_storage"

    def test_send_preserves_metadata(self, tmp_path):
        import json
        from authglow.services.email.file_storage import FileStorageEmailProvider

        storage_path = str(tmp_path / "emails_meta")
        provider = FileStorageEmailProvider(storage_path=storage_path)
        message = EmailMessage(
            to=["meta@example.com"],
            subject="Metadata Test",
            body_text="Content",
            from_email="sender@example.com",
            from_name="Sender",
        )

        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(provider.send(message))
        assert result.success is True

        import pathlib

        files = list(pathlib.Path(storage_path).glob("*.json"))
        assert len(files) >= 1
        with open(files[0]) as f:
            data = json.load(f)
        assert data["subject"] == "Metadata Test"
        assert data["from"]["email"] == "sender@example.com"
        assert data["from"]["name"] == "Sender"


class TestEmailTemplateRenderer:
    def test_render_auto_adds_html_extension(self, tmp_path):
        from authglow.services.email.base import EmailTemplateRenderer

        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "welcome.html").write_text("<h1>Hello {{ name }}</h1>")

        renderer = EmailTemplateRenderer(template_dir=str(template_dir))
        result = renderer.render_template("welcome", {"name": "World"}, is_html=True)
        assert "Hello World" in result

    def test_render_auto_adds_txt_extension(self, tmp_path):
        from authglow.services.email.base import EmailTemplateRenderer

        template_dir = tmp_path / "templates"
        template_dir.mkdir()
        (template_dir / "welcome.txt").write_text("Hello {{ name }}")

        renderer = EmailTemplateRenderer(template_dir=str(template_dir))
        result = renderer.render_template("welcome", {"name": "World"}, is_html=False)
        assert "Hello World" in result


class TestCreateEmailProvider:
    def test_console_provider_by_default(self):
        from authglow.services.email.factory import create_email_provider
        from authglow.services.email.console import ConsoleEmailProvider

        with patch("authglow.services.email.factory.get_settings") as mock_settings:
            mock_settings.return_value.email_backend = "console"
            provider = create_email_provider()
            assert isinstance(provider, ConsoleEmailProvider)

    def test_file_storage_provider(self):
        from authglow.services.email.factory import create_email_provider
        from authglow.services.email.file_storage import FileStorageEmailProvider

        with patch("authglow.services.email.factory.get_settings") as mock_settings:
            mock_settings.return_value.email_backend = "file_storage"
            mock_settings.return_value.email_storage_path = "/tmp/test_emails"
            provider = create_email_provider()
            assert isinstance(provider, FileStorageEmailProvider)

    def test_unknown_provider_defaults_to_console(self):
        from authglow.services.email.factory import create_email_provider
        from authglow.services.email.console import ConsoleEmailProvider

        with patch("authglow.services.email.factory.get_settings") as mock_settings:
            mock_settings.return_value.email_backend = "smtp"
            provider = create_email_provider()
            assert isinstance(provider, ConsoleEmailProvider)


class TestEmailService:
    def test_send_template(self):
        from authglow.services.email.base import EmailService
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider(output_stream=StringIO(), colorize=False)
        mock_renderer = MagicMock()
        mock_renderer.render_both = MagicMock(
            return_value=("HTML content", "Text content")
        )

        service = EmailService(provider=provider, template_renderer=mock_renderer)

        import asyncio

        try:
            loop = asyncio.get_event_loop()
            if loop.is_closed():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

        result = loop.run_until_complete(
            service.send_template(
                to=["test@example.com"],
                subject="Template Test",
                template_name="test_template",
                context={"name": "World"},
            )
        )
        assert result.success is True

    def test_validate_config(self):
        from authglow.services.email.base import EmailService
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider()
        service = EmailService(provider=provider)
        assert service.validate_config() is True

    def test_get_provider_name(self):
        from authglow.services.email.base import EmailService
        from authglow.services.email.console import ConsoleEmailProvider

        provider = ConsoleEmailProvider()
        service = EmailService(provider=provider)
        assert service.get_provider_name() == "console"
