"""Unit tests for phone verification (OTP service + providers + OIDC claim)."""

import asyncio
from datetime import timedelta
from unittest.mock import AsyncMock, MagicMock, patch

from authglow.core.datetime import utcnow
from authglow.models.user import User
from authglow.services.password import hash_password
from authglow.services.phone_verification import (
    PhoneVerificationService,
    generate_phone_code,
    render_phone_message,
)


def asyncio_run(coro):
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop.run_until_complete(coro)


def _make_user(**kwargs):
    return User(
        id=kwargs.get("id", "test-phone-user"),
        email=kwargs.get("email", "phone@example.com"),
        hashed_password=hash_password("TestP@ss1!"),
        is_active=True,
        email_verified=True,
        scopes=["read"],
        phone=kwargs.get("phone"),
        phone_verified=kwargs.get("phone_verified", False),
    )


def _authed_service(phone_verification_service, user):
    phone_verification_service.user_storage.get_user = AsyncMock(return_value=user)
    phone_verification_service.user_storage.update_user = AsyncMock()
    return phone_verification_service


class TestGeneratePhoneCode:
    def test_default_length_six_digits(self):
        for _ in range(50):
            code = generate_phone_code()
            assert len(code) == 6
            assert code.isdigit()

    def test_custom_length(self):
        assert len(generate_phone_code(4)) == 4
        assert len(generate_phone_code(8)) == 8

    def test_invalid_length_rejected(self):
        import pytest

        with pytest.raises(ValueError):
            generate_phone_code(3)
        with pytest.raises(ValueError):
            generate_phone_code(11)

    def test_codes_vary(self):
        assert len({generate_phone_code() for _ in range(20)}) > 1


class TestRenderPhoneMessage:
    def test_placeholder_replaced(self):
        assert render_phone_message("Code: {code}.", "123456") == "Code: 123456."

    def test_missing_placeholder_appends_code(self):
        assert render_phone_message("Your code:", "123456") == "Your code: 123456"


class TestRequestCode:
    def test_request_sends_and_stores_token(self, phone_verification_service):
        user = _make_user()
        svc = _authed_service(phone_verification_service, user)

        success, error = asyncio_run(svc.request_code(user.id, "+15551234567"))
        assert success is True
        assert error is None

        tokens = asyncio_run(svc.repository.list_for_phone("+15551234567"))
        assert len(tokens) == 1
        assert len(tokens[0].code) == 6
        assert user.phone == "+15551234567"
        assert user.phone_verified is False

    def test_request_unknown_user(self, phone_verification_service):
        phone_verification_service.user_storage.get_user = AsyncMock(return_value=None)
        success, error = asyncio_run(
            phone_verification_service.request_code("missing", "+15551234567")
        )
        assert success is False
        assert error == "User not found"

    def test_resend_cooldown(self, phone_verification_service):
        user = _make_user()
        svc = _authed_service(phone_verification_service, user)

        assert asyncio_run(svc.request_code(user.id, "+15551234567"))[0] is True
        success, error = asyncio_run(svc.request_code(user.id, "+15551234567"))
        assert success is False
        assert "Wait" in error

    def test_hourly_rate_limit(self, phone_verification_service):
        user = _make_user()
        svc = _authed_service(phone_verification_service, user)
        svc._settings.phone_resend_cooldown_seconds = 0
        svc._settings.phone_max_sends_per_hour = 2

        assert asyncio_run(svc.request_code(user.id, "+15551234567"))[0] is True
        assert asyncio_run(svc.request_code(user.id, "+15551234567"))[0] is True
        success, error = asyncio_run(svc.request_code(user.id, "+15551234567"))
        assert success is False
        assert "Too many" in error

    def test_provider_failure_surfaces(self, phone_verification_service):
        from authglow.services.phone.base import PhoneSendResult

        user = _make_user()
        svc = _authed_service(phone_verification_service, user)
        svc._provider.send_code = AsyncMock(
            return_value=PhoneSendResult(
                success=False, error="boom", provider="x", channel="sms"
            )
        )
        success, error = asyncio_run(svc.request_code(user.id, "+15551234567"))
        assert success is False
        assert error == "boom"


class TestVerifyCode:
    def _request(self, svc, user, phone="+15551234567"):
        assert asyncio_run(svc.request_code(user.id, phone))[0] is True
        tokens = asyncio_run(svc.repository.list_for_phone(phone))
        return tokens[0].code

    def test_verify_success_sets_flag(self, phone_verification_service):
        user = _make_user()
        svc = _authed_service(phone_verification_service, user)
        code = self._request(svc, user)

        success, error = asyncio_run(svc.verify_code(user.id, "+15551234567", code))
        assert success is True
        assert error is None
        assert user.phone_verified is True
        assert user.phone_verified_at is not None

    def test_verify_wrong_code(self, phone_verification_service):
        user = _make_user()
        svc = _authed_service(phone_verification_service, user)
        self._request(svc, user)

        success, error = asyncio_run(svc.verify_code(user.id, "+15551234567", "000000"))
        assert success is False
        assert error == "Invalid verification code"
        assert user.phone_verified is False

    def test_verify_locks_after_max_attempts(self, phone_verification_service):
        user = _make_user()
        svc = _authed_service(phone_verification_service, user)
        svc._settings.phone_max_attempts = 3
        code = self._request(svc, user)

        assert asyncio_run(svc.verify_code(user.id, "+15551234567", "000001"))[1] == (
            "Invalid verification code"
        )
        assert asyncio_run(svc.verify_code(user.id, "+15551234567", "000002"))[1] == (
            "Invalid verification code"
        )
        success, error = asyncio_run(svc.verify_code(user.id, "+15551234567", "000003"))
        assert success is False
        assert "Too many attempts" in error

        # Even the right code is rejected once locked.
        success, _ = asyncio_run(svc.verify_code(user.id, "+15551234567", code))
        assert success is False

    def test_verify_used_code_rejected(self, phone_verification_service):
        user = _make_user()
        svc = _authed_service(phone_verification_service, user)
        code = self._request(svc, user)

        assert asyncio_run(svc.verify_code(user.id, "+15551234567", code))[0] is True
        success, error = asyncio_run(svc.verify_code(user.id, "+15551234567", code))
        assert success is False
        assert "already used" in error

    def test_verify_expired_code(self, phone_verification_service):
        user = _make_user()
        svc = _authed_service(phone_verification_service, user)
        code = self._request(svc, user)

        async def _expire():
            tokens = await svc.repository.list_for_phone("+15551234567")
            token = tokens[0]
            token.expires_at = utcnow() - timedelta(minutes=1)
            await svc.repository.update(token)

        asyncio_run(_expire())
        success, error = asyncio_run(svc.verify_code(user.id, "+15551234567", code))
        assert success is False
        assert "expired" in error

    def test_verify_wrong_user_rejected(self, phone_verification_service):
        user = _make_user()
        svc = _authed_service(phone_verification_service, user)
        code = self._request(svc, user)

        success, error = asyncio_run(svc.verify_code("other-user", "+15551234567", code))
        assert success is False

    def test_cleanup_expired(self, phone_verification_service):
        user = _make_user()
        svc = _authed_service(phone_verification_service, user)
        self._request(svc, user)
        svc._settings.phone_resend_cooldown_seconds = 0

        async def _expire_all():
            for token in await svc.repository.list_for_phone("+15551234567"):
                token.expires_at = utcnow() - timedelta(minutes=1)
                await svc.repository.update(token)

        asyncio_run(_expire_all())
        deleted = asyncio_run(svc.cleanup_expired_tokens())
        assert deleted == 1


class TestPhoneVerifiedClaimFlip:
    """End-to-end: phone_number_verified flips False -> True after OTP verify."""

    def test_claim_flips_after_verify(self, oidc_service, phone_verification_service):
        user = _make_user(phone="+15551234567", phone_verified=False)

        pre_claims = oidc_service.build_user_claims(user, ["openid", "phone"])
        assert pre_claims["phone_number"] == "+15551234567"
        assert pre_claims["phone_number_verified"] is False

        async def _run() -> None:
            svc = phone_verification_service
            svc.user_storage.get_user = AsyncMock(return_value=user)
            svc.user_storage.update_user = AsyncMock()
            ok, _ = await svc.request_code(user.id, "+15551234567")
            assert ok is True
            tokens = await svc.repository.list_for_phone("+15551234567")
            ok, err = await svc.verify_code(user.id, "+15551234567", tokens[0].code)
            assert ok is True
            assert err is None

        asyncio_run(_run())
        assert user.phone_verified is True

        post_claims = oidc_service.build_user_claims(user, ["openid", "phone"])
        assert post_claims["phone_number_verified"] is True

    def test_userinfo_reflects_flag(self, oidc_service):
        user = _make_user(phone="+15551234567", phone_verified=True)
        oidc_service.user_storage = MagicMock()
        oidc_service.user_storage.get_user = AsyncMock(return_value=user)

        result = asyncio_run(oidc_service.get_user_info(user.id, ["openid", "phone"]))
        assert result is not None
        assert result.phone_number == "+15551234567"
        assert result.phone_number_verified is True


class TestPhoneProviderFactory:
    def test_default_backend_is_always_allow(self, test_settings):
        from authglow.services.phone.factory import create_phone_provider

        provider = create_phone_provider(settings=test_settings)
        assert provider.get_provider_name() == "always_allow"

    def test_unknown_backend_rejected(self, test_settings):
        import pytest

        from authglow.services.phone.factory import create_phone_provider

        test_settings.phone_verification_backend = "carrier_pigeon"
        with pytest.raises(ValueError, match="Unsupported PHONE_VERIFICATION_BACKEND"):
            create_phone_provider(settings=test_settings)

    def test_infobip_sms_provider_wiring(self, test_settings):
        from authglow.services.phone.factory import create_phone_provider

        test_settings.phone_verification_backend = "infobip_sms"
        test_settings.infobip_api_key = "key"
        test_settings.infobip_base_url = "example.api.infobip.com"
        test_settings.infobip_sms_sender = "InfoSMS"
        provider = create_phone_provider(settings=test_settings)
        assert provider.get_provider_name() == "infobip_sms"
        assert provider.get_channel() == "sms"
        assert provider.validate_config() is True

    def test_infobip_whatsapp_provider_wiring(self, test_settings):
        from authglow.services.phone.factory import create_phone_provider

        test_settings.phone_verification_backend = "infobip_whatsapp"
        test_settings.infobip_api_key = "key"
        test_settings.infobip_base_url = "https://example.api.infobip.com/"
        test_settings.infobip_whatsapp_sender = "441134960000"
        provider = create_phone_provider(settings=test_settings)
        assert provider.get_provider_name() == "infobip_whatsapp"
        assert provider.get_channel() == "whatsapp"
        assert provider.validate_config() is True

    def test_always_allow_sends(self, test_settings):
        from authglow.services.phone.factory import create_phone_provider

        provider = create_phone_provider(settings=test_settings)
        result = asyncio_run(provider.send_code("+15551234567", "123456", "msg"))
        assert result.success is True


class TestInfobipProviders:
    def _mock_client(self, status_code, payload):
        import json

        response = MagicMock()
        response.status_code = status_code
        response.json.return_value = payload
        response.text = json.dumps(payload)
        client = MagicMock()
        client.post = AsyncMock(return_value=response)
        return client

    def test_sms_success(self, test_settings):
        from authglow.services.phone.infobip_sms import InfobipSmsProvider

        provider = InfobipSmsProvider(
            api_key="key", base_url="example.api.infobip.com", sender="InfoSMS"
        )
        client = self._mock_client(
            200,
            {
                "bulkId": "b1",
                "messages": [
                    {
                        "messageId": "m1",
                        "status": {"groupName": "PENDING", "name": "PENDING_ACCEPTED"},
                        "destination": "15551234567",
                    }
                ],
            },
        )
        with patch(
            "authglow.services.phone.infobip_sms.get_http_client",
            AsyncMock(return_value=client),
        ):
            result = asyncio_run(provider.send_code("+15551234567", "123456", "hi 123456"))
        assert result.success is True
        assert result.message_id == "m1"
        _, kwargs = client.post.call_args
        assert kwargs["headers"]["Authorization"] == "App key"
        assert kwargs["json"]["messages"][0]["content"] == {"text": "hi 123456"}

    def test_sms_rejected_status(self, test_settings):
        from authglow.services.phone.infobip_sms import InfobipSmsProvider

        provider = InfobipSmsProvider(
            api_key="key", base_url="example.api.infobip.com", sender="InfoSMS"
        )
        client = self._mock_client(
            200,
            {
                "messages": [
                    {
                        "messageId": "m1",
                        "status": {"groupName": "REJECTED", "name": "REJECTED_DESTINATION"},
                    }
                ]
            },
        )
        with patch(
            "authglow.services.phone.infobip_sms.get_http_client",
            AsyncMock(return_value=client),
        ):
            result = asyncio_run(provider.send_code("+15551234567", "123456", "hi"))
        assert result.success is False
        assert "REJECTED_DESTINATION" in result.error

    def test_sms_http_error(self):
        from authglow.services.phone.infobip_sms import InfobipSmsProvider

        provider = InfobipSmsProvider(
            api_key="key", base_url="example.api.infobip.com", sender="InfoSMS"
        )
        response = MagicMock()
        response.status_code = 401
        response.text = "unauthorized"
        client = MagicMock()
        client.post = AsyncMock(return_value=response)
        with patch(
            "authglow.services.phone.infobip_sms.get_http_client",
            AsyncMock(return_value=client),
        ):
            result = asyncio_run(provider.send_code("+15551234567", "123456", "hi"))
        assert result.success is False
        assert "401" in result.error

    def test_sms_missing_config(self):
        from authglow.services.phone.infobip_sms import InfobipSmsProvider

        provider = InfobipSmsProvider(api_key=None, base_url=None, sender=None)
        assert provider.validate_config() is False
        result = asyncio_run(provider.send_code("+15551234567", "123456", "hi"))
        assert result.success is False

    def test_whatsapp_template_success(self):
        from authglow.services.phone.infobip_whatsapp import InfobipWhatsappProvider

        provider = InfobipWhatsappProvider(
            api_key="key",
            base_url="example.api.infobip.com",
            sender="441134960000",
            template_name="otp_template",
            template_lang="en_GB",
        )
        client = self._mock_client(
            200,
            {
                "messages": [
                    {
                        "messageId": "w1",
                        "status": {"groupName": "PENDING", "name": "PENDING_ENROUTE"},
                    }
                ]
            },
        )
        with patch(
            "authglow.services.phone.infobip_whatsapp.get_http_client",
            AsyncMock(return_value=client),
        ):
            result = asyncio_run(provider.send_code("+15551234567", "123456", "hi 123456"))
        assert result.success is True
        assert result.message_id == "w1"
        _, kwargs = client.post.call_args
        assert "/whatsapp/1/message/template" in client.post.call_args[0][0]
        content = kwargs["json"]["messages"][0]["content"]
        assert content["templateName"] == "otp_template"
        assert content["templateData"]["body"] == {"placeholders": ["123456"]}
        assert content["templateData"]["buttons"] == [{"type": "URL", "parameter": "123456"}]
        assert content["language"] == "en_GB"

    def test_whatsapp_text_fallback_without_template(self):
        from authglow.services.phone.infobip_whatsapp import InfobipWhatsappProvider

        provider = InfobipWhatsappProvider(
            api_key="key",
            base_url="example.api.infobip.com",
            sender="441134960000",
        )
        client = self._mock_client(
            200,
            {
                "messageId": "w2",
                "status": {"groupName": "PENDING", "name": "PENDING_ENROUTE"},
            },
        )
        with patch(
            "authglow.services.phone.infobip_whatsapp.get_http_client",
            AsyncMock(return_value=client),
        ):
            result = asyncio_run(provider.send_code("+15551234567", "123456", "hi 123456"))
        assert result.success is True
        assert "/whatsapp/1/message/text" in client.post.call_args[0][0]
        _, kwargs = client.post.call_args
        assert kwargs["json"]["content"] == {"text": "hi 123456"}


class TestPhoneVerificationServiceInit:
    def test_service_uses_settings_backend(self, test_settings):
        svc = PhoneVerificationService(settings=test_settings)
        assert svc.provider.get_provider_name() == "always_allow"

    def test_invalid_backend_raises(self, test_settings):
        import pytest

        test_settings.phone_verification_backend = "nope"
        with pytest.raises(ValueError, match="Unsupported PHONE_VERIFICATION_BACKEND"):
            PhoneVerificationService(settings=test_settings)
