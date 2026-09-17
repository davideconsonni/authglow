"""Service-level tests for ``authglow.services.passkey`` (COV-BE-002).

Covers what ``test_passkey.py`` (API) and
``repositories/file/test_passkey.py`` (persistence) leave out: the
``__init__`` repository resolution, the CRUD/challenge delegation,
``update_passkey_usage`` (lock + CAS retry), authentication-options
generation with transport filtering, and the ``verify_*`` challenge
guards plus success paths (WebAuthn crypto itself is mocked — only
the service wiring is pinned here).
"""

import asyncio
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

from authglow.core.datetime import utcnow
from authglow.models.passkey import Passkey, PasskeyChallenge


def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


def _svc(passkey_repo=None, challenge_repo=None):
    from authglow.services.passkey import PasskeyService

    return PasskeyService(
        rp_id="example.com",
        rp_name="AuthGlow",
        origin="https://example.com",
        passkey_repository=passkey_repo or MagicMock(),
        challenge_repository=challenge_repo or MagicMock(),
    )


def _passkey(**kw):
    base = {
        "credential_id": "Y3JlZC0x",
        "public_key": "cHVia2V5",
        "sign_count": 0,
        "aaguid": "00000000-0000-0000-0000-000000000000",
        "user_id": "u-1",
    }
    base.update(kw)
    return Passkey(**base)


def _challenge(challenge_str="Y2hhbGxlbmdl", type="authentication"):
    return PasskeyChallenge(
        challenge=challenge_str,
        user_id="u-1",
        expires_at=utcnow() + timedelta(minutes=5),
        type=type,
    )


class TestInit:
    def test_explicit_repositories(self):
        svc = _svc(passkey_repo="PR", challenge_repo="CR")
        assert svc._passkey_repo == "PR"
        assert svc._challenge_repo == "CR"
        assert svc.rp_id == "example.com"

    def test_default_repositories_via_factories(self):
        from authglow.services import passkey as passkey_mod

        with (
            patch(
                "authglow.repositories.dependencies.get_passkey_repository",
                return_value="PR",
            ) as f1,
            patch(
                "authglow.repositories.dependencies.get_webauthn_challenge_repository",
                return_value="CR",
            ) as f2,
        ):
            svc = passkey_mod.PasskeyService(
                rp_id="example.com", rp_name="AuthGlow", origin="https://example.com"
            )
        f1.assert_called_once()
        f2.assert_called_once()
        assert svc._passkey_repo == "PR"
        assert svc._challenge_repo == "CR"


class TestCrudDelegation:
    def test_get_user_passkeys(self):
        repo = MagicMock()
        repo.list_for_user = AsyncMock(return_value=[_passkey()])
        out = _run(_svc(passkey_repo=repo).get_user_passkeys("u-1"))
        assert len(out) == 1
        repo.list_for_user.assert_awaited_once_with("u-1")

    def test_save_passkey(self):
        repo = MagicMock()
        repo.save = AsyncMock()
        pk = _passkey()
        out = _run(_svc(passkey_repo=repo).save_passkey(pk))
        assert out is pk
        repo.save.assert_awaited_once_with(pk)

    def test_get_passkey(self):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=_passkey())
        out = _run(_svc(passkey_repo=repo).get_passkey("u-1", "Y3JlZC0x"))
        assert out is not None
        repo.get.assert_awaited_once_with("u-1", "Y3JlZC0x")

    def test_delete_passkey(self):
        repo = MagicMock()
        repo.delete = AsyncMock(return_value=True)
        assert _run(_svc(passkey_repo=repo).delete_passkey("u-1", "Y3JlZC0x")) is True

    def test_save_challenge(self):
        repo = MagicMock()
        repo.save = AsyncMock()
        ch = _challenge()
        out = _run(_svc(challenge_repo=repo).save_challenge(ch))
        assert out is ch

    def test_get_challenge(self):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=_challenge())
        out = _run(_svc(challenge_repo=repo).get_challenge("Y2hhbGxlbmdl"))
        assert out is not None

    def test_delete_challenge(self):
        repo = MagicMock()
        repo.delete = AsyncMock()
        _run(_svc(challenge_repo=repo).delete_challenge("Y2hhbGxlbmdl"))
        repo.delete.assert_awaited_once_with("Y2hhbGxlbmdl")


class TestUpdatePasskeyUsage:
    def test_updates_sign_count(self):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=_passkey())
        repo.update = AsyncMock()
        _run(_svc(passkey_repo=repo).update_passkey_usage("u-1", "Y3JlZC0x", 7))
        updated = repo.update.await_args.args[0]
        assert updated.sign_count == 7
        assert updated.last_used_at is not None

    def test_missing_passkey_noop(self):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=None)
        repo.update = AsyncMock()
        _run(_svc(passkey_repo=repo).update_passkey_usage("u-1", "nope", 7))
        repo.update.assert_not_awaited()

    def test_retries_on_concurrent_write(self):
        from authglow.core.concurrency import ConcurrentWriteError

        repo = MagicMock()
        repo.get = AsyncMock(return_value=_passkey())
        repo.update = AsyncMock(side_effect=[ConcurrentWriteError("race"), None])
        _run(_svc(passkey_repo=repo).update_passkey_usage("u-1", "Y3JlZC0x", 3))
        assert repo.update.await_count == 2


class TestAuthenticationOptions:
    def test_options_and_challenge(self):
        svc = _svc()
        pk = _passkey(transports=["usb", "internal"])
        options, challenge_str = svc.generate_authentication_options_dict([pk])
        assert challenge_str
        assert options["rpId"] == "example.com"
        assert options["allowCredentials"][0]["id"] == pk.credential_id

    def test_unknown_transports_filtered(self):
        svc = _svc()
        pk = _passkey(transports=["ble", "weird-link"])
        options, _ = svc.generate_authentication_options_dict([pk])
        transports = options["allowCredentials"][0].get("transports", [])
        assert "ble" in transports
        assert "weird-link" not in transports


class TestVerifyRegistration:
    def test_rejects_missing_challenge(self):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=None)
        svc = _svc(challenge_repo=repo)
        try:
            _run(
                svc.verify_registration(
                    credential_id="x",
                    client_data_json="x",
                    attestation_object="x",
                    challenge_str="nope",
                    transports=[],
                    name="k",
                )
            )
            raise AssertionError("expected ValueError")
        except ValueError as exc:
            assert "challenge" in str(exc)

    def test_rejects_wrong_challenge_type(self):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=_challenge(type="authentication"))
        svc = _svc(challenge_repo=repo)
        try:
            _run(
                svc.verify_registration(
                    credential_id="x",
                    client_data_json="x",
                    attestation_object="x",
                    challenge_str="Y2hhbGxlbmdl",
                    transports=[],
                    name="k",
                )
            )
            raise AssertionError("expected ValueError")
        except ValueError as exc:
            assert "challenge" in str(exc)

    def test_success_persists_and_cleans_challenge(self):
        import uuid

        from authglow.services import passkey as passkey_mod

        prepo = MagicMock()
        prepo.save = AsyncMock()
        crepo = MagicMock()
        crepo.get = AsyncMock(return_value=_challenge(type="registration"))
        crepo.delete = AsyncMock()
        svc = _svc(passkey_repo=prepo, challenge_repo=crepo)

        verification = SimpleNamespace(
            credential_id=b"cred-1",
            credential_public_key=b"pub-1",
            sign_count=0,
            aaguid=uuid.UUID("00000000-0000-0000-0000-000000000000"),
            credential_backed_up=True,
        )
        with patch.object(
            passkey_mod, "verify_registration_response", return_value=verification
        ):
            out = _run(
                svc.verify_registration(
                    credential_id="Y3JlZC0x",
                    client_data_json="e30",
                    attestation_object="e30",
                    challenge_str="Y2hhbGxlbmdl",
                    transports=["internal"],
                    name="My Key",
                )
            )
        assert out.user_id == "u-1"
        assert out.name == "My Key"
        assert out.backup_eligible is True
        prepo.save.assert_awaited_once()
        crepo.delete.assert_awaited_once_with("Y2hhbGxlbmdl")


class TestVerifyAuthentication:
    def test_rejects_missing_challenge(self):
        repo = MagicMock()
        repo.get = AsyncMock(return_value=None)
        svc = _svc(challenge_repo=repo)
        try:
            _run(
                svc.verify_authentication(
                    credential_id="x",
                    client_data_json="x",
                    authenticator_data="x",
                    signature="x",
                    challenge_str="nope",
                )
            )
            raise AssertionError("expected ValueError")
        except ValueError as exc:
            assert "challenge" in str(exc)

    def test_rejects_unknown_passkey(self):
        crepo = MagicMock()
        crepo.get = AsyncMock(return_value=_challenge(type="authentication"))
        prepo = MagicMock()
        prepo.get = AsyncMock(return_value=None)
        svc = _svc(passkey_repo=prepo, challenge_repo=crepo)
        try:
            _run(
                svc.verify_authentication(
                    credential_id="nope",
                    client_data_json="x",
                    authenticator_data="x",
                    signature="x",
                    challenge_str="Y2hhbGxlbmdl",
                )
            )
            raise AssertionError("expected ValueError")
        except ValueError as exc:
            assert "Passkey not found" in str(exc)

    def test_success_returns_user_and_count(self):
        from authglow.services import passkey as passkey_mod

        crepo = MagicMock()
        crepo.get = AsyncMock(return_value=_challenge(type="authentication"))
        crepo.delete = AsyncMock()
        prepo = MagicMock()
        prepo.get = AsyncMock(return_value=_passkey())
        prepo.update = AsyncMock()
        svc = _svc(passkey_repo=prepo, challenge_repo=crepo)

        verification = SimpleNamespace(new_sign_count=9)
        with patch.object(
            passkey_mod, "verify_authentication_response", return_value=verification
        ):
            user_id, count = _run(
                svc.verify_authentication(
                    credential_id="Y3JlZC0x",
                    client_data_json="e30",
                    authenticator_data="e30",
                    signature="e30",
                    challenge_str="Y2hhbGxlbmdl",
                )
            )
        assert user_id == "u-1"
        assert count == 9
        crepo.delete.assert_awaited_once_with("Y2hhbGxlbmdl")
