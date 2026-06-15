"""Passkey/WebAuthn service for AuthGlow.

Persistence is delegated to two repositories:

* ``self._passkey_repo`` — :class:`PasskeyRepository`
* ``self._challenge_repo`` — :class:`WebAuthnChallengeRepository`

The pre-refactor implementation constructed ``fsspec.core.url_to_fs``,
which bypassed the Settings-driven backend selection and would have
crashed on any non-``file`` backend (``s3`` / ``gcs`` / ``abfs``).
The refactored service resolves its repositories via the standard
factory, which routes through ``BaseFileRepository._init_filesystem``
and honours ``Settings.storage_backend``.

WebAuthn crypto (``verify_registration``, ``verify_authentication``,
``generate_*_options_dict``) stays in the service because it is
purely synchronous cryptography with no I/O.
"""

import json
from typing import Optional

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from authglow.core.concurrency import ConcurrentWriteError, named_lock
from authglow.core.datetime import utcnow
from authglow.models.passkey import (
    Passkey,
    PasskeyChallenge,
)
from authglow.models.user import User
from authglow.repositories.protocols import (
    PasskeyRepository,
    WebAuthnChallengeRepository,
)


class PasskeyService:
    """Service for managing WebAuthn passkeys."""

    def __init__(
        self,
        rp_id: str,
        rp_name: str,
        origin: str,
        passkey_repository: Optional[PasskeyRepository] = None,
        challenge_repository: Optional[WebAuthnChallengeRepository] = None,
    ):
        """Initialize passkey service with WebAuthn config + repositories.

        ``rp_id``, ``rp_name`` and ``origin`` are the WebAuthn relying
        party parameters. The repositories are resolved via the
        corresponding ``get_*`` factory in
        :mod:`authglow.repositories.dependencies` when ``None`` is
        passed (the production default).

        The historical ``storage_path`` argument has been removed:
        the on-disk path is now derived from
        ``Settings.storage_path`` + the repository's ``_subdir``,
        which removes the ``fsspec.core.url_to_fs`` bypass that
        would have crashed on any non-``file`` backend.
        """
        from authglow.repositories.dependencies import (
            get_passkey_repository,
            get_webauthn_challenge_repository,
        )

        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        self._passkey_repo = passkey_repository or get_passkey_repository()
        self._challenge_repo = challenge_repository or get_webauthn_challenge_repository()
        self._lock = named_lock()

    # ------------------------------------------------------------------
    # Passkey CRUD — persistence
    # ------------------------------------------------------------------

    async def get_user_passkeys(self, user_id: str) -> list[Passkey]:
        """Get all passkeys for a user."""
        return await self._passkey_repo.list_for_user(user_id)

    async def save_passkey(self, passkey: Passkey) -> Passkey:
        """Save a new passkey (first-time registration only)."""
        await self._passkey_repo.save(passkey)
        return passkey

    async def get_passkey(self, user_id: str, credential_id: str) -> Optional[Passkey]:
        """Get a specific passkey."""
        return await self._passkey_repo.get(user_id, credential_id)

    async def delete_passkey(self, user_id: str, credential_id: str) -> bool:
        """Delete a passkey."""
        return await self._passkey_repo.delete(user_id, credential_id)

    async def update_passkey_usage(self, user_id: str, credential_id: str, sign_count: int):
        """Update passkey last used time and sign count.

        Protected by a named lock to prevent concurrent sign_count
        corruption. The repository ``update`` call uses optimistic
        concurrency (``_version`` field) so a cross-process race
        surfaces as :class:`ConcurrentWriteError` and is retried.
        """
        async with self._lock(f"passkey:{user_id}:{credential_id}"):
            for _ in range(5):
                passkey = await self._passkey_repo.get(user_id, credential_id)
                if passkey is None:
                    return
                passkey.last_used_at = utcnow()
                passkey.sign_count = sign_count
                try:
                    await self._passkey_repo.update(passkey)
                    return
                except ConcurrentWriteError:
                    continue

    # ------------------------------------------------------------------
    # WebAuthn challenge — persistence (auto-expire on read)
    # ------------------------------------------------------------------

    async def save_challenge(self, challenge: PasskeyChallenge) -> PasskeyChallenge:
        """Save a WebAuthn challenge."""
        await self._challenge_repo.save(challenge)
        return challenge

    async def get_challenge(self, challenge_str: str) -> Optional[PasskeyChallenge]:
        """Get and validate a challenge (auto-deletes expired)."""
        return await self._challenge_repo.get(challenge_str)

    async def delete_challenge(self, challenge_str: str):
        """Delete a challenge after use."""
        await self._challenge_repo.delete(challenge_str)

    # ------------------------------------------------------------------
    # WebAuthn crypto — pure functions, no I/O
    # ------------------------------------------------------------------

    def generate_registration_options_dict(
        self,
        user: User,
        user_passkeys: Optional[list] = None,
    ) -> tuple[dict, str]:
        """
        Generate WebAuthn registration options.

        Args:
            user: The user registering a new passkey.
            user_passkeys: Existing passkeys for the user, used to prevent
                duplicate registrations via exclude_credentials.

        Returns:
            Tuple of (options_dict, challenge_string)
        """
        from webauthn.helpers import base64url_to_bytes

        existing_passkeys = user_passkeys or []

        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user.id.encode("utf-8"),
            user_name=user.email,
            user_display_name=f"{user.first_name or ''} {user.last_name or ''}".strip()
            or user.email,
            exclude_credentials=[
                PublicKeyCredentialDescriptor(id=base64url_to_bytes(pk.credential_id))
                for pk in existing_passkeys
            ],
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=UserVerificationRequirement.PREFERRED,
            ),
            attestation=AttestationConveyancePreference.NONE,
            supported_pub_key_algs=[
                COSEAlgorithmIdentifier.ECDSA_SHA_256,
                COSEAlgorithmIdentifier.RSASSA_PKCS1_v1_5_SHA_256,
            ],
        )

        options_dict = json.loads(options_to_json(options))
        challenge_str = options_dict["challenge"]

        return options_dict, challenge_str

    def generate_authentication_options_dict(
        self, user_passkeys: list[Passkey]
    ) -> tuple[dict, str]:
        """
        Generate WebAuthn authentication options.

        Returns:
            Tuple of (options_dict, challenge_string)
        """
        from webauthn.helpers import base64url_to_bytes

        options = generate_authentication_options(
            rp_id=self.rp_id,
            allow_credentials=[
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(pk.credential_id),
                    transports=[
                        AuthenticatorTransport(t)
                        for t in pk.transports
                        if t in ["usb", "nfc", "ble", "internal"]
                    ],
                )
                for pk in user_passkeys
            ],
            user_verification=UserVerificationRequirement.PREFERRED,
        )

        options_dict = json.loads(options_to_json(options))
        challenge_str = options_dict["challenge"]

        return options_dict, challenge_str

    async def verify_registration(
        self,
        credential_id: str,
        client_data_json: str,
        attestation_object: str,
        challenge_str: str,
        transports: list[str],
        name: str,
    ) -> Passkey:
        """
        Verify registration response and create passkey.

        Args:
            credential_id: Base64url credential ID from client
            client_data_json: Base64url client data JSON
            attestation_object: Base64url attestation object
            challenge_str: Expected challenge string
            transports: List of transports
            name: User-friendly name for the passkey

        Returns:
            Created Passkey object

        Raises:
            Exception if verification fails
        """
        from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

        challenge = await self.get_challenge(challenge_str)
        if not challenge or challenge.type != "registration":
            raise ValueError("Invalid or expired challenge")

        verification = verify_registration_response(
            credential=json.dumps(
                {
                    "id": credential_id,
                    "rawId": credential_id,
                    "response": {
                        "clientDataJSON": client_data_json,
                        "attestationObject": attestation_object,
                    },
                    "type": "public-key",
                }
            ),
            expected_challenge=base64url_to_bytes(challenge_str),
            expected_origin=self.origin,
            expected_rp_id=self.rp_id,
        )

        passkey = Passkey(
            credential_id=bytes_to_base64url(verification.credential_id),
            public_key=bytes_to_base64url(verification.credential_public_key),
            sign_count=verification.sign_count,
            transports=transports,
            aaguid=str(verification.aaguid),
            user_id=challenge.user_id,
            device_type=None,
            name=name,
            backup_eligible=verification.credential_backed_up,
            backup_state=verification.credential_backed_up,
        )

        await self.save_passkey(passkey)
        await self.delete_challenge(challenge_str)

        return passkey

    async def verify_authentication(
        self,
        credential_id: str,
        client_data_json: str,
        authenticator_data: str,
        signature: str,
        challenge_str: str,
    ) -> tuple[str, int]:
        """
        Verify authentication response.

        Args:
            credential_id: Base64url credential ID
            client_data_json: Base64url client data JSON
            authenticator_data: Base64url authenticator data
            signature: Base64url signature
            challenge_str: Expected challenge string

        Returns:
            Tuple of (user_id, new_sign_count)

        Raises:
            Exception if verification fails
        """
        from webauthn.helpers import base64url_to_bytes

        challenge = await self.get_challenge(challenge_str)
        if not challenge or challenge.type != "authentication":
            raise ValueError("Invalid or expired challenge")

        passkey = await self.get_passkey(challenge.user_id, credential_id)
        if not passkey:
            raise ValueError("Passkey not found")

        verification = verify_authentication_response(
            credential=json.dumps(
                {
                    "id": credential_id,
                    "rawId": credential_id,
                    "response": {
                        "clientDataJSON": client_data_json,
                        "authenticatorData": authenticator_data,
                        "signature": signature,
                    },
                    "type": "public-key",
                }
            ),
            expected_challenge=base64url_to_bytes(challenge_str),
            expected_origin=self.origin,
            expected_rp_id=self.rp_id,
            credential_public_key=base64url_to_bytes(passkey.public_key),
            credential_current_sign_count=passkey.sign_count,
        )

        await self.update_passkey_usage(
            passkey.user_id,
            credential_id,
            verification.new_sign_count,
        )

        await self.delete_challenge(challenge_str)

        return passkey.user_id, verification.new_sign_count
