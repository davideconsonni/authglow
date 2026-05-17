"""Passkey/WebAuthn service for AuthGlow."""

import json
import secrets
from datetime import datetime, timedelta
from typing import Optional

import fsspec
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
)
from webauthn.helpers.structs import (
    PublicKeyCredentialDescriptor,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    ResidentKeyRequirement,
    AttestationConveyancePreference,
    AuthenticatorTransport,
)
from webauthn.helpers.cose import COSEAlgorithmIdentifier

from authglow.core.async_io import AsyncFileSystem
from authglow.core.concurrency import named_lock
from authglow.models.passkey import (
    Passkey,
    PasskeyChallenge,
    PasskeyRegistrationOptions,
    PasskeyAuthenticationOptions,
)
from authglow.models.user import User
from authglow.core.datetime import utcnow


class PasskeyService:
    """Service for managing WebAuthn passkeys."""

    def __init__(self, storage_path: str, rp_id: str, rp_name: str, origin: str):
        """
        Initialize passkey service.

        Args:
            storage_path: fsspec path for storing passkeys
            rp_id: Relying Party ID (domain, e.g., "localhost" or "example.com")
            rp_name: Relying Party name (e.g., "AuthGlow")
            origin: Full origin URL (e.g., "http://localhost:8000")
        """
        self.storage_path = storage_path.rstrip("/")
        self.rp_id = rp_id
        self.rp_name = rp_name
        self.origin = origin
        self.fs = fsspec.core.url_to_fs(storage_path)[0]
        self._afs = AsyncFileSystem(self.fs)
        self._lock = named_lock()

        # Ensure storage directories exist
        self.fs.mkdirs(f"{self.storage_path}/passkeys", exist_ok=True)
        self.fs.mkdirs(f"{self.storage_path}/challenges", exist_ok=True)

    def _get_passkey_path(self, user_id: str, credential_id: str) -> str:
        """Get storage path for a passkey."""
        return f"{self.storage_path}/passkeys/{user_id}_{credential_id}.json"

    def _get_challenge_path(self, challenge_id: str) -> str:
        """Get storage path for a challenge."""
        return f"{self.storage_path}/challenges/{challenge_id}.json"

    async def get_user_passkeys(self, user_id: str) -> list[Passkey]:
        """Get all passkeys for a user."""
        try:
            files = await self._afs.glob(
                f"{self.storage_path}/passkeys/{user_id}_*.json"
            )
            passkeys = []

            for file_path in files:
                data = await self._afs.read_json(file_path)
                passkeys.append(Passkey(**data))

            return sorted(passkeys, key=lambda p: p.created_at, reverse=True)
        except Exception:
            return []

    async def save_passkey(self, passkey: Passkey) -> Passkey:
        """Save a passkey."""
        path = self._get_passkey_path(passkey.user_id, passkey.credential_id)

        await self._afs.write_json(path, passkey.model_dump(mode="json"))

        return passkey

    async def get_passkey(self, user_id: str, credential_id: str) -> Optional[Passkey]:
        """Get a specific passkey."""
        path = self._get_passkey_path(user_id, credential_id)

        try:
            data = await self._afs.read_json(path)
            return Passkey(**data)
        except Exception:
            return None

    async def delete_passkey(self, user_id: str, credential_id: str) -> bool:
        """Delete a passkey."""
        path = self._get_passkey_path(user_id, credential_id)

        try:
            await self._afs.rm(path)
            return True
        except Exception:
            return False

    async def update_passkey_usage(
        self, user_id: str, credential_id: str, sign_count: int
    ):
        """Update passkey last used time and sign count.

        Protected by a named lock to prevent concurrent sign_count corruption.
        """
        async with self._lock(f"passkey:{user_id}:{credential_id}"):
            passkey = await self.get_passkey(user_id, credential_id)
            if passkey:
                passkey.last_used_at = utcnow()
                passkey.sign_count = sign_count
                await self.save_passkey(passkey)

    async def save_challenge(self, challenge: PasskeyChallenge) -> PasskeyChallenge:
        """Save a WebAuthn challenge."""
        path = self._get_challenge_path(challenge.challenge)

        await self._afs.write_json(path, challenge.model_dump(mode="json"))

        return challenge

    async def get_challenge(self, challenge_str: str) -> Optional[PasskeyChallenge]:
        """Get and validate a challenge."""
        path = self._get_challenge_path(challenge_str)

        try:
            data = await self._afs.read_json(path)
            challenge = PasskeyChallenge(**data)

            # Check if expired
            if challenge.expires_at < utcnow():
                await self._afs.rm(path)  # Clean up expired challenge
                return None

            return challenge
        except Exception:
            return None

    async def delete_challenge(self, challenge_str: str):
        """Delete a challenge after use."""
        path = self._get_challenge_path(challenge_str)
        try:
            await self._afs.rm(path)
        except Exception:
            pass

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

        # Get and validate challenge
        challenge = await self.get_challenge(challenge_str)
        if not challenge or challenge.type != "registration":
            raise ValueError("Invalid or expired challenge")

        # Verify the registration response
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

        # Create passkey from verification
        passkey = Passkey(
            credential_id=bytes_to_base64url(verification.credential_id),
            public_key=bytes_to_base64url(verification.credential_public_key),
            sign_count=verification.sign_count,
            transports=transports,
            aaguid=str(verification.aaguid),
            user_id=challenge.user_id,
            name=name,
            backup_eligible=verification.credential_backed_up,
            backup_state=verification.credential_backed_up,
        )

        # Save passkey and delete challenge
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

        # Get and validate challenge
        challenge = await self.get_challenge(challenge_str)
        if not challenge or challenge.type != "authentication":
            raise ValueError("Invalid or expired challenge")

        # Find the passkey by credential_id
        # credential_id is in base64url format, same as we stored it
        passkey = await self.get_passkey(challenge.user_id, credential_id)
        if not passkey:
            raise ValueError("Passkey not found")

        # Verify the authentication response
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

        # Update passkey usage
        await self.update_passkey_usage(
            passkey.user_id,
            credential_id,
            verification.new_sign_count,
        )

        # Delete challenge
        await self.delete_challenge(challenge_str)

        return passkey.user_id, verification.new_sign_count
