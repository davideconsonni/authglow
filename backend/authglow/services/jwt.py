import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import jwt

from authglow.core.config import get_settings
from authglow.core.crypto import decrypt_private_key, encrypt_private_key
from authglow.core.token_blacklist import token_blacklist
from authglow.models.oidc import SCOPE_TO_CLAIMS, IDTokenClaims
from authglow.models.token import Token, TokenData


class JWTService:
    """Service for creating and validating JWT tokens using RS256.

    Supports JWK key rotation: the active key is used for signing,
    while all active + verifying keys are used for verification.
    """

    def __init__(self):
        """Initialize JWT service with settings and keyring."""
        self.settings = get_settings()

        keyring_path = os.path.join(self.settings.keys_dir, "keyring.json")
        if not os.path.exists(keyring_path):
            raise RuntimeError(f"Keyring not found at {keyring_path}")

        with open(keyring_path, "r", encoding="utf-8") as f:
            self._keyring = json.load(f)

        self._active_kid = self._keyring["active_kid"]

        self._private_key = self._load_private_key(self._active_kid)
        self._public_keys: Dict[str, bytes] = self._load_public_keys()

    def _load_private_key(self, kid: str) -> bytes:
        """Load and decrypt the private key for a given kid."""
        priv_path = os.path.join(self.settings.keys_dir, kid, "private_key.pem")
        if not os.path.exists(priv_path):
            raise RuntimeError(f"Private key missing for kid={kid}: {priv_path}")
        with open(priv_path, "rb") as f:
            raw = f.read()
        return decrypt_private_key(raw, secret_key=self.settings.secret_key)

    def _load_public_keys(self) -> Dict[str, bytes]:
        """Load all public keys for verification (active + verifying, not revoked)."""
        public_keys: Dict[str, bytes] = {}
        for kid, meta in self._keyring["keys"].items():
            status = meta.get("status", "")
            if status in ("active", "verifying"):
                pub_path = os.path.join(self.settings.keys_dir, kid, "public_key.pem")
                if os.path.exists(pub_path):
                    with open(pub_path, "rb") as f:
                        public_keys[kid] = f.read()
        return public_keys

    def _reload_keyring(self):
        """Reload keyring from disk (used after rotation/revocation)."""
        keyring_path = os.path.join(self.settings.keys_dir, "keyring.json")
        with open(keyring_path, "r", encoding="utf-8") as f:
            self._keyring = json.load(f)
        self._active_kid = self._keyring["active_kid"]
        self._private_key = self._load_private_key(self._active_kid)
        self._public_keys = self._load_public_keys()

    def _encode_token(self, payload: dict) -> str:
        """Encode a token payload using the active private key, including kid in header."""
        return jwt.encode(
            payload,
            self._private_key,
            algorithm=self.settings.jwt_algorithm,
            headers={"kid": self._active_kid},
        )

    def _decode_token(self, token: str) -> Optional[dict[str, Any]]:
        """Decode a token using the appropriate public key.

        Strategy:
        1. Extract ``kid`` from the unverified JWT header.
        2. If the kid is known and not revoked, verify with that key.
        3. If the kid is missing or unknown, try all non-revoked keys.
        4. A revoked kid always fails.
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            return None

        kid = unverified_header.get("kid")

        # Check if kid is revoked
        if kid and kid in self._keyring["keys"]:
            if self._keyring["keys"][kid].get("status") == "revoked":
                return None

        # If kid is known and we have its public key, verify with it
        if kid and kid in self._public_keys:
            try:
                result: dict[str, Any] = jwt.decode(
                    token,
                    self._public_keys[kid],
                    algorithms=[self.settings.jwt_algorithm],
                    options={"verify_exp": True},
                )
                return result
            except jwt.PyJWTError:
                return None

        # Fallback: try all non-revoked keys (backward compat, no-kid tokens)
        for verify_kid, pub_key in self._public_keys.items():
            if verify_kid in self._keyring["keys"]:
                if self._keyring["keys"][verify_kid].get("status") == "revoked":
                    continue
            try:
                decoded: dict[str, Any] = jwt.decode(
                    token,
                    pub_key,
                    algorithms=[self.settings.jwt_algorithm],
                    options={"verify_exp": True},
                )
                return decoded
            except jwt.PyJWTError:
                continue

        return None

    def create_access_token(
        self,
        user_id: str,
        email: str,
        scopes: List[str],
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create an access token with a unique jti for revocation support."""
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=self.settings.access_token_expire_minutes
            )

        token_data = {
            "jti": str(uuid4()),
            "sub": user_id,
            "email": email,
            "scopes": scopes,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "token_type": "access",
        }
        return self._encode_token(token_data)

    def create_refresh_token(self, user_id: str, email: str, scopes: List[str]) -> str:
        """Create a refresh token."""
        expire = datetime.now(timezone.utc) + timedelta(
            days=self.settings.refresh_token_expire_days
        )
        token_data = {
            "sub": user_id,
            "email": email,
            "scopes": scopes,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "token_type": "refresh",
        }
        return self._encode_token(token_data)

    def create_mfa_session_token(self, user_id: str, email: str) -> str:
        """Create a temporary session token for MFA verification."""
        expire = datetime.now(timezone.utc) + timedelta(minutes=5)
        token_data = {
            "sub": user_id,
            "email": email,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "token_type": "mfa_session",
        }
        return self._encode_token(token_data)

    def decode_token(self, token: str) -> Optional[TokenData]:
        """Decode and validate a JWT token.

        Returns None if the token is invalid, expired, or revoked (blacklisted).
        """
        payload = self._decode_token(token)
        if not payload:
            return None

        sub = payload.get("sub")
        email = payload.get("email")
        exp_val = payload.get("exp")
        iat_val = payload.get("iat")
        jti = payload.get("jti")

        if not isinstance(sub, str):
            return None
        if not isinstance(email, str):
            return None
        if not isinstance(exp_val, (int, float)):
            return None
        if not isinstance(iat_val, (int, float)):
            return None

        token_data = TokenData(
            sub=sub,
            email=email,
            scopes=payload.get("scopes", []),
            exp=datetime.fromtimestamp(exp_val, tz=timezone.utc),
            iat=datetime.fromtimestamp(iat_val, tz=timezone.utc),
            token_type=str(payload.get("token_type", "access")),
            jti=jti if isinstance(jti, str) else None,
            aud=payload.get("aud") if isinstance(payload.get("aud"), str) else None,
        )

        if token_data.exp < datetime.now(timezone.utc):
            return None

        if token_data.jti and token_blacklist().is_revoked(token_data.jti):
            return None

        return token_data

    def create_id_token(
        self,
        user_id: str,
        client_id: str,
        scopes: List[str],
        user_claims: Dict[str, Any],
        nonce: Optional[str] = None,
        auth_time: Optional[datetime] = None,
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create an OpenID Connect ID Token."""
        iat = datetime.now(timezone.utc)
        if expires_delta:
            expire = iat + expires_delta
        else:
            expire = iat + timedelta(minutes=10)

        id_token_data = {
            "iss": self.settings.issuer,
            "sub": user_id,
            "aud": client_id,
            "exp": int(expire.timestamp()),
            "iat": int(iat.timestamp()),
            "token_version": "3.0-fix-timestamp",
        }
        if nonce:
            id_token_data["nonce"] = nonce
        if auth_time:
            id_token_data["auth_time"] = int(auth_time.replace(tzinfo=timezone.utc).timestamp())

        for scope in scopes:
            if scope in SCOPE_TO_CLAIMS:
                for claim in SCOPE_TO_CLAIMS[scope]:
                    if claim in user_claims and user_claims[claim] is not None:
                        id_token_data[claim] = user_claims[claim]

        return self._encode_token(id_token_data)

    def decode_id_token(self, token: str) -> Optional[IDTokenClaims]:
        """Decode and validate an ID token."""
        payload = self._decode_token(token)
        if not payload:
            return None
        claims = IDTokenClaims(**payload)
        if datetime.fromtimestamp(claims.exp, tz=timezone.utc) < datetime.now(timezone.utc):
            return None
        return claims

    def create_token_response(
        self, user_id: str, email: str, scopes: List[str], include_refresh: bool = True
    ) -> Token:
        """Create a complete token response."""
        access_token = self.create_access_token(user_id, email, scopes)
        token_response = Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=self.settings.access_token_expire_minutes * 60,
            scope=" ".join(scopes),
        )
        if include_refresh:
            refresh_token = self.create_refresh_token(user_id, email, scopes)
            token_response.refresh_token = refresh_token
        return token_response

    # --- Key Rotation & Management ---

    def rotate_keys(self) -> Dict[str, str]:
        """Rotate the active signing key.

        Generates a new RSA key pair, marks the old active key as 'verifying',
        and makes the new key the active signer.

        Returns:
            Dict with ``old_kid`` and ``new_kid``.
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        old_kid = self._active_kid

        # Generate new kid using the canonical _new_kid from config
        from authglow.core.config import _new_kid

        new_kid = _new_kid()
        new_dir = os.path.join(self.settings.keys_dir, new_kid)
        os.makedirs(new_dir, exist_ok=True)

        # Generate fresh key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )
        priv_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        encrypted_priv = encrypt_private_key(priv_bytes, secret_key=self.settings.secret_key)
        with open(os.path.join(new_dir, "private_key.pem"), "wb") as f:
            f.write(encrypted_priv)
        with open(os.path.join(new_dir, "public_key.pem"), "wb") as f:
            f.write(pub_bytes)

        # Update keyring in memory and on disk
        now_str = datetime.now(timezone.utc).isoformat()
        self._keyring["keys"][new_kid] = {
            "created_at": now_str,
            "status": "active",
            "algorithm": self.settings.jwt_algorithm,
            "key_size": 2048,
        }
        self._keyring["keys"][old_kid]["status"] = "verifying"
        self._keyring["keys"][old_kid]["retired_at"] = now_str
        self._keyring["active_kid"] = new_kid

        self._save_keyring()

        # Reload in-process key references
        self._reload_keyring()

        return {"old_kid": old_kid, "new_kid": new_kid}

    def revoke_key(self, kid: str) -> bool:
        """Revoke a key so tokens signed with it are rejected.

        The active key cannot be revoked.

        Returns:
            True if the key was revoked, False if the kid is unknown or is the active key.
        """
        if kid == self._active_kid:
            return False
        if kid not in self._keyring["keys"]:
            return False

        self._keyring["keys"][kid]["status"] = "revoked"
        self._keyring["keys"][kid]["revoked_at"] = datetime.now(timezone.utc).isoformat()
        self._save_keyring()
        self._reload_keyring()
        return True

    def get_keyring_info(self) -> Dict[str, Any]:
        """Return keyring metadata for inspection.

        Returns:
            Dict with ``active_kid`` and a ``keys`` dict keyed by kid with
            status, created_at, algorithm, and key_size.
        """
        return {
            "active_kid": self._active_kid,
            "keys": dict(self._keyring["keys"]),
        }

    def _save_keyring(self):
        """Atomically save the current keyring state to disk."""
        keyring_path = os.path.join(self.settings.keys_dir, "keyring.json")
        tmp = keyring_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._keyring, f, indent=2)
        os.replace(tmp, keyring_path)

        # Also update legacy symlinks for backward compat
        from authglow.core.config import _write_active_symlinks

        _write_active_symlinks(self.settings.keys_dir, self._keyring)
