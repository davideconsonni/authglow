import base64
import hashlib
import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, cast
from uuid import uuid4

import jwt

from authglow.core.config import get_settings
from authglow.core.crypto import decrypt_private_key, encrypt_private_key
from authglow.models.oidc import SCOPE_TO_CLAIMS, IDTokenClaims
from authglow.models.token import Token, TokenData
from authglow.services.auth.token_blacklist import token_blacklist


async def resolve_rbac_permissions(user_id: str) -> tuple:
    """Resolve RBAC permissions and roles for a user.

    Returns (permissions, roles) tuples of lists, both may be empty.
    Uses lazy imports to avoid circular dependencies.
    """
    try:
        from authglow.services.rbac import RBACService

        rbac = RBACService()
        perms = list(await rbac.get_user_permissions(user_id))
        user_roles = await rbac.get_user_roles(user_id)
        role_names: list[str] = []
        for ur in user_roles or []:
            role = await rbac.get_role(ur.role_id)
            if role:
                role_names.append(role.name)
        return perms, role_names
    except Exception:
        return [], []


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

    def _decode_token(
        self,
        token: str,
        audience: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Decode a token using the appropriate public key.

        Strategy:
        1. Extract ``kid`` from the unverified JWT header.
        2. If the kid is known and not revoked, verify with that key.
        3. If the kid is missing or unknown, try all non-revoked keys.
        4. A revoked kid always fails.

        All tokens must have a valid issuer matching the configured issuer
        and the required claims ``exp``, ``iat``, ``sub``.

        Args:
            token: The encoded JWT.
            audience: When provided, PyJWT enforces ``aud == audience`` and the
                ``aud`` claim is added to the required claims list. When
                ``None`` the ``aud`` claim is not validated, preserving
                back-compat with legacy cookie/MFA tokens that may not carry
                an audience.
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            return None

        kid = unverified_header.get("kid")
        decode_algorithms: List[str] = [self.settings.jwt_algorithm]
        decode_issuer: str = self.settings.issuer
        required_claims: List[str] = ["exp", "iat", "sub"]
        if audience is not None:
            required_claims.append("aud")
        decode_options = cast(
            "jwt.types.Options",
            {
                "require": required_claims,
                "verify_aud": audience is not None,
            },
        )
        decode_kwargs: Dict[str, Any] = {
            "algorithms": decode_algorithms,
            "issuer": decode_issuer,
            "options": decode_options,
        }
        if audience is not None:
            decode_kwargs["audience"] = audience

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
                    **decode_kwargs,
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
                    **decode_kwargs,
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
        permissions: Optional[List[str]] = None,
        roles: Optional[List[str]] = None,
        audience: Optional[str] = None,
        azp: Optional[str] = None,
    ) -> str:
        """Create an access token with a unique jti for revocation support.

        Args:
            audience: When the token is issued on behalf of an OAuth2 client,
                pass the client_id. The ``aud`` claim is then bound to that
                client, enabling OIDC Core §3.1.3.7 audience validation on
                the resource server. When ``None`` (cookie-first / password
                grant flows) no ``aud`` claim is set, preserving the legacy
                back-compat path.
            azp: Authorized party (OIDC Core §2). When ``audience`` is set,
                ``azp`` defaults to the same value if not explicitly
                provided. Following the AuthGlow convention, ``azp`` is
                always set whenever the token is aud-bound.
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=self.settings.access_token_expire_minutes
            )

        token_data = {
            "iss": self.settings.issuer,
            "jti": str(uuid4()),
            "sub": user_id,
            "email": email,
            "scopes": scopes,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "token_type": "access",
        }
        if permissions:
            token_data["permissions"] = permissions
        if roles:
            token_data["roles"] = roles
        if audience is not None:
            token_data["aud"] = audience
            token_data["azp"] = azp if azp is not None else audience
        return self._encode_token(token_data)

    def create_refresh_token(self, user_id: str, email: str, scopes: List[str]) -> str:
        """Create a refresh token with jti for individual revocation."""
        expire = datetime.now(timezone.utc) + timedelta(
            days=self.settings.refresh_token_expire_days
        )
        token_data = {
            "iss": self.settings.issuer,
            "jti": str(uuid4()),
            "sub": user_id,
            "email": email,
            "scopes": scopes,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "token_type": "refresh",
        }
        return self._encode_token(token_data)

    def create_mfa_session_token(self, user_id: str, email: str) -> str:
        """Create a temporary session token for MFA verification with jti for revocation."""
        expire = datetime.now(timezone.utc) + timedelta(minutes=5)
        token_data = {
            "iss": self.settings.issuer,
            "jti": str(uuid4()),
            "sub": user_id,
            "email": email,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "token_type": "mfa_session",
        }
        return self._encode_token(token_data)

    def decode_token(
        self,
        token: str,
        expected_aud: Optional[str] = None,
    ) -> Optional[TokenData]:
        """Decode and validate a JWT token.

        Returns None if the token is invalid, expired, or revoked (blacklisted).

        Args:
            token: The encoded JWT.
            expected_aud: When provided, the token's ``aud`` claim must equal
                this value (OIDC Core §3.1.3.7). When ``None`` the ``aud`` claim
                is not enforced, preserving back-compat with cookie/MFA tokens.
        """
        payload = self._decode_token(token, audience=expected_aud)
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
            permissions=payload.get("permissions"),
            roles=payload.get("roles"),
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
        acr: Optional[str] = None,
        amr: Optional[List[str]] = None,
        access_token: Optional[str] = None,
        authorization_code: Optional[str] = None,
    ) -> str:
        """Create an OpenID Connect ID Token.

        If *access_token* is provided, the ``at_hash`` claim is computed
        (OIDC Core §3.1.3.6). If *authorization_code* is provided, the
        ``c_hash`` claim is computed similarly.

        The hash algorithm is left-half SHA-256, base64url-encoded with
        no padding.
        """
        iat = datetime.now(timezone.utc)
        if expires_delta:
            expire = iat + expires_delta
        else:
            expire = iat + timedelta(minutes=10)

        id_token_data = {
            "iss": self.settings.issuer,
            "sub": user_id,
            "aud": client_id,
            "azp": client_id,
            "exp": int(expire.timestamp()),
            "iat": int(iat.timestamp()),
            "sid": secrets.token_hex(16),
            "token_version": "3.0-fix-timestamp",
        }
        if nonce:
            id_token_data["nonce"] = nonce
        if auth_time:
            id_token_data["auth_time"] = int(auth_time.replace(tzinfo=timezone.utc).timestamp())
        if acr:
            id_token_data["acr"] = acr
        if amr:
            id_token_data["amr"] = amr
        if access_token:
            digest = hashlib.sha256(access_token.encode()).digest()
            id_token_data["at_hash"] = base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()
        if authorization_code:
            digest = hashlib.sha256(authorization_code.encode()).digest()
            id_token_data["c_hash"] = base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()

        for scope in scopes:
            if scope in SCOPE_TO_CLAIMS:
                for claim in SCOPE_TO_CLAIMS[scope]:
                    if claim in user_claims and user_claims[claim] is not None:
                        id_token_data[claim] = user_claims[claim]

        return self._encode_token(id_token_data)

    def decode_id_token(self, token: str, expected_aud: str) -> Optional[IDTokenClaims]:
        """Decode and validate an ID token.

        Args:
            token: The encoded ID token (JWT).
            expected_aud: The client_id the token must be issued for. The
                token's ``aud`` claim must equal this value (OIDC Core
                §3.1.3.7). This is a required argument: the caller must
                always know which client it is speaking on behalf of.

        Returns None on signature failure, expiration, missing ``aud``,
        audience mismatch, or any other validation error.
        """
        payload = self._decode_token(token, audience=expected_aud)
        if not payload:
            return None
        claims = IDTokenClaims(**payload)
        if datetime.fromtimestamp(claims.exp, tz=timezone.utc) < datetime.now(timezone.utc):
            return None
        return claims

    def create_token_response(
        self,
        user_id: str,
        email: str,
        scopes: List[str],
        include_refresh: bool = True,
        permissions: Optional[List[str]] = None,
        roles: Optional[List[str]] = None,
        audience: Optional[str] = None,
        azp: Optional[str] = None,
    ) -> Token:
        """Create a complete token response.

        ``audience``/``azp`` are forwarded to the access token so the
        response is aud-bound when the caller knows the client_id.
        """
        access_token = self.create_access_token(
            user_id,
            email,
            scopes,
            permissions=permissions,
            roles=roles,
            audience=audience,
            azp=azp,
        )
        token_response = Token(
            access_token=access_token,
            token_type="Bearer",
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
