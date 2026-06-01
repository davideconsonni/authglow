from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt

from authglow.core.config import get_settings
from authglow.core.crypto import decrypt_private_key
from authglow.models.oidc import SCOPE_TO_CLAIMS, IDTokenClaims
from authglow.models.token import Token, TokenData


class JWTService:
    """Service for creating and validating JWT tokens using RS256."""

    def __init__(self):
        """Initialize JWT service with settings and RSA keys."""
        self.settings = get_settings()

        try:
            with open(self.settings.private_key_path, "rb") as f:
                raw = f.read()
                self._private_key = decrypt_private_key(raw, secret_key=self.settings.secret_key)

            with open(self.settings.public_key_path, "rb") as f:
                self._public_key = f.read()
        except FileNotFoundError as e:
            raise RuntimeError(f"Missing RSA key file: {e}")

    def _encode_token(self, payload: dict) -> str:
        """Encode a token payload using the private key."""
        return jwt.encode(payload, self._private_key, algorithm=self.settings.jwt_algorithm)

    def _decode_token(self, token: str) -> Optional[dict[str, Any]]:
        """Decode a token using the public key."""
        try:
            result: dict[str, Any] = jwt.decode(
                token,
                self._public_key,
                algorithms=[self.settings.jwt_algorithm],
                options={"verify_exp": True},
            )
            return result
        except jwt.PyJWTError:
            return None

    def create_access_token(
        self,
        user_id: str,
        email: str,
        scopes: List[str],
        expires_delta: Optional[timedelta] = None,
    ) -> str:
        """Create an access token."""
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=self.settings.access_token_expire_minutes
            )

        token_data = {
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
        """Decode and validate a JWT token."""
        payload = self._decode_token(token)
        if not payload:
            return None

        sub = payload.get("sub")
        email = payload.get("email")
        exp_val = payload.get("exp")
        iat_val = payload.get("iat")

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
            token_type=payload.get("token_type", "access"),
        )

        if token_data.exp < datetime.now(timezone.utc):
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
