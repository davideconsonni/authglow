from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from authglow.core.config import get_settings
from authglow.models.token import TokenData, Token
from authglow.models.oidc import IDTokenClaims, SCOPE_TO_CLAIMS


class JWTService:
    """Service for creating and validating JWT tokens using RS256."""

    def __init__(self):
        """Initialize JWT service with settings and RSA keys."""
        self.settings = get_settings()
        
        # Load raw key bytes/string directly from files
        try:
            with open(self.settings.private_key_path, "rb") as f:
                self._private_key = f.read()
                
            with open(self.settings.public_key_path, "rb") as f:
                self._public_key = f.read()
        except FileNotFoundError as e:
            # This should not happen if config initialization is correct
            raise RuntimeError(f"Missing RSA key file: {e}")

    def _encode_token(self, payload: dict) -> str:
        """Encode a token payload using the private key."""
        return jwt.encode(
            payload,
            self._private_key,
            algorithm=self.settings.jwt_algorithm
        )

    def _decode_token(self, token: str) -> Optional[dict]:
        """Decode a token using the public key."""
        try:
            return jwt.decode(
                token,
                self._public_key,
                algorithms=[self.settings.jwt_algorithm]
            )
        except jwt.PyJWTError:
            return None

    def create_access_token(
        self,
        user_id: str,
        email: str,
        scopes: List[str],
        expires_delta: Optional[timedelta] = None
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
            "token_type": "access"
        }
        return self._encode_token(token_data)

    def create_refresh_token(
        self,
        user_id: str,
        email: str,
        scopes: List[str]
    ) -> str:
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
            "token_type": "refresh"
        }
        return self._encode_token(token_data)

    def create_mfa_session_token(
        self,
        user_id: str,
        email: str
    ) -> str:
        """Create a temporary session token for MFA verification."""
        expire = datetime.now(timezone.utc) + timedelta(minutes=5)
        token_data = {
            "sub": user_id,
            "email": email,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "token_type": "mfa_session"
        }
        return self._encode_token(token_data)

    def decode_token(self, token: str) -> Optional[TokenData]:
        """Decode and validate a JWT token."""
        payload = self._decode_token(token)
        if not payload:
            return None

        return TokenData(
            sub=payload.get("sub"),
            email=payload.get("email"),
            scopes=payload.get("scopes", []),
            exp=datetime.fromtimestamp(payload.get("exp"), tz=timezone.utc),
            iat=datetime.fromtimestamp(payload.get("iat"), tz=timezone.utc),
            token_type=payload.get("token_type", "access")
        )

    def create_id_token(
        self,
        user_id: str,
        client_id: str,
        scopes: List[str],
        user_claims: Dict[str, Any],
        nonce: Optional[str] = None,
        auth_time: Optional[datetime] = None,
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create an OpenID Connect ID Token."""
        # Use timezone-aware datetime objects to generate correct UTC timestamps
        iat = datetime.now(timezone.utc)
        if expires_delta:
            expire = iat + expires_delta
        else:
            # 10 minutes is a reasonable lifetime for debugging and production
            expire = iat + timedelta(minutes=10)

        id_token_data = {
            "iss": self.settings.issuer,
            "sub": user_id,
            "aud": client_id,
            "exp": int(expire.timestamp()),
            "iat": int(iat.timestamp()),
            "token_version": "3.0-fix-timestamp",  # Diagnostic claim
        }
        if nonce:
            id_token_data["nonce"] = nonce
        if auth_time:
            # Ensure auth_time is timezone-aware (assuming it's a naive UTC datetime)
            id_token_data["auth_time"] = int(
                auth_time.replace(tzinfo=timezone.utc).timestamp()
            )

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
        return IDTokenClaims(**payload)

    def create_token_response(
        self,
        user_id: str,
        email: str,
        scopes: List[str],
        include_refresh: bool = True
    ) -> Token:
        """Create a complete token response."""
        access_token = self.create_access_token(user_id, email, scopes)
        token_response = Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=self.settings.access_token_expire_minutes * 60,
            scope=" ".join(scopes)
        )
        if include_refresh:
            refresh_token = self.create_refresh_token(user_id, email, scopes)
            token_response.refresh_token = refresh_token
        return token_response