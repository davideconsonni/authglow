"""JWT token service."""

from datetime import datetime, timedelta
from typing import Optional, List
import jwt
from authglow.core.config import get_settings
from authglow.models.token import TokenData, Token


class JWTService:
    """Service for creating and validating JWT tokens."""

    def __init__(self):
        """Initialize JWT service with settings."""
        self.settings = get_settings()

    def create_access_token(
        self,
        user_id: str,
        email: str,
        scopes: List[str],
        expires_delta: Optional[timedelta] = None
    ) -> str:
        """Create an access token."""
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=self.settings.access_token_expire_minutes
            )

        token_data = {
            "sub": user_id,
            "email": email,
            "scopes": scopes,
            "exp": expire,
            "iat": datetime.utcnow(),
            "token_type": "access"
        }

        encoded_jwt = jwt.encode(
            token_data,
            self.settings.jwt_secret_key,
            algorithm=self.settings.jwt_algorithm
        )
        return encoded_jwt

    def create_refresh_token(
        self,
        user_id: str,
        email: str,
        scopes: List[str]
    ) -> str:
        """Create a refresh token."""
        expire = datetime.utcnow() + timedelta(
            days=self.settings.refresh_token_expire_days
        )

        token_data = {
            "sub": user_id,
            "email": email,
            "scopes": scopes,
            "exp": expire,
            "iat": datetime.utcnow(),
            "token_type": "refresh"
        }

        encoded_jwt = jwt.encode(
            token_data,
            self.settings.jwt_secret_key,
            algorithm=self.settings.jwt_algorithm
        )
        return encoded_jwt

    def decode_token(self, token: str) -> Optional[TokenData]:
        """Decode and validate a JWT token."""
        try:
            payload = jwt.decode(
                token,
                self.settings.jwt_secret_key,
                algorithms=[self.settings.jwt_algorithm]
            )

            token_data = TokenData(
                sub=payload.get("sub"),
                email=payload.get("email"),
                scopes=payload.get("scopes", []),
                exp=datetime.fromtimestamp(payload.get("exp")),
                iat=datetime.fromtimestamp(payload.get("iat")),
                token_type=payload.get("token_type", "access")
            )

            return token_data

        except jwt.ExpiredSignatureError:
            return None
        except jwt.JWTError:
            return None

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
