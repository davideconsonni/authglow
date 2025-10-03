"""JWT token service."""

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
import jwt
from authglow.core.config import get_settings
from authglow.models.token import TokenData, Token
from authglow.models.oidc import IDTokenClaims, SCOPE_TO_CLAIMS


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

    def create_mfa_session_token(
        self,
        user_id: str,
        email: str
    ) -> str:
        """Create a temporary session token for MFA verification.

        This token is valid for 5 minutes and only for MFA verification.
        """
        expire = datetime.utcnow() + timedelta(minutes=5)

        token_data = {
            "sub": user_id,
            "email": email,
            "exp": expire,
            "iat": datetime.utcnow(),
            "token_type": "mfa_session"
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
        except jwt.PyJWTError:
            return None

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
        """Create an OpenID Connect ID Token.

        Args:
            user_id: Subject identifier
            client_id: Client ID (audience)
            scopes: Requested scopes
            user_claims: User information to include based on scopes
            nonce: Nonce from authorization request
            auth_time: Time when user authenticated
            expires_delta: Token expiration time

        Returns:
            Encoded JWT ID token
        """
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(
                minutes=self.settings.access_token_expire_minutes
            )

        iat = datetime.utcnow()

        # Build ID token claims
        id_token_data = {
            "iss": self.settings.issuer,
            "sub": user_id,
            "aud": client_id,
            "exp": int(expire.timestamp()),
            "iat": int(iat.timestamp()),
        }

        # Add optional claims
        if nonce:
            id_token_data["nonce"] = nonce

        if auth_time:
            id_token_data["auth_time"] = int(auth_time.timestamp())

        # Add user claims based on requested scopes
        for scope in scopes:
            if scope in SCOPE_TO_CLAIMS:
                for claim in SCOPE_TO_CLAIMS[scope]:
                    if claim in user_claims and user_claims[claim] is not None:
                        id_token_data[claim] = user_claims[claim]

        # Encode ID token
        encoded_jwt = jwt.encode(
            id_token_data,
            self.settings.jwt_secret_key,
            algorithm=self.settings.jwt_algorithm
        )

        return encoded_jwt

    def decode_id_token(self, token: str) -> Optional[IDTokenClaims]:
        """Decode and validate an ID token."""
        try:
            payload = jwt.decode(
                token,
                self.settings.jwt_secret_key,
                algorithms=[self.settings.jwt_algorithm]
            )

            return IDTokenClaims(**payload)

        except jwt.ExpiredSignatureError:
            return None
        except jwt.PyJWTError:
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
