"""Federation state token — signed, stateless CSRF protection for OIDC flows.

Why JWT and not server-side state:
    The `state` parameter in OAuth2 / OIDC is the CSRF token for the
    authorization code flow (RFC 6749 §10.12, OIDC Core §3.1.2.1).
    A common implementation stores it server-side, keyed by a session
    cookie — but that requires shared state across instances, which
    does not scale on serverless platforms and ties the flow to cookies.

    The standard alternative — used by AWS Cognito, Auth0, Okta,
    Microsoft Identity Platform — is to make `state` a signed, self-
    contained token. All context needed to validate the callback
    (`provider_id`, `redirect_uri`, `nonce`, expiry) lives in the
    claims and is protected by a signature. Any instance can verify
    the state independently: no shared store, no session cookie.

Security properties:
    * HS256 with ``SECRET_KEY`` — constant-time signature check.
    * ``exp`` claim, 10-minute lifetime (matches typical OIDC round-trip).
    * ``aud=federation`` claim to scope the token and reject cross-purpose use.
    * ``jti`` claim for traceability in audit logs.
    * The ``nonce`` claim is also verified against the ``id_token`` at
      callback time (OIDC Core §3.1.3.7 / §15.5.2).
"""

import secrets
import time
from typing import Any, Dict, Optional

import jwt

from authglow.core.config import get_settings

ALGORITHM = "HS256"
AUDIENCE = "federation"
ISSUER = "authglow"
EXPIRY_SECONDS = 600  # 10 minutes


class FederationStateError(Exception):
    """Raised when a federation state token is missing, invalid, or expired."""


class FederationStateToken:
    """Sign and verify OIDC federation state tokens (HS256 JWT)."""

    def __init__(self):
        self.settings = get_settings()

    def sign(
        self,
        provider_id: str,
        redirect_uri: str,
        nonce: Optional[str] = None,
    ) -> Dict[str, str]:
        """Generate a signed state token and matching nonce.

        Returns:
            A dict with ``state`` (the JWT to send to the IdP) and
            ``nonce`` (the value to embed in the authorization URL and
            to verify against the ``id_token`` at callback time).
        """
        issued_at = int(time.time())
        nonce = nonce or secrets.token_urlsafe(32)
        claims: Dict[str, Any] = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": provider_id,
            "provider_id": provider_id,
            "redirect_uri": redirect_uri,
            "nonce": nonce,
            "jti": secrets.token_hex(8),
            "iat": issued_at,
            "exp": issued_at + EXPIRY_SECONDS,
        }
        token = jwt.encode(claims, self.settings.secret_key, algorithm=ALGORITHM)
        return {"state": token, "nonce": nonce}

    def verify(self, token: str) -> Dict[str, Any]:
        """Verify a state token's signature and claims.

        Returns the decoded claims on success.

        Raises:
            FederationStateError: if the token is missing, malformed,
                expired, has the wrong audience, or fails the signature
                check. Callers should translate this to HTTP 400.
        """
        if not token:
            raise FederationStateError("State parameter is missing")

        try:
            claims = jwt.decode(
                token,
                self.settings.secret_key,
                algorithms=[ALGORITHM],
                audience=AUDIENCE,
                issuer=ISSUER,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "jti", "nonce"]},
            )
        except jwt.ExpiredSignatureError as e:
            raise FederationStateError("State token has expired") from e
        except jwt.InvalidAudienceError as e:
            raise FederationStateError("State token has wrong audience") from e
        except jwt.InvalidIssuerError as e:
            raise FederationStateError("State token has wrong issuer") from e
        except jwt.MissingRequiredClaimError as e:
            raise FederationStateError(f"State token missing required claim: {e.claim}") from e
        except jwt.InvalidTokenError as e:
            raise FederationStateError(f"State token is invalid: {e}") from e

        if (
            not claims.get("provider_id")
            or not claims.get("redirect_uri")
            or not claims.get("nonce")
        ):
            raise FederationStateError("State token missing context claims")

        return claims
