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

    When the federation flow is initiated from an OAuth2 authorize page,
    the OAuth2 context (client_id, scope, redirect_uri, …) is also
    embedded in the state token claims so the callback can bridge back
    into the OAuth2 authorization code flow.

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
from typing import Any, Dict, Optional, cast

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
        from authglow.core.crypto import derive_federation_state_key

        self.settings = get_settings()
        self._signing_key = derive_federation_state_key()

    def sign(
        self,
        provider_id: str,
        redirect_uri: str,
        nonce: Optional[str] = None,
        oauth2_context: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Generate a signed state token and matching nonce.

        Args:
            provider_id: The federated IdP identifier.
            redirect_uri: Where to redirect after the callback completes.
            nonce: Optional nonce; generated if not provided.
            oauth2_context: Optional OAuth2 authorization context dict
                with keys: client_id, oauth_redirect_uri, scope,
                app_state, code_challenge, code_challenge_method,
                response_type, oidc_nonce.

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
        if oauth2_context:
            claims["oauth2_context"] = oauth2_context

        token = jwt.encode(claims, self._signing_key, algorithm=ALGORITHM)
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
                self._signing_key,
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

    @staticmethod
    def get_oauth2_context(claims: Dict[str, Any]) -> Optional[Dict[str, str]]:
        """Extract OAuth2 authorization context from verified state claims.

        Returns None if the federation flow was not initiated from an
        OAuth2 authorize page.
        """
        ctx = claims.get("oauth2_context")
        if not ctx or not isinstance(ctx, dict):
            return None
        if not ctx.get("client_id") or not ctx.get("oauth_redirect_uri"):
            return None
        return cast(Dict[str, str], ctx)
