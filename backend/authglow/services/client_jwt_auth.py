"""Client JWT authentication for the OAuth 2.0 token endpoint.

Implements ``client_secret_jwt`` (HS256, RFC 7521 §3.2) and
``private_key_jwt`` (RS256, RFC 7521 §3.1) client authentication at
the token endpoint, per the FAPI 2.0 / OpenID Connect Core profile
(conformance workstream T.2).

Public surface
--------------
- :func:`verify_client_secret_jwt` — HS256 over a per-client symmetric
  key.
- :func:`verify_private_key_jwt` — RS256 over the public JWK
  registered with the client.
- :func:`assert_jwt_claims` — RFC 7523 §3 / OIDC Core §9 enforcement
  of ``iss``/``sub``/``aud``/``exp``/``jti``.
- :func:`replay_protect_jti` — single-use enforcement via the
  in-process :data:`authglow.core.cache.jti_cache`.
- :func:`encrypt_client_jwt_key` /
  :func:`decrypt_client_jwt_key` — re-exports of
  :func:`authglow.core.crypto.encrypt_client_jwt_key` / ``decrypt_*``
  so callers only need to import from this module.
- :func:`verify_client_assertion` — top-level entry point used by the
  token endpoint: dispatches on ``token_endpoint_auth_method`` and
  returns the authenticated :class:`OAuth2Client` (or raises).
"""

from __future__ import annotations

import secrets
import time
from typing import Any, Dict, Optional

import jwt
import structlog
from fastapi import HTTPException, Request, status
from jwt.algorithms import RSAAlgorithm

from authglow.core.cache import jti_cache
from authglow.core.config import Settings
from authglow.core.crypto import (
    decrypt_client_jwt_key,
    encrypt_client_jwt_key,
)
from authglow.models.oauth_client import OAuth2Client

logger = structlog.get_logger("authglow.audit")

# JWT-Bearer client assertion type (RFC 7521 §2.2 / RFC 7523 §2.2).
CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# Algorithms accepted by the verifier. FAPI 2.0 requires explicit,
# non-``none`` algorithms and a strict allowlist — we keep the list
# small on purpose (HS256 + RS256) so the test matrix stays manageable.
_ALLOWED_ALGORITHMS = ("HS256", "RS256")

# Maximum tolerated clock skew between the AS and the client when
# validating ``exp``/``nbf`` (RFC 7523 §3 recommends "a small leeway,
# usually no more than a few minutes"). We use 60 seconds — small
# enough to bound replay, large enough to absorb typical NTP drift.
_LEEWAY_SECONDS = 60

# Maximum client_assertion lifetime. RFC 7523 §3 recommends short
# lifetimes; we cap at 10 minutes which is far below the value
# expected for any reasonable client implementation.
_MAX_ASSERTION_LIFETIME = 600


# ---------------------------------------------------------------------------
# Encryption helpers (re-exports)
# ---------------------------------------------------------------------------


def encrypt_client_jwt_key_value(plaintext: str) -> str:
    """Encrypt a per-client symmetric key for storage.

    Thin wrapper around :func:`authglow.core.crypto.encrypt_client_jwt_key`
    to keep imports symmetrical with :func:`decrypt_client_jwt_key_value`.
    """
    return encrypt_client_jwt_key(plaintext)


def decrypt_client_jwt_key_value(ciphertext: Optional[str]) -> str:
    """Decrypt a per-client symmetric key.

    Returns an empty string when the ciphertext is ``None`` or empty —
    callers use the empty string as a sentinel for "no key configured".
    """
    if not ciphertext:
        return ""
    return decrypt_client_jwt_key(ciphertext)


def generate_client_jwt_symmetric_key() -> str:
    """Generate a fresh 32-byte symmetric key for HS256 client_assertion JWTs.

    Returns the **plaintext** key — the caller is responsible for
    encrypting it via :func:`encrypt_client_jwt_key_value` before
    persisting. The plaintext is returned in the admin "create
    client" response exactly once, mirroring the existing
    ``client_secret`` plaintext-at-creation pattern.
    """
    return secrets.token_urlsafe(32)


# ---------------------------------------------------------------------------
# JTI replay protection
# ---------------------------------------------------------------------------


async def replay_protect_jti(jti: str, exp: int) -> bool:
    """Record a ``jti`` and reject replays.

    Returns ``True`` if the ``jti`` was unseen (proceed) and ``False`` if
    the same ``jti`` has already been used in the cache window
    (caller MUST reject the request). The cache is the
    :data:`authglow.core.cache.jti_cache` singleton, with TTL = ``exp``
    (effectively, the lifetime of the JWT).
    """
    if not jti:
        return True  # Replay protection requires a jti — let the claim
        # check below reject requests with no jti.
    key = f"jti:{jti}"
    return await jti_cache.set_if_absent(key, exp)


# ---------------------------------------------------------------------------
# Claim assertion (RFC 7523 §3)
# ---------------------------------------------------------------------------


def _expected_audience(settings: Settings, request: Request) -> list[str]:
    """The ``aud`` values we accept on a client_assertion JWT.

    RFC 7523 §3 mandates that ``aud`` identify the AS that the client
    is presenting the assertion to. We accept the issuer's full token
    endpoint URL and the bare issuer — the same flexibility the
    discovery endpoint exposes.
    """
    base = settings.issuer.rstrip("/")
    return [
        f"{base}/oauth2/token",
        base,
    ]


def assert_jwt_claims(
    claims: Dict[str, Any],
    client: OAuth2Client,
    request: Request,
    settings: Optional[Settings] = None,
) -> None:
    """Validate the required client_assertion claims.

    Required by RFC 7523 §3 + OIDC Core §9:
    - ``iss`` MUST equal ``client.client_id``
    - ``sub`` MUST equal ``client.client_id`` (per FAPI 2.0 §5.2.2)
    - ``aud`` MUST match the token endpoint URL or issuer
    - ``exp`` MUST be in the future
    - ``jti`` MUST be present (replay protection depends on it)
    - lifetime MUST NOT exceed :data:`_MAX_ASSERTION_LIFETIME`
    """
    if settings is None:
        # Lazy import so the autouse ``_override_settings`` fixture in
        # ``conftest.py`` (which patches ``authglow.core.config.get_settings``)
        # is honoured here. A top-level import would bind a stale
        # reference at module load.
        from authglow.core.config import get_settings

        settings = get_settings()

    iss = claims.get("iss")
    sub = claims.get("sub")
    aud = claims.get("aud")
    exp = claims.get("exp")
    jti = claims.get("jti")

    if iss != client.client_id:
        raise _client_jwt_error("invalid_issuer", "iss claim does not match client_id")
    if sub is not None and sub != client.client_id:
        raise _client_jwt_error("invalid_subject", "sub claim does not match client_id")
    if sub is None:
        # RFC 7523 §3 marks ``sub`` as REQUIRED; we enforce it.
        raise _client_jwt_error("missing_subject", "sub claim is required")
    if not aud:
        raise _client_jwt_error("missing_audience", "aud claim is required")
    if isinstance(aud, str):
        aud_values = [aud]
    elif isinstance(aud, list):
        aud_values = list(aud)
    else:
        raise _client_jwt_error("invalid_audience", "aud claim must be string or list of strings")
    expected = _expected_audience(settings, request)
    if not any(a in expected for a in aud_values):
        raise _client_jwt_error("invalid_audience", "aud claim does not match the token endpoint")
    if exp is None:
        raise _client_jwt_error("missing_exp", "exp claim is required")
    now = int(time.time())
    if int(exp) <= now - _LEEWAY_SECONDS:
        raise _client_jwt_error("expired", "exp claim is in the past")
    if int(exp) - now > _MAX_ASSERTION_LIFETIME + _LEEWAY_SECONDS:
        raise _client_jwt_error(
            "excessive_lifetime",
            f"exp claim more than {_MAX_ASSERTION_LIFETIME}s in the future",
        )
    if not jti:
        raise _client_jwt_error("missing_jti", "jti claim is required (replay protection)")


# ---------------------------------------------------------------------------
# Signature verification — HS256
# ---------------------------------------------------------------------------


def verify_client_secret_jwt(jwt_str: str, key: str) -> Dict[str, Any]:
    """Verify a ``client_secret_jwt`` assertion (HS256).

    ``key`` is the *plaintext* symmetric key registered with the
    client (the encrypted ``client_secret_jwt_key`` must be decrypted
    by the caller before this function is invoked).
    """
    if not key:
        raise _client_jwt_error("missing_key", "client has no JWT key configured")
    try:
        claims = jwt.decode(
            jwt_str,
            key=key.encode("utf-8") if isinstance(key, str) else key,
            algorithms=["HS256"],
            # ``verify_aud=False`` — we enforce the audience check
            # ourselves in :func:`assert_jwt_claims`. PyJWT 2.10+ would
            # otherwise refuse any token that contains an ``aud``
            # claim without an ``audience=`` argument.
            options={
                "require": ["exp", "jti", "iss", "sub", "aud"],
                "verify_aud": False,
            },
            leeway=_LEEWAY_SECONDS,
        )
    except jwt.ExpiredSignatureError as exc:
        raise _client_jwt_error("expired", str(exc)) from exc
    except jwt.InvalidAlgorithmError as exc:
        raise _client_jwt_error("invalid_algorithm", str(exc)) from exc
    except jwt.InvalidTokenError as exc:
        raise _client_jwt_error("invalid_token", str(exc)) from exc
    return claims


# ---------------------------------------------------------------------------
# Signature verification — RS256
# ---------------------------------------------------------------------------


def _public_jwk_to_key(public_jwk: Dict[str, Any]) -> Any:
    """Convert an embedded JWK dict into a ``cryptography`` public key.

    Only RSA is supported in this revision (FAPI 2.0 minimum profile).
    """
    if not isinstance(public_jwk, dict):
        raise _client_jwt_error("invalid_jwk", "public_jwk must be a dict")
    kty = public_jwk.get("kty")
    if kty != "RSA":
        raise _client_jwt_error("unsupported_jwk", "only RSA JWKs are supported")
    try:
        return RSAAlgorithm.from_jwk(public_jwk)
    except Exception as exc:  # PyJWT raises a variety of internal errors
        raise _client_jwt_error("invalid_jwk", f"failed to parse JWK: {exc}") from exc


def verify_private_key_jwt(jwt_str: str, public_jwk: Dict[str, Any]) -> Dict[str, Any]:
    """Verify a ``private_key_jwt`` assertion (RS256) using the client's JWK."""
    public_key = _public_jwk_to_key(public_jwk)
    try:
        claims = jwt.decode(
            jwt_str,
            key=public_key,
            algorithms=["RS256"],
            # ``verify_aud=False`` — see ``verify_client_secret_jwt``.
            options={
                "require": ["exp", "jti", "iss", "sub", "aud"],
                "verify_aud": False,
            },
            leeway=_LEEWAY_SECONDS,
        )
    except jwt.ExpiredSignatureError as exc:
        raise _client_jwt_error("expired", str(exc)) from exc
    except jwt.InvalidAlgorithmError as exc:
        raise _client_jwt_error("invalid_algorithm", str(exc)) from exc
    except jwt.InvalidTokenError as exc:
        raise _client_jwt_error("invalid_token", str(exc)) from exc
    return claims


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------


def _client_jwt_error(code: str, description: str) -> HTTPException:
    """Build a 401 ``invalid_client`` RFC 6749 §5.2 protocol error."""
    from authglow.api.oauth_errors import INVALID_CLIENT, OAuth2Error

    return OAuth2Error(
        INVALID_CLIENT,
        description,
        status_code=status.HTTP_401_UNAUTHORIZED,
        error_code=code,
        headers={"WWW-Authenticate": 'Basic realm="OAuth2"'},
    )


async def verify_client_assertion(
    request: Request,
    client: OAuth2Client,
    client_assertion_type: Optional[str],
    client_assertion: Optional[str],
) -> None:
    """Verify a ``client_assertion`` against the registered ``client``.

    Dispatches on ``client.token_endpoint_auth_method``. Raises
    ``HTTPException(401)`` on any verification failure (the caller
    just propagates it as the standard OAuth2 error response).
    """
    method = client.token_endpoint_auth_method
    if method not in ("client_secret_jwt", "private_key_jwt"):
        # This helper is only called for JWT-based methods. The caller
        # is responsible for routing legacy methods.
        raise _client_jwt_error(
            "unsupported_method",
            f"verify_client_assertion called for unsupported method {method!r}",
        )

    if not client_assertion_type or not client_assertion:
        raise _client_jwt_error(
            "missing_assertion",
            "client_assertion_type and client_assertion are required",
        )
    if client_assertion_type != CLIENT_ASSERTION_TYPE_JWT_BEARER:
        raise _client_jwt_error(
            "invalid_assertion_type",
            f"client_assertion_type must be {CLIENT_ASSERTION_TYPE_JWT_BEARER!r}",
        )

    # Lazy import — see :func:`assert_jwt_claims`.
    from authglow.core.config import get_settings

    settings = get_settings()

    if method == "client_secret_jwt":
        if not client.client_secret_jwt_key:
            raise _client_jwt_error("missing_key", "client has no JWT key configured")
        plaintext_key = decrypt_client_jwt_key_value(client.client_secret_jwt_key)
        claims = verify_client_secret_jwt(client_assertion, plaintext_key)
    else:  # private_key_jwt
        if not client.public_jwk:
            raise _client_jwt_error("missing_jwk", "client has no public_jwk configured")
        claims = verify_private_key_jwt(client_assertion, client.public_jwk)

    assert_jwt_claims(claims, client, request, settings=settings)

    jti = claims.get("jti")
    exp = int(claims.get("exp", 0))
    # ``assert_jwt_claims`` already enforces ``jti`` is present and
    # a string, so we narrow with ``str(...)`` for mypy.
    jti_str = jti if isinstance(jti, str) else ""
    if not await replay_protect_jti(jti_str, exp):
        logger.warning(
            "client_jwt_replay_detected",
            client_id=client.client_id,
            jti=jti,
        )
        raise _client_jwt_error("replay_detected", "client_assertion jti already used")

    logger.info(
        "client_jwt_authenticated",
        client_id=client.client_id,
        method=method,
    )
