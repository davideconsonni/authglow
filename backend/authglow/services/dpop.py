"""DPoP (Demonstration of Proof-of-Possession) — RFC 9449.

DPoP binds an access token to a client's key pair, so a stolen
bearer token alone is insufficient to call the resource server.
The client signs a small JWT ("DPoP proof") with its private key
on every request to the token endpoint and on every protected API
call. The server verifies the proof using the public key
embedded in the proof itself (``jwk`` header).

This module implements the verifier side only. The public surface
is intentionally small:

- :func:`compute_jkt` — JWK SHA-256 thumbprint (RFC 7638).
  Used to fill the ``cnf.jkt`` claim of bound access tokens.
- :func:`verify_dpop_proof` — full verification (signature, claims,
  replay) of a DPoP proof JWT.
- :func:`extract_dpop_proof` — header parser.
- :func:`build_cnf_claim` — convenience wrapper for the
  ``cnf`` claim structure.
- :func:`replay_protect_dpop_jti` — single-use enforcement
  via the in-process :data:`authglow.core.cache.jti_cache`.

ES256 (ECDSA P-256) is the only accepted algorithm — required by
FAPI 2.0 §5.2.2 and the OAuth 2.0 Security BCP.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from typing import Any, Dict, Optional

import jwt
import structlog
from fastapi import HTTPException, Request, status
from jwt.algorithms import ECAlgorithm

from authglow.core.cache import jti_cache

logger = structlog.get_logger("authglow.audit")

# DPoP proof HTTP header (RFC 9449 §8.1).
DPOP_HEADER = "DPoP"

# Only ES256 is supported — see module docstring.
_ALLOWED_DPOP_ALG = "ES256"

# Lifetime bounds (RFC 9449 §4.2 — DPoP proofs are short-lived).
_LEEWAY_SECONDS = 60
_MAX_PROOF_LIFETIME = 120


# ---------------------------------------------------------------------------
# JWK thumbprint (RFC 7638)
# ---------------------------------------------------------------------------


def _canonical_jwk(jwk: Dict[str, Any]) -> bytes:
    """Produce the canonical JWK JSON form required by RFC 7638.

    Members are sorted alphabetically and only the required
    members for the key type are kept (``kty``, ``crv``, ``x``,
    ``y`` for EC).
    """
    if jwk.get("kty") != "EC":
        raise ValueError(f"compute_jkt only supports EC keys for DPoP, got kty={jwk.get('kty')!r}")
    required = {"crv", "x", "y"}
    members = sorted((k, v) for k, v in jwk.items() if k == "kty" or k in required)
    return json.dumps(members, separators=(",", ":"), sort_keys=False).encode()


def compute_jkt(jwk: Dict[str, Any]) -> str:
    """Return the base64url(SHA-256) thumbprint of an EC public JWK.

    The thumbprint is the value used in the ``cnf.jkt`` claim to
    bind a token to a specific key.
    """
    canonical = _canonical_jwk(jwk)
    digest = hashlib.sha256(canonical).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------


def extract_dpop_proof(request: Request) -> Optional[str]:
    """Return the raw ``DPoP`` proof JWT from the request, or ``None``.

    The DPoP proof travels in the dedicated ``DPoP`` header. Per
    RFC 9449 §8.1 it is the proof JWT itself (not the access
    token) — the access token is in ``Authorization: DPoP <at>``.
    """
    header = request.headers.get(DPOP_HEADER)
    if not header:
        return None
    return header.strip() or None


# ---------------------------------------------------------------------------
# cnf claim
# ---------------------------------------------------------------------------


def build_cnf_claim(jwk: Dict[str, Any]) -> Dict[str, str]:
    """Build the ``cnf`` claim for a DPoP-bound access token.

    Returns ``{"jkt": "<thumbprint>"}``. The thumbprint is computed
    from the client's public key. The client must present a DPoP
    proof signed with the matching private key on every API call.
    """
    return {"jkt": compute_jkt(jwk)}


# ---------------------------------------------------------------------------
# Replay protection
# ---------------------------------------------------------------------------


def replay_protect_dpop_jti(jti: str, ttl: int) -> bool:
    """Record a DPoP proof ``jti`` and reject replays.

    Returns ``True`` if the ``jti`` was unseen (proceed) and
    ``False`` if the same ``jti`` has already been used in the
    cache window (caller MUST reject). The cache is the
    :data:`authglow.core.cache.jti_cache` singleton, keyed under
    the ``dpop:`` namespace so it does not collide with the
    client_assertion JTI cache.
    """
    if not jti:
        return True
    key = f"dpop:{jti}"
    if key in jti_cache:
        return False
    jti_cache[key] = time.time() + max(1, ttl)
    return True


# ---------------------------------------------------------------------------
# Proof verification
# ---------------------------------------------------------------------------


def _dpop_error(code: str, description: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail={
            "error": "invalid_dpop_proof",
            "error_description": description,
            "error_code": code,
        },
        headers={"WWW-Authenticate": 'DPoP error="invalid_dpop_proof"'},
    )


def _public_key_from_jwk(jwk: Dict[str, Any]) -> Any:
    """Convert an EC JWK dict into a ``cryptography`` public key.

    Raises :class:`ValueError` if the JWK is malformed or not EC.
    """
    if not isinstance(jwk, dict):
        raise ValueError("DPoP proof jwk header must be a dict")
    if jwk.get("kty") != "EC":
        raise ValueError("DPoP proof jwk.kty must be 'EC' (ES256)")
    if jwk.get("crv") != "P-256":
        raise ValueError("DPoP proof jwk.crv must be 'P-256' (ES256)")
    try:
        return ECAlgorithm.from_jwk(jwk)
    except Exception as exc:  # PyJWT internal errors
        raise ValueError(f"failed to parse DPoP jwk: {exc}") from exc


def verify_dpop_proof(
    proof_jwt: str,
    *,
    expected_htm: str,
    expected_htu: str,
    access_token: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify a DPoP proof JWT.

    Parameters
    ----------
    proof_jwt
        The raw JWT string from the ``DPoP`` header.
    expected_htm
        The HTTP method the proof must declare (e.g. ``"POST"``).
    expected_htu
        The full URL the proof must declare.
    access_token
        When provided, the proof must include a matching ``ath``
        claim (the base64url SHA-256 of the access token). Used on
        the resource server to bind the proof to the token.

    Returns the decoded claims on success. Raises
    :class:`HTTPException(401)` on any verification failure.
    """
    if not proof_jwt:
        raise _dpop_error("missing_proof", "DPoP proof is required")

    # We pass ``verify_aud=False`` and enforce the URL claim
    # ourselves — RFC 9449 uses ``htu`` for the URL, not ``aud``.
    try:
        unverified_header = jwt.get_unverified_header(proof_jwt)
    except jwt.InvalidTokenError as exc:
        raise _dpop_error("invalid_token", f"malformed DPoP proof: {exc}") from exc

    alg = unverified_header.get("alg")
    if alg != _ALLOWED_DPOP_ALG:
        raise _dpop_error(
            "invalid_algorithm",
            f"DPoP proof alg must be {_ALLOWED_DPOP_ALG!r}, got {alg!r}",
        )
    jwk_header = unverified_header.get("jwk")
    if not jwk_header:
        raise _dpop_error("missing_jwk", "DPoP proof must carry a 'jwk' header")
    try:
        public_key = _public_key_from_jwk(jwk_header)
    except ValueError as exc:
        raise _dpop_error("invalid_jwk", str(exc))

    try:
        claims = jwt.decode(
            proof_jwt,
            key=public_key,
            algorithms=[_ALLOWED_DPOP_ALG],
            options={
                "require": ["htm", "htu", "iat", "jti"],
                "verify_aud": False,
                "verify_exp": False,  # DPoP proofs use iat-only lifetime
                "verify_iat": False,  # DPoP proofs have a short
                # lifetime window enforced manually below — PyJWT's
                # default ``verify_iat`` is too strict for the
                # DPoP use case (RFC 9449 §4.2 leeway is up to the
                # verifier).
            },
        )
    except jwt.InvalidAlgorithmError as exc:
        raise _dpop_error("invalid_algorithm", str(exc)) from exc
    except jwt.InvalidTokenError as exc:
        raise _dpop_error("invalid_token", str(exc)) from exc

    # Claim validation
    htm = claims.get("htm")
    htu = claims.get("htu")
    iat = claims.get("iat")
    jti = claims.get("jti")

    if htm != expected_htm:
        raise _dpop_error(
            "htm_mismatch",
            f"DPoP proof htm must be {expected_htm!r}, got {htm!r}",
        )
    if htu != expected_htu:
        raise _dpop_error(
            "htu_mismatch",
            f"DPoP proof htu must be {expected_htu!r}, got {htu!r}",
        )
    if not iat:
        raise _dpop_error("missing_iat", "DPoP proof must include iat")
    now = int(time.time())
    if int(iat) > now + _LEEWAY_SECONDS:
        raise _dpop_error("iat_in_future", "DPoP proof iat is in the future")
    if now - int(iat) > _MAX_PROOF_LIFETIME + _LEEWAY_SECONDS:
        raise _dpop_error(
            "expired",
            f"DPoP proof iat older than {_MAX_PROOF_LIFETIME}s",
        )
    if not jti:
        raise _dpop_error("missing_jti", "DPoP proof must include jti")

    # When an access_token is supplied, verify the ``ath`` claim
    # binds the proof to the token (RFC 9449 §4.2 / §6.1).
    if access_token is not None:
        expected_ath = (
            base64.urlsafe_b64encode(hashlib.sha256(access_token.encode("ascii")).digest())
            .rstrip(b"=")
            .decode("ascii")
        )
        ath = claims.get("ath")
        if ath != expected_ath:
            raise _dpop_error(
                "ath_mismatch",
                "DPoP proof ath does not match the access token",
            )

    # Replay protection: a single jti may be used at most once
    # within the proof's lifetime.
    remaining_ttl = max(1, int(iat) + _MAX_PROOF_LIFETIME - now)
    if not replay_protect_dpop_jti(str(jti), remaining_ttl):
        logger.warning(
            "dpop_proof_replay_detected",
            jti=jti,
        )
        raise _dpop_error("replay_detected", "DPoP proof jti already used")

    return claims
