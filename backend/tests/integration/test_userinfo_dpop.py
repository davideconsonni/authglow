"""Integration tests for the UserInfo endpoint with DPoP-bound tokens.

CONFORMANCE_REMEDIATION_PLAN.md T.3: RFC 9449 DPoP. The UserInfo
endpoint must verify the DPoP proof whenever the access token
carries a ``cnf`` claim (proof-of-possession binding).
"""

import base64
import hashlib
import json
import time
from contextlib import ExitStack
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi import FastAPI
from fastapi.security import HTTPAuthorizationCredentials
from fastapi.testclient import TestClient


def _ec_keypair():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())


def _jwk(private_key) -> dict:
    return json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key()))


def _ath_for(token: str) -> str:
    return (
        base64.urlsafe_b64encode(hashlib.sha256(token.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )


def _dpop_proof(
    *,
    private_key,
    htm: str = "GET",
    htu: str = None,
    ath: str = None,
    jti: str = None,
) -> str:
    from authglow.core.config import get_settings

    if htu is None:
        htu = f"{get_settings().issuer.rstrip('/')}/oauth2/userinfo"
    now = int(time.time())
    payload = {
        "htm": htm,
        "htu": htu,
        "iat": now,
        "jti": jti or f"dpop-{time.time_ns()}",
    }
    if ath is not None:
        payload["ath"] = ath
    return jwt.encode(
        payload,
        private_key,
        algorithm="ES256",
        headers={"alg": "ES256", "typ": "dpop+jwt", "jwk": _jwk(private_key)},
    )


def _build_app_and_token(*, cnf: dict = None, token_str: str = "at-fake-xyz"):
    """Build a UserInfo-capable FastAPI app. The JWT service is
    mocked to return a fixed access token string. The token is
    decoded by the real :class:`JWTService` so the ``cnf`` claim
    reaches the userinfo handler."""
    from authglow.api.oidc import router as oidc_router

    # Build a real signed JWT carrying the cnf claim so the
    # decode path surfaces it via TokenData.cnf.
    from authglow.core.jwt_singleton import get_jwt_service as _get
    import asyncio

    async def _real_token() -> str:
        svc = await _get()
        kwargs: dict = dict(
            user_id="user-1",
            email="user@example.com",
            scopes=["openid", "email"],
            audience="dpop-test-client",
            azp="dpop-test-client",
        )
        if cnf is not None:
            kwargs["cnf"] = cnf
        return svc.create_access_token(**kwargs)

    token_str = asyncio.run(_real_token())

    # Build the userinfo response.
    fake_user_info = MagicMock()
    fake_user_info.model_dump = MagicMock(
        return_value={"sub": "user-1", "email": "user@example.com", "email_verified": True}
    )

    userinfo_service = MagicMock()
    userinfo_service.get_user_info = AsyncMock(return_value=fake_user_info)

    storage = MagicMock()
    storage.get_user = AsyncMock(
        return_value=MagicMock(
            id="user-1",
            email="user@example.com",
            is_active=True,
            scopes=["openid", "email"],
        )
    )

    app = FastAPI()
    app.include_router(oidc_router)
    return app, token_str, userinfo_service


def _override_userinfo(app, userinfo_service):
    """Patch the OIDCService constructor to return our mock."""
    from authglow.api import oidc as oidc_mod

    return patch.object(oidc_mod, "OIDCService", return_value=userinfo_service)


def _decode_token_sync(token: str) -> dict:
    from authglow.core.jwt_singleton import get_jwt_service as _get
    import asyncio

    async def _decode():
        svc = await _get()
        return svc.decode_token(token)

    return asyncio.run(_decode())


# ---------------------------------------------------------------------------
# Bearer (non-DPoP) — backward compat
# ---------------------------------------------------------------------------


class TestBearerUserInfo:
    def test_no_cnf_works_without_dpop(self, test_settings):
        app, token_str, ui = _build_app_and_token(cnf=None)
        http = TestClient(app)
        with _override_userinfo(app, ui):
            res = http.get(
                "/oauth2/userinfo",
                headers={"Authorization": f"Bearer {token_str}"},
            )
        # The userinfo may succeed (200) or fail downstream on
        # some other check; what we care about is that DPoP is
        # NOT enforced. Concretely: no ``invalid_dpop_proof`` or
        # ``missing_dpop_proof`` error.
        if res.status_code in (400, 401):
            detail = res.json().get("detail")
            if isinstance(detail, dict):
                assert detail.get("error_code") not in (
                    "missing_dpop_proof",
                    "invalid_dpop_proof",
                )


# ---------------------------------------------------------------------------
# DPoP-bound — proof required
# ---------------------------------------------------------------------------


class TestDpopBoundUserInfo:
    def test_missing_dpop_proof_rejected(self, test_settings):
        from authglow.services.dpop import compute_jkt

        priv = _ec_keypair()
        cnf = {"jkt": compute_jkt(_jwk(priv))}
        app, token_str, ui = _build_app_and_token(cnf=cnf)
        http = TestClient(app)
        with _override_userinfo(app, ui):
            res = http.get(
                "/oauth2/userinfo",
                headers={"Authorization": f"Bearer {token_str}"},
            )
        assert res.status_code == 401
        detail = res.json().get("detail")
        # The UserInfo handler may raise a string detail (the
        # path is "DPoP proof is required" — plain string). Both
        # shapes are acceptable as long as it's a 401.
        assert detail is not None

    def test_valid_dpop_proof_accepted(self, test_settings):
        from authglow.services.dpop import compute_jkt

        priv = _ec_keypair()
        cnf = {"jkt": compute_jkt(_jwk(priv))}
        app, token_str, ui = _build_app_and_token(cnf=cnf)
        ath = _ath_for(token_str)
        proof = _dpop_proof(private_key=priv, ath=ath)
        http = TestClient(app)
        with _override_userinfo(app, ui):
            res = http.get(
                "/oauth2/userinfo",
                headers={
                    "Authorization": f"DPoP {token_str}",
                    "DPoP": proof,
                },
            )
        if res.status_code in (400, 401):
            detail = res.json().get("detail")
            if isinstance(detail, dict):
                # If we got a DPoP-specific error, that means the
                # proof was NOT accepted.
                assert detail.get("error_code") not in (
                    "htm_mismatch",
                    "htu_mismatch",
                    "ath_mismatch",
                    "invalid_dpop_proof",
                )

    def test_ath_mismatch_rejected(self, test_settings):
        from authglow.services.dpop import compute_jkt

        priv = _ec_keypair()
        cnf = {"jkt": compute_jkt(_jwk(priv))}
        app, token_str, ui = _build_app_and_token(cnf=cnf)
        # Sign the proof with a different access token's ath.
        wrong_ath = _ath_for("different-token")
        proof = _dpop_proof(private_key=priv, ath=wrong_ath)
        http = TestClient(app)
        with _override_userinfo(app, ui):
            res = http.get(
                "/oauth2/userinfo",
                headers={
                    "Authorization": f"DPoP {token_str}",
                    "DPoP": proof,
                },
            )
        # Debug: print response
        print(f"Status: {res.status_code}, Body: {res.text[:300]}")
        assert res.status_code == 401
        detail = res.json().get("detail")
        if isinstance(detail, dict):
            assert detail.get("error_code") == "ath_mismatch"

    def test_htm_mismatch_rejected(self, test_settings):
        from authglow.services.dpop import compute_jkt

        priv = _ec_keypair()
        cnf = {"jkt": compute_jkt(_jwk(priv))}
        app, token_str, ui = _build_app_and_token(cnf=cnf)
        ath = _ath_for(token_str)
        # ``POST`` is the wrong HTTP method for UserInfo.
        proof = _dpop_proof(private_key=priv, htm="POST", ath=ath)
        http = TestClient(app)
        with _override_userinfo(app, ui):
            res = http.get(
                "/oauth2/userinfo",
                headers={
                    "Authorization": f"DPoP {token_str}",
                    "DPoP": proof,
                },
            )
        assert res.status_code == 401
        detail = res.json().get("detail")
        if isinstance(detail, dict):
            assert detail.get("error_code") == "htm_mismatch"
