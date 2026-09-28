"""Group: OAuth2 / OpenID Connect protocol surface."""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Optional

import jwt as pyjwt

from checktool.registry import Group, GroupContext, register_group

REDIRECT_URI = "http://localhost:9999/callback"


def _half_hash(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()


@register_group
class OAuth2Group(Group):
    slug = "oauth2"
    title = "OAuth2 / OIDC protocol"
    description = "Discovery, JWKS, DCR, authorization code + PKCE, ID token, refresh, introspect, revoke, client credentials."
    requires_admin = True

    def run(self, ctx: GroupContext) -> None:
        client_id: Optional[str] = None
        client_secret: Optional[str] = None
        try:
            admin_email = ctx.admin_email
            admin_password = ctx.admin_password
            if not admin_email or not admin_password:
                ctx.skip("OAuth2 end-to-end flow", "no admin credentials available for login")
                return

            # --- discovery -------------------------------------------------
            disc_resp = ctx.request(
                "The OIDC discovery document is published", "GET", "/.well-known/openid-configuration"
            )
            disc = ctx.json(disc_resp)
            required = (
                "issuer",
                "authorization_endpoint",
                "token_endpoint",
                "userinfo_endpoint",
                "jwks_uri",
                "registration_endpoint",
                "revocation_endpoint",
                "introspection_endpoint",
            )
            missing = [f for f in required if not disc.get(f)]
            ctx.check(
                "Discovery advertises every required endpoint",
                disc_resp.status_code == 200 and not missing,
                f"missing: {missing}" if missing else ctx.evidence(disc_resp),
            )
            ctx.check(
                "Discovery is authorization-code + PKCE S256, no implicit",
                disc.get("response_types_supported") == ["code"]
                and disc.get("code_challenge_methods_supported") == ["S256"]
                and "implicit" not in str(disc.get("grant_types_supported", [])),
                str(disc.get("response_types_supported")),
            )
            issuer = disc.get("issuer", "")

            # --- jwks ------------------------------------------------------
            jwks_resp = ctx.request("Public signing keys are published", "GET", "/.well-known/jwks.json")
            jwks = ctx.json(jwks_resp)
            keys = jwks.get("keys", []) if isinstance(jwks, dict) else []
            ctx.check(
                "JWKS exposes at least one RSA signing key",
                jwks_resp.status_code == 200 and bool(keys) and keys[0].get("kty") == "RSA",
                ctx.evidence(jwks_resp),
            )
            public_key = (
                pyjwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(keys[0])) if keys else None
            )

            # --- dynamic client registration ------------------------------
            reg_resp = ctx.request(
                "A third-party client registers itself (RFC 7591)",
                "POST",
                "/oauth2/register",
                json={
                    "redirect_uris": [REDIRECT_URI],
                    "client_name": f"{ctx.config.namespace} probe",
                    "scope": "openid profile email offline_access read",
                    "grant_types": ["authorization_code", "refresh_token", "client_credentials"],
                    "token_endpoint_auth_method": "client_secret_basic",
                },
            )
            reg = ctx.json(reg_resp)
            client_id = reg.get("client_id")
            client_secret = reg.get("client_secret")
            ctx.check(
                "Dynamic registration returns client credentials",
                reg_resp.status_code == 201 and bool(client_id and client_secret),
                ctx.evidence(reg_resp),
            )
            if not client_id or not client_secret:
                return
            basic = (client_id, client_secret)

            # --- authorization code + PKCE --------------------------------
            state = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(32)
            rnd = ctx.api.authorize_code(
                email=admin_email,
                password=admin_password,
                client_id=client_id,
                redirect_uri=REDIRECT_URI,
                nonce=nonce,
                state=state,
            )
            code = rnd.get("code")
            ctx.check("Authorize returns an authorization code", bool(code), str(rnd))
            ctx.check(
                "Authorize echoes the state parameter intact",
                rnd.get("state") == state,
                str(rnd.get("state")),
            )
            ctx.check(
                "Authorize response carries the iss parameter (RFC 9207)",
                rnd.get("iss") == issuer,
                str(rnd.get("iss")),
            )
            if not code:
                return

            bundle, tok_resp = ctx.api.exchange_code(
                code=code,
                verifier=rnd["verifier"],
                client_id=client_id,
                redirect_uri=REDIRECT_URI,
                auth=basic,
            )
            ctx.check(
                "Code exchange yields access, refresh and ID tokens",
                bool(bundle.access_token and bundle.refresh_token and bundle.id_token),
                ctx.evidence(tok_resp),
            )

            wrong = ctx.api.post(
                "/oauth2/token",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": REDIRECT_URI,
                    "code_verifier": "wrong-verifier",
                    "client_id": client_id,
                },
                auth=basic,
            )
            ctx.check(
                "Re-using the code with a wrong verifier fails (400 invalid_grant)",
                wrong.status_code == 400 and ctx.json(wrong).get("error") == "invalid_grant",
                ctx.evidence(wrong),
            )

            # --- ID token verification ------------------------------------
            if bundle.id_token and public_key is not None:
                try:
                    claims = pyjwt.decode(
                        bundle.id_token,
                        public_key,  # type: ignore[arg-type]
                        algorithms=["RS256"],
                        audience=client_id,
                        issuer=issuer,
                    )
                    ctx.check("ID token signature and standard claims verify", True)
                    ctx.check(
                        "ID token echoes the nonce",
                        claims.get("nonce") == nonce,
                        str(claims.get("nonce")),
                    )
                    ctx.check(
                        "ID token at_hash binds the access token",
                        claims.get("at_hash") == _half_hash(bundle.access_token),
                        str(claims.get("at_hash")),
                    )
                    ctx.check(
                        "ID token c_hash binds the authorization code",
                        claims.get("c_hash") == _half_hash(code),
                        str(claims.get("c_hash")),
                    )
                except Exception as exc:  # noqa: BLE001
                    ctx.check("ID token signature and standard claims verify", False, str(exc))

            # --- userinfo --------------------------------------------------
            ui = ctx.api.get(
                "/oauth2/userinfo",
                headers={"Authorization": f"Bearer {bundle.access_token}"},
                use_bearer=False,
            )
            ctx.check(
                "UserInfo accepts the access token",
                ui.status_code == 200 and bool(ctx.json(ui).get("sub")),
                ctx.evidence(ui),
            )

            # --- refresh rotation -----------------------------------------
            if bundle.refresh_token:
                refreshed, rresp = ctx.api.refresh_token(bundle.refresh_token, client_id, auth=basic)
                ctx.check(
                    "Refresh rotates to new tokens",
                    bool(refreshed.access_token) and refreshed.refresh_token != bundle.refresh_token,
                    ctx.evidence(rresp),
                )
            else:
                ctx.check("Authorization code flow issued a refresh token", False, "no refresh_token")

            # --- introspect / revoke --------------------------------------
            active = ctx.api.post("/oauth2/introspect", data={"token": bundle.access_token}, auth=basic)
            ctx.check(
                "Introspection reports the access token active",
                ctx.json(active).get("active") is True,
                ctx.evidence(active),
            )
            if bundle.refresh_token:
                ctx.api.post("/oauth2/revoke", data={"token": bundle.refresh_token}, auth=basic)
                inactive = ctx.api.post(
                    "/oauth2/introspect", data={"token": bundle.refresh_token}, auth=basic
                )
                ctx.check(
                    "Revoked token introspects as inactive",
                    ctx.json(inactive).get("active") is False,
                    ctx.evidence(inactive),
                )

            # --- client credentials ---------------------------------------
            cc_bundle, cc_resp = ctx.api.client_credentials(client_id, client_secret)
            ctx.check(
                "Client credentials grant yields a machine access token",
                bool(cc_bundle.access_token),
                ctx.evidence(cc_resp),
            )
        finally:
            if client_id:
                resp = ctx.api.delete(f"/api/oauth-clients/{client_id}")
                if resp.status_code not in (200, 204):
                    ctx.warn(f"could not delete test OAuth client {client_id}: HTTP {resp.status_code}")
