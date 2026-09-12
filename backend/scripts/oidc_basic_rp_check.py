"""Black-box OIDC Basic RP conformance probe (OA-401).

Acts as a generic third-party Relying Party using only the public
protocol surface (discovery document + standard OAuth2/OIDC requests).
Uses no AuthGlow code — plain ``httpx`` + ``PyJWT`` — so it catches
wire-format deviations the in-repo suite cannot see by construction.

Usage:
    python backend/scripts/oidc_basic_rp_check.py [BASE_URL] [REPORT_MD]

Defaults: ``http://127.0.0.1:8001`` (backend demo mode). The demo
password is read at runtime from ``GET /api/meta`` (rotates per boot,
never hardcoded). Exit code = number of failed checks. Prints a
Markdown report to stdout (redirect it to the report file).

OA-401: every failed MUST is mapped to a plan item in the report.
"""

import base64
import hashlib
import secrets
import sys
import urllib.parse

import httpx
import jwt as pyjwt

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8001"
RESULTS: list = []

try:
    # Windows consoles default to cp1252 — the report uses →/§.
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:  # noqa: BLE001
    pass


def check(name: str, cond: bool, evidence: str = "", must: str = "") -> None:
    """Record one conformance check."""
    RESULTS.append({"name": name, "ok": bool(cond), "evidence": evidence, "must": must})


def _pkce() -> tuple:
    verifier = secrets.token_urlsafe(32)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def _half_hash(value: str) -> str:
    digest = hashlib.sha256(value.encode()).digest()
    return base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()


def _post_with_csrf(client: httpx.Client, url: str, data: dict) -> httpx.Response:
    """POST like a browser: on CSRF 403 fetch a token and retry once."""
    res = client.post(url, data=data)
    if res.status_code == 403 and "CSRF" in res.text:
        token = client.get("/api/oauth2/csrf-token").json()["csrf_token"]
        res = client.post(url, data=data, headers={"X-CSRF-Token": token})
    return res


def authorize_round(client: httpx.Client, reg: dict, email: str, password: str) -> dict:
    """Login + consent (if needed) → redirect params dict."""
    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = _pkce()
    res = _post_with_csrf(
        client,
        f"{BASE}/api/oauth2/authorize",
        data={
            "client_id": reg["client_id"],
            "redirect_uri": reg["redirect_uri"],
            "response_type": "code",
            "scope": "openid profile email offline_access",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "nonce": nonce,
            "email": email,
            "password": password,
        },
    )
    if res.status_code == 302:
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(res.headers["location"]).query))
        return {"params": params, "state": state, "nonce": nonce, "verifier": verifier}
    body = res.json()
    if isinstance(body, dict) and body.get("consent_required"):
        cres = _post_with_csrf(
            client,
            f"{BASE}/oauth2/consent",
            data={"session_token": body["session_token"], "approved": "true"},
        )
        cbody = cres.json()
        params = dict(
            urllib.parse.parse_qsl(urllib.parse.urlparse(cbody["redirect_url"]).query)
        )
        return {"params": params, "state": state, "nonce": nonce, "verifier": verifier}
    if isinstance(body, dict) and body.get("redirect_url"):
        params = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(body["redirect_url"]).query))
        return {"params": params, "state": state, "nonce": nonce, "verifier": verifier}
    raise AssertionError(f"authorize round failed: {res.status_code} {res.text[:300]}")


def main() -> int:
    client = httpx.Client(base_url=BASE, timeout=20.0)

    # 0. Demo credentials (rotated per boot, read at runtime).
    meta = client.get("/api/meta").json()
    email = meta.get("demo_user_email", "admin@example.com")
    password = meta.get("demo_user_password", "")
    check("demo meta exposes credentials", bool(password), "GET /api/meta", "env")

    # 1. Discovery document.
    disc = client.get("/.well-known/openid-configuration").json()
    for field in (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "registration_endpoint",
        "revocation_endpoint",
        "introspection_endpoint",
        "end_session_endpoint",
    ):
        check(f"discovery has {field}", bool(disc.get(field)), str(disc.get(field))[:80], "OIDC Discovery §3")
    check(
        "discovery response_types code-only",
        disc.get("response_types_supported") == ["code"],
        str(disc.get("response_types_supported")),
        "OA-202/A8",
    )
    check(
        "discovery response_modes query-only",
        disc.get("response_modes_supported") == ["query"],
        str(disc.get("response_modes_supported")),
        "OA-202",
    )
    check(
        "discovery PKCE S256-only",
        disc.get("code_challenge_methods_supported") == ["S256"],
        str(disc.get("code_challenge_methods_supported")),
        "RFC 7636",
    )
    check(
        "discovery no implicit grant",
        "implicit" not in str(disc.get("grant_types_supported", [])),
        str(disc.get("grant_types_supported")),
        "BCP",
    )
    issuer = disc["issuer"]

    # 2. JWKS.
    jwks = client.get(disc["jwks_uri"].replace(issuer, "") or "/.well-known/jwks.json").json()
    keys = jwks.get("keys", [])
    check("jwks non-empty RSA sig keys", bool(keys) and keys[0].get("kty") == "RSA", f"{len(keys)} keys", "OIDC Discovery §3")
    jwk = keys[0]
    pubkey = pyjwt.algorithms.RSAAlgorithm.from_jwk(__import__("json").dumps(jwk))

    # 3. Dynamic Client Registration.
    reg_res = client.post(
        "/oauth2/register",
        json={
            "redirect_uris": ["http://localhost:9999/cb"],
            "client_name": "OA-401 Basic Probe",
            "scope": "openid profile email offline_access",
            "grant_types": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_method": "client_secret_basic",
        },
    )
    check("DCR registers (201)", reg_res.status_code == 201, f"{reg_res.status_code}", "RFC 7591 §3")
    reg = reg_res.json()
    reg["redirect_uri"] = "http://localhost:9999/cb"
    check("DCR returns client credentials", bool(reg.get("client_id") and reg.get("client_secret")), "client_id present", "RFC 7591 §3")
    basic = (reg["client_id"], reg["client_secret"])

    # 4-5. Authorize round → code + state echo + iss (RFC 9207).
    rnd = authorize_round(client, reg, email, password)
    params = rnd["params"]
    check("authorize yields code", bool(params.get("code")), "code present", "RFC 6749 §4.1.2")
    check("authorize echoes state intact", params.get("state") == rnd["state"], "state ok", "RFC 6749 §4.1.2")
    check("authorize response carries iss", params.get("iss") == issuer, str(params.get("iss")), "RFC 9207 §2")
    code = params["code"]

    # 6. Code exchange (Basic auth, PKCE).
    tok = client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": reg["redirect_uri"],
            "code_verifier": rnd["verifier"],
        },
        auth=basic,
    ).json()
    check(
        "token exchange yields access/refresh/id_token",
        bool(tok.get("access_token") and tok.get("refresh_token") and tok.get("id_token")),
        f"token_type={tok.get('token_type')}",
        "RFC 6749 §4.1.4",
    )

    # 7. ID token verification (signature + claims).
    try:
        claims = pyjwt.decode(tok["id_token"], pubkey, algorithms=["RS256"], audience=reg["client_id"], issuer=issuer)
        sig_ok = True
    except Exception as exc:  # noqa: BLE001
        claims, sig_ok = {}, f"decode failed: {exc}"
    check("id_token signature + iss/aud/exp", sig_ok is True, str(sig_ok) if sig_ok is not True else "ok", "OIDC Core §3.1.3")
    if sig_ok is True:
        check("id_token nonce echoed", claims.get("nonce") == rnd["nonce"], "nonce ok", "OIDC Core §3.1.3.6")
        check("id_token at_hash binds access token", claims.get("at_hash") == _half_hash(tok["access_token"]), str(claims.get("at_hash")), "OIDC Core §3.1.3.6")
        check("id_token c_hash binds code", claims.get("c_hash") == _half_hash(code), str(claims.get("c_hash")), "OA-303")
        check("id_token sid present", bool(claims.get("sid")) and len(claims["sid"]) == 32, str(claims.get("sid")), "OA-204")
        sub = claims.get("sub")
    else:
        sub = None

    # 8. UserInfo.
    ui = client.get("/oauth2/userinfo", headers={"Authorization": f"Bearer {tok['access_token']}"})
    check("userinfo 200 + sub match", ui.status_code == 200 and ui.json().get("sub") == sub, f"{ui.status_code}", "OIDC Core §5.3")

    # 9. Refresh rotation.
    ref = client.post(
        "/oauth2/token",
        data={"grant_type": "refresh_token", "refresh_token": tok["refresh_token"]},
        auth=basic,
    ).json()
    check(
        "refresh rotates to new tokens",
        bool(ref.get("access_token")) and ref.get("refresh_token") != tok["refresh_token"],
        "rotated",
        "RFC 6749 §6 / OA-105",
    )

    # 10. Introspect active, revoke, introspect inactive.
    ina = client.post("/oauth2/introspect", data={"token": ref["access_token"]}, auth=basic).json()
    check("introspect active token", ina.get("active") is True, str(ina.get("active")), "RFC 7662")
    rev = client.post("/oauth2/revoke", data={"token": ref["refresh_token"]}, auth=basic)
    check("revoke returns 200", rev.status_code == 200, f"{rev.status_code}", "RFC 7009")
    inb = client.post("/oauth2/introspect", data={"token": ref["refresh_token"]}, auth=basic).json()
    check("introspect revoked token inactive", inb.get("active") is False, str(inb.get("active")), "RFC 7662 / OA-104")

    # 11. Logout kills the session (POST, bearer).
    lout = client.post("/oauth2/logout", headers={"Authorization": f"Bearer {ref['access_token']}"})
    ui2 = client.get("/oauth2/userinfo", headers={"Authorization": f"Bearer {ref['access_token']}"})
    check("logout → userinfo 401", lout.status_code == 200 and ui2.status_code == 401, f"{lout.status_code}/{ui2.status_code}", "OA-102")

    # 12. Negatives (fresh code for the verifier probe).
    rnd2 = authorize_round(client, reg, email, password)
    bad = client.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": rnd2["params"]["code"],
            "redirect_uri": reg["redirect_uri"],
            "code_verifier": "wrong-verifier",
        },
        auth=basic,
    )
    check(
        "wrong verifier → 400 invalid_grant",
        bad.status_code == 400 and bad.json().get("error") == "invalid_grant",
        f"{bad.status_code} {bad.text[:80]}",
        "OA-302",
    )
    evil = _post_with_csrf(
        client,
        f"{BASE}/api/oauth2/authorize",
        data={
            "client_id": reg["client_id"],
            "redirect_uri": "https://evil.example.com/cb",
            "scope": "openid",
            "state": secrets.token_urlsafe(32),
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
            "email": email,
            "password": password,
        },
    )
    check("evil redirect_uri rejected", evil.status_code == 400, f"{evil.status_code}", "RFC 6749 §3.1.2")
    # NOTE: httpx needs follow_redirects=False here; _post_with_csrf
    # follows the csrf-token GET only, never the authorize redirect.
    # With session cookies present the CSRF middleware fires before
    # validation, so attach a token explicitly.
    csrf = client.get("/api/oauth2/csrf-token").json()["csrf_token"]
    impl_client = httpx.Client(base_url=BASE, timeout=20.0, cookies=client.cookies)
    impl = impl_client.post(
        f"{BASE}/api/oauth2/authorize",
        headers={"X-CSRF-Token": csrf},
        data={
            "client_id": reg["client_id"],
            "redirect_uri": reg["redirect_uri"],
            "response_type": "token",
            "scope": "openid",
            "state": secrets.token_urlsafe(32),
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
            "email": email,
            "password": password,
        },
        follow_redirects=False,
    )
    loc = impl.headers.get("location", "")
    check(
        "implicit response_type refused via redirect",
        impl.status_code == 302 and "unsupported_response_type" in loc,
        f"{impl.status_code}",
        "BCP / OA-201",
    )

    # Report.
    failed = [r for r in RESULTS if not r["ok"]]
    lines = []
    lines.append("# OA-401 OIDC Basic RP report")
    lines.append("")
    lines.append(
        "Self-made Basic profile probe (not an OpenID Foundation "
        "certification run): a generic third-party RP speaking only the "
        "public protocol surface. Backend demo mode, credentials read "
        f"at runtime from `/api/meta`. Base: `{BASE}`."
    )
    lines.append("")
    lines.append(f"{len(RESULTS) - len(failed)}/{len(RESULTS)} checks passed")
    lines.append("")
    lines.append("| Check | Result | Evidence | MUST/Item |")
    lines.append("|---|---|---|---|")
    for r in RESULTS:
        lines.append(f"| {r['name']} | {'PASS' if r['ok'] else 'FAIL'} | {r['evidence']} | {r['must']} |")
    lines.append("")
    if failed:
        lines.append("## Failed MUST → plan items")
        for r in failed:
            lines.append(f"- {r['name']} ({r['must']}): {r['evidence']}")
    else:
        lines.append("No failures — nothing to map to new plan items.")
    report = "\n".join(lines) + "\n"
    print(report)
    if len(sys.argv) > 2:
        with open(sys.argv[2], "w", encoding="utf-8") as fh:
            fh.write(report)
    return len(failed)


if __name__ == "__main__":
    sys.exit(main())
