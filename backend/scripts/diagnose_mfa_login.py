"""Diagnose the user-reported MFA "Invalid code" failure against a RUNNING backend.

Replays EXACTLY what the browser does, but prints the REAL HTTP status
and body at every step (the frontend masks everything as
"Invalid code. Please try again.").

Usage (backend must be running, default http://localhost:8000)::

    .venv/Scripts/python scripts/diagnose_mfa_login.py \
        --email diag@example.com --password 'TestP@ss123!' \
        [--base-url http://localhost:8000] [--fresh]

--fresh: register a brand-new user and run the whole flow end to end
         (register → login → enroll → verify-enroll → login → verify-login).
Without --fresh: only steps login → verify-login for an EXISTING user
(add the TOTP secret to https://totp.app/ first).

At each "paste code" prompt, read the 6-digit code from totp.app
(or any authenticator holding the printed secret) and type it here.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import secrets
import sys
import time
from urllib.parse import parse_qs, urlparse

import httpx


def pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def show(title: str, resp: httpx.Response) -> None:
    print(f"\n--- {title} ---")
    print(f"HTTP {resp.status_code}")
    try:
        print(f"BODY: {resp.text[:2000]}")
    except Exception as exc:  # pragma: no cover
        print(f"(unreadable body: {exc})")


def authorize(
    client: httpx.Client,
    base: str,
    client_id: str,
    redirect_uri: str,
    email: str,
    password: str,
) -> dict:
    _, challenge = pkce_pair()
    state = secrets.token_urlsafe(32)
    r = client.post(
        f"{base}/api/oauth2/authorize",
        data={
            "email": email,
            "password": password,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": "read",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": state,
        },
    )
    show("POST /api/oauth2/authorize", r)
    return r.json() if r.status_code == 200 else {}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8000")
    ap.add_argument("--email", required=True)
    ap.add_argument("--password", required=True)
    ap.add_argument("--fresh", action="store_true")
    args = ap.parse_args()

    base = args.base_url.rstrip("/")
    client = httpx.Client(timeout=30.0)

    # 0. Discover the first-party client exactly like LoginForm does.
    r = client.get(f"{base}/api/auth/oidc/config")
    show("GET /api/auth/oidc/config", r)
    if r.status_code != 200:
        print("FATAL: cannot reach backend or config endpoint.")
        return 2
    cfg = r.json()
    client_id, redirect_uri = cfg["client_id"], cfg["redirect_uri"]

    if args.fresh:
        # 1. Register.
        email = f"diag{int(time.time())}@example.com"
        print(f"\nRegistering fresh user {email} ...")
        r = client.post(
            f"{base}/api/users",
            json={
                "email": email,
                "password": args.password,
                "first_name": "Diag",
                "last_name": "User",
            },
        )
        show("POST /api/users (register)", r)
        if r.status_code not in (200, 201):
            print("FATAL: registration failed.")
            return 2
    else:
        email = args.email

    # 2. Password login → expect auth-code redirect (no MFA yet, or MFA gate).
    body = authorize(client, base, client_id, redirect_uri, email, args.password)
    if body.get("mfa_required"):
        print("\nMFA gate hit on first login (user already has MFA).")
        session_token = body["session_token"]
    elif body.get("redirect_url"):
        print("\nLogin OK (no MFA gate). Proceeding to enroll.")
        session_token = None
    else:
        print("\nFATAL: unexpected authorize response — see body above.")
        return 2

    # 3. If no MFA yet: exchange code → cookie session → enroll → verify.
    secret = None
    if session_token is None:
        parsed = urlparse(body["redirect_url"])
        code = parse_qs(parsed.query).get("code", [None])[0]
        if not code:
            print("FATAL: no ?code= in redirect_url.")
            return 2
        # Fresh PKCE for the exchange is overkill here: reuse is invalid,
        # so redo authorize is simpler — instead use cookie-less token flow
        # via the session cookie the exchange would set. Simpler path:
        # re-authorize is NOT needed; enroll needs a Bearer token, so do a
        # minimal PKCE round-trip now.
        verifier, challenge = pkce_pair()
        state = secrets.token_urlsafe(32)
        r = client.post(
            f"{base}/api/oauth2/authorize",
            data={
                "email": email,
                "password": args.password,
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "response_type": "code",
                "scope": "openid profile email read offline_access",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "state": state,
            },
        )
        show("POST /api/oauth2/authorize (PKCE for token)", r)
        code = parse_qs(urlparse(r.json()["redirect_url"]).query)["code"][0]
        r = client.post(
            f"{base}/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
            },
        )
        show("POST /oauth2/token (code exchange, cookies set)", r)

        r = client.post(f"{base}/api/mfa/enroll")
        show("POST /api/mfa/enroll", r)
        if r.status_code != 200:
            print("FATAL: enroll failed.")
            return 2
        enroll = r.json()
        secret = enroll["secret"]
        print(f"\n*** TOTP SECRET (add to https://totp.app/): {secret} ***")
        print(f"*** BACKUP CODES: {enroll['backup_codes']} ***")

        code_in = input("\nType the 6-digit code from totp.app (enrollment verify): ").strip()
        r = client.post(f"{base}/api/mfa/verify", json={"code": code_in})
        show("POST /api/mfa/verify (enrollment)", r)
        if r.status_code != 200:
            print("FATAL: enrollment verify failed — secret/time mismatch at enroll time.")
            return 2
        print("\nEnrollment COMPLETE.")

    # 4. Fresh password login WITHOUT cookies (like a new browser session).
    client.cookies.clear()
    body = authorize(client, base, client_id, redirect_uri, email, args.password)
    if not body.get("mfa_required"):
        print("\nUNEXPECTED: no MFA gate after enrollment — see body above.")
        return 2
    session_token = body["session_token"]
    print(f"\nMFA session: {session_token[:16]}...")

    # 5. THE failing step: verify with a fresh, correct TOTP code.
    code_in = input("Type the CURRENT 6-digit code from totp.app (login verify): ").strip()
    r = client.post(
        f"{base}/api/mfa/verify-oauth-login",
        json={"session_token": session_token, "code": code_in},
    )
    show("POST /api/mfa/verify-oauth-login (LOGIN)", r)
    if r.status_code == 200:
        print("\n*** SUCCESS: MFA login works. Bug NOT reproduced on this backend. ***")
        return 0
    print(
        "\n*** BUG REPRODUCED. Paste the HTTP status + BODY above when reporting. ***"
        "\n(The frontend would have shown: 'Invalid code. Please try again.')"
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())
