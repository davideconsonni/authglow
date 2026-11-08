"""Plain-``requests`` implementation of the AuthGlow browser auth flows.

Shared by ``locustfile.py`` (measured load) and ``run_baseline.py``
(seeding/admin). The flow is exactly what the first-party SPA performs:

1. ``GET /api/oauth2/csrf-token``           -> CSRF token + session cookie
2. ``POST /api/oauth2/authorize``           -> 302 with the auth code (PKCE)
3. ``POST /oauth2/token`` (authorization_code) -> access + refresh tokens
4. ``POST /oauth2/token`` (refresh_token)    -> rotated refresh token

Keeping one implementation here means the load scenario cannot drift
from the seeding path used to build the test fixture.
"""

import base64
import hashlib
import secrets
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

import requests

DEFAULT_SCOPE = "openid profile read offline_access"
REQUEST_TIMEOUT = 30.0


class FlowError(RuntimeError):
    """A step of the auth flow failed; carries the HTTP context."""

    def __init__(self, step: str, status_code: Optional[int], detail: str):
        super().__init__(f"{step} failed (status {status_code}): {detail}")
        self.step = step
        self.status_code = status_code
        self.detail = detail


def pkce_pair() -> Tuple[str, str]:
    """Return a fresh (verifier, S256 challenge) PKCE pair (RFC 7636)."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def fetch_csrf_token(session: requests.Session, base: str) -> str:
    """GET /api/oauth2/csrf-token and return the token (cookie set on session)."""
    resp = session.get(f"{base}/api/oauth2/csrf-token", timeout=REQUEST_TIMEOUT)
    if resp.status_code != 200:
        raise FlowError("csrf-token", resp.status_code, resp.text[:300])
    token: str = resp.json()["csrf_token"]
    return token


def redirect_target(resp: requests.Response) -> Optional[str]:
    """Where the authorize call points: Location header (302) or redirect_url JSON.

    The SPA-facing API answers 200 with ``{"redirect_url": ...}`` (same
    payload the browser would follow); raw HTTP clients get the classic
    302 with ``Location``. Both appear in practice depending on headers.
    Public because ``locustfile.py`` parses the same payload on locust's
    response wrapper (duck-typed: status_code/headers/json()).
    """
    if resp.status_code in (302, 303) and resp.headers.get("Location"):
        return resp.headers["Location"]
    if resp.status_code == 200:
        try:
            target = resp.json().get("redirect_url")
        except ValueError:
            return None
        return target if isinstance(target, str) else None
    return None


def _code_from_redirect(resp: requests.Response, step: str) -> str:
    """Extract the auth code from an authorize response, raising FlowError."""
    location = redirect_target(resp)
    if location is None:
        raise FlowError(step, resp.status_code, resp.text[:300])
    query = parse_qs(urlparse(location).query)
    if "code" not in query:
        raise FlowError(step, resp.status_code, f"no code in redirect: {location[:300]}")
    return query["code"][0]


def authorize(
    session: requests.Session,
    base: str,
    *,
    client_id: str,
    redirect_uri: str,
    email: str,
    password: str,
    scope: str = DEFAULT_SCOPE,
    csrf_token: Optional[str] = None,
) -> str:
    """POST /api/oauth2/authorize with credentials; return the auth code."""
    token = csrf_token or fetch_csrf_token(session, base)
    verifier, challenge = pkce_pair()
    resp = session.post(
        f"{base}/api/oauth2/authorize",
        data={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": secrets.token_urlsafe(24),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "email": email,
            "password": password,
        },
        headers={"X-CSRF-Token": token},
        allow_redirects=False,
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code not in (200, 302, 303):
        raise FlowError("authorize", resp.status_code, resp.text[:300])
    return _code_from_redirect(resp, "authorize")


def exchange_code(
    session: requests.Session,
    base: str,
    *,
    client_id: str,
    redirect_uri: str,
    code: str,
    code_verifier: str,
    csrf_token: Optional[str] = None,
) -> Dict[str, str]:
    """POST /oauth2/token authorization_code grant; return the token dict."""
    headers = {"X-CSRF-Token": csrf_token} if csrf_token else {}
    resp = session.post(
        f"{base}/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "code_verifier": code_verifier,
        },
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code != 200:
        raise FlowError("token(code)", resp.status_code, resp.text[:300])
    tokens: Dict[str, str] = resp.json()
    return tokens


def login(
    session: requests.Session,
    base: str,
    *,
    client_id: str,
    redirect_uri: str,
    email: str,
    password: str,
    scope: str = DEFAULT_SCOPE,
) -> Dict[str, str]:
    """Full ceremony: csrf -> authorize -> code exchange. Returns tokens.

    The returned dict contains ``access_token`` and (when ``offline_access``
    was granted) ``refresh_token``; ``_csrf_token`` is kept so follow-up
    cookie-carrying POSTs can pass the CSRF gate without another GET.
    """
    token = fetch_csrf_token(session, base)
    verifier, challenge = pkce_pair()
    resp = session.post(
        f"{base}/api/oauth2/authorize",
        data={
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": secrets.token_urlsafe(24),
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "email": email,
            "password": password,
        },
        headers={"X-CSRF-Token": token},
        allow_redirects=False,
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code not in (200, 302, 303):
        raise FlowError("authorize", resp.status_code, resp.text[:300])
    code = _code_from_redirect(resp, "authorize")
    tokens = exchange_code(
        session,
        base,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code=code,
        code_verifier=verifier,
        csrf_token=token,
    )
    tokens["_csrf_token"] = token
    return tokens


def refresh(
    session: requests.Session,
    base: str,
    *,
    client_id: str,
    refresh_token: str,
    csrf_token: Optional[str] = None,
) -> Dict[str, str]:
    """POST /oauth2/token refresh_token grant; returns the rotated pair."""
    headers = {"X-CSRF-Token": csrf_token} if csrf_token else {}
    resp = session.post(
        f"{base}/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "client_id": client_id,
            "refresh_token": refresh_token,
        },
        headers=headers,
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code != 200:
        raise FlowError("token(refresh)", resp.status_code, resp.text[:300])
    tokens: Dict[str, str] = resp.json()
    return tokens


def create_admin(base: str, setup_token: str, email: str, password: str) -> None:
    """POST /api/setup/create-admin with the one-time setup bearer token."""
    resp = requests.post(
        f"{base}/api/setup/create-admin",
        json={"email": email, "password": password},
        headers={"Authorization": f"Bearer {setup_token}"},
        timeout=REQUEST_TIMEOUT,
    )
    if resp.status_code != 200:
        raise FlowError("setup/create-admin", resp.status_code, resp.text[:300])


def create_users(
    base: str,
    admin_access_token: str,
    emails_and_passwords: List[Tuple[str, str]],
) -> None:
    """Bulk-create seeded users through POST /api/admin/users/create.

    ``email_verified=True`` keeps the seeding path off the (unconfigured)
    SMTP code path; passwords must satisfy the live password policy.
    """
    for email, password in emails_and_passwords:
        resp = requests.post(
            f"{base}/api/admin/users/create",
            json={
                "email": email,
                "password": password,
                "first_name": "Load",
                "last_name": "Tester",
                "scopes": ["read"],
                "email_verified": True,
            },
            headers={"Authorization": f"Bearer {admin_access_token}"},
            timeout=REQUEST_TIMEOUT,
        )
        if resp.status_code != 201:
            raise FlowError(f"admin/users/create {email}", resp.status_code, resp.text[:300])
