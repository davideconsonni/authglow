"""Minimal black-box HTTP client for AuthGlow.

Wraps :mod:`httpx` with the few behaviours the checktool needs:
bearer authentication, 429-aware backoff, transparent CSRF retry, and
the OAuth2 authorization-code + PKCE dance used both to bootstrap the
admin session and to exercise the protocol.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import httpx

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_MAX_RETRIES = 3


def _detect_shell() -> str:
    """Default curl syntax for the current platform."""
    return "powershell" if os.name == "nt" else "bash"


def _shell_quote(value: str, shell: str) -> str:
    """Quote *value* for the given shell.

    bash/cmd use single quotes; PowerShell uses double quotes (a single
    quote is harmless there, but a bare ``'...'`` handed to the native
    ``curl.exe`` gets mangled, while ``"..."`` survives intact).
    """
    if shell == "powershell":
        return '"' + value.replace('"', '`"') + '"'
    return "'" + value.replace("'", "'\\''") + "'"


def _form_items(data: Any) -> List[Tuple[str, str]]:
    """Normalise a form payload to a list of ``(name, value)`` string pairs."""
    if isinstance(data, dict):
        pairs: List[Tuple[Any, Any]] = list(data.items())
    elif isinstance(data, (list, tuple)):
        pairs = list(data)
    else:
        return []
    return [(str(k), "" if v is None else str(v)) for k, v in pairs]


@dataclass
class RequestSpec:
    """A recorded HTTP request, enough to rebuild an equivalent curl command."""

    method: str
    path: str
    json: Any = None
    data: Any = None
    headers: Dict[str, str] = field(default_factory=dict)
    auth: Optional[Tuple[str, str]] = None


def pkce_pair() -> Tuple[str, str]:
    """Return a fresh ``(verifier, challenge)`` pair (RFC 7636 S256)."""
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
    return verifier, challenge


def parse_redirect_params(url: str) -> Dict[str, str]:
    """Return the query-string parameters of a redirect URL as a dict."""
    return dict(urllib.parse.parse_qsl(urllib.parse.urlparse(url).query))


@dataclass
class TokenBundle:
    """A token-endpoint response."""

    access_token: str
    refresh_token: Optional[str] = None
    id_token: Optional[str] = None
    expires_in: Optional[int] = None
    raw: Optional[Dict[str, Any]] = None


class ApiClient:
    """Thin, resilient HTTP client bound to one AuthGlow base URL."""

    def __init__(self, base_url: str, timeout: float = 20.0, verbose: bool = False):
        self.base_url = base_url.rstrip("/")
        self.verbose = verbose
        self._client = httpx.Client(base_url=self.base_url, timeout=timeout)
        self.access_token: Optional[str] = None
        #: Last request actually sent (for curl rendering / manual replay).
        self.last_request: Optional[RequestSpec] = None
        #: Optional observer invoked after every request (used to print curl).
        self.on_request: Optional[Callable[[RequestSpec, httpx.Response], None]] = None

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "ApiClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- low level ------------------------------------------------------

    def request(
        self,
        method: str,
        path: str,
        *,
        json: Any = None,
        data: Any = None,
        headers: Optional[Dict[str, str]] = None,
        auth: Optional[Tuple[str, str]] = None,
        allow_redirects: bool = False,
        use_bearer: bool = True,
    ) -> httpx.Response:
        hdrs = dict(headers or {})
        if auth is not None:
            request_auth: Optional[Tuple[str, str]] = auth
        else:
            request_auth = None
            if use_bearer and self.access_token and "Authorization" not in hdrs:
                hdrs["Authorization"] = f"Bearer {self.access_token}"

        attempt = 0
        csrf_retried = False
        while True:
            resp = self._client.request(
                method.upper(),
                path,
                json=json,
                data=data,
                headers=hdrs,
                auth=request_auth,
                follow_redirects=allow_redirects,
            )
            if resp.status_code == 429 and attempt < _MAX_RETRIES:
                time.sleep(self._retry_delay(resp, attempt))
                attempt += 1
                continue
            # CSRF gate: a cookie-bearing unsafe request without an explicit
            # credential header is rejected 403 with a CSRF hint. Fetch a
            # token (exempt path) and retry once.
            if (
                resp.status_code == 403
                and method.upper() in _UNSAFE_METHODS
                and not csrf_retried
                and "csrf" in resp.text.lower()
            ):
                token = self.fetch_csrf_token()
                if token:
                    hdrs["X-CSRF-Token"] = token
                    csrf_retried = True
                    continue
            self.last_request = RequestSpec(
                method=method.upper(),
                path=path,
                json=json,
                data=data,
                headers=dict(hdrs),
                auth=request_auth,
            )
            if self.on_request is not None:
                try:
                    self.on_request(self.last_request, resp)
                except Exception:  # noqa: BLE001 - observation must never break a run
                    pass
            return resp

    @staticmethod
    def _retry_delay(resp: httpx.Response, attempt: int) -> float:
        header = resp.headers.get("Retry-After")
        if header:
            try:
                return min(float(header), 10.0)
            except ValueError:
                pass
        return min(1.0 * (attempt + 1), 5.0)

    def get(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("GET", path, **kw)

    def post(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("POST", path, **kw)

    def put(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("PUT", path, **kw)

    def patch(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("PATCH", path, **kw)

    def delete(self, path: str, **kw: Any) -> httpx.Response:
        return self.request("DELETE", path, **kw)

    # -- helpers --------------------------------------------------------

    def fetch_csrf_token(self) -> Optional[str]:
        resp = self._client.get("/api/oauth2/csrf-token")
        if resp.status_code == 200:
            token = resp.json().get("csrf_token")
            return str(token) if token else None
        return None

    def json(self, resp: httpx.Response) -> Any:
        """Best-effort JSON decode; returns ``{}`` on non-JSON bodies."""
        try:
            return resp.json()
        except Exception:  # noqa: BLE001
            return {}

    def snippet(self, resp: httpx.Response, limit: int = 200) -> str:
        text = (resp.text or "").replace("\n", " ").strip()
        return text[:limit]

    def evidence(self, resp: httpx.Response) -> str:
        """Compact evidence string for a failed check."""
        return f"HTTP {resp.status_code}: {self.snippet(resp)}"

    def curl(self, spec: Optional[RequestSpec] = None, *, shell: Optional[str] = None) -> str:
        """Render the last request (or *spec*) as an equivalent ``curl`` command.

        ``shell`` selects the quoting style (``bash`` / ``powershell``);
        when omitted the current platform is used. The real bearer token
        and any basic-auth credentials are included so the command can be
        replayed as-is.
        """
        spec = spec if spec is not None else self.last_request
        if spec is None:
            return ""
        shell = shell or _detect_shell()

        def quote(value: Any) -> str:
            return _shell_quote(str(value), shell)

        executable = "curl.exe" if shell == "powershell" else "curl"
        parts: List[str] = [executable, "-sS"]
        method = spec.method.upper()
        if method != "GET":
            parts += ["-X", method]
        parts.append(quote(self.base_url + spec.path))
        if spec.auth is not None:
            parts += ["-u", quote(f"{spec.auth[0]}:{spec.auth[1]}")]

        headers = dict(spec.headers)
        if spec.json is not None and "Content-Type" not in headers:
            headers["Content-Type"] = "application/json"
        elif spec.data is not None and "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        for key, value in headers.items():
            parts += ["-H", quote(f"{key}: {value}")]

        if spec.json is not None:
            body = json.dumps(spec.json, separators=(",", ":"))
            parts += ["-d", quote(body)]
        elif spec.data is not None:
            for key, value in _form_items(spec.data):
                parts += ["--data-urlencode", quote(f"{key}={value}")]

        return " ".join(parts)

    # -- OIDC / OAuth2 helpers -----------------------------------------

    def oidc_config(self) -> Dict[str, Any]:
        resp = self.get("/api/auth/oidc/config")
        return self.json(resp) if resp.status_code == 200 else {}

    def authorize_code(
        self,
        *,
        email: str,
        password: str,
        client_id: str,
        redirect_uri: str,
        scope: str = "openid profile email read offline_access",
        verifier: Optional[str] = None,
        challenge: Optional[str] = None,
        nonce: Optional[str] = None,
        state: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run one password login round and return the authorization params.

        Returns a dict with at least ``code``; also ``state``, ``iss`` and
        the PKCE ``verifier`` actually used.
        """
        if verifier is None or challenge is None:
            verifier, challenge = pkce_pair()
        state = state or secrets.token_urlsafe(32)
        form: Dict[str, str] = {
            "email": email,
            "password": password,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": scope,
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        if nonce:
            form["nonce"] = nonce

        resp = self.post("/api/oauth2/authorize", data=form)
        result: Dict[str, Any] = {"status": resp.status_code, "verifier": verifier, "state": state}

        if resp.status_code == 302:
            params = parse_redirect_params(resp.headers.get("location", ""))
            result.update(params)
            return result

        body = self.json(resp)
        if isinstance(body, dict) and body.get("mfa_required"):
            result["mfa_required"] = True
            result["session_token"] = body.get("session_token")
            return result
        if isinstance(body, dict) and body.get("password_expired"):
            result["password_expired"] = True
            return result
        if isinstance(body, dict) and body.get("consent_required"):
            consent = self.post(
                "/oauth2/consent",
                data={"session_token": body.get("session_token", ""), "approved": "true"},
            )
            cbody = self.json(consent)
            redirect_url = cbody.get("redirect_url", "")
            result.update(parse_redirect_params(redirect_url))
            result["consent"] = True
            return result
        if isinstance(body, dict) and body.get("redirect_url"):
            result.update(parse_redirect_params(body["redirect_url"]))
            return result

        result["body"] = self.snippet(resp)
        return result

    def exchange_code(
        self,
        *,
        code: str,
        verifier: str,
        client_id: str,
        redirect_uri: str,
        auth: Optional[Tuple[str, str]] = None,
    ) -> Tuple[TokenBundle, httpx.Response]:
        resp = self.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
                "code_verifier": verifier,
            },
            auth=auth,
        )
        return self._token_bundle(resp), resp

    def refresh_token(
        self, refresh_token: str, client_id: str, auth: Optional[Tuple[str, str]] = None
    ) -> Tuple[TokenBundle, httpx.Response]:
        resp = self.post(
            "/oauth2/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
            },
            auth=auth,
        )
        return self._token_bundle(resp), resp

    def client_credentials(
        self, client_id: str, client_secret: str, scope: str = "read"
    ) -> Tuple[TokenBundle, httpx.Response]:
        resp = self.post(
            "/oauth2/token",
            data={"grant_type": "client_credentials", "scope": scope},
            auth=(client_id, client_secret),
        )
        return self._token_bundle(resp), resp

    def _token_bundle(self, resp: httpx.Response) -> TokenBundle:
        body = self.json(resp)
        if not isinstance(body, dict):
            return TokenBundle(access_token="")
        return TokenBundle(
            access_token=body.get("access_token", ""),
            refresh_token=body.get("refresh_token"),
            id_token=body.get("id_token"),
            expires_in=body.get("expires_in"),
            raw=body,
        )

    def admin_login(self, email: str, password: str) -> TokenBundle:
        """Log in as an admin and store the bearer token on the client."""
        cfg = self.oidc_config()
        client_id = cfg.get("client_id")
        redirect_uri = cfg.get("redirect_uri")
        if not client_id or not redirect_uri:
            raise RuntimeError("GET /api/auth/oidc/config did not return client_id/redirect_uri")

        round_params = self.authorize_code(
            email=email,
            password=password,
            client_id=client_id,
            redirect_uri=redirect_uri,
        )
        if round_params.get("mfa_required"):
            raise RuntimeError(
                "admin account requires MFA; the checktool needs a non-MFA admin "
                "(create a dedicated checktool admin or disable MFA for it)"
            )
        if not round_params.get("code"):
            raise RuntimeError(
                f"password login failed (HTTP {round_params.get('status')}): "
                f"{round_params.get('body') or round_params}"
            )
        bundle, resp = self.exchange_code(
            code=round_params["code"],
            verifier=round_params["verifier"],
            client_id=client_id,
            redirect_uri=redirect_uri,
        )
        if not bundle.access_token:
            raise RuntimeError(f"code exchange failed (HTTP {resp.status_code}): {self.snippet(resp)}")
        self.access_token = bundle.access_token
        return bundle
