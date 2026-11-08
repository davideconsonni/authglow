"""Locust scenario for the AuthGlow login/refresh load baseline (PERF-011).

Two virtual-user classes mirror the hot paths the perf plan cares about
(login and refresh-token rotation — where PERF-001/002/003 stack up):

* ``LoginUser``   — full first-party browser login, measured step by step
                    plus a synthetic ``LOGIN end-to-end`` aggregate.
* ``RefreshUser`` — holds one refresh-token chain per simulated browser
                    and performs the rotation grant over and over. The
                    setup login is deliberately NOT counted, so refresh
                    percentiles stay pure.

Configuration comes from the manifest JSON written by ``run_baseline.py``
(env ``LOADTEST_MANIFEST`` path, ``LOADTEST_API_BASE`` override). To run
against an already-seeded staging instance, build a manifest with the
same shape (see README) and start locust directly.
"""

import itertools
import json
import os
import secrets
import threading
import time
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

import authflow
import requests
from locust import HttpUser, between, events, task

MANIFEST_PATH = os.environ.get("LOADTEST_MANIFEST")
if not MANIFEST_PATH:
    raise RuntimeError("LOADTEST_MANIFEST env var (path to manifest.json) is required")

with open(MANIFEST_PATH, encoding="utf-8") as fh:
    MANIFEST: Dict[str, Any] = json.load(fh)

API_BASE = os.environ.get("LOADTEST_API_BASE", MANIFEST["api_base"])

_pool_lock = threading.Lock()
_vu_counter = itertools.count()


def assign_credential() -> Dict[str, str]:
    """Give each virtual user its OWN seeded account (counter assignment).

    Isolation rationale (PERF-011 debugging, 2026-11-08): sharing breaks
    the baseline in two ways — two RefreshUsers on one email interleave
    rotation chains (theft detection → 401 floods), and even a plain
    LoginUser re-logging as an email a Refresher owns invalidates that
    refresher's family. With one account per virtual user every 401 in
    the run is a genuine server signal. If ``--users`` exceeds the seed
    pool the assignment wraps and sharing returns: keep ``--seed-users``
    >= ``--users`` (the driver default already does).
    """
    users = MANIFEST["users"]
    with _pool_lock:
        idx = next(_vu_counter)
    return dict(users[idx % len(users)])


class LoadUserBase(HttpUser):
    """Shared plumbing: config, an unmeasured side session, token state."""

    abstract = True
    wait_time = between(1, 3)

    def on_start(self) -> None:
        self.base = API_BASE
        self.client_id = MANIFEST["client_id"]
        self.redirect_uri = MANIFEST["redirect_uri"]
        self.scope = MANIFEST.get("scope", authflow.DEFAULT_SCOPE)
        # Plain session for unmeasured setup/recovery traffic.
        self.raw = requests.Session()
        self.refresh_token: Optional[str] = None
        self.csrf_token: Optional[str] = None
        self.email = ""
        # Each virtual user owns one seeded account for its whole life.
        self.cred: Dict[str, str] = assign_credential()

    def plain_login(self) -> None:
        """Login on a brand-new unmeasured session; refresh ``self.refresh_token``.

        A fresh ``Session`` per call keeps every login on the credential
        path: with ambient cookies the server would short-circuit via the
        existing-session check and skip bcrypt, silently skewing both the
        setup cost and which user the chain belongs to.
        """
        cred = self.cred
        self.email = cred["email"]
        self.raw = requests.Session()
        # Retry so a transient failure cannot kill+respawn the user (a
        # respawn consumes a fresh counter slot; past the pool end it
        # wraps onto a live account and poisons its rotation chain).
        last_exc: Optional[Exception] = None
        for attempt in range(3):
            try:
                tokens = authflow.login(
                    self.raw,
                    self.base,
                    client_id=self.client_id,
                    redirect_uri=self.redirect_uri,
                    email=cred["email"],
                    password=cred["password"],
                    scope=self.scope,
                )
                self.refresh_token = tokens.get("refresh_token")
                self.csrf_token = tokens.get("_csrf_token")
                if self.refresh_token:
                    return
                last_exc = RuntimeError("login response missing refresh_token")
            except (requests.RequestException, authflow.FlowError) as exc:
                last_exc = exc
            time.sleep(0.5 * (attempt + 1))
        raise last_exc if last_exc else RuntimeError("plain_login failed")

    def fire(self, name: str, elapsed_ms: float, exception: Optional[BaseException] = None) -> None:
        """Emit a synthetic request event (used for the end-to-end login)."""
        events.request.fire(
            request_type="FLOW",
            name=name,
            response_time=elapsed_ms,
            response_length=0,
            exception=exception,
        )


class LoginUser(LoadUserBase):
    """Simulates a stream of fresh browser sign-ins (bcrypt-dominated path)."""

    weight = 1

    @task
    def perform_login(self) -> None:
        cred = self.cred
        start = time.perf_counter()
        try:
            # Fresh browser: drop ambient cookies so authorize takes the
            # credential path (bcrypt), not the existing-session shortcut.
            self.client.cookies.clear()
            # 1) CSRF token (GET — exempt from the cookie gate, sets the cookie)
            csrf_resp = self.client.get(
                f"{self.base}/api/oauth2/csrf-token",
                name="login csrf-token",
                timeout=authflow.REQUEST_TIMEOUT,
                catch_response=True,
            )
            with csrf_resp:
                if csrf_resp.status_code != 200:
                    csrf_resp.failure(f"csrf-token status {csrf_resp.status_code}")
                    return
                csrf_token = csrf_resp.json()["csrf_token"]

            # 2) Authorize with credentials -> redirect payload carrying the
            #    auth code (302 Location, or SPA-style 200 {redirect_url}).
            verifier, challenge = authflow.pkce_pair()
            auth_resp = self.client.post(
                f"{self.base}/api/oauth2/authorize",
                name="login authorize",
                data={
                    "client_id": self.client_id,
                    "redirect_uri": self.redirect_uri,
                    "response_type": "code",
                    "scope": self.scope,
                    "state": secrets.token_urlsafe(24),
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "email": cred["email"],
                    "password": cred["password"],
                },
                headers={"X-CSRF-Token": csrf_token},
                allow_redirects=False,
                timeout=authflow.REQUEST_TIMEOUT,
                catch_response=True,
            )
            with auth_resp:
                if auth_resp.status_code not in (200, 302, 303):
                    auth_resp.failure(f"authorize status {auth_resp.status_code}")
                    return
                location = authflow.redirect_target(auth_resp)
                query = parse_qs(urlparse(location or "").query)
                if "code" not in query:
                    auth_resp.failure("authorize redirect missing code")
                    return
                code = query["code"][0]

            # 3) Code exchange -> tokens.
            token_resp = self.client.post(
                f"{self.base}/oauth2/token",
                name="login token exchange",
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": self.redirect_uri,
                    "client_id": self.client_id,
                    "code_verifier": verifier,
                },
                headers={"X-CSRF-Token": csrf_token},
                timeout=authflow.REQUEST_TIMEOUT,
                catch_response=True,
            )
            with token_resp:
                if token_resp.status_code != 200:
                    token_resp.failure(f"token(code) status {token_resp.status_code}")
                    return
                tokens = token_resp.json()
                if "access_token" not in tokens:
                    token_resp.failure("token(code) missing access_token")
                    return
                self.refresh_token = tokens.get("refresh_token")

            self.fire("LOGIN end-to-end", (time.perf_counter() - start) * 1000)
        except (requests.RequestException, authflow.FlowError) as exc:
            self.fire("LOGIN end-to-end", (time.perf_counter() - start) * 1000, exception=exc)


class RefreshUser(LoadUserBase):
    """Simulates a fleet of signed-in sessions rotating their refresh token."""

    weight = 3

    def on_start(self) -> None:
        super().on_start()
        self.plain_login()
        if not self.refresh_token:
            raise RuntimeError("seeded login did not yield a refresh token")

    @task
    def perform_refresh(self) -> None:
        resp = self.client.post(
            f"{self.base}/oauth2/token",
            name="refresh rotation",
            data={
                "grant_type": "refresh_token",
                "client_id": self.client_id,
                "refresh_token": self.refresh_token,
            },
            timeout=authflow.REQUEST_TIMEOUT,
            catch_response=True,
        )
        with resp:
            if resp.status_code != 200:
                body = (resp.text or "")[:160].replace("\n", " ")
                resp.failure(f"refresh status {resp.status_code}: {body}")
                # The chain is dead (expired/rotated/reuse-detected): re-login
                # unmeasured so this virtual user keeps refreshing, not stalls.
                self.plain_login()
                return
            try:
                tokens = resp.json()
                self.refresh_token = tokens["refresh_token"]
            except (ValueError, KeyError) as exc:
                resp.failure(f"refresh body error: {exc}")
                self.plain_login()
                return
            resp.success()
