"""Instance discovery and admin-session bootstrap.

Goal: ask the operator as little as possible. Order of resolution:

1. Demo instance -> credentials from ``GET /api/meta`` (rotated each boot).
2. Fresh instance (``needs_setup``) -> create the first admin with the
   setup token (``SETUP_TOKEN`` / ``--setup-token`` / local
   ``data/keys/setup_token`` / interactive prompt) and remember it.
3. Already provisioned -> ``--email``/``--password``, env
   ``AUTHGLOW_ADMIN_EMAIL``/``AUTHGLOW_ADMIN_PASSWORD``, the saved
   checktool state file, or an interactive prompt.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import httpx

from checktool.client import ApiClient
from checktool.config import CheckConfig
from checktool.console import ConsoleUI

STATE_PATH = Path(__file__).resolve().parent / ".state.json"

DEFAULT_GENERATED_ADMIN = "checktool-admin@example.com"


@dataclass
class Credentials:
    email: str
    password: str
    source: str


def _generate_password() -> str:
    # Guaranteed uppercase + lowercase + digit + special + length >= 20.
    return "Ct1!" + secrets.token_urlsafe(18)


def healthy(api: ApiClient) -> bool:
    try:
        return api.get("/health").status_code == 200
    except httpx.HTTPError:
        return False


def _meta(api: ApiClient) -> dict:
    resp = api.get("/api/meta")
    return api.json(resp) if resp.status_code == 200 else {}


def _needs_setup(api: ApiClient) -> bool:
    resp = api.get("/api/setup/check")
    return bool(api.json(resp).get("needs_setup"))


def _provided(config: CheckConfig) -> Optional[Credentials]:
    if config.email and config.password:
        return Credentials(config.email, config.password, "--email/--password")
    env_email = os.environ.get("AUTHGLOW_ADMIN_EMAIL")
    env_password = os.environ.get("AUTHGLOW_ADMIN_PASSWORD")
    if env_email and env_password:
        return Credentials(env_email, env_password, "env AUTHGLOW_ADMIN_*")
    return None


def _read_state() -> Optional[Credentials]:
    if not STATE_PATH.exists():
        return None
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    email, password = data.get("email"), data.get("password")
    if email and password:
        return Credentials(email, password, "saved checktool state")
    return None


def _write_state(creds: Credentials) -> None:
    try:
        STATE_PATH.write_text(
            json.dumps({"email": creds.email, "password": creds.password}),
            encoding="utf-8",
        )
    except OSError as exc:  # non-fatal
        print(f"warning: could not persist checktool credentials: {exc}")


def _setup_token(config: CheckConfig) -> Optional[str]:
    if config.setup_token:
        return config.setup_token
    env = os.environ.get("SETUP_TOKEN")
    if env:
        return env
    if config.is_local:
        for rel in ("data/keys/setup_token", "backend/data/keys/setup_token"):
            path = Path(rel)
            if path.exists():
                try:
                    token = path.read_text(encoding="utf-8").strip()
                except OSError:
                    continue
                if token:
                    return token
    return None


def _create_admin(
    api: ApiClient, config: CheckConfig, ui: ConsoleUI, provided: Optional[Credentials]
) -> Credentials:
    creds = provided or Credentials(
        DEFAULT_GENERATED_ADMIN, _generate_password(), "generated"
    )
    token = _setup_token(config)
    if not token and config.interactive:
        token = ui.prompt_password("Setup token (printed in the server log on first boot)")
    if not token:
        raise RuntimeError(
            "this instance needs initial setup, but no setup token is available. "
            "Set SETUP_TOKEN, pass --setup-token, or run the backend locally so "
            "data/keys/setup_token can be read."
        )

    resp = api.post(
        "/api/setup/create-admin",
        json={
            "email": creds.email,
            "password": creds.password,
            "first_name": "Checktool",
            "last_name": "Admin",
        },
        headers={"Authorization": f"Bearer {token}"},
        use_bearer=False,
    )
    if resp.status_code not in (200, 201):
        raise RuntimeError(
            f"setup/create-admin failed (HTTP {resp.status_code}): {api.snippet(resp)}"
        )
    ui.success(f"created initial admin {creds.email} via setup token")
    _write_state(creds)
    return creds


def resolve_admin_credentials(
    api: ApiClient, config: CheckConfig, ui: ConsoleUI
) -> Credentials:
    """Resolve admin credentials without logging in yet."""
    meta = _meta(api)
    if meta.get("demo_mode") and meta.get("demo_user_password"):
        ui.info("demo instance: using credentials from GET /api/meta")
        return Credentials(
            meta.get("demo_user_email") or DEFAULT_GENERATED_ADMIN,
            meta["demo_user_password"],
            "demo /api/meta",
        )

    if _needs_setup(api):
        return _create_admin(api, config, ui, _provided(config))

    provided = _provided(config)
    if provided:
        return provided

    saved = _read_state()
    if saved:
        ui.info(f"using saved checktool credentials ({saved.email})")
        return saved

    if config.interactive:
        email = ui.prompt_text("Admin email")
        password = ui.prompt_password("Admin password")
        if email and password:
            return Credentials(email, password, "interactive prompt")

    raise RuntimeError(
        "no admin credentials available for this instance. Pass --email/--password, "
        "set AUTHGLOW_ADMIN_EMAIL/AUTHGLOW_ADMIN_PASSWORD, or run interactively."
    )


def login_admin(api: ApiClient, creds: Credentials, ui: ConsoleUI) -> None:
    """Log in and attach the bearer token to ``api``."""
    ui.info(f"logging in as {creds.email} ({creds.source})")
    api.admin_login(creds.email, creds.password)
    ui.success("admin session established")
