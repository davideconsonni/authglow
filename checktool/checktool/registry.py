"""Group registry and execution context.

A *group* is one self-consistent unit of verification: it creates its own
fixtures (namespaced with the run id), exercises a feature end to end,
asserts the result, and cleans up after itself. Groups never depend on
state produced by another group.

To add a group: create ``checktool/groups/<slug>.py`` with a
:class:`Group` subclass decorated by :func:`register_group`, and import
it from ``checktool/groups/__init__.py``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Type

import httpx

from checktool.client import ApiClient
from checktool.config import CheckConfig
from checktool.console import ConsoleUI
from checktool.helpers import mask_secret
from checktool.results import Artifact, CheckResult, GroupResult


class GroupContext:
    """Shared helpers handed to every group's ``run`` method."""

    def __init__(
        self,
        api: ApiClient,
        config: CheckConfig,
        ui: ConsoleUI,
        result: GroupResult,
        admin_email: Optional[str] = None,
        admin_password: Optional[str] = None,
    ):
        self.api = api
        self.config = config
        self.ui = ui
        self.result = result
        self.admin_email = admin_email
        self.admin_password = admin_password

    def new_client(self) -> ApiClient:
        """A fresh, independent client (used to act as a different user)."""
        client = ApiClient(
            self.api.base_url, timeout=self.config.timeout, verbose=self.config.verbose
        )
        # Keep the curl observer attached so every client's calls are visible.
        client.on_request = self.api.on_request
        return client

    # -- fixture naming -------------------------------------------------

    def name(self, suffix: str) -> str:
        """A unique, namespaced name for a created fixture."""
        return f"{self.config.namespace}-{suffix}"

    def email(self, label: str) -> str:
        # ``example.com`` is accepted by email-validator; ``.test``/``.invalid``
        # are treated as special-use and rejected by the backend models.
        return f"{self.config.namespace}-{label}@example.com"

    # -- narration ------------------------------------------------------

    def step(self, description: str, method: str, path: str) -> None:
        self.ui.step(description, method, path)

    def request(
        self,
        description: str,
        method: str,
        path: str,
        **kw: Any,
    ) -> httpx.Response:
        """Log a plain-language step, perform the HTTP request, return it."""
        self.ui.step(description, method, path)
        return self.api.request(method, path, **kw)

    def check(self, name: str, ok: bool, evidence: str = "") -> bool:
        """Record and display one assertion."""
        ok = bool(ok)
        self.result.checks.append(CheckResult(name=name, ok=ok, evidence="" if ok else evidence))
        self.ui.check(ok, name, evidence)
        return ok

    def warn(self, message: str) -> None:
        self.result.warnings.append(message)
        self.ui.warn(message)

    def skip(self, name: str, reason: str = "") -> None:
        self.ui.skipped(name, reason)

    def confirm(self, message: str, default: bool = False) -> bool:
        return self.ui.confirm(message, default)

    def json(self, resp: httpx.Response) -> Any:
        return self.api.json(resp)

    def evidence(self, resp: httpx.Response) -> str:
        return self.api.evidence(resp)

    def expose(
        self,
        label: str,
        value: Any,
        *,
        note: str = "",
        secret: bool = True,
        replay: bool = True,
        api: Optional[ApiClient] = None,
    ) -> Any:
        """Publish a created secret / id (console + report).

        With ``--no-secrets`` and ``secret=True`` the value is masked.
        ``replay`` attaches the curl of the latest request so the creation
        can be reproduced by hand; it is always recorded in the report.
        Pass ``api`` when the value came from a client other than the
        admin one (e.g. a per-user ``ctx.new_client()``).
        """
        source = api or self.api
        display = mask_secret(value) if secret and not self.config.show_secrets else str(value)
        curl = ""
        if replay and source.last_request is not None:
            curl = source.curl(shell=self.config.curl_shell)
        self.result.artifacts.append(Artifact(label=label, value=display, curl=curl))
        self.ui.artifact(label, display, note)
        return value

    def curl(self) -> str:
        """Print (and return) the curl of the latest request."""
        command = self.api.curl(shell=self.config.curl_shell)
        self.ui.curl(command)
        return command


class Group:
    """Base class for a check group."""

    slug: str = ""
    title: str = ""
    description: str = ""
    requires_admin: bool = False

    def run(self, ctx: GroupContext) -> None:  # pragma: no cover - abstract
        raise NotImplementedError


_REGISTRY: Dict[str, Type[Group]] = {}


def register_group(cls: Type[Group]) -> Type[Group]:
    """Class decorator that adds a group to the global registry."""
    if not cls.slug:
        raise ValueError(f"{cls.__name__} must define a non-empty 'slug'")
    if cls.slug in _REGISTRY:
        raise ValueError(f"duplicate group slug: {cls.slug!r}")
    _REGISTRY[cls.slug] = cls
    return cls


def all_groups() -> List[Type[Group]]:
    """Return registered groups in registration (import) order."""
    return list(_REGISTRY.values())


def get_group(slug: str) -> Optional[Type[Group]]:
    return _REGISTRY.get(slug)


def slugs() -> List[str]:
    return list(_REGISTRY)
