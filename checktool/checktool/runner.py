"""Sequential group execution."""

from __future__ import annotations

import time
from typing import List, Optional, Type

import httpx

from checktool.client import ApiClient, RequestSpec
from checktool.config import CheckConfig
from checktool.console import ConsoleUI
from checktool.registry import Group, GroupContext
from checktool.results import GroupResult, RunReport


def run_groups(
    groups: List[Type[Group]],
    api: ApiClient,
    config: CheckConfig,
    ui: ConsoleUI,
    report: RunReport,
    admin_email: Optional[str] = None,
    admin_password: Optional[str] = None,
) -> None:
    """Run each group in order, isolating failures to their own group."""
    if config.show_curl:

        def _observe(spec: RequestSpec, _resp: httpx.Response) -> None:
            ui.curl(api.curl(spec, shell=config.curl_shell))

        api.on_request = _observe

    for group_cls in groups:
        result = GroupResult(slug=group_cls.slug, title=group_cls.title)
        ui.group_start(group_cls.slug, group_cls.title, group_cls.description)
        ctx = GroupContext(
            api=api,
            config=config,
            ui=ui,
            result=result,
            admin_email=admin_email,
            admin_password=admin_password,
        )
        started = time.perf_counter()
        try:
            group_cls().run(ctx)
        except Exception as exc:  # noqa: BLE001 - one bad group must not stop the rest
            result.fatal = f"{type(exc).__name__}: {exc}"
        finally:
            result.duration_s = time.perf_counter() - started
        ui.group_end(result)
        report.results.append(result)
