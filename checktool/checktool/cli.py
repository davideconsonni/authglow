"""Command-line entry point for the AuthGlow checktool.

Interactive (no group flags, TTY present) or non-interactive
(``--groups`` / ``--all``). By default it targets a local instance; pass
``--base-url`` for a remote one.
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from typing import List, Optional, Type

import checktool.groups  # noqa: F401  (importing registers every group)
from checktool import __version__, bootstrap
from checktool.client import ApiClient
from checktool.config import DEFAULT_BASE_URL, CheckConfig
from checktool.console import ConsoleUI
from checktool.coverage import audit
from checktool.registry import Group, all_groups
from checktool.results import RunReport
from checktool.runner import run_groups


def _force_utf8() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
        except Exception:  # noqa: BLE001
            pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="checktool",
        description="Black-box end-to-end verifier for a running AuthGlow instance.",
    )
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="target instance (default: %(default)s)")
    parser.add_argument("--groups", help="comma-separated group slugs to run")
    parser.add_argument("--all", action="store_true", help="run every group")
    parser.add_argument("--list", action="store_true", help="list available groups and exit")
    parser.add_argument("--coverage", action="store_true", help="print the frontend->backend gap report and exit")
    parser.add_argument("-y", "--yes", action="store_true", help="do not ask for confirmation")
    parser.add_argument("--email", help="admin email (non-demo, already-provisioned instance)")
    parser.add_argument("--password", help="admin password")
    parser.add_argument("--setup-token", help="setup token for a fresh instance")
    parser.add_argument("--timeout", type=float, default=20.0, help="HTTP timeout in seconds")
    parser.add_argument("--report", help="write a Markdown report to this path")
    parser.add_argument("--relax-rate-limits", action="store_true", help="temporarily disable rate limits (admin)")
    parser.add_argument("--show-curl", action="store_true", help="print an equivalent curl command for every request")
    parser.add_argument("--no-secrets", action="store_true", help="mask created secrets in console and report")
    parser.add_argument(
        "--curl-shell",
        choices=["bash", "powershell"],
        help="curl syntax for --show-curl/report (default: current platform)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="show more detail")
    return parser


def _resolve_selection(
    ui: ConsoleUI, config: CheckConfig, args: argparse.Namespace
) -> Optional[List[Type[Group]]]:
    groups = all_groups()
    by_slug = {g.slug: g for g in groups}

    if args.groups:
        selected = []
        for slug in [s.strip() for s in args.groups.split(",") if s.strip()]:
            group = by_slug.get(slug)
            if group is None:
                ui.error(f"unknown group '{slug}'. Use --list to see the available groups.")
                return None
            selected.append(group)
        return selected

    if args.all:
        return groups

    if config.interactive:
        slugs = ui.select_groups(groups)
        selected = [by_slug[s] for s in slugs if s in by_slug]
        if not selected:
            ui.error("no groups selected.")
            return None
        return selected

    ui.error("nothing to run. Use --groups a,b or --all (add --list to explore).")
    return None


def _confirm_remote(ui: ConsoleUI, config: CheckConfig) -> bool:
    if config.is_local or config.yes:
        return True
    message = (
        f"Target '{config.normalized_url}' is remote. The checks create and delete "
        "users, roles, clients and keys there. Continue?"
    )
    if config.interactive:
        return ui.confirm(message, default=False)
    ui.error(f"refusing to run against remote target {config.normalized_url} without --yes")
    return False


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8()
    args = build_parser().parse_args(argv)

    interactive = sys.stdin.isatty() and sys.stdout.isatty()
    config = CheckConfig(
        base_url=args.base_url,
        email=args.email,
        password=args.password,
        setup_token=args.setup_token,
        yes=args.yes,
        verbose=args.verbose,
        timeout=args.timeout,
        relax_rate_limits=args.relax_rate_limits,
        report_path=args.report,
        interactive=interactive,
        show_curl=args.show_curl,
        show_secrets=not args.no_secrets,
        curl_shell=args.curl_shell,
    )
    ui = ConsoleUI(verbose=config.verbose)

    if args.list:
        ui.print_groups(all_groups())
        return 0
    if args.coverage:
        audit.print_report(ui)
        return 0

    selected = _resolve_selection(ui, config, args)
    if selected is None:
        return 1

    ui.banner(config, __version__)
    if config.show_curl:
        ui.warn("--show-curl prints live bearer tokens to the console")

    if not _confirm_remote(ui, config):
        return 1

    report = RunReport(
        target=config.normalized_url,
        mode=config.mode,
        started_at=datetime.now(),
        coverage_markdown=audit.build_markdown(),
    )

    api = ApiClient(config.normalized_url, timeout=config.timeout, verbose=config.verbose)
    try:
        if not bootstrap.healthy(api):
            ui.error(
                f"cannot reach {config.normalized_url} (GET /health failed). "
                "Is the backend running?"
            )
            return 2

        admin_email: Optional[str] = None
        admin_password: Optional[str] = None
        if any(g.requires_admin for g in selected):
            try:
                creds = bootstrap.resolve_admin_credentials(api, config, ui)
                bootstrap.login_admin(api, creds, ui)
                admin_email, admin_password = creds.email, creds.password
            except RuntimeError as exc:
                ui.error(str(exc))
                return 2

        restore_enabled = _relax(api, config, ui, selected)
        try:
            run_groups(selected, api, config, ui, report, admin_email, admin_password)
        finally:
            _restore(api, ui, restore_enabled)
    except KeyboardInterrupt:
        ui.error("interrupted")
        return 130
    finally:
        api.close()

    ui.summary(report)

    if config.report_path:
        try:
            with open(config.report_path, "w", encoding="utf-8") as handle:
                handle.write(report.to_markdown())
            ui.info(f"report written to {config.report_path}")
        except OSError as exc:
            ui.error(f"could not write report: {exc}")

    return report.exit_code()


def _relax(
    api: ApiClient, config: CheckConfig, ui: ConsoleUI, selected: List[Type[Group]]
) -> Optional[bool]:
    if not config.relax_rate_limits or not any(g.requires_admin for g in selected):
        return None
    status = api.get("/api/admin/rate-limits/status")
    if status.status_code != 200:
        ui.warn("could not read rate-limit status; leaving limits untouched")
        return None
    previous = api.json(status).get("enabled")
    api.put("/api/admin/rate-limits/config", json={"enabled": False})
    ui.info("rate limits temporarily disabled for this run")
    return previous if isinstance(previous, bool) else None


def _restore(api: ApiClient, ui: ConsoleUI, previous: Optional[bool]) -> None:
    if previous is None:
        return
    api.put("/api/admin/rate-limits/config", json={"enabled": previous})
    ui.info(f"rate limits restored (enabled={previous})")


if __name__ == "__main__":
    sys.exit(main())
