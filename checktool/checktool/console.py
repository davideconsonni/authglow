"""Rich-based console UI for the checktool.

Keeps every user-facing message here so the groups stay focused on
behaviour. Interactive selection uses :mod:`questionary`.
"""

from __future__ import annotations

from typing import List, Sequence, Type

import questionary
from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from checktool.config import CheckConfig
from checktool.results import GroupResult, RunReport


class ConsoleUI:
    """Encapsulates terminal output and prompts."""

    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self.console = Console(highlight=False, soft_wrap=False)

    # -- decoration -----------------------------------------------------

    def banner(self, config: CheckConfig, version: str) -> None:
        target = config.normalized_url
        mode = config.mode
        body = Text()
        body.append("AuthGlow checktool", style="bold")
        body.append(f"  v{version}\n", style="dim")
        body.append("Target  ", style="bold")
        body.append(f"{target}\n")
        body.append("Mode    ", style="bold")
        body.append(f"{mode}\n", style="green" if mode == "local" else "yellow")
        body.append("Run id  ", style="bold")
        body.append(f"{config.namespace}", style="dim")
        self.console.print(Panel(body, border_style="cyan", expand=False))

    def info(self, message: str) -> None:
        self.console.print(f"[dim]{message}[/dim]")

    def error(self, message: str) -> None:
        self.console.print(f"[bold red]error:[/bold red] {message}")

    def warn(self, message: str) -> None:
        self.console.print(f"[yellow]warning:[/yellow] {message}")

    def success(self, message: str) -> None:
        self.console.print(f"[green]{message}[/green]")

    def artifact(self, label: str, value: str, note: str = "") -> None:
        """Print a created secret / id the operator may want to reuse."""
        suffix = f"  [dim]({escape(note)})[/dim]" if note else ""
        self.console.print(
            f"    [bold yellow]*[/bold yellow] [bold]{escape(label)}[/bold]: "
            f"[cyan]{escape(str(value))}[/cyan]{suffix}"
        )

    def curl(self, command: str) -> None:
        """Print a replayable curl command.

        Rendered with ``soft_wrap`` so a long command (JWT bearer tokens)
        stays a single logical line: the terminal may wrap it visually,
        but rich inserts no hard newlines, so copy/paste replays it as one
        command instead of a stack of fragments.
        """
        if command:
            self.console.print(f"    [dim]$ {escape(command)}[/dim]", soft_wrap=True)

    # -- group listing --------------------------------------------------

    def print_groups(self, groups: Sequence[Type]) -> None:
        table = Table(title="Available check groups", show_lines=False)
        table.add_column("Slug", style="cyan", no_wrap=True)
        table.add_column("Title", style="bold")
        table.add_column("What it verifies")
        for g in groups:
            table.add_row(g.slug, g.title, g.description)
        self.console.print(table)

    # -- selection / confirmation --------------------------------------

    def select_groups(self, groups: Sequence[Type]) -> List[str]:
        choices = [
            questionary.Choice(
                title=f"{g.title}  —  {g.description}",
                value=g.slug,
                checked=True,
            )
            for g in groups
        ]
        answer = questionary.checkbox(
            "Which groups do you want to run? (space to toggle, enter to confirm)",
            choices=choices,
        ).ask()
        return list(answer or [])

    def confirm(self, message: str, default: bool = False) -> bool:
        answer = questionary.confirm(message, default=default).ask()
        return bool(answer)

    def prompt_text(self, message: str) -> str:
        return (questionary.text(message).ask() or "").strip()

    def prompt_password(self, message: str) -> str:
        return (questionary.password(message).ask() or "").strip()

    # -- run narration --------------------------------------------------

    def group_start(self, slug: str, title: str, description: str) -> None:
        self.console.print()
        self.console.print(
            Panel(
                Text(description, style="white"),
                title=f"[bold]{title}[/bold]  [dim]({slug})[/dim]",
                border_style="blue",
                expand=False,
            )
        )

    def step(self, description: str, method: str, path: str) -> None:
        self.console.print(
            f"  [cyan]→[/cyan] {description}  [dim]{method} {path}[/dim]"
        )

    def check(self, ok: bool, name: str, evidence: str = "") -> None:
        if ok:
            self.console.print(f"    [green]✓[/green] {name}")
        else:
            detail = f"  [dim]({evidence})[/dim]" if evidence else ""
            self.console.print(f"    [red]✗[/red] {name}{detail}")

    def skipped(self, name: str, reason: str = "") -> None:
        detail = f"  [dim]({reason})[/dim]" if reason else ""
        self.console.print(f"    [yellow]•[/yellow] {name} [dim]skipped[/dim]{detail}")

    def group_end(self, result: GroupResult) -> None:
        if result.fatal:
            self.console.print(f"  [bold red]group error:[/bold red] {result.fatal}")
            return
        style = "green" if result.ok else "red"
        self.console.print(
            f"  [{style}]group result: {result.passed} passed, "
            f"{result.failed} failed[/{style}] [dim]({result.duration_s:.1f}s)[/dim]"
        )

    # -- summary --------------------------------------------------------

    def summary(self, report: RunReport) -> None:
        self.console.print()
        table = Table(title="Summary", show_lines=False)
        table.add_column("Group", style="bold")
        table.add_column("Passed", justify="right", style="green")
        table.add_column("Failed", justify="right", style="red")
        table.add_column("Status")
        for r in report.results:
            if r.fatal:
                status = "[red]ERROR[/red]"
            elif r.ok:
                status = "[green]PASS[/green]"
            else:
                status = "[red]FAIL[/red]"
            table.add_row(r.title, str(r.passed), str(r.failed), status)
        self.console.print(table)

        if report.failed or report.fatal:
            self.console.print(
                f"[bold red]{report.failed} failed check(s) "
                f"and {report.fatal} group error(s)[/bold red]"
            )
        else:
            self.console.print(
                f"[bold green]All {report.passed} checks passed.[/bold green]"
            )
