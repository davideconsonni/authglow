"""Result models and Markdown serialization for the checktool."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional


@dataclass
class CheckResult:
    """One assertion inside a group.

    ``name`` is a short plain-language description of what was verified,
    ``ok`` is the outcome, and ``evidence`` is a compact string (HTTP
    status, snippet, value) shown when the check fails.
    """

    name: str
    ok: bool
    evidence: str = ""


@dataclass
class Artifact:
    """A secret / id created during a group, worth replaying by hand.

    ``value`` is already masked when ``--no-secrets`` is in effect.
    ``curl`` is the request that produced it (manual replay), when known.
    """

    label: str
    value: str
    curl: str = ""


@dataclass
class GroupResult:
    """Outcome of running one group."""

    slug: str
    title: str
    checks: List[CheckResult] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    artifacts: List[Artifact] = field(default_factory=list)
    fatal: Optional[str] = None
    duration_s: float = 0.0

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.ok)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if not c.ok)

    @property
    def ok(self) -> bool:
        return self.fatal is None and self.failed == 0


@dataclass
class RunReport:
    """Full result of one checktool run."""

    target: str
    mode: str
    started_at: datetime
    results: List[GroupResult] = field(default_factory=list)
    coverage_markdown: str = ""

    @property
    def passed(self) -> int:
        return sum(r.passed for r in self.results)

    @property
    def failed(self) -> int:
        return sum(r.failed for r in self.results)

    @property
    def fatal(self) -> int:
        return sum(1 for r in self.results if r.fatal is not None)

    @property
    def total_checks(self) -> int:
        return sum(len(r.checks) for r in self.results)

    def exit_code(self) -> int:
        """Exit code = number of failures (capped at 255, like POSIX)."""
        return min(255, self.failed + self.fatal)

    def to_markdown(self) -> str:
        lines: List[str] = []
        lines.append("# AuthGlow checktool report")
        lines.append("")
        lines.append(f"- Target: `{self.target}`")
        lines.append(f"- Mode: `{self.mode}`")
        lines.append(f"- Started: {self.started_at.isoformat(timespec='seconds')}")
        lines.append(
            f"- Result: {self.passed}/{self.total_checks} checks passed "
            f"across {len(self.results)} group(s)"
        )
        lines.append("")
        lines.append("| Group | Passed | Failed | Status |")
        lines.append("|---|---|---|---|")
        for r in self.results:
            status = "PASS" if r.ok else ("ERROR" if r.fatal else "FAIL")
            lines.append(f"| {r.title} (`{r.slug}`) | {r.passed} | {r.failed} | {status} |")
        lines.append("")

        fatal_groups = [r for r in self.results if r.fatal]
        failed = [r for r in self.results if not r.fatal and r.failed]

        if fatal_groups or failed:
            lines.append("## Failures")
            lines.append("")
            for r in fatal_groups:
                lines.append(f"### {r.title} (`{r.slug}`) — group error")
                lines.append("")
                lines.append(f"`{r.fatal}`")
                lines.append("")
            for r in failed:
                lines.append(f"### {r.title} (`{r.slug}`)")
                lines.append("")
                for c in r.checks:
                    if not c.ok:
                        evidence = f" — `{c.evidence}`" if c.evidence else ""
                        lines.append(f"- {c.name}{evidence}")
                lines.append("")
        else:
            lines.append("No failures.")
            lines.append("")

        warnings = [(r.title, w) for r in self.results for w in r.warnings]
        if warnings:
            lines.append("## Warnings")
            lines.append("")
            for title, w in warnings:
                lines.append(f"- {title}: {w}")
            lines.append("")

        groups_with_artifacts = [r for r in self.results if r.artifacts]
        if groups_with_artifacts:
            lines.append("## Artifacts & replay")
            lines.append("")
            for r in groups_with_artifacts:
                lines.append(f"### {r.title} (`{r.slug}`)")
                lines.append("")
                for artifact in r.artifacts:
                    lines.append(f"- **{artifact.label}**: `{artifact.value}`")
                    if artifact.curl:
                        lines.append("")
                        lines.append("  ```bash")
                        lines.append(f"  {artifact.curl}")
                        lines.append("  ```")
                lines.append("")

        if self.coverage_markdown:
            lines.append(self.coverage_markdown)

        return "\n".join(lines).rstrip() + "\n"
