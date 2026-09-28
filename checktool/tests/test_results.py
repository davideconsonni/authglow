"""Unit tests for checktool result models and report serialization."""

from datetime import datetime

from checktool.results import CheckResult, GroupResult, RunReport


def _group(slug: str, ok: bool) -> GroupResult:
    result = GroupResult(slug=slug, title=slug.title())
    result.checks.append(CheckResult("it works", ok, "" if ok else "boom"))
    return result


class TestGroupResult:
    def test_counts(self):
        result = GroupResult(slug="g", title="G")
        result.checks = [CheckResult("a", True), CheckResult("b", False), CheckResult("c", True)]
        assert result.passed == 2
        assert result.failed == 1
        assert result.ok is False

    def test_ok_when_no_failures(self):
        result = GroupResult(slug="g", title="G")
        result.checks = [CheckResult("a", True)]
        assert result.ok is True

    def test_fatal_marks_not_ok(self):
        result = GroupResult(slug="g", title="G", fatal="RuntimeError: nope")
        assert result.ok is False


class TestRunReport:
    def test_exit_code_counts_failures_and_fatals(self):
        report = RunReport(target="t", mode="local", started_at=datetime.now())
        report.results = [_group("a", True), _group("b", False)]
        report.results.append(GroupResult(slug="c", title="C", fatal="boom"))
        assert report.exit_code() == 2

    def test_markdown_lists_failures(self):
        report = RunReport(target="http://x", mode="remote", started_at=datetime.now())
        report.results = [_group("b", False)]
        md = report.to_markdown()
        assert "AuthGlow checktool report" in md
        assert "boom" in md
        assert "## Failures" in md

    def test_markdown_has_no_failures_section_when_green(self):
        report = RunReport(target="http://x", mode="local", started_at=datetime.now())
        report.results = [_group("a", True)]
        md = report.to_markdown()
        assert "No failures." in md
