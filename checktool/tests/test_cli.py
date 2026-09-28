"""Unit tests for the checktool command-line surface."""

from checktool import cli
from checktool.config import CheckConfig
from checktool.console import ConsoleUI


class TestParser:
    def test_defaults(self):
        args = cli.build_parser().parse_args([])
        assert args.base_url == "http://127.0.0.1:8001"
        assert args.groups is None
        assert args.all is False

    def test_all_and_groups(self):
        args = cli.build_parser().parse_args(["--all", "--base-url", "http://x"])
        assert args.all is True
        assert args.base_url == "http://x"


class TestSelection:
    def _ui(self):
        return ConsoleUI(quiet=True)

    def test_explicit_groups_resolve(self):
        args = cli.build_parser().parse_args(["--groups", "auth,rbac"])
        selected = cli._resolve_selection(self._ui(), CheckConfig(), args)
        assert [g.slug for g in selected] == ["auth", "rbac"]

    def test_unknown_group_returns_none(self):
        args = cli.build_parser().parse_args(["--groups", "nope"])
        assert cli._resolve_selection(self._ui(), CheckConfig(), args) is None

    def test_all_returns_every_group(self):
        args = cli.build_parser().parse_args(["--all"])
        selected = cli._resolve_selection(self._ui(), CheckConfig(), args)
        assert {g.slug for g in selected} >= {"bootstrap", "auth", "oauth2"}

    def test_no_selection_non_interactive_returns_none(self):
        args = cli.build_parser().parse_args([])
        config = CheckConfig(interactive=False)
        assert cli._resolve_selection(self._ui(), config, args) is None


class TestMain:
    def test_list_exits_zero(self):
        assert cli.main(["--list"]) == 0

    def test_coverage_exits_zero(self):
        assert cli.main(["--coverage"]) == 0

    def test_unknown_group_exits_one(self):
        assert cli.main(["--groups", "nope"]) == 1

    def test_unreachable_target_exits_two(self):
        # Port 9 (discard) is not listening: connection should fail fast.
        assert cli.main(["--base-url", "http://127.0.0.1:9", "--groups", "bootstrap"]) == 2
