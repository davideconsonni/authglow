#!/usr/bin/env python3
"""Select only the tests affected by a set of changed files.

Maps changed source modules to their test files using three signals:

1. Direct references — test files whose content mentions the module's
   dotted path (imports, ``patch("authglow....")`` targets, type refs).
2. Name convention — test files whose name contains the module stem
   (``jwt.py`` → ``test_jwt.py``, ``test_jwt_key_rotation.py``).
3. Structural triggers — files whose blast radius is everything
   (``conftest.py``, dependency pins, ``main.py``, anything in
   ``authglow/core/``, repository protocol/base contracts) escalate
   to the full unit (+integration) suite, mirroring the AGENTS.md rule.

Usage (from ``backend/``)::

    python scripts/affected_tests.py                     # working-tree changes
    python scripts/affected_tests.py --base origin/main  # committed changes since BASE
    python scripts/affected_tests.py --run               # also execute pytest -n auto
    python scripts/affected_tests.py --files backend/authglow/services/jwt.py ...

Output: selected test paths (or a scope sentinel ``FULL``/``FULL_PLUS_IT``)
on stdout, one per line, so the list can be piped; diagnostics on stderr.
Frontend changes are never mapped to backend tests — the script only
prints the matching ``npx vitest related --run`` hint for them.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Set

BACKEND_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_ROOT.parent

# Files whose change can affect any test: escalate scope instead of mapping.
# (path-prefix match, relative to the repo root, forward slashes)
FULL_IT_TRIGGERS = (
    "backend/tests/conftest.py",
    "backend/main.py",
    "backend/pyproject.toml",
    "backend/uv.lock",
    "backend/requirements",
    "backend/authglow/core/",
)
FULL_UNIT_TRIGGERS = (
    "backend/authglow/repositories/protocols.py",
    "backend/authglow/repositories/dependencies.py",
    "backend/authglow/repositories/exceptions.py",
    "backend/authglow/repositories/file/base.py",
    "backend/authglow/repositories/file/in_memory.py",
    "backend/authglow/repositories/in_memory",
)
# Directories whose real consumers are integration tests (HTTP wiring,
# middleware chain): include the whole integration folder in the scope.
IT_SCOPED_PREFIXES = (
    "backend/authglow/api/",
    "backend/authglow/middleware/",
)


def _git(*args: str) -> str:
    """Run a git command at the repo root and return stdout as text lines."""
    result = subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=True,
    )
    return result.stdout


def changed_files(base: Optional[str]) -> List[str]:
    """Repo-relative changed paths: working tree (default) or committed vs *base*."""
    if base:
        output = _git("diff", "--name-only", f"{base}...HEAD")
    else:
        output = _git("diff", "--name-only", "HEAD")
        output += _git("ls-files", "--others", "--exclude-standard")
    return sorted({line.strip() for line in output.splitlines() if line.strip()})


def discover_test_files(tests_dir: Path) -> Dict[str, str]:
    """Return {backend-relative path: file content} for every test_*.py under tests/."""
    found: Dict[str, str] = {}
    for path in sorted(tests_dir.rglob("test_*.py")):
        if "__pycache__" in path.parts:
            continue
        try:
            found[path.relative_to(BACKEND_ROOT).as_posix()] = path.read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError as exc:  # unreadable file: skip but keep selection honest
            print(f"warning: cannot read {path}: {exc}", file=sys.stderr)
    return found


def is_test_file(rel: str) -> bool:
    parts = rel.split("/")
    return parts[0] == "backend" and "tests" in parts and parts[-1].startswith("test_")


def stem(rel: str) -> str:
    return Path(rel).stem


def map_files(files: List[str]) -> "tuple[str, Set[str], List[str], List[str]]":
    """Return (scope, selections) where scope is one of '', 'UNIT', 'FULL'."""
    tests = discover_test_files(BACKEND_ROOT / "tests")
    selections: Set[str] = set()
    scope = ""
    frontend: List[str] = []
    ignored: List[str] = []

    for rel in files:
        if rel.startswith("frontend/"):
            frontend.append(rel)
            continue
        if not rel.startswith("backend/"):
            ignored.append(rel)
            continue
        if any(rel.startswith(t) or rel == t for t in FULL_IT_TRIGGERS):
            scope = "FULL"
            continue
        if any(rel.startswith(t) or rel == t for t in FULL_UNIT_TRIGGERS):
            scope = max(scope, "UNIT", key=lambda s: ("", "UNIT", "FULL").index(s))
            continue
        if is_test_file(rel):
            selections.add(rel[len("backend/") :])
            continue
        if rel.endswith("__init__.py"):
            needle = stem_dir(rel)
        elif rel.endswith(".py") and "/authglow/" in f"/{rel}":
            needle = rel[len("backend/") : -len(".py")].replace("/", ".")
        else:
            ignored.append(rel)
            continue

        hit = False
        for test_path, content in tests.items():
            if needle in content:
                selections.add(test_path)
                hit = True
        # Name convention catches tests exercising the module through
        # fixtures or the public API without importing it directly.
        module_stem = stem(rel)
        for test_path in tests:
            if f"test_{module_stem}" in Path(test_path).stem or (
                f"_{module_stem}_" in f"_{Path(test_path).stem}_"
            ):
                selections.add(test_path)
                hit = True
        if rel.startswith(IT_SCOPED_PREFIXES):
            for test_path in tests:
                if "/tests/integration/" in f"/{test_path}":
                    selections.add(test_path)
            hit = True
            scope = max(scope, "UNIT", key=lambda s: ("", "UNIT", "FULL").index(s))
        if not hit:
            print(f"note: no direct test match for {rel}", file=sys.stderr)

    return scope, selections, frontend, ignored


def stem_dir(rel: str) -> str:
    """Dotted package path for an ``__init__.py`` (e.g. backend/authglow/core/ -> authglow.core)."""
    path = Path(rel)
    parts = [p for p in path.parts[1:] if p != "authglow" and p not in ("backend", "__init__.py")]
    joined = ".".join(["authglow"] + parts)
    return joined


def vitest_hint(frontend: List[str]) -> None:
    if not frontend:
        return
    src = [f for f in frontend if "/src/" in f]
    files = " ".join(src) if src else "<changed frontend files>"
    print(
        f"frontend: cd frontend && npx vitest related --run {files}",
        file=sys.stderr,
    )


def pytest_python() -> str:
    """Interpreter to run pytest with: prefer the project venv when present.

    ``sys.executable`` is used as-is when the script is already running under
    the venv; otherwise a local ``.venv`` is preferred so that the selected
    tests import against the project dependencies, not a stray global Python.
    """
    for candidate in (
        BACKEND_ROOT / ".venv" / "Scripts" / "python.exe",
        BACKEND_ROOT / ".venv" / "bin" / "python",
    ):
        if candidate.exists():
            return str(candidate)
    return sys.executable


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--base",
        metavar="REF",
        help="compare committed changes against REF (default: working tree vs HEAD)",
    )
    parser.add_argument(
        "--files",
        nargs="*",
        metavar="PATH",
        help="explicit repo-relative paths instead of the git diff",
    )
    parser.add_argument(
        "--run",
        action="store_true",
        help="execute pytest (-q --tb=line -n auto) with the selected scope",
    )
    args = parser.parse_args(argv)

    files = args.files if args.files is not None else changed_files(args.base)
    if not files:
        print("no changed files", file=sys.stderr)
        return 0

    scope, selections, frontend, ignored = map_files(files)
    vitest_hint(frontend)
    for rel in ignored:
        print(f"skipped (not test-relevant): {rel}", file=sys.stderr)

    if scope == "FULL":
        print("scope: FULL (unit + integration)")
        pytest_paths: List[str] = ["tests/unit", "tests/integration"]
    elif scope == "UNIT":
        pytest_paths = sorted(selections) or ["tests/unit"]
        print("scope: selected tests + core-escalation to unit")
    elif selections:
        pytest_paths = sorted(selections)
        print(f"scope: {len(pytest_paths)} affected test file(s)")
    else:
        print("scope: none (no affected backend tests)")
        return 0

    for path in pytest_paths:
        print(path)

    if args.run:
        cmd = [pytest_python(), "-m", "pytest", "-q", "--tb=line", "-n", "auto", *pytest_paths]
        print(f"running: {' '.join(cmd)}", file=sys.stderr)
        return subprocess.call(cmd, cwd=BACKEND_ROOT)
    return 0


if __name__ == "__main__":
    sys.exit(main())
