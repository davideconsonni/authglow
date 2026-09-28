#!/usr/bin/env bash
# Launch the AuthGlow checktool (Linux / macOS).
# On first run it creates a local virtual environment (.venv) and installs the
# tool in editable mode, so later runs are instant and reflect code changes.
# It re-installs automatically when pyproject.toml (dependencies) changes.
#
# Usage:
#   ./run.sh                  # interactive: pick groups
#   ./run.sh --all            # run every group
#   ./run.sh --groups auth,rbac
#   ./run.sh --base-url https://my-instance --all
#   ./run.sh --help
#
# If needed: chmod +x run.sh

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
venv="$here/.venv"
py="$venv/bin/python"
stamp="$venv/.checktool-installed"
pyproject="$here/pyproject.toml"

if [ ! -x "$py" ]; then
    base=""
    for candidate in python3 python; do
        if command -v "$candidate" >/dev/null 2>&1; then
            base="$candidate"
            break
        fi
    done
    if [ -z "$base" ]; then
        echo "Python 3.11+ was not found on PATH. Install Python and retry." >&2
        exit 1
    fi
    echo "Creating virtual environment at $venv ..."
    "$base" -m venv "$venv"
fi

needs_install=0
if [ ! -f "$stamp" ]; then
    needs_install=1
elif [ "$pyproject" -nt "$stamp" ]; then
    needs_install=1
fi

if [ "$needs_install" -eq 1 ]; then
    echo "Installing checktool dependencies ..."
    "$py" -m pip install --quiet --disable-pip-version-check -e "$here"
    touch "$stamp"
fi

exec "$py" -m checktool "$@"
