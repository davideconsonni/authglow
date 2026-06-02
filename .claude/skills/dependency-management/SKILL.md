# Dependency Management Skill

## Overview
This project uses `uv` to manage Python dependencies. Dependencies are declared in `requirements.in` and pinned/locked in `requirements.txt` (auto-generated, never manually edited).

## Key Files
- **`requirements.in`** — Source of truth for direct dependencies. This is the only file you should edit when adding, removing, or changing dependencies.
- **`requirements.txt`** — Auto-generated lockfile with pinned versions and hashes. **Never edit this file directly.** It is always produced by the compile command.

## Commands

### Compile dependencies (no upgrade)
Generates `requirements.txt` from `requirements.in` without changing resolved versions:
```bash
uv pip compile requirements.in -o requirements.txt --python-version 3.13 --python-platform linux
```

### Compile dependencies with upgrade
Upgrades all dependencies to their latest compatible versions:
```bash
uv pip compile requirements.in -o requirements.txt --python-version 3.13 --python-platform linux --upgrade
```

### Upgrade a single package
To upgrade only one specific package while keeping others pinned:
```bash
uv pip compile requirements.in -o requirements.txt --python-version 3.13 --python-platform linux --upgrade-package <package-name>
```

## Rules
1. **Always edit `requirements.in`** to add, remove, or modify a dependency. Never edit `requirements.txt` directly.
2. After any change to `requirements.in`, recompile by running the appropriate command above.
3. Target platform is always **linux** and Python version is always **3.13** — include both flags in every compile command.
4. Commit both `requirements.in` and `requirements.txt` together after changes so they stay in sync.