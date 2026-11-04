---
name: update-dependencies
description: Update a repository's dependencies to the latest released versions, majors included, one ecosystem at a time, then run the repository's own validation commands. Use when the user asks to update libraries, dependencies, or packages, bump versions, or upgrade to the latest.
compatibility: Needs the package manager of each detected ecosystem on PATH (npm/pnpm/yarn/bun, uv/pip/poetry/pipenv, cargo, go, bundle, composer).
---

# Update Dependencies

Bring every dependency manifest in the repository to the latest released
versions — majors included — in verifiable phases, without committing.

A **phase** is one ecosystem's manifest and lockfile in one directory. A
**gate** is one of the repository's own validation commands, run after a phase.

## Rules

- Work in phases: finish one ecosystem (update + gate) before the next.
- Stop at the first failing command. A failure is a finding, not something to
  paper over.
- Update to latest majors. Moving only within existing semver ranges is not
  enough.
- Keep dependency edits isolated from unrelated worktree edits, and report the
  latter separately.
- Preserve unrelated worktree changes — never reset, checkout, clean, stash, or
  overwrite them.
- Do not commit unless the user asks.
- Package-manager audit fixes (`npm audit fix`, `pip-audit --fix`) are not an
  update mechanism; use the per-ecosystem update tools below.

## Step 1 — Recon

Inventory every manifest and lockfile, detect the package manager for each, and
record the baseline.

- Walk the repo for: `package.json`, `pyproject.toml`, `requirements*.in`,
  `requirements*.txt`, `Cargo.toml`, `go.mod`, `Gemfile`, `composer.json`.
- Pick the manager from the lockfile beside the manifest (§Ecosystem commands);
  fall back to the ecosystem default.
- Run `git status --short` and record whether the tree started clean.

Completion: a list of `(ecosystem, directory, manager, manifest, lockfile)` and
a recorded baseline.

## Step 2 — Choose the phase order

Order phases so foundational things update before their consumers: libraries
before applications, a workspace root before leaf packages, a shared compiler or
runtime before the code it builds. If the repository documents an order
(`AGENTS.md`, `CONTRIBUTING.md`, a Makefile), follow that.

Completion: an explicit ordered list of phases for this run.

## Step 3 — Update a phase

Bump the phase's manifest and lockfile to latest (majors included) with the
command from §Ecosystem commands, then install.

Completion: the manifest and lockfile changed and the install command exited 0.

## Step 4 — Gate the phase

Run the repository's own validation commands for the changed area. Discover
them, don't assume:

1. `AGENTS.md` / `CLAUDE.md` / `CONTRIBUTING.md` — the repo's canonical commands.
2. Scripts in `package.json` / `Makefile` / `justfile` / `Taskfile` /
   `tox.ini` / `noxfile.py`.
3. CI workflows (`.github/workflows/`, `.gitlab-ci.yml`).

Run the subset covering the changed phase, in the repo's order, stopping at the
first failure.

Completion: every discovered command for the phase passed, or the run stopped
at the first failure with its output captured.

## Step 5 — Handle a failure

Classify it before reacting:

- **Update-caused** — the new version broke the build, types, or tests.
- **Pre-existing** — it fails on unchanged code too; report it, leave it alone.

For an update-caused failure, check ecosystem lag first: a just-released major
its dependents do not yet accept. Node is the common offender — `npm install`
throws `ERESOLVE`, or a peer range rejects the new major.

On ecosystem lag, cap the offending package to the newest version its
dependents accept, reinstall, and report the cap and why — do not bypass with
`--force` / `--legacy-peer-deps`. Real cases: `typescript@7` is rejected by
`typescript-eslint`, which peer-requires `<6.1`; `vitest@5` loses the
`@testing-library/jest-dom` matcher typings. Prefer the newest version that
keeps all peers satisfied, and offer to lift the cap later.

Fix application code, config, or deprecation errors only when the user asks;
otherwise stop and report.

Completion: the failure is classified, and either resolved by a documented cap
or reported with the first failing command and its error summary.

## Step 6 — Report

Run `git status --short` and `git diff --stat`, then report:

- Each phase, with the packages changed in its manifest and lockfile.
- The validation commands that passed.
- The first failing command, if any, with its relevant error summary.
- Any cap applied and its reason.
- Any unrelated pre-existing worktree changes.

## Ecosystem commands

Detect the manager from the lockfile; the default is listed first.

| Ecosystem | Manifest / lockfile | Update to latest (majors) | Install |
|---|---|---|---|
| Node (npm) | `package.json` / `package-lock.json` | `npx --yes npm-check-updates -u` | `npm install` |
| Node (pnpm) | `package.json` / `pnpm-lock.yaml` | `pnpm dlx npm-check-updates -u` | `pnpm install` |
| Node (yarn) | `package.json` / `yarn.lock` | `yarn dlx npm-check-updates -u` | `yarn install` |
| Node (bun) | `package.json` / `bun.lock` | `bunx npm-check-updates -u` | `bun install` |
| Python (uv project) | `pyproject.toml` / `uv.lock` | `uv lock --upgrade` | `uv sync` |
| Python (uv pip) | `requirements.in` → `requirements.txt` | `uv pip compile requirements.in -o requirements.txt --upgrade` | `uv pip install --upgrade -r requirements.txt` |
| Python (pip) | `requirements.txt` | relax pins, then `pip install --upgrade -r requirements.txt` | — |
| Python (poetry) | `pyproject.toml` / `poetry.lock` | `poetry update` | `poetry install` |
| Python (pipenv) | `Pipfile` / `Pipfile.lock` | `pipenv update` | `pipenv install --dev` |
| Rust | `Cargo.toml` / `Cargo.lock` | `cargo update` (in-range); `cargo upgrade` for majors (cargo-edit) | `cargo fetch` |
| Go | `go.mod` / `go.sum` | `go get -u ./... && go mod tidy` | `go mod download` |
| Ruby | `Gemfile` / `Gemfile.lock` | `bundle update` | `bundle install` |
| PHP | `composer.json` / `composer.lock` | `composer update` | `composer install` |

Notes:

- `npm-check-updates` is intentional: `npm update` stays inside the existing
  semver ranges and therefore misses majors.
- `poetry update` / `bundle update` / `composer update` cross majors already;
  `cargo update` does not — use `cargo upgrade` when majors must move.
- For a plain `requirements.txt`, pins must be relaxed before
  `pip install --upgrade` can move them; prefer compiling from `requirements.in`.
