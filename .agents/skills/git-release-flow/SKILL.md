---
name: git-release-flow
description: Trunk-based git workflow with a deploy branch, PRs, rebase merges, semver tags, changelog and hotfixes. Use when the user creates a branch, opens or merges a pull request, rebases, releases, deploys, creates a version tag, updates the changelog, or fixes an urgent production bug. Use before any git or GitHub operation.
---

# Git Release Flow

One branch holds the truth (`TRUNK`, default `main`).
One branch deploys (`DEPLOY`, default `release`).
All work happens on short branches that are deleted after merge.

## Config

Change these only if the repo uses other names:

- `TRUNK` = `main` — every change lands here first.
- `DEPLOY` = `release` — pushing here is the deploy. It always means "latest".
- Tag format = `vX.Y.Z` (example: `v1.4.0`).
- Changelog = `CHANGELOG.md` at repo root.

## Human gates (non-negotiable, no exceptions)

- Never run `git commit` (or any command that creates a commit) without the user's explicit OK. Propose the message, wait for approval, then commit.
- Never run `git push` (branches, `DEPLOY`, or tags). Push is always manual by the user: print the exact command, wait until the user confirms it was pushed, then continue.

## Hard rules

- Never commit directly to `TRUNK` or `DEPLOY`. Every change goes through a branch and a PR, so CI checks it.
- Merge direction is one-way: `TRUNK` into `DEPLOY`. Never merge `DEPLOY` back into `TRUNK`, or the two histories mix and you lose the clean "what is deployed" picture.
- `DEPLOY` has no own commits. Each push to `DEPLOY` is exactly one merge from `TRUNK`, so every deploy maps to one known state of `TRUNK`.
- Only a push to `DEPLOY` deploys. Tags never deploy. A tag is just a photo of a commit you can download later.
- Merges into `TRUNK` use rebase (linear history). Rebase the branch onto `TRUNK` before merging, so `TRUNK` stays a straight line that is easy to read and revert.
- Delete the work branch after merge. Old branches rot and confuse the next release.
- Never force-push `TRUNK` or `DEPLOY`. A rollback is a new push on top, never a rewritten history.

## Branch names

- `feat/<what>` — new feature (example: `feat/login-rate-limit`).
- `fix/<what>` — bug fix (example: `fix/refresh-token-expiry`).
- `chore/<what>` — tooling, docs, no behavior change (example: `chore/update-ci`).
- `hotfix/<what>` — urgent production fix. Same flow as `fix`, only reviewed faster.

## Feature flow

1. Start fresh: `git checkout TRUNK && git pull`.
2. Create the branch from `TRUNK`.
3. Commit in small steps on the branch. Each commit needs the user's explicit OK first.
4. Before opening the PR, align with the latest truth: `git fetch origin && git rebase origin/TRUNK`. Fix conflicts on the branch, never on `TRUNK`.
5. When the branch must go up, do not push it yourself. Print `git push -u origin <branch>` and wait for the user to confirm it was pushed. Then open a PR to `TRUNK`. CI must be green before merge.
6. Add one entry under `Unreleased` in the changelog (see below). This collects what the next release will contain. If there is truly nothing to note, say why in the PR.
7. Merge with rebase, then delete the branch.

## Release flow

Do the steps in order. Stop if one fails. Releasing means: take the current truth, mark it as deployed, give it a version photo.

1. Pull both: `git checkout TRUNK && git pull`, then `git checkout DEPLOY && git pull`.
2. Merge the truth into the deploy branch: `git checkout DEPLOY && git merge TRUNK --no-ff`. There should be no conflicts, because every branch was already rebased onto `TRUNK`. If a conflict appears, abort the merge (`git merge --abort`): the fix belongs on `TRUNK` first, then restart the release.
3. Do not push `DEPLOY` yourself. Print `git push origin DEPLOY` and wait for the user to confirm it was pushed. That push is the deploy.
4. Propose the version number (see next section) and ask the user to confirm or change it. Never tag a number the user did not confirm.
5. Update the changelog: move the `Unreleased` entries under a new `## [X.Y.Z] - YYYY-MM-DD` section. Leave an empty `## [Unreleased]` on top for the next cycle.
6. Create the annotated tag on the `DEPLOY` commit locally: `git tag -a vX.Y.Z -m "vX.Y.Z"`. Do not push it yourself. Print `git push origin vX.Y.Z` and wait for the user to confirm it was pushed.
7. Create a GitHub Release from that tag and paste the same changelog text, so the downloadable version and the notes match.

## Version step

1. Find the last version: `git describe --tags --abbrev=0`.
2. List what changed since then: `git log <last-tag>..DEPLOY --oneline`.
3. Propose one bump and explain it in one line:
   - major (example: `v2.0.0`): something breaks compatibility, old clients or configs must change.
   - minor (example: `v1.5.0`): a new feature that keeps compatibility.
   - patch (example: `v1.4.1`): fixes only, no new behavior.
4. Ask the user: "Propose vX.Y.Z because <reason>. Confirm or change." Tag only the confirmed number.

## Changelog

Keep a Changelog format. Create the file if it does not exist yet:

```md
# Changelog

## [Unreleased]

### Added
- Login rate limit (not released yet).

## [1.2.0] - 2026-01-01

### Added
- Passkey login.

### Fixed
- Refresh token expiry.
```

Rules:

- During feature work, entries go under `Unreleased`. That section is the shopping list of the next release.
- At release time, those entries move under the new version section with the date. Then `Unreleased` starts empty again.
- Old version sections are history: never edit them.
- Use only the subsections you need: `Added`, `Changed`, `Fixed`.

## Hotfix

An urgent production bug takes the fast lane, but the same road:

1. Branch `hotfix/<what>` from `TRUNK`, not from `DEPLOY`. The fix must land in the truth first, or the next release will reintroduce the bug.
2. PR to `TRUNK`, quick review, rebase merge.
3. Run the normal release flow right away with a patch version.

## Rollback

Never reset or force-push `DEPLOY` to "go back". History rewrites hide what was deployed and when. Instead, add a new commit on top:

1. `git checkout TRUNK && git pull`.
2. `git revert <bad-commit>`, or fix the bug forward if a revert is messy.
3. PR, rebase merge, then a normal release with a new patch version. The bad deploy stays in history, visible and explainable.
