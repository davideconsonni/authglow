---
name: authglow-review
description: Review AuthGlow changes or a chosen topic and report prioritized findings. Use when asked to review uncommitted or unpushed changes, a branch, or a specific theme (module, flow, endpoint), or to audit a change against the repo standards, documentation freshness, test coverage, OAuth2/OIDC compliance, performance, security, and lint. Asks the user for the review scope before starting, prioritizes findings, and ends by offering a remediation plan.
license: MIT
compatibility: Read-only review. Needs repository access and the backend (ruff, mypy, pytest) and frontend (npm/npm run lint) toolchains available on PATH to execute the lint and test checks.
---

# AuthGlow Review

Use this skill to review AuthGlow changes or a named area of the codebase and
report findings in priority order. It is a **read-only** reviewer: it inspects,
executes lint/tests, and reports — it never changes source.

## Non-negotiable rules

- **Read-only.** Never edit, write, or delete source files. Never commit, push,
  stage, or otherwise change git state. You only read and run non-mutating
  commands.
- **Ask the scope before analysis.** Complete Step 0 and wait for the answer
  before scanning anything.
- **Structural search first.** Locate and read code through the **codegraph**
  (or **serena**) MCP before any raw file search, to minimize tokens. Fall back
  to plain search only when the MCP has no match. See Step 1.
- **Evidence, not opinion.** Every finding cites a `file:line` reference and the
  check that produced it. If you could not verify something, say so explicitly
  instead of guessing.
- **Execute the lint check.** Report the real output of the linters and type
  checkers; never assume a clean result.
- **Do not write the remediation plan unasked.** End by *offering* it.

## Step 0 — Ask the scope (blocking)

Ask the user exactly one scoping question, then wait. Do not start until they
answer:

- **(A) Uncommitted / unpushed changes** — review the current working tree,
  staged changes, and local commits not yet on the remote.
- **(B) A specific theme** — review a named module, flow, endpoint, or feature
  (for example "the refresh-token rotation path" or
  `authglow/services/oauth2.py`).

If the answer is ambiguous, ask one clarifying follow-up. Never assume scope.

## Step 1 — Locate code with structural search first

Use the mounted code-intelligence MCP before reading files:

- **codegraph** (`codegraph_explore`): name the symbols spanning a flow to get
  their verbatim source plus the call path between them in one call. Query by
  symbol, file, or natural-language question. Use it to read a file/symbol
  before editing-free review, to trace "how X reaches Y", and to see blast
  radius.
- **serena**: use its symbol search and reading tools when codegraph returns
  nothing useful.

Only when the MCP has no coverage, fall back to `grep`/`glob` and direct reads.
When running shell commands, prefer the token-thrifty helper from the repo
instructions where one exists (for example the `rtk` prefix documented in the
global agent instructions).

## Step 2 — Resolve the target

**(A) Uncommitted / unpushed changes:**

```bash
git status --short
git diff
git diff --staged
git log --oneline @{u}..   # local commits not on the upstream, if it exists
```

Include untracked files worth reviewing. Build the list of changed files and
the intent behind each.

**(B) A theme:** map the theme to concrete modules/symbols with codegraph, then
read those symbols and the code they call.

## Step 3 — The seven checks

Run each check against the resolved target. Use the reference files in this
skill directory for detail, and read the live repo standards rather than an
outdated copy.

1. **Standards alignment** — `AGENTS.md` (backend and frontend conventions:
   import order, naming, Pydantic/FastAPI patterns, structlog-only logging,
   UTC, repository/service layering) and `ARCHITECTURE.md` (where things belong,
   the reference table). Index: `references/repo-standards.md`.
2. **Documentation freshness** — after structural changes, `ARCHITECTURE.md`
   (directory maps + reference table), `docs/README.md` index,
   `docs/reference/features.md`, `docs/flows/*`, and plan frontmatter must stay
   accurate. Flag stale or missing doc updates.
3. **Test coverage** — does the change carry matching unit/integration tests
   (`backend/tests/unit`, `backend/tests/integration`, frontend `*.test.ts`)?
   Respect the repo's test-isolation rules and the `xfail(strict=True)` pattern
   for known gaps. Judge coverage of the changed behavior, not a global number.
4. **OAuth2/OIDC compliance (mandatory)** — verify the change against the
   relevant RFCs/OIDC specs and AuthGlow's role as an Authorization/Resource
   Server. When in doubt, fetch the standard. Checklist and RFC list:
   `references/oauth2-oidc-checklist.md`.
5. **Performance** — N+1 accesses, blocking I/O not wrapped in
   `asyncio.to_thread`, missing `lru_cache`/`TTLCache` where warranted, hot-path
   allocations, frontend re-renders, query-key misuse, bundle growth.
6. **Security** — secret handling, PII masking in logs, rate limits, input
   validation, authorization/scope checks, user-enumeration resistance, security
   headers, error leakage, dependency risk.
7. **Lint and typecheck (execute them)** — backend: `ruff check`, `ruff format
   --check`, `mypy`; frontend: `npm run lint` and the type-check/build. Run from
   `backend/` and `frontend/` respectively. Report the actual output.

## Step 4 — Report

Use `references/severity-rubric.md` for severity definitions and the finding
format. Report as a table ordered by severity, highest first:

```
| ID | Severity | Area | Location | Finding | Fix hint |
```

Then add a short per-finding detail block for anything Blocking or High. Close
with a one-line summary of the target reviewed and the tools you used.

If a requested check could not be run (missing toolchain, no coverage data),
state that plainly rather than implying a pass.

## Step 5 — Offer the remediation plan

After the report, ask the user whether they want a remediation plan. Only if
they say yes, draft it (grouped by severity, smallest safe change first, with
verification steps per item). Do not create files unless the user asks.

## References

- `references/repo-standards.md` — where the standards live and the
  most-often-violated rules.
- `references/oauth2-oidc-checklist.md` — RFC/spec list and server-side
  controls to verify.
- `references/severity-rubric.md` — severity levels and the finding format.

## Stop conditions

Stop and ask the user when:

- the review scope is still ambiguous after the scoping question;
- verifying a finding would require changing files or git state;
- a check needs a toolchain that is not installed;
- the change depends on protocol behavior the specs do not settle, and the
  compliance question needs the user's decision.
