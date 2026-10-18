# Severity rubric and finding format

## Severity levels

| Level | Meaning | Examples |
| --- | --- | --- |
| **Blocker** | Must be fixed before merge/release. Correctness, security, or protocol violation. | OAuth2/OIDC spec violation, auth bypass, secret disclosure, refresh-reuse not revoked, `redirect_uri` prefix matching, data loss. |
| **High** | Should be fixed before merge. Likely to cause incidents or violate repo standards. | Missing authorization/scope check, PII unmasked in logs, N+1 on a hot path, no test for critical new behavior, breaking an `AGENTS.md` rule. |
| **Medium** | Fix soon; degrades quality or maintainability. | Stale docs after a structural change, missing rate limit, suboptimal caching, unclear error handling. |
| **Low** | Minor; polish. | Naming/formatting nits the linter does not catch, redundant code, small doc wording. |
| **Info** | Observation, no action required. | Context worth knowing, alternative approaches, follow-ups to consider. |

When unsure between two levels, state the uncertainty and pick the higher one
for security or protocol areas.

## Finding format

Report findings as a table ordered by severity, highest first:

```
| ID | Severity | Area | Location | Finding | Fix hint |
| --- | --- | --- | --- | --- | --- |
| R1 | Blocker | OAuth2 | authglow/services/oauth2.py:214 | Refresh reuse does not revoke the token family | Invalidate the family and emit an audit event |
```

- **ID** — `R1`, `R2`, … 
- **Area** — one of Standards, Docs, Tests, OAuth2/OIDC, Performance, Security, Lint.
- **Location** — `path/to/file.ext:line` (line is the anchor, not a range).
- **Finding** — one sentence, factual, evidence-based.
- **Fix hint** — the smallest change that resolves it.

For each **Blocker** and **High**, add a short block below the table:

```
### R1 — <title>
- What: <observed behavior, with file:line>
- Why it matters: <impact>
- Suggested fix: <smallest safe change>
- Evidence: <test output / command run / spec section>
```

## Report close

End with:

- the reviewed target (scope A or B) and what it covered;
- the exact commands/tools used (codegraph, serena, `ruff`, `mypy`, `npm run lint`, …);
- any check that could not be run and why;
- the offer to prepare a remediation plan.
