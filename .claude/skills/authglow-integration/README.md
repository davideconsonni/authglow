# AuthGlow Integration Skill

This skill helps a coding agent integrate an application with the current
AuthGlow OAuth2/OIDC contract. It is intentionally standards-first and does
not replace the OIDC libraries of the host framework.

## Where to keep it

Keep this directory at:

```text
.claude/skills/authglow-integration/
```

That location is read natively by Claude Code, and by OpenCode and GitHub
Copilot through their Claude-compatible skill discovery. Keep `SKILL.md` and
the `references/` and `checklists/` directories together.

## Recommended invocation

```text
Integrate this application with the current AuthGlow issuer. Inspect the
project first, choose the correct OAuth2/OIDC flow, implement it with the
host framework's maintained library, and complete the security/compliance
checklist before reporting success.
```

## Modes

- `integrate`: implement a new integration.
- `audit`: inspect and remediate an existing integration.
- `migrate`: replace another identity provider.
- `troubleshoot`: diagnose a protocol or configuration failure.

The skill discovers the active AuthGlow version from the issuer metadata or
checkout. It does not assume that a historical README or hardcoded endpoint
is current.
