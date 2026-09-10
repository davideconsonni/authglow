# AuthGlow Docs

Start here. For code style, naming, and test commands see `AGENTS.md`; for the structural map see `ARCHITECTURE.md`.

## Coding agents: where to look first

| Task | Read |
|------|------|
| Implement an OAuth2/OIDC flow | `flows/README.md` + the flow file, then `reference/features.md` |
| Add a feature or endpoint | `reference/features.md`, then `ARCHITECTURE.md` (where to add what) |
| Work a security/audit item | `plans/active/README.md` for the tracking plan, then the plan file |
| Evaluate SAML | `analysis/saml/00-assessment.md` (draft analysis, not an approved plan) |
| Set up locally | `getting-started/quick-setup.md` |

## Map

| Directory | Content |
|-----------|---------|
| `getting-started/` | `quick-setup.md` — zero-to-signed-in (local + deployed) |
| `reference/` | `features.md` — complete feature catalog, endpoint by endpoint |
| `guides/` | `audit-logging.md`, `custom-claim-resolvers.md`, `phone-verification.md` |
| `guides/federation/` | `google.md`, `cie.md` — OIDC federation provider guides |
| `flows/` | Per-flow guides: standard, actors, conformance, endpoints (`flows/README.md` index) |
| `analysis/saml/` | SAML 2.0 assessment, phases 0–3 (draft analysis, may become a plan) |
| `plans/active/` | Open plans, one file per workstream (`plans/active/README.md` index) |
| `plans/archive/` | Completed or superseded plans (`plans/archive/README.md` index) |

## Naming conventions

- File names are kebab-case English (`vapt-fix-plan.md`, `quick-setup.md`).
- Plans carry YAML frontmatter (`type: plan`, `status: active|done|superseded`) and stable item IDs (`VAPT-NNN`, `OIDC-NNN`).
- Analysis files carry `type: analysis`, `status: draft`, `may-become-plan: true`.
- Root files (`README.md`, `AGENTS.md`, `ARCHITECTURE.md`, `DESIGN.md`, `SECURITY.md`) stay at the repo root.
