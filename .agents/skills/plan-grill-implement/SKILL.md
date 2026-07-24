---
name: plan-grill-implement
description: Execute a plan item through a structured workflow — plan, grill, implement, test, mark done. Use when the user points to a specific item in a plan document (e.g. VAPT finding, roadmap item) and wants end-to-end execution.
---

Execute the following workflow for the plan item the user selects. Do NOT skip steps. Do NOT proceed to the next step without explicit user approval.

## Workflow

### Step 1 — Plan

Read the plan item the user indicated. Produce a detailed implementation plan covering:

- What the finding/issue requires (current state vs desired state)
- Files to create or modify (with line references)
- Test strategy (unit, integration, edge cases)
- Risk assessment (what could break, backward compatibility)
- Estimated scope (number of files, complexity)

Present the plan and wait for user approval before proceeding.

---

### Step 2 — Grill

Run `/grill-me` on the plan. Challenge every assumption, surface hidden trade-offs, and stress-test the approach. Do not proceed until the user confirms the plan is solid.

---

### Step 3 — Implement

Run `/implement` to execute the approved plan. Follow the project's coding standards (see `AGENTS.md`). Write code that matches the surrounding conventions.

---

### Step 4 — Test

Run the relevant tests:

- **Backend**: `pytest -q --tb=line -n auto` (full suite) or targeted test files for the changed area
- **Frontend**: `npm test -- path/to/file` for changed components
- **Lint/typecheck**: `ruff check`, `mypy`, `npm run lint`, `tsc` as appropriate

Fix any failures before proceeding.

---

### Step 5 — Mark Done

Only after the user explicitly approves the work:

- Update the plan document (e.g. `docs/plans/VAPT_FIX_PLAN.md`)
- Change `[ ]` to `[x]` for the completed item
- Append a short note with the commit SHA or a summary of what was done

Do NOT mark items done without user confirmation.

---

## Rules

- **One item at a time.** Do not batch multiple plan items.
- **No assumptions.** If a step is unclear, ask before proceeding.
- **Respect the gates.** Each step requires explicit approval before moving to the next.
- **Follow project conventions.** Read `AGENTS.md` for coding standards, test patterns, and commit guidelines.
