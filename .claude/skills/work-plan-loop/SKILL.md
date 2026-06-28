---
name: work-plan-loop
description: Guides a coding agent through an iterative loop for working through any itemized plan of work — new feature backlogs, bug lists, VAPT/security remediation, performance findings, compliance gaps, UX issues, or any other long-running list of activities. For each item in turn it analyzes the item (including cross-cutting impact on other functionality, backend, or frontend), confirms the approach with the user, implements it, writes antiregression tests, reports results, marks it done in the plan, then proposes the next item — without ever committing or pushing on its own. Use this whenever the user points to a plan, backlog, ticket list, remediation report, or findings list and asks to work through it, go through it one item at a time, or execute it — even if the word "plan" never comes up.
---

# Work Plan Loop

This skill turns a list of work items into a steady, repeatable loop: one item at a time, fully analyzed, confirmed, implemented, tested, and closed out before moving to the next. It's deliberately not tied to any single kind of work — new features, bug fixes, a VAPT remediation list, a performance backlog, compliance gaps, UX issues, or any other long plan of activities all fit the same loop.

**One rule has no exceptions:** this loop never runs `git commit`, `git push`, or the equivalent in another VCS — not while implementing, not while marking an item done, not if the user asks for it directly mid-loop. Committing and pushing are checkpoints the user makes deliberately; the loop only ever drafts the command, never runs it. Everything else in this skill is open to judgment. This isn't.

## Step 1 — Find and read the plan

If the user hasn't said where the plan lives or which one to use, ask before doing anything else — don't guess at a file.

Read the whole plan once before touching any single item. Plans show up in all kinds of shapes — a markdown checklist, a table with a status column, a CSV export from a tracker, a flat list of findings. Get a feel for how items are structured, whether a "done/status" convention already exists, and whether there's an implied order or set of dependencies. You'll need this context to pick items sensibly and to flag progress later.

## Step 2 — Pick the next item

Default to the next open item in the plan's own order. If you have a good reason to deviate — a dependency, something blocking several other items, a quick win worth batching with what you just did — say so and let the user confirm before you switch the order. Don't silently reorder the plan.

## Step 3 — Analyze and confirm

Before writing any code, explain the item in plain terms:

- **Problem** — what's actually wrong or missing
- **Solution** — what you intend to do about it
- **Impact** — what it touches, and what touches it back

Treat impact as something to verify, not just describe. Actively check the codebase for what else depends on this area — other modules or services calling into it, the backend/frontend contract if the change crosses that boundary, other items in the plan that might quietly assume the current behavior. A plan item almost never spells out its own blast radius; confirming it is part of this step, not an afterthought left for later.

Then stop and ask the user to confirm the approach. This isn't a formality — a wrong assumption at this stage compounds: tests get written against the wrong behavior, the item gets marked done on the wrong basis, and the next item may build on shaky ground.

Only propose alternatives when there's a genuine tradeoff worth surfacing — different risk, different blast radius, different long-term cost. Don't manufacture options just to look thorough; if there's one sensible way to do it, say so and move on.

## Step 4 — Implement

How you implement is up to you. If the project already has its own conventions skill, architecture doc, or coding standards in context, follow those — this skill governs the loop, not the implementation details. Otherwise, use your best engineering judgment and stay consistent with what's already in the codebase.

Implementing means changes in the working tree, full stop — see the non-negotiable rule above.

## Step 5 — Write antiregression tests

Add tests appropriate to what changed — unit, integration, frontend/e2e, whatever the change actually calls for. These aren't just a check for today; they're meant to be re-run later, possibly much later, to catch regressions as the plan grows. Two things matter for that to work well:

- **Keep tests runnable at different granularities.** Split them across files by module or feature area, so the suite can run in full or just for the part that changed. One giant test file defeats the purpose the first time someone needs a quick check on a single area.
- **Pin behavior, not just the happy path.** The goal is for a future run to notice if this item's functionality breaks, so cover the cases that matter for that — not exhaustive coverage for its own sake.

Run the suite in quiet/concise mode (e.g. `-q`, a dot reporter, suppressed stack traces on green runs). The loop will touch many items over time, and a wall of passing-test output adds nothing the next time it runs.

## Step 6 — Report to the user

Tell the user plainly what changed and what the tests now verify. Keep it tight: what was the problem, what you did, what's now covered, anything they should know before moving on. No need to repeat the full diff or paste back file contents they can already see.

## Step 7 — Mark the item done

Flag the item as done directly in the plan, using whatever convention the plan already has (a checkbox, a status column, an emoji). If there's no existing convention, propose a simple one and use it consistently from then on.

No commit or push here either. Draft the exact `git add` / `git commit -m "..."` (and `git push` if relevant) command and message, and hand it to the user — running it is always their action, never yours.

## Step 8 — Check in, then propose the next item

Before moving on, take stock of the loop itself. If several items have gone by and a lot of file reads, tool output, and back-and-forth have piled up in the conversation, say so and suggest the user compact the context or start a fresh session before continuing (a `/compact`-style command if the tool offers one, or simply a new chat). Long work-plan loops are exactly the kind of session that grows large enough to hurt the quality of what comes next — better to flag it early than let it degrade quietly.

Then show the next candidate item — enough of it that the user can say "go" without re-reading the whole plan — and wait for confirmation before starting Step 3 on it. If the plan is exhausted, say so plainly instead of inventing more work.

## Throughout the loop

- Be economical with tokens: don't restate the whole plan or dump full files back at the user each cycle.
- Be clear, not clinical: explain things so someone who hasn't been staring at the diff can follow what happened and why.
- This skill stays general on purpose. It doesn't prescribe a tech stack, a test framework, or a commit style — those come from the project itself or from other skills already in play. If a particular plan type (VAPT, performance, UX, ...) ends up needing its own deeper guidance over time, that's a good candidate for a `references/` file rather than baking it into the core loop.
