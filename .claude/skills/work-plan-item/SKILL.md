---
name: work-plan-item
description: Work a single plan item (security finding, remediation task, perf item, roadmap checkbox) through verify,
  implement, test, and ship. Use when the user names a plan item ID, asks to process/triage/work a plan, or says
  "work-plan-item".
---

# Work Plan Item

Turn one plan item into a verified, tested, committed change. A **plan item** is a single checkbox entry with a stable ID
in a plan file (e.g. `VAPT-056`, `AUTH-001`, `PERF-003`).

Work the steps in order. Each step ends with a completion criterion — do not advance until it holds.

## Step 1 — Triage

Read the plan file and the item's section (scope, location, fix proposal, priority hints). If the user has not picked an
item yet, recommend exactly one and say why in one line.

Completion: one item ID is selected by the user.

## Step 2 — Verify

Never trust the plan's claim about the code. Check the current on-disk state with the cheapest precise tool available
(structural index first, then targeted file reads): the symbols named in Location, their callers, and existing tests
covering them.

Classify the item as `open`, `already-closed`, or `partial`, citing file paths and line numbers. List residual gaps, if
any. Note any drift between the plan's cited line numbers and the current code.

Completion: the classification plus gap list is reported to the user — delivered inside the Step 3 report (the Verdict
and Where-to-verify blocks), not as a separate message.

## Step 3 — Propose

Report verification + proposal as **one message** with this fixed shape. The reader is a technical colleague who must
follow the causal chain and still be able to check everything: narrative first, code references gathered at the end,
never mixed into the prose.

1. **Verdict** (title line) — item ID, `open` / `already-closed` / `partial`, plus the essence of the finding in one
   clause. If already-closed, the report stops here.
2. **How it works today** — the current mental model in 2–4 plain bullets, causal order. No file paths.
3. **Why it costs / what's broken** — the mechanism, 2–3 bullets. No file paths.
4. **What I propose** — the change at the model level, 3–5 bullets. End with *why it lands at the chosen layer* when
   the plan suggested a different one. No file paths.
5. **Trade-offs** — max 2 bullets: only decisions the user could reasonably reject, each with a one-line mitigation or
   in-repo precedent.
6. **Where to verify** — every `file:line` reference, grouped per claim, compact. The only block carrying paths.
7. **Out of scope** — one line, names only.

Formatting rules for the report: one idea per bullet; short sentences; hard cap ~25 lines (blocks 1–7, question
excluded); block titles localized to the user's language. Clarity comes from the structure, never from attitude:
no sarcasm, no editorializing, no rhetorical questions, no dramatized metaphors.

Then ask exactly one question in plain text — **proceed / add scope / grill-me** — with each option explained
in one line on first use (proceed = implement the minimal plan as written; add scope = widen the fix to the areas
you name; grill-me = I ask you hard questions before any code is written). A grill session happens only before
implementation, never after. If the user answers "I don't know / explain it to me", switch to explanation mode:
re-explain finding → fix → consequences in plain words, then re-ask. Prefer plain-text questions over popup dialogs;
use a popup only after the user has accepted one.

Completion: the user picks one of the three.

## Step 4 — Implement

If the session is in read-only plan mode, stop and ask for the switch to build mode instead of editing. Keep the diff
minimal: only the hunks the plan requires, no drive-by refactors, no reformatting of unrelated lines.

Completion: the diff contains only the item's change.

## Step 5 — Prove

Tests are non-regression assets: they prove the behavior now and guard it later. Without asking further, extend the
tests of the touched area and run **only** those — never a catch-all suite. The full suite runs solely for core-layer
changes or pre-commit. Keep lint and type checks to the touched files.

Completion: targeted tests green, lint and type checks clean on touched files.

## Step 6 — Boyscout

Any garbage found along the way (dead mocks, real bugs, sloppy code, credentials in logs) is reported to the user,
never silently fixed. Pre-existing failures in untouched files are reported the same way.

Completion: the finding list is reported, or "nothing to report".

## Step 7 — Close the loop

Ask two yes/no questions:

- Tick the plan checkbox, with a Done note citing commit and tests (check first whether the plan has an internal
  changelog section to fill).
- Add a root changelog Unreleased entry (only if the change is user-visible enough to deserve one).

Completion: both answers executed.

## Step 8 — Ship

If the repo defines a flow skill (e.g. `git-release-flow`), follow it: branch plus pull request, never commit to trunk,
merge per the skill's rules. Otherwise commit directly. In all cases: write the commit message yourself, commit only
with explicit user approval, and never push — pushing is always the user's manual action, with no exceptions. After the
merge, delete the work branch.

Present each gate action as exactly three things: the command block (if the user must run something), the reply you
expect from them, and one sentence on what happens next. Do everything else yourself without narrating it.

After an amend + force-push, state explicitly that the SAME pull request updates in place: repeat its number and URL,
name the new commit SHA, and say CI will re-run on it — no new PR will appear. On PR creation, print the PR URL on
its own prominent line.

Completion: change committed on the right branch (or trunk, if no flow skill exists) and branch cleaned up after merge.

## Step 9 — Next

Ask whether to switch back to plan mode and work the next plan item.

Completion: the user's answer is obtained.

## Standing rules

- Code comments are in English, explain the why, and never reference plan IDs — plans can disappear, the code stays.
- One question per decision; propose options with one marked recommended.
- Language: write like you speak to a busy colleague — plain, direct, no idioms, no rhetorical flourishes, no
  colorful metaphors. Tone stays neutral and professional: never mock, editorialize, or adopt a persona voice; the
  reader trusts the analysis, not the theatrics. Match the user's language (Italian user → Italian). Explain any term
  you cannot avoid the first time you use it (grill-me, rebase, amend, force-push).
- Never auto-fix a pre-existing failure without being asked.
