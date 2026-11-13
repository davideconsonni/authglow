# GitHub Copilot Instructions

This repository uses `AGENTS.md` as the canonical source of truth for all coding conventions, architecture, and testing workflows.

Always consult and adhere to [AGENTS.md](../AGENTS.md).

### Critical Testing & Non-Regression Rules
1. **Never run bare `pytest`, `npm test`, or Playwright across the entire repository** during task or feature implementation.
2. **Targeted Verification**: Always verify changes using only the single affected test file (e.g. `pytest tests/unit/test_<module>.py`) or `./scripts/affected_tests.py --run`.
3. **Frontend Verification**: Use `npx vitest related --run <files>` or `npm test -- path/to/file.test.ts`.
4. **Playwright E2E**: Never trigger Playwright suites unless specifically implementing or debugging an E2E spec.
5. **Full Suite**: Only for final verification before opening a PR. Pytest is already preconfigured to run parallelized (`-n auto`).
