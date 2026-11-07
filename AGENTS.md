# AGENTS.md

Essential instructions for AI coding agents working in the AuthGlow repository.

## Project Overview

AuthGlow is an authentication and OAuth2/OIDC platform with a Python 3.13/FastAPI backend (`backend/`) and a React 19/TypeScript frontend (`frontend/`).

## Progressive Context Router

Before writing code or designing changes, consult the modular documentation on demand:

| Domain | Document to Read |
|---|---|
| Architecture & where to add code | [`ARCHITECTURE.md`](ARCHITECTURE.md) |
| Repositories & storage backends | [`docs/internals/architecture/repository-pattern.md`](docs/internals/architecture/repository-pattern.md) |
| RBAC permissions & admin gating | [`docs/internals/architecture/rbac-authorization.md`](docs/internals/architecture/rbac-authorization.md) |
| Custom token claims & resolvers | [`docs/internals/architecture/claim-policy.md`](docs/internals/architecture/claim-policy.md) |
| Audit logging integration | [`docs/internals/guides/audit-logging.md`](docs/internals/guides/audit-logging.md) |
| Secret management & GitGuardian | [`docs/internals/security/secret-management.md`](docs/internals/security/secret-management.md) |
| OAuth2 / OIDC protocol flows | [`docs/product/flows/README.md`](docs/product/flows/README.md) |
| Visual design & CSS tokens | [`DESIGN.md`](DESIGN.md) |

## CodeGraph

If a `.codegraph/` index is present, use the `codegraph_explore` tool before grep, find, or reading source files to understand or locate code. It returns relevant symbols, source, call paths, and dependencies in one query.

## Build & Dev Commands

### Backend (from `backend/`)

```bash
uvicorn main:app --reload            # Dev server
pytest tests/unit/test_jwt.py        # Run single test file
python scripts/affected_tests.py --run   # Run only tests affected by changed files
pytest -q --tb=line -n auto          # Run full suite (parallel via pytest-xdist)
ruff check authglow/                 # Lint
ruff format authglow/                # Format
mypy authglow/                       # Type check
```

### Frontend (from `frontend/`)

```bash
npm run dev                          # Dev server
npm run build                        # Build (type-check + bundle)
npm run lint                         # Lint
npm test                             # Unit tests (vitest)
npm test -- path/to/file             # Run single test file
npx playwright test                  # E2E tests
```

## Anti-Regression & Testing Rules

1. **Test Scope**: Run only the test files matching the changed area (e.g., modified `services/jwt.py` → `pytest tests/unit/test_jwt.py`). Automate the mapping with `python scripts/affected_tests.py` from `backend/` (prints the affected test paths; add `--run` to execute them, `--base origin/main` for committed changes). Frontend equivalent: `npx vitest related --run <changed files>`. Run the full suite (`-n auto`) only for `core/` changes or prior to final completion.
2. **Bash Timeout**: Pass `timeout: 300000` to the Bash/shell tool when executing the full test suite.
3. **Test Isolation**:
   - Never modify `tests/conftest.py` for isolated feature testing.
   - Inject `settings=test_settings` explicitly in service/repository constructors to bypass `lru_cache` and prevent state contamination across workers.
   - Keep `bcrypt_rounds=4` in test settings.
   - Never hardcode real secrets or generic password hashes: use `secrets.token_urlsafe()` and test fixtures from `conftest.py`.
4. **Pre-Existing Failures**: Separate test failures into (a) files you touched (must fix) and (b) untouched files (report clearly, ask user before investigating).

## Core Conventions

### Backend (Python 3.13)
- **Formatting**: ruff (line length 100, double quotes).
- **Typing**: Return type annotations required on all functions. Use `Optional[T]` (not `T | None`).
- **Dates & Times**: Always use `utcnow()` from `authglow.core.datetime` (never naive datetimes).
- **Logging**: `structlog.get_logger("authglow.audit")` exclusively. Structured JSON, no stdlib `logging`.
- **Async I/O**: File I/O via `async_io.py:AsyncFileSystem`. CPU operations (bcrypt) via `asyncio.to_thread()`.
- **Error Handling**: `fastapi.HTTPException` with explicit status codes. Domain exceptions mapped in route handlers.

### Frontend (TypeScript / React)
- **Typing**: Strict TypeScript, `verbatimModuleSyntax`, `import type` for types.
- **Components**: Functional components only. Named exports. Props interfaces named `<Component>Props`.
- **Styling**: Tailwind CSS with design tokens (`DESIGN.md`). Combine classes via `cn()`.
- **State**: Zustand for client stores, TanStack Query for server state.
- **Routing**: Import paths aliased via `@/` (maps to `src/*`). No barrel `index.ts` files.
