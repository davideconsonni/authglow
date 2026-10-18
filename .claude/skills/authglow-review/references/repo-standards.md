# Repo standards — where to look

Read the live files; this is only an index of what to check, not a copy.

## Primary sources

| File | Governs |
| --- | --- |
| `AGENTS.md` | Code style, naming, import order, error handling, logging, Pydantic/FastAPI patterns, test conventions, audit logging, secret management. |
| `ARCHITECTURE.md` | Directory map and the "Quick Reference — Where to Add What" table. Update after structural changes. |
| `DESIGN.md` | Frontend visual design system (colors, typography). |
| `SECURITY.md` | Vulnerability reporting policy. |
| `docs/README.md` | Docs map and naming conventions. |
| `docs/reference/features.md` | Complete feature catalog, endpoint by endpoint. |

## Most-often-violated rules to check explicitly

Backend (`AGENTS.md`):

- Import order: stdlib → third-party → first-party, each alphabetically sorted; private modules use a leading underscore.
- `Optional[X]` not `X | None`; return annotations on every function.
- structlog only (no stdlib `logging`); single logger `authglow.audit`; PII masked per `audit_email_log_level`.
- UTC everywhere via `authglow.core.datetime.utcnow`; crypto randomness via `secrets`.
- FastAPI: `router = APIRouter()` per module, DI via `Depends(get_<service>)`, rate limits with `@limiter.limit(...)`, `response_model` on decorators, handlers `async def`, file I/O via `asyncio.to_thread`.
- Repository pattern: services depend on Protocols, not impls; cross-entity atomicity (locks) lives in services; lru_cache bypass via explicit `settings=` in factories.
- Audit logging on every security-relevant endpoint (auth, token lifecycle, user lifecycle, admin, API keys, OAuth2/OIDC events).
- Pydantic: `model_dump()` / `model_copy(update=...)`, not `.dict()` / `.copy()`.

Frontend (`AGENTS.md`):

- 100% functional components, named exports (except `App.tsx`); `import type` for types.
- Import order: react/lib → `@/` alias → relative co-located only. No barrel files.
- Tailwind utility classes; `cn()` for conditional classes; design tokens (`text-text-primary`, `bg-surface-1`).
- Zustand for client state, TanStack Query for server state; query keys as `string[]`; conditional queries via `{ enabled }`.
- Forms via react-hook-form + zod; `role="alert"` on errors; `data-testid` for E2E.
- Accessibility: `aria-label` on icon-only controls, `htmlFor`/`id` on labels, semantic HTML.

## Consistency checks

- New router/service/model/repository placed per the `ARCHITECTURE.md` reference table.
- New config/env vars added to `backend/authglow/core/config.py` **and** `backend/.env.example`.
- New endpoints reflected in `docs/reference/features.md`.
- Tests colocated with the changed area, following the isolation rules in `AGENTS.md`
  (own `conftest.py` for new test packages, `settings=` passed explicitly, `bcrypt_rounds=4`,
  `xfail(strict=True, reason="OA-xxx: ...")` for known gaps).
