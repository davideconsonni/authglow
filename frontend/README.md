# AuthGlow Frontend

React 19 + TypeScript + Vite SPA: login, OAuth2 consent, MFA/passkeys, federation buttons, admin console, OAuth Playground. Served by the backend container in production (`FRONTEND_DIST_DIR`), via `npm run dev` locally.

## Commands (from `frontend/`)

```bash
npm install
npm run dev        # Vite dev server
npm run build      # production bundle (dist/)
npm run preview    # preview the built bundle
npm run typecheck  # tsc --noEmit
npm run lint       # eslint .
npm test                    # vitest (all)
npm test -- path/to/file    # single file
npx playwright test         # E2E
```

## Layout (`src/`)

- `pages/` — route components (`auth/`, `admin/`); admin pages lazy-loaded via `React.lazy()`
- `components/ui/` — shadcn/ui primitives; `components/shared|auth|admin|layout/` — feature components
- `stores/` — Zustand (`authStore`, `toastStore`, `playgroundStore`); `hooks/` — `useAuth`, `useApi`, `useTheme`, …
- `lib/` — `api.ts` (HTTP client + `ApiError`), `constants.ts` (ROUTES, API_URL), `jwt.ts`, `utils.ts`

## Conventions

- `@/` alias → `src/*`; `import type` for type-only imports; no barrel `index.ts` re-exports.
- Forms: react-hook-form + zod; server state: TanStack Query via `useApiQuery`/`useApiMutation`.
- Styling: Tailwind utilities + `cn()`; `data-testid` on interactive elements for Playwright.
- Backend API base: `VITE_API_URL` (see `.env.example`); OpenAPI at `http://localhost:8000/docs`.
