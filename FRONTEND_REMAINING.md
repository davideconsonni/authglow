# AuthGlow Frontend — Remaining Work

> Based on full OpenAPI audit and UX review.  
> Pick one or more items per deployment cycle.

---

## Phase 14 — Admin Playground & OAuth2 Debugging

The Playground page is a blank shell. Make it a functional OAuth2/OIDC debug console.

- [x] **14.1** Token Introspection — `POST /oauth2/introspect` with a textarea for the token, show decoded claims
- [ ] **14.2** UserInfo — `GET /oauth2/userinfo` button that shows the OIDC user info response
- [ ] **14.3** Revoke token — `POST /oauth2/revoke` with token input + feedback
- [ ] **14.4** API Key token exchange — `POST /api/token/api-key` demo
- [ ] **14.5** OIDC Discovery — show `GET /.well-known/openid-configuration` response
- [ ] **14.6** Format responses as pretty-printed JSON with syntax highlighting
- [ ] **14.7** E2E test: create client → authorize → introspect → revoke flow

---

## Phase 15 — Performance & Code Splitting

Bundle is 927KB at build time. Reduce with lazy loading.

- [ ] **15.1** `React.lazy()` + `Suspense` for all admin pages (they import Recharts, the heaviest dep)
- [ ] **15.2** `React.lazy()` for security page (imports webauthn, MFA components)
- [ ] **15.3** Add `<Suspense fallback={<LoadingState />}>` in App.tsx route definitions
- [ ] **15.4** Verify build chunk sizes with `vite build --report`
- [ ] **15.5** E2E test: ensure lazy-loaded routes render without flash of empty content

---

## Phase 16 — E2E Test Robustness

Current E2E tests are fragile (rate-limit, inconsistent selectors).

- [ ] **16.1** Single login per test suite via token injection (skip `/api/token` entirely)
- [ ] **16.2** Add `data-testid` attributes to key interactive elements (login button, submit, modal actions)
- [ ] **16.3** E2E coverage for critical user flows:
  - [ ] Login → Dashboard → Profile → Logout
  - [ ] Create API key → Copy → Revoke
  - [ ] Create OAuth client → Rotate secret → Delete
  - [ ] Admin: Search user → Toggle active → View detail drawer
  - [ ] Admin: Bulk select → Deactivate → Verify
- [ ] **16.4** Visual regression: screenshot comparison for key pages (auth, dashboard, profile)
- [ ] **16.5** Run E2E in CI mode with `--reporter=json` for programmatic pass/fail checks

---

## Phase 17 — Mobile Responsive Polish

- [ ] **17.1** Auth pages: verify split layout collapses to single column on `<md`
- [ ] **17.2** Admin tables: horizontal scroll with sticky first column on `<lg`
- [ ] **17.3** Sidebar: auto-close on route change for mobile
- [ ] **17.4** Form modals: full-screen on mobile, dialog on desktop
- [ ] **17.5** Touch targets: ensure all buttons > 44px on mobile
- [ ] **17.6** E2E test: run full suite at mobile viewport (375x812)

---

## Phase 18 — Polish & QA

- [ ] **18.1** Audit all pages for WCAG AA: focus rings, aria labels, keyboard navigation
- [ ] **18.2** Add `<title>` per route (document.title via useEffect or helmet)
- [ ] **18.3** 404 page with branded illustration + back-to-dashboard link
- [ ] **18.4** Rate-limit friendly UI: show countdown when backend returns 429
- [ ] **18.5** Toast/notification system for success/error messages (replace inline divs)
- [ ] **18.6** Consistent loading skeleton for tables (not just spinner)

---

## Suggested Execution Order

```
Phase 14 [PLAYGROUND]    ██████████
Phase 15 [CODE SPLIT]    ████████░░
Phase 16 [E2E TESTS]     ██████████
Phase 17 [MOBILE]        ██████░░░░
Phase 18 [POLISH]        ████████░░
```
