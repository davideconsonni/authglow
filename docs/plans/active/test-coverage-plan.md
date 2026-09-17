---
type: plan
status: active
ids: COV-NNN
---

# AuthGlow Test Coverage Plan

Baseline Codecov (commit `2de07f0`, 2026-09-14 — **precedente ai merge AUTH-001/005/admin-events, ribasare alla prima sessione**):

- **Totale: 66.39%** — 21216 linee, 14086 hit, 6037 miss, 1093 partial
- **Backend: ~84.5% di media** — 7 file sotto il 50%
- **Frontend: ~32% di media** — 55 file su 131 a 0% (mai toccati dai test)

Ogni item è tracciato con checkbox `[ ]`. Segnare `[x]` solo con test verdi + lint/typecheck puliti sui file toccati, aggiungendo il riferimento al commit.

## Sessione 0 — Ribasare (una tantum, prima di tutto)

- [x] COV-000: baseline locale su `main` (2026-09-17) — backend 82.45% statements, frontend 37.49% linee / 549 test verdi. Upload CI ok per entrambi (nessun bug di upload). Trovate e sistemate 2 regressioni AUTH-005 in `test_offline_access_gate.py` (commit a parte). Dettagli nel Diario.

## Backend — file sotto il 50% (priorità alta)

- [x] COV-BE-001: `backend/authglow/api/rbac.py` — 29.8% → 98% (178/178 statement, 5 partial branch difensivi). Nuovo `tests/unit/test_rbac_api.py` (36 test: tutti gli endpoint + 409/404/403 + anti-lockout admin + audit). Vedi Diario.
- [x] COV-BE-002: `backend/authglow/services/passkey.py` — 36.1% → 99% (83/83 statement, 1 partial branch difensivo sul retry loop). Nuovo `tests/unit/test_passkey_service.py` (20 test: init/factory, CRUD, usage+retry CAS, options+transport filter, verify success/errori con crypto mockata). Vedi Diario.
- [x] COV-BE-003: `backend/authglow/api/email_verification.py` — 38.6% → 100% (44/44 statement, tutti i branch). Nuovo `tests/unit/test_email_verification_api.py` (8 test: verify success±token/failure + resend auth/anonima/422/failure). Vedi Diario.
- [x] COV-BE-004: `backend/authglow/api/passkey.py` — 40.7% → 100% (151/151 statement, tutti i branch). Nuovo `tests/unit/test_passkey_api.py` (19 test: get_current_user, registration begin/complete±, auth begin±, list/delete) + 1 negative test in `test_passkey.py` (utente cancellato → 400 generico anti-enumeration, comportamento intenzionale invariato). Vedi Diario.
- [ ] COV-BE-005: `backend/authglow/api/federation.py` — 46.1%, 133 scoperte (il file più pesante del gruppo)
- [ ] COV-BE-006: `backend/authglow/api/phone_verification.py` — 48.6%, 18 scoperte
- [ ] COV-BE-007: `backend/authglow/api/password_reset.py` — 49.6%, 66 scoperte

## Backend — fascia 50–66% (priorità media)

- [ ] COV-BE-008: `backend/authglow/api/user_profile.py` — 51.0%, 47 scoperte
- [ ] COV-BE-009: `backend/authglow/api/mfa.py` — 52.1%, 89 scoperte
- [ ] COV-BE-010: `backend/authglow/services/device_auth.py` — 55.8%, 38 scoperte
- [ ] COV-BE-011: `backend/authglow/api/oauth_client.py` — 57.0%, 49 scoperte
- [ ] COV-BE-012: `backend/authglow/api/api_key.py` — 57.5%, 68 scoperte
- [ ] COV-BE-013: `backend/authglow/api/device_auth.py` — 58.5%, 42 scoperte
- [ ] COV-BE-014: `backend/authglow/api/par.py` — 61.2%, 13 scoperte (piccolo, chiudere in fretta)
- [ ] COV-BE-015: `backend/authglow/core/permissions.py` — 62.7%, 22 scoperte
- [ ] COV-BE-016: repository file `device_authorization` / `admin_action` / `security_event` / `login_history` — 58–64%, ~13–37 scoperte ciascuno
- [ ] COV-BE-017: `backend/authglow/api/admin.py` — 66.0%, 198 scoperte (il file con più linee scoperte in assoluto; da spezzare per endpoint)

## Frontend — pagine a 0% (priorità alta, sono le più visibili)

- [ ] COV-FE-001: `frontend/src/pages/ApiKeysPage.tsx` — 0%, 195 linee
- [ ] COV-FE-002: `frontend/src/pages/admin/AdminRbacPage.tsx` — 0%, 178 linee
- [ ] COV-FE-003: `frontend/src/components/layout/Sidebar.tsx` — 0%, 101 linee
- [ ] COV-FE-004: `frontend/src/pages/DashboardPage.tsx` — 0%, 52 linee
- [ ] COV-FE-005: `frontend/src/pages/DeviceVerificationPage.tsx` — 0%, 65 linee
- [ ] COV-FE-006: pagine admin piccole a 0% — `AdminConsentsPage`, `AdminDashboardPage`, `AdminDeviceAuthsPage`, `AdminPasswordResetsPage`, `AdminPlaygroundPage`, `AdminSessionsPage` (20–39 linee ciascuna, accorparle in una sessione)

## Frontend — playground flows a 0% (priorità alta, toccati da AUTH-005)

- [ ] COV-FE-007: `AuthorizationCodeFlow.tsx` (91), `PkceFlow.tsx` (88), `RefreshTokenFlow.tsx` (57), `ClientCredentialsFlow.tsx` (53), `IntrospectionFlow.tsx` (59), `ApiKeyExchangeFlow.tsx` (44), `GenericRequestFlow.tsx` (37), `OidcDiscoveryFlow.tsx` (33)

## Frontend — auth/profile a 0% o quasi (priorità media)

- [ ] COV-FE-008: `MFAVerifyForm.tsx` (93), `PasskeyLoginButton.tsx` (34), `FederationLoginButtons.tsx` (25), `RegisterForm.tsx` (40), `ForgotPasswordForm.tsx` (23), `ResetPasswordForm.tsx` (26), `OAuthCallbackPage.tsx` (27)
- [ ] COV-FE-009: `MFAEnrollment.tsx` (69), `PasskeyManager.tsx` (40), `ChangePasswordForm.tsx` (34), `ChangeEmailForm.tsx` (21), `BackupCodes.tsx` (32), `ProfilePage.tsx` (79), `SetupWizard.tsx` (19)

## Frontend — lib/stores e UI primitives (priorità bassa)

- [ ] COV-FE-010: `lib/utils.ts` (26), `stores/playgroundStore.ts` (21), `lib/loginStorage.ts` (6)
- [ ] COV-FE-011: primitives `ui/*`, `shared/*`, `layout/*` minori a 0% — solo smoke test di render, niente logica (chiudere in blocco se avanza tempo)

## Regole per ogni sessione

```text
1. Un item alla volta, branch dedicato (fix/coverage-<id> o chore/)
2. Test solo sui file dell'item — mai suite completa salvo cambi a core/
3. Lint + typecheck solo sui file toccati
4. Coverage locale prima/dopo (pytest --cov / vitest --coverage) per provare il guadagno
5. Spuntare la checkbox con riferimento al commit/PR
6. Mai abbassare la coverage esistente: se un refactor toglie linee coperte, aggiungere test
```

Non chiudere un item solo perché "ho aggiunto qualche test": è **DONE** quando le linee scoperte del file scendono in modo stabile e la suite dell'area resta verde.

## Handoff tra sessioni

Ogni sessione finisce scrivendo qui sotto (sezione Diario) tre righe:

```text
- Item lavorato + commit/PR
- Guadagno coverage misurato (file: prima% → dopo%)
- Prossimo item consigliato + note (branch da cancellare, flaky visti)
```

## Diario

- 2026-09-17 — COV-000 (locale, no commit): backend 82.45% statements / frontend 37.49% linee (549 passed, 6 skipped). CI verificata: entrambi gli upload configurati (`backend/coverage.xml` flag backend + `frontend/coverage/lcov.info` flag frontend), ma il workflow gira solo su schedule giornaliero + dispatch manuale — Codecov (66.39% al 2026-09-14) è vecchio di 3 giorni e non vede AUTH-001/005/admin-events. Trovate 2 regressioni AUTH-005 in `test_offline_access_gate.py` (client pubblico + secret via POST): sistemate togliendo il secret, 2/2 verdi. Suite backend completa verde a pezzi: unit a-m 859 + unit n-z 728 + repositories/conformance 821 + integration 444 = 2852 passed. Prossimo: COV-BE-001 (`api/rbac.py`).
- NOTE AMBIENTE (Windows, non riscoprire): (1) `-n auto` va OOM (0x8007000e, worker down + hang) — usare `-n 4` e mai due suite xdist in parallelo; (2) `rtk pytest` non accetta directory come argomento — usare `.venv/Scripts/python.exe -m pytest <path>` diretto; (3) mai `rtk proxy python` (bypassa il venv: `ModuleNotFoundError` ovunque); (4) riferimento CI resta ubuntu (lì `-n auto` funziona).
- 2026-09-17 — COV-BE-001 (branch `fix/coverage-rbac-api`): `api/rbac.py` 29.8% → 98%. I test esistenti coprivano solo il service: aggiunti 36 test HTTP-level con handler diretti + RBACService/UserStorage patchati (nessun disco toccato). 78 verdi con `test_rbac.py`. Prossimo: COV-BE-002 (`services/passkey.py`).
- 2026-09-17 — COV-BE-002 (branch `fix/coverage-passkey-service`): `services/passkey.py` 36.1% → 99%. Nuovo `tests/unit/test_passkey_service.py` (20 test, repo mockati + `verify_*_response` mockate; i factory sono import lazy dentro `__init__`, quindi si patcha `authglow.repositories.dependencies`, non il modulo service). 61 verdi con `test_passkey.py` + repo tests. Prossimo: COV-BE-003 (`api/email_verification.py`).
- 2026-09-17 — COV-BE-003 (branch `fix/coverage-email-verification`): `api/email_verification.py` 38.6% → 100%. Nuovo `tests/unit/test_email_verification_api.py` (8 test, service mockati via patch dei factory). Nota: gli handler hanno `@limiter.limit`, quindi serve un `Request` starlette vero (il MagicMock viene rifiutato) — stesso pattern di `test_admin_users_update._make_request`. 32 verdi con `test_email_verification.py`. Prossimo: COV-BE-004 (`api/passkey.py`).
- 2026-09-17 — COV-BE-004 (branch `fix/coverage-passkey-api`): `api/passkey.py` 40.7% (Codecov) → 100% locale. Nuovo `tests/unit/test_passkey_api.py` (19 test, handler diretti + Request starlette vera per il limiter). Scoperta lungo la strada: il 404 "User not found" di `/auth/complete` viene piegato nel 400 generico — comportamento intenzionale anti-enumeration, NON cambiato (solo test che lo pinna). 81 verdi con le suite passkey. Prossimo: COV-BE-005 (`api/federation.py`).
