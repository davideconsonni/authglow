# Frontend Coverage Plan — estensione UI verso endpoint backend non surfacciati

> **Status**: piano attivo, una fase alla volta.
> **Source**: analisi di copertura frontend ↔ backend (2026-08-25). ~95% degli endpoint backend (~150, 21 router)
> ha già una superficie UI; questo piano chiude i gap residui.
> **Workflow**: per ogni fase → piano dettagliato → grill → implement → test → mark done (solo dopo approvazione utente).

## Gap trovati (analisi 2026-08-25)

| # | Endpoint backend | Uso frontend | Impatto |
|---|------------------|--------------|---------|
| 1 | flag `password_expired` mai verificato al login (`api/auth.py`) | nessuno | **Funzionale end-to-end** — feature morta |
| 2 | `GET /api/admin/claim-templates` (`claim_policy.py:359`) | nessuno | UX — regole claim policy scritte da zero |
| 3 | `GET /oauth2/jwks/status` (`oidc.py`) | nessuno | Info pubblica JWKS non visibile in admin |
| 4 | `GET /api/admin/settings/schema` (`admin_settings.py:560`) | nessuno | Form settings hardcoded invece di schema-driven |
| 5 | `/oauth2/register` DCR CRUD (`oidc.py`) | nessuno | Nessun flow Playground per Dynamic Client Registration |
| 6 | `POST /api/auth/my-token` (`auth.py:2077`) | nessuno | Endpoint debug inutilizzato |
| 7 | `/oauth2/logout` RP-initiated GET/POST (`oidc.py`) | nessuno | Nessun flow Playground |
| 8 | `POST /api/password/change`, `GET /api/users`, `GET /api/admin/keys/{id}`, letture detail RBAC | nessuno | Ridondanti — candidati a deprecazione |

Falsi allarmi verificati (non-gap): federation `PUT /admin/providers/{id}` esiste (`federation.py:685`);
passkey delete usato (`PasskeyManager.tsx:68`); `GET /api/users` sostituito da `/api/admin/users`.

---

## Checklist fasi

- [x] **Fase 1 — Cambio password forzato (`password_expired`)** ⚠️ gap funzionale
      Login verifica il flag → pagina dedicata di cambio password → reset flag via `set_password(require_change=False)`.
- [ ] **Fase 2 — Claim Templates nel UI**
      Menu "Parti da un template" in `TokenClaimsTab` / `ApiKeyClaimsTab` alimentato da `GET /api/admin/claim-templates`.
- [ ] **Fase 3 — Stato pubblico JWKS**
      Card "Stato JWKS pubblico" in `AdminJwkKeysPage` alimentata da `GET /oauth2/jwks/status`.
- [ ] **Fase 4 — Admin Settings schema-driven**
      Usare `GET /api/admin/settings/schema` per generare/validare i campi di `AdminSettingsPage`.
- [ ] **Fase 5 — Playground: flow DCR + RP-Initiated Logout**
      Due nuovi flow component registrati in `components/playground/flows.ts`.
- [ ] **Fase 6 — "Il mio token"**
      Surface di `GET /api/auth/my-token` con il componente `JwtDecoder` esistente (Dashboard o Sessioni).
- [ ] **Fase 7 — Pulizia endpoint ridondanti**
      Deprecazione/rimozione backend di `/api/password/change`, `GET /api/users`, `GET /api/admin/keys/{id}` (decisione dopo verifica d'uso).

---

## Fase 1 — Cambio password forzato (dettaglio)

### Verifica preliminare (2026-08-25, confermata nel codice)

- Flag esiste: `models/user.py:60`; settato dall'admin in `api/admin.py:843`; presente nel token payload `models/token.py:21`; esposto in `AdminUserDetail` (`models/admin.py:50,76`).
- **Il login NON lo controlla**: `api/auth.py` `authorize_post` verifica le credenziali (~:903) e prosegue su MFA (:930) / auth-code senza mai leggere `user.password_expired`.
- Reset flag già disponibile: `UserService.set_password(user_id, hash, require_change=False)` → `repositories/file/user.py:481` scrive `password_expired = require_change`.
- Il frontend gestisce già risposte strutturate dal login: `OAuthAuthorizePage.tsx:372-384` (`redirect_url` / `consent_required` / `mfa_required`).
- Nessuna pagina di cambio password forzato esistente.

### Modifiche backend

1. **`backend/authglow/api/auth.py`** — in `authorize_post`, dopo i check suspended/lockout e PRIMA del ramo MFA e di `record_login`:
   ```python
   if user.password_expired:
       return {"password_expired": True, "email": user.email}
   ```
   Credenziali verificate (non è un failed login), ma login non completato: nessun cookie, nessun auth code, nessun `last_login`.
2. **`backend/authglow/api/password_reset.py`** — nuovo endpoint `POST /api/auth/expired-password/change` (`@limiter.limit("5/minute")`):
   - Input model `ExpiredPasswordChange`: `email`, `current_password`, `new_password`.
   - Flow: `get_user_by_email` → verify current password → `PasswordValidator.validate(new)` → new ≠ old → hash → `set_password(require_change=False)` → audit `password_changed_after_expiry`.
   - Errori anti-enumeration: `401 Invalid credentials` (utente inesistente o password errata); `400` se flag non attivo.
3. **Test**: nuovo `backend/tests/unit/test_expired_password_flow.py`
   - authorize ritorna `{"password_expired": True}` e non crea auth code; flag False → nessun campo.
   - change: happy path (flag resettato + hash aggiornato + audit), credenziali errate 401, password debole 400, uguale alla vecchia 400, flag non attivo 400, utente inesistente 401.

### Modifiche frontend

| File | Modifica |
|------|----------|
| `frontend/src/lib/constants.ts` | `ROUTES.AUTH.PASSWORD_EXPIRED = '/auth/password-expired'` |
| `frontend/src/pages/auth/ForceChangePasswordPage.tsx` (nuovo) | react-hook-form + zod (current/new/confirm), POST al nuovo endpoint, toast + redirect al login. `AuthLayout`, errori `role="alert"`, `data-testid="force-change-submit"` |
| `frontend/src/pages/OAuthAuthorizePage.tsx` (~:384) | `if (data.password_expired) navigate(ROUTES.AUTH.PASSWORD_EXPIRED, { state: { email } })` — pattern `mfa_required` |
| `frontend/src/App.tsx` (~:197) | Rotta dentro `GuestRoute` |
| `frontend/src/pages/auth/ForceChangePasswordPage.test.tsx` (nuovo) | submit → payload corretto; errore visibile; redirect dopo successo |

### Rischi & compatibilità

- Client programmatici vedono body JSON nuovo HTTP 200 (coerente col pattern `mfa_required`; flusso first-party).
- Sessioni pregresse non revocate (scope minimale; estendibile in seguito).
- Brute force sul nuovo endpoint mitigato da rate limit + obbligo password corrente.
- Interazione MFA: `password_expired` prevale sull'MFA challenge (il cambio richiede solo la prova delle credenziali).

### Note di completamento

_(da compilare a fine fase: commit SHA o riepilogo)_

**✅ Completata 2026-08-25.** Riepilogo:

- **Backend**: gate `password_expired` in `authorize_post` (`api/auth.py`, ritorna `{"password_expired": true, "email": ...}` senza cookie/auth-code/MFA); endpoint `POST /api/auth/expired-password/change` in `api/password_reset.py` (rate limit 5/min, audit `password_changed_after_expiry`); modello `ExpiredPasswordChange` in `models/password_reset.py`.
- **Frontend**: `ForceChangePasswordPage.tsx` (nuovo, su `AuthLayout`) + rotta `/auth/password-expired` in `GuestRoute` + branch `password_expired` in `OAuthAuthorizePage.handleLogin`.
- **Bug fix collaterale** (emerso dal test manuale): `UserService.set_password` invalidava solo la cache per-id; ora invalida anche quella per-email — senza di che il rilogin post-cambio verificava l'hash STALE → loop di cambio password infinito. Regression test con servizio+repo+cache reali: `TestSetPasswordCacheInvalidation`.
- **Debito di test pre-esistente ripagato**: i 6 fallimenti di `TestTokenEndpointClientAuth` erano causati dal WIP (decorator rate-limit sul token endpoint, envelope RFC 6749 §5.2, PKCE spostato su authorize) non riflesso nei test. Riparati solo i test, nessun cambio produzione.
- **Verifica**: 11/11 unit backend nuovi, 6/6 component test frontend, 19/19 `test_auth_api.py`, tsc/eslint/ruff puliti. Flusso manuale expire→cambio→rilogin confermato dall'utente.
- Commit di riferimento: incluso in `3e895f1` (feat: implement forced password change for expired accounts and update OAuth2 error handling).
