# AuthGlow Frontend — Piano di Sviluppo

> Basato su [`DESIGN.md`](DESIGN.md) e [`FEATURES.md`](FEATURES.md).  
> L'app React è in `frontend/`, il backend API in `backend/`.

---

## Tech Stack

| Layer | Scelta |
|-------|--------|
| Framework | React 19 + TypeScript + Vite |
| CSS | Tailwind CSS (design tokens via `tailwind.config.ts`) |
| Componenti | shadcn/ui |
| Icone | Lucide React |
| Routing | React Router v7 |
| Server state | TanStack Query v5 |
| Form validation | React Hook Form + Zod |
| Animazioni | Framer Motion |
| Charts | Recharts |
| Passkeys | `@simplewebauthn/browser` |
| HTTP client | `fetch` nativo wrappato in `lib/api.ts` |

---

## Struttura Target

```
frontend/src/
├── components/
│   ├── ui/                      # Primitivi shadcn/ui
│   ├── layout/
│   │   ├── AppShell.tsx         # Shell con sidebar + topbar + content
│   │   ├── Sidebar.tsx          # Navigazione floating
│   │   ├── TopBar.tsx           # User menu, notifiche
│   │   └── PageHeader.tsx       # Titolo + breadcrumb + azioni
│   ├── auth/
│   │   ├── LoginForm.tsx
│   │   ├── RegisterForm.tsx
│   │   ├── ForgotPasswordForm.tsx
│   │   ├── ResetPasswordForm.tsx
│   │   ├── MFAVerifyForm.tsx
│   │   └── SocialLogin.tsx
│   ├── oauth/
│   │   └── ConsentScreen.tsx
│   ├── setup/
│   │   └── SetupWizard.tsx
│   ├── dashboard/
│   │   ├── StatsCard.tsx
│   │   ├── ActivityFeed.tsx
│   │   └── QuickActions.tsx
│   ├── profile/
│   │   ├── ProfileForm.tsx
│   │   ├── ChangePasswordForm.tsx
│   │   ├── ChangeEmailForm.tsx
│   │   ├── MFAEnrollment.tsx
│   │   ├── BackupCodes.tsx
│   │   ├── TrustedDevices.tsx
│   │   ├── PasskeyManager.tsx
│   │   ├── SessionList.tsx
│   │   └── ApiKeyList.tsx
│   ├── admin/
│   │   ├── StatsOverview.tsx
│   │   ├── StatsTimeseries.tsx
│   │   ├── UserTable.tsx
│   │   ├── UserDetail.tsx
│   │   ├── OAuthClientTable.tsx
│   │   ├── OAuthClientForm.tsx
│   │   ├── SessionTable.tsx
│   │   ├── ConsentTable.tsx
│   │   ├── ApiKeyTable.tsx
│   │   ├── RoleTable.tsx
│   │   ├── PermissionTable.tsx
│   │   ├── JwkKeyTable.tsx
│   │   └── PasswordResetTable.tsx
│   └── shared/
│       ├── LoadingState.tsx
│       ├── ErrorState.tsx
│       ├── EmptyState.tsx
│       └── ConfirmDialog.tsx
├── hooks/
│   ├── useAuth.ts
│   ├── useApi.ts
│   └── useTheme.ts
├── lib/
│   ├── api.ts
│   ├── constants.ts
│   └── utils.ts
├── pages/
│   ├── auth/
│   │   ├── LoginPage.tsx
│   │   ├── RegisterPage.tsx
│   │   ├── ForgotPasswordPage.tsx
│   │   ├── ResetPasswordPage.tsx
│   │   ├── MFAVerifyPage.tsx
│   │   └── EmailVerifiedPage.tsx
│   ├── OAuthConsentPage.tsx
│   ├── SetupPage.tsx
│   ├── DashboardPage.tsx
│   ├── ProfilePage.tsx
│   ├── SecurityPage.tsx
│   ├── SessionsPage.tsx
│   ├── ApiKeysPage.tsx
│   └── admin/
│       ├── AdminDashboardPage.tsx
│       ├── AdminUsersPage.tsx
│       ├── AdminOAuthClientsPage.tsx
│       ├── AdminSessionsPage.tsx
│       ├── AdminConsentsPage.tsx
│       ├── AdminApiKeysPage.tsx
│       ├── AdminRbacPage.tsx
│       ├── AdminJwkKeysPage.tsx
│       ├── AdminPasswordResetsPage.tsx
│       └── AdminPlaygroundPage.tsx
├── stores/
│   └── authStore.ts
├── styles/
│   └── globals.css
├── App.tsx
├── main.tsx
└── vite-env.d.ts
```

## Design Tokens (Tailwind Config)

I colori vanno estesi in `tailwind.config.ts`:

```ts
colors: {
  bg:   { primary: '#050816', secondary: '#0A1024', tertiary: '#11182F' },
  surface: { 1: '#121A32', 2: '#182345', 3: '#202D56' },
  brand: { violet: '#8B5CF6', magenta: '#D946EF', blue: '#60A5FA' },
  semantic: { success: '#22C55E', warning: '#F59E0B', error: '#EF4444', info: '#38BDF8' },
  text:  { primary: '#FFFFFF', secondary: '#CBD5E1', muted: '#94A3B8' },
}
```

Spacing: multipli di 8px (4, 8, 12, 16, 24, 32, 40, 48, 64, 80, 96, 128).  
Border radius: 24px per cards, 8px default.  
Box shadow: `glow-violet`, `glow-magenta`, `glow-blue` (da `DESIGN.md` §10).  
Gradienti: solo su CTA buttons e brand elements (`DESIGN.md` §5).  
Font: Inter, Segoe UI, Roboto, sans-serif.  
Motion: 150ms micro, 250ms default, 400ms complex, 500ms page transitions (`DESIGN.md` §13).  
Elevation: Level 0–4 (`DESIGN.md` §9). Glassmorphism: subtle blur + subtle transparency + subtle border (`DESIGN.md` §11).

---

## Fase 1 — Fondamenta e Design System

- [x] **1.1** Installare Tailwind CSS + postcss + autoprefixer
- [x] **1.2** Installare shadcn/ui (`npx shadcn@latest init`) e i componenti base: Button, Input, Card, Dialog, DropdownMenu, Tabs, Table, Popover, Tooltip, Command, Drawer
- [x] **1.3** Configurare `tailwind.config.ts` con tutti i design token colori (bg, surface, brand, semantic, text)
- [x] **1.4** Scrivere `styles/globals.css` con `@tailwind` directives, CSS custom properties, scrollbar dark, classi `glow-*`
- [x] **1.5** Creare `lib/constants.ts` (API base URL, route path constanti) e `lib/utils.ts` (formatters, helpers)
- [x] **1.6** Creare `lib/api.ts`: wrapper fetch con base URL, interceptor per Bearer token, gestione 401 → logout
- [x] **1.7** Creare `stores/authStore.ts` (Zustand): token, user, isAuthenticated, login(), logout(), refresh()
- [x] **1.8** Creare `hooks/useAuth.ts`: hook per accedere allo store e esporre login/logout/currentUser
- [x] **1.9** Creare `hooks/useApi.ts`: hook generico per TanStack Query (useQuery, useMutation wrappers)
- [x] **1.10** Installare React Router e configurare in `App.tsx`: layout route (protette con `AppShell`, pubbliche standalone)
- [x] **1.11** Creare `components/layout/AppShell.tsx` — sidebar floating + topbar + area contenuto con `<Outlet />`
- [x] **1.12** Creare `components/layout/Sidebar.tsx` — navigazione con icone Lucide, sezioni (Dashboard, Profile, Security, Admin), collassabile su mobile
- [x] **1.13** Creare `components/layout/TopBar.tsx` — user avatar, dropdown menu (profile, logout)
- [x] **1.14** Creare `components/layout/PageHeader.tsx` — titolo, breadcrumb, slot azioni destra
- [x] **1.15** Creare `components/shared/LoadingState.tsx`, `ErrorState.tsx`, `EmptyState.tsx`, `ConfirmDialog.tsx`
- [x] **1.16** Creare `.env` frontend con `VITE_API_URL=http://localhost:8000`

---

## Fase 2 — Autenticazione (Login, Register, Password Reset)

> **Specifiche** da [`FEATURES.md` §1] e [`DESIGN.md` §17].  
> Layout auth: brand column sinistra + form destra (desktop), stacked (mobile).

- [x] **2.1** `LoginForm.tsx` — campi email, password; React Hook Form + Zod
- [x] **2.2** `LoginPage.tsx` — brand column (logo, tagline) + `LoginForm`; supporta `?redirect=` query param
- [x] **2.3** Gestione risposta API login:
  - Successo token → salva in `authStore`, redirect alla dashboard
  - `mfa_required` → redirect a `/auth/mfa-verify?session_token=...`
  - `consent_required` → redirect a `/oauth/consent?session_token=...` (per flussi OAuth2)
  - Errore 401 → messaggio form (account lockout dopo N tentativi)
  - Errore 423 → "Account temporaneamente bloccato"
- [x] **2.4** `RegisterForm.tsx` — campi nome, cognome, email, password, conferma password; password meter visivo (policy da FEATURES.md)
- [x] **2.5** `RegisterPage.tsx` — layout auth, form, link "Hai già un account?"
- [x] **2.6** `ForgotPasswordForm.tsx` — campo email, submit → sempre messaggio "Se l'email esiste hai ricevuto un link" (anti-enumeration)
- [x] **2.7** `ForgotPasswordPage.tsx` — layout auth con form
- [x] **2.8** `ResetPasswordForm.tsx` — token da query string, campi nuova password + conferma
- [x] **2.9** `ResetPasswordPage.tsx` — layout auth; token valido → form, invalido/scaduto → messaggio errore
- [x] **2.10** `EmailVerifiedPage.tsx` — pagina standalone; token valido → success, invalido → errore con link re-send

---

## Fase 3 — MFA (TOTP, Backup Codes, Trusted Devices)

> **Specifiche** da [`FEATURES.md` §2] e [`DESIGN.md` §18].  
> Flusso: login → `mfa_required` → MFA page → verify → dashboard.

- [x] **3.1** `MFAVerifyForm.tsx` — 6 input singoli con auto-focus/auto-tab; supporta anche backup codes (8+ caratteri)
- [x] **3.2** `MFAVerifyPage.tsx` — icona sicurezza + form; riceve `session_token` via query; gestisce lockout (3 tentativi, countdown 30s)
- [x] **3.3** `SecurityPage.tsx` — hub sicurezza personale: sezioni MFA, backup codes, trusted devices, passkeys, password change
- [x] **3.4** `MFAEnrollment.tsx` — step 1: mostra QR code (base64 dal backend) + secret text + 10 backup codes da copiare/salvare; step 2: verifica con primo codice TOTP
- [x] **3.5** `BackupCodes.tsx` — lista codici rimanenti (mascherati), bottone rigenera, download, copia
- [x] **3.6** `TrustedDevices.tsx` — tabella dispositivi (nome, data, IP), bottone rimuovi

---

## Fase 4 — Passkeys (WebAuthn / FIDO2)

> **Specifiche** da [`FEATURES.md` §3] e [`DESIGN.md` §19].  
> Passkeys visualmente promosse con glow accent e icona sicurezza.

- [x] **4.1** Installare `@simplewebauthn/browser`
- [x] **4.2** `PasskeyManager.tsx` — lista passkey registrate (dispositivo, tipo, transports, data creazione, ultimo uso)
- [x] **4.3** Bottone "Aggiungi Passkey" → `POST /api/passkey/register/begin` → `startRegistration()` → `POST /api/passkey/register/complete`
- [x] **4.4** `LoginForm` integrato: pulsante "Accedi con Passkey" → `POST /api/passkey/auth/begin` → `startAuthentication()` → JWT
- [x] **4.5** Rimozione passkey con conferma dialog

---

## Fase 5 — OAuth2 Consent Screen

> **Specifiche** da [`FEATURES.md` §8] e [`DESIGN.md` §17].  
> Layout stand-alone (no sidebar), stile auth pages.

- [x] **5.1** `OAuthConsentPage.tsx` — riceve `session_token` via query
- [x] **5.2** `GET /api/oauth2/consent/check` — se già consented → redirect automatico con auth code
- [x] **5.3** `ConsentScreen.tsx` — header: logo/nome client + icona sicurezza; body: descrizione client, scope list con icone e descrizioni human-readable; footer: checkbox "Remember", bottoni "Approva" (gradient) / "Nega" (outlined)
- [x] **5.4** Risposta API consent: approved → redirect URL con auth code; denied → redirect con error

---

## Fase 6 — Setup Wizard (Primo Admin)

> **Specifiche** da [`FEATURES.md` §18].

- [x] **6.1** `SetupPage.tsx` — step 1: `GET /api/setup/check`; se setup già fatto → redirect a login
- [x] **6.2** `SetupWizard.tsx` — form email + password admin; validazione password policy; submit → `POST /api/setup/create-admin`
- [x] **6.3** Conferma creazione → messaggio success + link a login

---

## Fase 7 — Dashboard Utente e Profilo

> **Specifiche** da [`FEATURES.md` §13] e [`DESIGN.md` §20–21].

- [x] **7.1** `DashboardPage.tsx` — cards: ultimo accesso, stato MFA, sessioni attive, numero API keys; quick actions
- [x] **7.2** `ProfilePage.tsx` — form profilo (nome, cognome, avatar URL) con `PATCH /api/profile/me`
- [x] **7.3** `ChangePasswordForm.tsx` — password corrente + nuova + conferma; `POST /api/profile/me/change-password`
- [x] **7.4** `ChangeEmailForm.tsx` — nuova email + password conferma; `POST /api/profile/me/change-email`
- [x] **7.5** `SessionsPage.tsx` — `SessionList` tabella sessioni attive (client, IP, data); bottone revoca singolo + revoca tutti
- [x] **7.6** `ApiKeysPage.tsx` — `ApiKeyList` CRUD: crea (nome, scopes, scadenza), lista, revoca, elimina; key in chiaro mostrata solo alla creazione in dialog copia
- [x] **7.7** Preferenze utente: `PATCH /api/profile/me/preferences` (tema sempre dark per spec)

---

## Fase 8 — Admin Dashboard e User Management

> **Specifiche** da [`FEATURES.md` §12].

- [x] **8.1** `AdminDashboardPage.tsx` — `StatsOverview` (cards: utenti totali, attivi, MFA%, nuovi oggi/settimana/mese) + `StatsTimeseries` (grafico nuovi utenti 30gg con Recharts)
- [x] **8.2** `AdminUsersPage.tsx` — ricerca (email, nome), filtri (is_active, mfa_enabled), paginazione server-side
- [x] **8.3** `UserTable.tsx` — colonne: nome, email, MFA, attivo, data creazione, azioni
- [x] **8.4** `UserDetail.tsx` — drawer/dialog con dettaglio utente: info, scopes, stato MFA, passkeys count, ruoli; azioni: modifica, attiva/disattiva, reset MFA, elimina
- [x] **8.5** Bulk operations: seleziona utenti → attiva, disattiva, assegna scope, elimina; dialog conferma con report successi/fallimenti

---

## Fase 9 — Admin OAuth2 Clients

- [x] **9.1** `AdminOAuthClientsPage.tsx` — tabella client con colonne: nome, client_id, tipo (confidential/public), redirect URIs, grant types, attivo
- [x] **9.2** `OAuthClientForm.tsx` — dialog creazione/modifica client: tutti i campi da `FEATURES.md` §7
- [x] **9.3** Rotazione secret: bottone → `POST /api/oauth-clients/{id}/rotate-secret` → mostra nuovo secret una volta sola
- [x] **9.4** Attiva/disattiva client con toggle; elimina con conferma

---

## Fase 10 — Admin Sessioni, Consensi, API Keys, Password Resets

- [x] **10.1** `AdminSessionsPage.tsx` — tabella sessioni con filtro email, revoca singola, cleanup massivo
- [x] **10.2** `AdminConsentsPage.tsx` — tabella consensi con filtro email, revoca
- [x] **10.3** `AdminApiKeysPage.tsx` — tabella globale API keys, filtro utente, cleanup scadute
- [x] **10.4** `AdminPasswordResetsPage.tsx` — tabella token reset, statistiche, revoca per utente, cleanup

---

## Fase 11 — Admin RBAC

> **Specifiche** da [`FEATURES.md` §11].

- [x] **11.1** `AdminRbacPage.tsx` — tre tab: Permissions, Roles, User Assignments
- [x] **11.2** `PermissionTable.tsx` — CRUD permessi (`name`, `description`)
- [x] **11.3** `RoleTable.tsx` — CRUD ruoli (`name`, `description`, `permissions` multi-select)
- [x] **11.4** Assegnazione ruoli agli utenti: cerca utente, seleziona ruolo, opzionale scadenza
- [x] **11.5** Vista permessi effettivi per utente (unione ruoli)

---

## Fase 12 — Admin JWK Keys e Playground

- [x] **12.1** `AdminJwkKeysPage.tsx` — tabella chiavi JWK: kid, status (active/verifying/revoked), created_at, algoritmo; azioni: ruota, revoca
- [x] **12.2** `AdminPlaygroundPage.tsx` — console interattiva per testare endpoint OAuth2/OIDC (simile a quello del vecchio admin HTML ma in React)

---

## Fase 13 — Polish e Produzione

> **Specifiche** da [`DESIGN.md` §13,24-25,28-29].

- [x] **13.1** Tutti gli **empty states**: icona Lucide + spiegazione + CTA primario (es. "Nessun utente ancora. Invita il primo.")
- [x] **13.2** Tutti gli **error states**: messaggi friendly, mai stack traces; retry button dove appropriato
- [x] **13.3** **Loading skeletons**: per card, tabelle, form (usando `animate-pulse` con colori surface)
- [x] **13.4** **Animazioni Framer Motion**:
  - Page transitions: fade + slide-y 8px, 500ms `ease-out`
  - Stagger children per liste (cards, tabelle) con `staggerChildren: 0.05`
  - Button hover: scale(1.02), active: scale(0.98)
  - Card hover: elevate glow shadow
  - Dialog/Sheet: slide-in da destra/basso
- [x] **13.5** **Responsive**: desktop-first con breakpoint sm:640, md:768, lg:1024, xl:1280, 2xl:1536
  - Sidebar → drawer su `<md`
  - Tabelle → stacked cards su `<lg`
  - Auth pages → single column su `<md`
  - PageHeader → wrap su mobile
- [x] **13.6** **Accessibilità WCAG AA**:
  - Focus ring visibile su tutti gli elementi interattivi (`ring-2 ring-brand-violet`)
  - `aria-label` su icone e pulsanti icon-only
  - `role="alert"` su messaggi errore form
  - Keyboard navigation: Tab/Shift+Tab, Enter/Space per attivare, Escape per chiudere dialog
  - Screen reader: descrizioni per tabelle, grafici, stati vuoti
- [x] **13.7** Aggiungere `VITE_API_URL=http://localhost:8000` al `.env` o `.env.example` del frontend
- [x] **13.8** Verificare build produzione: `npm run build` senza errori

---

## Route Map Completo

```
/auth/login                        → LoginPage
/auth/register                     → RegisterPage
/auth/forgot-password              → ForgotPasswordPage
/auth/reset-password?token=...     → ResetPasswordPage
/auth/mfa-verify?session_token=...  → MFAVerifyPage
/auth/verify-email?token=...       → EmailVerifiedPage
/oauth/consent?session_token=...   → OAuthConsentPage
/setup                             → SetupPage

/dashboard                         → DashboardPage
/profile                           → ProfilePage
/security                          → SecurityPage (MFA, passkeys, password)
/sessions                          → SessionsPage
/api-keys                          → ApiKeysPage

/admin                             → AdminDashboardPage
/admin/users                       → AdminUsersPage
/admin/oauth-clients               → AdminOAuthClientsPage
/admin/sessions                    → AdminSessionsPage
/admin/consents                    → AdminConsentsPage
/admin/api-keys                    → AdminApiKeysPage
/admin/rbac                        → AdminRbacPage
/admin/jwk-keys                    → AdminJwkKeysPage
/admin/password-resets             → AdminPasswordResetsPage
/admin/playground                  → AdminPlaygroundPage
```

## API Endpoint Map

> Per ogni pagina, gli endpoint backend da chiamare.  
> Tutti i dettagli in [`FEATURES.md`](FEATURES.md).

| Pagina | Endpoint |
|--------|----------|
| Login | `POST /api/token`, `POST /oauth2/authorize` |
| Register | `POST /api/users` |
| Forgot Password | `POST /api/password/reset/request` |
| Reset Password | `POST /api/password/reset/confirm` |
| MFA Verify | `POST /api/mfa/verify-login`, `POST /oauth2/mfa-verify` |
| Email Verify | `POST /api/email/verify` |
| Setup | `GET /api/setup/check`, `POST /api/setup/create-admin` |
| OAuth Consent | `GET /api/oauth2/consent/check`, `POST /oauth2/consent` |
| Dashboard | `GET /api/users/me` |
| Profile | `GET /api/profile/me`, `PATCH /api/profile/me`, `POST /api/profile/me/change-password`, `POST /api/profile/me/change-email`, `GET /api/profile/me/preferences`, `PATCH /api/profile/me/preferences` |
| Security/MFA | `POST /api/mfa/enroll`, `POST /api/mfa/verify`, `POST /api/mfa/regenerate-backup-codes`, `GET /api/mfa/trusted-devices`, `DELETE /api/mfa/trusted-devices/{id}` |
| Passkeys | `POST /api/passkey/register/begin`, `POST /api/passkey/register/complete`, `POST /api/passkey/auth/begin`, `POST /api/passkey/auth/complete`, `GET /api/passkey/list`, `DELETE /api/passkey/{id}` |
| Sessions | `GET /api/admin/sessions` (utente usa filtro) |
| API Keys | `POST /api/keys`, `GET /api/keys`, `DELETE /api/keys/{id}`, `POST /api/keys/{id}/revoke` |
| Admin Dashboard | `GET /api/admin/stats`, `GET /api/admin/stats/timeseries` |
| Admin Users | `GET /api/admin/users/search`, `GET /api/admin/users/{id}`, `PUT /api/admin/users/{id}`, `DELETE /api/admin/users/{id}`, `POST /api/admin/users/bulk`, `POST /api/admin/users/{id}/reset-mfa` |
| Admin OAuth Clients | `POST /api/oauth-clients`, `GET /api/oauth-clients`, `GET /api/oauth-clients/{id}`, `PUT /api/oauth-clients/{id}`, `DELETE /api/oauth-clients/{id}`, `POST /api/oauth-clients/{id}/rotate-secret`, `POST /api/oauth-clients/{id}/activate`, `POST /api/oauth-clients/{id}/deactivate` |
| Admin Sessions | `GET /api/admin/sessions`, `POST /api/admin/tokens/refresh/{id}/revoke`, `POST /api/admin/sessions/cleanup` |
| Admin Consents | `GET /api/admin/oauth-consents`, `POST /api/admin/oauth-consents/{id}/revoke` |
| Admin API Keys | `GET /api/admin/keys`, `GET /api/admin/users/{id}/keys`, `POST /api/admin/keys/cleanup` |
| Admin RBAC | `POST/GET/DELETE /api/rbac/permissions`, `POST/GET/PATCH/DELETE /api/rbac/roles`, `POST/GET/DELETE /api/rbac/user-roles` |
| Admin JWK Keys | `GET /api/admin/jwk-keys`, `POST /api/admin/jwk-keys/rotate`, `POST /api/admin/jwk-keys/{kid}/revoke` |
| Admin Password Resets | `GET /api/admin/password-resets`, `GET /api/admin/users/{id}/password-resets`, `POST /api/admin/users/{id}/revoke-resets`, `POST /api/admin/password-resets/cleanup`, `GET /api/admin/password-resets/stats` |

---

## Convenzioni di Codice

- **No commenti** nel codice (salvo casi eccezionali)
- **Tailwind utility-first**: nessun inline style; tutto via classi
- **Componenti shadcn/ui**: import da `@/components/ui/`, customizzati con `cn()`
- **Form**: React Hook Form + Zod schema per ogni form; `FormField` wrapper da shadcn
- **API calls**: sempre via `lib/api.ts`; TanStack Query per GET, `useMutation` per POST/PUT/DELETE
- **Token JWT**: in `authStore`; `api.ts` interceptor lo aggiunge come `Authorization: Bearer`
- **Error boundary**: a livello pagina, wrappa in `ErrorState`
- **Nomi file**: PascalCase per componenti, camelCase per hooks/lib/utils
- **Path alias**: `@/` mappa a `src/` (configurato in `vite.config.ts` + `tsconfig.json`)

---

## Ordine di Esecuzione Consigliato

```
Fase 1  [FONDAMENTA]        ██████████  Bloccante
Fase 2  [AUTH]              ██████████  Dopo Fase 1
Fase 5  [OAUTH CONSENT]     ████████░░  Dopo Fase 2
Fase 3  [MFA]               ██████░░░░  Dopo Fase 2
Fase 4  [PASSKEYS]          ██████░░░░  Dopo Fase 3
Fase 6  [SETUP WIZARD]      █████░░░░░  Dopo Fase 1
Fase 7  [DASHBOARD UTENTE]  ██████░░░░  Dopo Fase 2
Fase 8  [ADMIN DASHBOARD]   █████░░░░░  Dopo Fase 1
Fase 9  [ADMIN CLIENTS]     ████░░░░░░  Dopo Fase 8
Fase 10 [ADMIN SESSIONI]    ████░░░░░░  Dopo Fase 8
Fase 11 [ADMIN RBAC]        ████░░░░░░  Dopo Fase 8
Fase 12 [ADMIN JWK]         ███░░░░░░░  Dopo Fase 8
Fase 13 [POLISH]            ████████░░  In parallelo
```
