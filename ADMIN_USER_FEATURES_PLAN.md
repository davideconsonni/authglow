# Admin User Management — Implementation Plan

## Feature checklist (spuntiamo man mano)

- [x] **Fase 1 — Fondamenta UI**
  - [x] 1.1 Edit user fields inline (nome, cognome, email_verified)
  - [x] 1.2 Assegna/Rimuovi scope su singolo utente
  - [x] 1.3 Filtri di ricerca avanzati (status, MFA, scope, data creazione)
- [ ] **Fase 2 — Password e Credenziali**
  - [ ] 2.1 Imposta password per utente
  - [ ] 2.2 Invia email reset password per conto dell'utente
  - [ ] 2.3 Forza scadenza password
  - [ ] 2.4 Sblocca account (rimuovi lockout)
  - [ ] 2.5 Reset tentativi falliti
- [ ] **Fase 3 — Sessioni e Token**
  - [ ] 3.1 Revoca tutte le sessioni di un utente
  - [ ] 3.2 Revoca refresh token specifici
  - [ ] 3.3 Visualizzazione sessioni attive per utente
- [ ] **Fase 4 — MFA e Passkey**
  - [ ] 4.1 Disabilita MFA forzatamente (senza reset)
  - [ ] 4.2 Rigenera backup codes
  - [ ] 4.3 Visualizzazione completa passkey nel drawer (con rimozione)
- [ ] **Fase 5 — Provisioning e Lifecycle**
  - [ ] 5.1 Crea utente con password immediata (non solo invite)
  - [ ] 5.2 Modifica email utente (con/senza verifica)
  - [ ] 5.3 Modifica telefono, avatar
- [ ] **Fase 6 — Attività e Audit**
  - [ ] 6.1 Login history per utente
  - [ ] 6.2 Eventi di sicurezza (cambi password, email, MFA)
  - [ ] 6.3 Applicazioni connesse e revoca consensi OAuth
- [ ] **Fase 7 — Advanced**
  - [ ] 7.1 Esportazione dati utente (JSON)
  - [ ] 7.2 Cronologia azioni admin su quell'utente
  - [ ] 7.3 Disattivazione temporanea / suspension programmata

---

## Dettaglio Fasi

---

### Fase 1 — Fondamenta UI

Operazioni principalmente frontend su backend già esistente.

| # | Feature | Backend | Frontend | Test |
|---|---------|---------|----------|------|
| 1.1 | Edit user fields inline (nome, cognome, `email_verified`) | ✅ `PUT /api/admin/users/{id}` già supporta `first_name`, `last_name`, `email_verified` | Nuova sezione nel drawer utente con campi editabili inline | BE: esistenti + estendere test su update fields; FE: test componenti edit |
| 1.2 | Assegna/Rimuovi scope su singolo utente | ✅ `PUT /api/admin/users/{id}` già supporta `scopes` | UI per gestire scope nel drawer (aggiungi/rimuovi badge) | BE: già coperto; FE: test interazione scope selector |
| 1.3 | Filtri di ricerca avanzati | ✅ `GET /api/admin/users/search` già supporta `is_active`, `mfa_enabled` | Dropdown filtri sopra la tabella (Status, MFA, Scopes, Data creazione) | BE: esistenti; FE: test filtri combinati |

**Backend changes (1.1-1.3):** Minimi — potenzialmente aggiungere campo `scopes` come filtro alla search.

**Frontend changes:** Principalmente AdminUsersPage.tsx + UserDrawer.

---

### Fase 2 — Password e Credenziali

| # | Feature | Backend | Frontend | Test |
|---|---------|---------|----------|------|
| 2.1 | Imposta password per utente | Nuovo endpoint `POST /api/admin/users/{id}/set-password` { `password`, `require_change` } | Bottone "Set Password" nelle azioni → modal con campo password + toggle "richiedi cambio al prossimo login" | BE: unit test nuova funzione `set_password` + test API; FE: test form submit + validazione |
| 2.2 | Invia email reset password | Nuovo endpoint `POST /api/admin/users/{id}/send-password-reset` (riusa flusso reset esistente) | Bottone "Send Password Reset" → confirm dialog | BE: test trigger email; FE: test confirm + toast |
| 2.3 | Forza scadenza password | Nuovo campo `password_expired: bool = False` su User + endpoint `POST /api/admin/users/{id}/expire-password` | Bottone "Expire Password" → confirm dialog | BE: test che utente con password_expired venga reindirizzato a cambio password al login; FE: test UI |
| 2.4 | Sblocca account (lockout) | Nuovo endpoint `POST /api/admin/users/{id}/unlock` — resetta `locked_until` e `failed_login_attempts` | Bottone "Unlock Account" (solo se locked) nelle azioni → confirm dialog | BE: unit test unlock su utente bloccato; FE: test visibilità condizionale bottone |
| 2.5 | Reset tentativi falliti | Nuovo endpoint `POST /api/admin/users/{id}/reset-failed-attempts` — azzera solo `failed_login_attempts` | Bottone "Reset Failed Attempts" nelle azioni → confirm dialog | BE: unit test reset; FE: test UI |

**Backend changes:** Nuovi endpoint in `admin.py`, nuove funzioni in `storage.py`, eventuale nuovo campo `password_expired` su modello User.

---

### Fase 3 — Sessioni e Token

| # | Feature | Backend | Frontend | Test |
|---|---------|---------|----------|------|
| 3.1 | Revoca tutte le sessioni di un utente | Nuovo endpoint `POST /api/admin/users/{id}/revoke-sessions` — cancella tutti i refresh token dell'utente | Bottone "Revoke All Sessions" nel drawer | BE: unit test su `revoke_all_user_sessions`; FE: test confirm + toast |
| 3.2 | Revoca refresh token specifici | `POST /api/admin/tokens/refresh/{token_id}/revoke` già esiste | Sezione "Active Sessions" nel drawer con lista token e bottone revoca per ciascuno | BE: già coperto; FE: test revoca singolo |
| 3.3 | Visualizzazione sessioni attive | Nuovo endpoint `GET /api/admin/users/{id}/sessions` — lista refresh token + metadata (created_at, last_used_at, device_info) | Tabella "Active Sessions" nel drawer (dispositivo, creato, ultimo uso, revoca) | BE: test nuova query; FE: test rendering lista + revoca |

**Backend changes:** Nuovo endpoint per sessioni per utente, nuova funzione in `refresh_token.py` storage.

**Nota:** Serve arricchire i refresh token con metadata (user-agent, IP) per una visualizzazione utile.

---

### Fase 4 — MFA e Passkey

| # | Feature | Backend | Frontend | Test |
|---|---------|---------|----------|------|
| 4.1 | Disabilita MFA forzatamente | Modificare endpoint reset-mfa esistente o nuovo endpoint `POST /api/admin/users/{id}/disable-mfa` — pulisce MFA senza rigenerare | Bottone separato "Disable MFA" (vs "Reset MFA") nelle azioni | BE: test che MFA venga disabilitato; FE: test bottone distinto |
| 4.2 | Rigenera backup codes | Nuovo endpoint `POST /api/admin/users/{id}/regenerate-backup-codes` | Bottone "Regenerate Backup Codes" → mostra nuovi codici in modale | BE: test generazione codici; FE: test visualizzazione codici |
| 4.3 | Passkey completa nel drawer | ✅ `GET /api/admin/users/{id}/passkeys/list` e `DELETE /api/admin/users/{id}/passkeys/{credential_id}` già esistono | Sezione passkey nel drawer: lista con nome dispositivo, data creazione, bottone elimina per ciascuno | BE: già coperto; FE: test rendering + eliminazione |

**Backend changes:** Minimi (nuovo endpoint disable-mfa, regenerate-backup-codes).

---

### Fase 5 — Provisioning e Lifecycle

| # | Feature | Backend | Frontend | Test |
|---|---------|---------|----------|------|
| 5.1 | Crea utente con password | Nuovo endpoint `POST /api/admin/users/create` — crea utente con password già impostata + `is_invited: false` | Modal "Create User" (email, password, nome, cognome, scopes) distinta da "Invite User" | BE: test creazione con password hashata; FE: test form con validazione password |
| 5.2 | Modifica email utente | Aggiungere `email` al `UserUpdate` model + validazione unicità su `PUT /api/admin/users/{id}` | Campo email editabile nel drawer (con toggle "verify email after change") | BE: test cambio email + unicità; FE: test edit + feedback |
| 5.3 | Modifica telefono, avatar | Aggiungere `phone`, `avatar_url` al `UserUpdate` model | Campi editabili nel drawer | BE: test update fields; FE: test form |

**Backend changes:** Nuovo endpoint create, estensione UserUpdate model.

---

### Fase 6 — Attività e Audit

| # | Feature | Backend | Frontend | Test |
|---|---------|---------|----------|------|
| 6.1 | Login history per utente | Nuovo endpoint `GET /api/admin/users/{id}/login-history` (basato su audit log) | Tab "Login History" nel drawer: tabella con timestamp, IP, user-agent, success/fail | BE: test query audit log filtrata; FE: test rendering lista |
| 6.2 | Eventi di sicurezza | Nuovo endpoint `GET /api/admin/users/{id}/security-events` | Tab "Security Events" nel drawer: cambio password, cambio email, reset MFA, login da nuovo dispositivo | BE: test audit events; FE: test timeline UI |
| 6.3 | Applicazioni connesse e revoca OAuth | `GET /api/admin/oauth-consents` già esiste. Nuovo endpoint filtrato per user_id. | Tab "Connected Apps" nel drawer: lista app OAuth con bottone revoca | BE: test filtro per user_id; FE: test lista + revoca |

**Backend changes:** Nuovi endpoint di query su audit log, filtro OAuth consents per utente.

---

### Fase 7 — Advanced

| # | Feature | Backend | Frontend | Test |
|---|---------|---------|----------|------|
| 7.1 | Esportazione dati utente | Nuovo endpoint `GET /api/admin/users/{id}/export` — ritorna JSON con tutti i dati utente | Bottone "Export User Data" nel drawer → scarica JSON | BE: test completezza export; FE: test download |
| 7.2 | Cronologia azioni admin | Nuovo endpoint `GET /api/admin/users/{id}/admin-actions` — azioni admin su questo utente | Tab "Admin Actions" nel drawer: chi ha fatto cosa, quando | BE: test audit trail; FE: test timeline |
| 7.3 | Disattivazione temporanea | Aggiungere `suspended_until: Optional[datetime]` a User + endpoint `POST /api/admin/users/{id}/suspend` con durata | Modal "Suspend User" con selettore durata (ore/giorni) | BE: test scadenza suspension; FE: test UI con durata |

---

## Ordine di implementazione consigliato

```
Fase 1 (fondamenta UI) → Fase 2 (password) → Fase 3 (sessioni)
→ Fase 4 (MFA/passkey) → Fase 5 (provisioning) → Fase 6 (audit) → Fase 7 (advanced)
```

**Fase 1** è propedeutica — migliora la UI esistente e dà accesso a funzioni backend già pronte.
**Fase 2, 3, 4** sono il cuore CIAM: gestione credenziali e accesso.
**Fase 5** completa il lifecycle.
**Fase 6 e 7** sono value-add per compliance e visibilità.
