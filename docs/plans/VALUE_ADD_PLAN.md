# Value-Add Plan — 3 differenziatori rispetto al mercato

> **Status**: piano attivo, una iniziativa alla volta, fasi sequenziali.
> **Creato**: 2026-08-25 dopo sessione di lavoro approfondita sul codebase.
> **Workflow per ogni fase**: verifica nel codice → piano dettagliato → grill → implement →
> test → mark done (solo dopo conferma utente). Stesso metodo di FRONTEND_COVERAGE_PLAN.md.

## Perché queste tre

| Iniziativa | Pubblico | Gap di mercato colpito | Fondazione già presente |
|------------|----------|------------------------|-------------------------|
| A — Config-as-Code + CLI | DevOps / self-hoster | Export Keycloak parziali; tooling Auth0 a pagamento; Zitadel = Terraform | Repository pattern su JSON + CAS versioning |
| B — Webhooks firmati + Impersonation | Chi costruisce SaaS sopra l'IdP | Webhook esterni = dolore #1 integrazione; impersonation raro anche a pagamento (Auth0: solo extension) | `SecurityEventService` + audit strutturato |
| C — Risk scoring euristico + step-up MFA | Sicurezza | Keycloak: niente nativo; Zitadel: fai-da-te. **Il marketing dell'app lo promette già** (banner login "AI-Native") ma nel codice non esiste | `LoginHistoryService`, fingerprint dispositivi, trusted devices MFA |

Verifica pre-piano (2026-08-25): nessun riferimento a webhook / risk scoring / impersonation
nel backend o frontend — tutte greenfield. Base CLI: directory `backend/scripts/`.

---

## Iniziativa A — Configuration-as-Code & CLI

> Obiettivo: gestire AuthGlow come codice — export versionabile, apply con dry-run,
> operazioni quotidiane da terminale.

- [ ] **A1 — Export configurazione**: `GET /api/admin/config/export` → bundle JSON unico
      (clients + claim policies + RBAC roles/permissions/user-roles). MAI secret in chiaro
      (client_secret sono hashati; settings vivono in env, fuori dal bundle).
- [ ] **A2 — Import con dry-run**: `POST /api/admin/config/import?mode=dry_run|merge`
      → report diff (nuovi / modificati / conflitti); merge idempotente per ID naturale;
      replace NON previsto v1 (troppo distruttivo).
- [ ] **A3 — CLI**: `backend/scripts/authglow_cli.py` comandi `export`, `apply --dry-run`,
      `apply`; auth via admin API key (già esiste il meccanismo) o credenziali admin.
- [ ] **A4 — Roundtrip test**: export → import su istanza pulita → secondo export identico
      (conformità), + test unitari conflitti.

## Iniziativa B — Event Webhooks firmati + Impersonation

> Obiettivo: far uscire gli eventi dall'IdP (integrazione senza polling dei file) e dare
> al supporto il potere di "entrare nei panni" con audit obbligatorio.

- [x] **B1 — Modello + CRUD**: entità `WebhookEndpoint` (url https, secret, events[],
      active) + repository + endpoint admin `/api/admin/webhooks` CRUD.
      _Decisioni dal grill (2026-08-25, vedi CONTEXT.md + ADR 0001/0002): nome canonico
      "Webhook Endpoint" (id `wh_…`, path `/api/admin/webhooks`); catalogo eventi CHIUSO in
      `models/webhook_events.py`, `events[]` obbligatorio ed esplicito; scope GLOBALE
      admin-only (ADR 0001); URL Policy = HTTPS sempre, localhost-HTTP (loopback) sempre consentito
      riusando `_validate_redirect_uri`; Signing Secret `whsec_…` generato server-side,
      rivelato una volta sola, cifrato a riposo con `encrypt_field`, rotazione immediata
      senza grace period (ADR 0002); flag `active` manuale-only, mai auto-quarantena;
      repository per-id JSON `<storage>/webhooks/{wh_id}.json` via fsspec (backend-agnostico),
      Protocol + factory per swap futuro su Postgres._
      _✅ Completata 2026-08-25_: `models/webhook.py|webhook_events.py`,
      `WebhookRepository` Protocol (+ entry tabella conformità),
      `FileWebhookRepository` con segreto cifrato a riposo,
      factory `get_webhook_repository`, router `api/webhooks.py`
      (POST/GET list/GET one/PATCH/DELETE/rotate-secret, lock named "webhooks"),
      registrato in `main.py`. Test: 7 repo + 11 API + voce protocolli = 78 passed;
      ruff pulito; ciclo completo verificato LIVE su server demo
      (create→secret once→list masked→patch→rotate→delete→404).
- [ ] **B2 — Dispatcher HMAC**: consegna POST firmata (`X-AuthGlow-Signature: sha256=…`,
      timestamp anti-replay), fire-and-forget async con retry/backoff (3 tentativi),
      log consegne (successo/fallimento/status).
- [x] **B3 — Emissione eventi v1**: `user.created`, `user.updated`, `user.deleted`,
      `login.success`, `login.failed`, `password.changed`, `mfa.enrolled`, `session.revoked`.
      Hook nei punti esistenti (services, non route).
      _✅ Completata 2026-08-25_: helper `emit_webhook_event()` fire-and-forget nel dispatcher;
      hook in `services/user.py` (create/delete), `services/login_history.py`
      (success+failed), `services/user_profile.py` (password.changed + user.updated),
      `services/refresh_token.py` (session.revoked ×3 metodi), `api/mfa.py` (mfa.enrolled),
      `api/password_reset.py` ×2 + `api/auth.py` (password.changed / login.failed —
      deviazioni documentate dai punti route, semantica corretta).
      Scoperta collaterale: i failed-login del path principale NON finivano mai nella login
      history (gap pre-esistente, solo contatore lockout) — segnalato come follow-up.
      Verifica live: bad login → consegna firmata `login.failed` ok=True status=200.
      Test: 5 emissioni unitarie nuove; 94 passed sulle aree B.
- [x] **B4 — UI admin Webhooks**: pagina CRUD + bottone "Send test event" + lista ultime
      consegne per endpoint.
      _✅ Completata 2026-08-25_: nuova pagina `AdminWebhooksPage` (`/admin/webhooks`,
      sidebar + rotta lazy) con: form creazione (URL + checkbox catalogo eventi), tabella
      con badge active/disabled e chip eventi, azioni per riga = Test event (toast esito +
      apre log), Delivery log espandibile (ultime 20, newest-first), Rotate secret
      (confirm → modal reveal-once con Copy), Enable/Disable toggle, Delete (confirm).
      Modal "Signing Secret" reveal-once con CopyButton.       Test: 5/5 pagina; suite completa
      frontend verde; build di produzione ok.
      _Aggiunta post-review utente_: azione **Edit** per riga (matita) → stesso form pre-compilato
      che salva via `PATCH /api/admin/webhooks/{id}` (url + events); il flag active resta sul
      toggle di riga. Test edit: 6/6 pagina, tsc/lint puliti.
- [ ] **B5 — Impersonation**: `POST /api/admin/users/{id}/impersonate` → sessione marcata
      (`amr` include `impersonated`, claim `impersonator_id`), banner fisso nell'UI,
      audit event obbligatorio, scadenza breve (30 min), azione solo per scope admin.
- [ ] **B6 — Test**: unit dispatcher (firma/retry), unit impersonation (scope/expiry/audit),
      integration flusso completo.

## Iniziativa C — Risk scoring euristico + step-up MFA

> Obiettivo: consegnare ciò che il banner di login promette — accessi sospetti chiedono
> più verifiche, accessi normali non vengono disturbati.

- [ ] **C1 — Motore score**: modulo `authglow/services/risk.py` con segnali da dati già
      registrati: nuovo device fingerprint, nuovo IP/subnet, ora insolita per l'utente,
      fallimenti recenti, account appena creato. Output: score 0-100 + lista motivazioni.
- [ ] **C2 — Step-up nel login**: in `authorize_post`/MFA branch — score alto forza la
      challenge MFA ANCHE se dispositivo trusted; score critico → lockout temporaneo soft.
      Se MFA non abilitata e score critico → email alert (canale console/demo ok).
- [ ] **C3 — Osservabilità**: score + motivazioni salvati negli security-events esistenti
      e visibili nella vista admin utente già presente.
- [ ] **C4 — Configurabilità**: soglie/pesi nelle settings schema (categoria `security`)
      con default prudenti.
- [ ] **C5 — Test scenari**: matrice segnali→score→decisione; regressione che un accesso
      normale/trusted NON generi attrito.

---

## Regole di ingaggio

1. Una fase alla volta, mai batch.
2. Nessuna fase parte senza verifica del punto nel codice corrente (i piani possono essere
   smentiti dai fatti — vedi Fase 4 del piano precedente).
3. Ogni fase termina con test dell'area + lint/typecheck + (dove utile) prova live.
4. Mark done solo dopo conferma utente.
5. Segreti mai in chiaro in export/log/test (policy repo).

## Ordine proposto

**B1-B4 prima** (valore immediato, fondazione eventi pronta), poi **B5**, poi **A**, infine
**C** (più ricerca). Da decidere insieme a ogni traguardo.
