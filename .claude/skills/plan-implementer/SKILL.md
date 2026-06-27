---
name: plan-implementer
description: Implementa la prossima voce (o una voce specifica) di un piano in docs/plans/. Flusso completo: seleziona voce → pianifica → sviluppa → testa (unit/integration/Playwright) → spunta la voce nel piano → suggerisci la prossima. Usare quando l'utente dice "implementa il prossimo task di VAPT", "lavoriamo sul piano performance", "fai VAPT-042", "continua con il piano di conformance", o menziona un file in docs/plans/.
---

# Plan Implementer

Skill per implementare in modo disciplinato le voci di un piano di remediation/miglioramento archiviato in `docs/plans/`. Lavori una voce alla volta, la chiudi, e proponi la successiva.

## Input dell'utente

L'utente può invocare la skill in due forme:

1. **Con piano e (opzionale) ID**: `implementa VAPT-042 del piano VAPT_FIX_PLAN` / `fai B.3` / `1.2 del piano performance`.
2. **Solo piano, prendo la prima voce aperta**: `prossimo task del piano VAPT` / `lavoriamo sul piano conformance` / `continua con performance`.

Se l'utente non specifica né piano né file, elenca i file `.md` in `docs/plans/` e chiedi quale usare.

## Fase 0 — Carica contesto

Prima di selezionare la voce, leggi una volta:

- `AGENTS.md` (convenzioni codice, comandi test/lint/typecheck, regole anti-regressione)
- `ARCHITECTURE.md` (se il piano tocca struttura: nuovi router, service, repository, page)
- `references/conventions.md` (in questa skill — riassunto compatto)

Queste letture avvengono una volta per sessione di lavoro sul piano, non per ogni item. Se il piano è molto verticale (es. solo frontend), puoi saltare `ARCHITECTURE.md` e limitarti a `AGENTS.md` sezione Frontend.

## Fase 1 — Seleziona la voce

1. Risolvere il path del piano. L'utente può dare:
   - Il nome del file senza estensione (`VAPT_FIX_PLAN`) → `docs/plans/VAPT_FIX_PLAN.md`
   - Un path esplicito (`docs/plans/...md`)
   - Solo "il piano performance" → match per keyword sul filename (case-insensitive substring)

2. Leggi il file. Sezioni chiave da individuare:
   - Header iniziale con stato, scope, data
   - Lista voci con checkbox
   - Eventuale sezione finale "Suggested fix order" / "Roadmap" / "Workstream"

3. Se l'utente ha specificato un ID, cerca la riga con quel match (vedi `references/plan-parsers.md` per le regex dei 3 formati osservati). Conferma che la voce sia ancora `- [ ]` (non `[x]`); se è già chiusa, avvisa e chiedi se procedere comunque o sceglierne un'altra.

4. Se l'utente NON ha specificato un ID, scegli la prossima voce aperta:
   - **Default**: prima `- [ ]` nell'ordine del documento. I piani esistenti sono già ordinati per priorità/severità (VAPT: CRITICAL → INFO, CONFORMANCE: A → F, PERFORMANCE: Tier 1 → 4).
   - **Override**: se il piano ha una sezione finale "Suggested fix order" (es. VAPT_FIX_PLAN.md ce l'ha) con un elenco numerato esplicito, rispettala — è la sequenza curata dall'autore del piano. Fanne l'override solo se l'ordine del documento e quello suggerito divergono.

5. Estrai i metadati della voce:
   - ID (es. `VAPT-042`, `A.1`, `1.1`)
   - Titolo
   - Blocco `**Location**` o riferimenti `[file:line]`
   - Blocco `**Description**`
   - Blocco `**Fix**` o istruzioni equivalenti
   - Status block (per CONFORMANCE, es. `> **Stato**: ... 12/12 task chiusi.`)

## Fase 2 — Analizza struttura nested

I piani hanno strutture diverse. Prima di proporre il piano d'azione, rileva il formato:

- **Flat** (VAPT_FIX_PLAN, CONFORMANCE_REMEDIATION_PLAN): ogni `- [ ]` è un'unità atomica. Non ci sono sotto-task annidati.
- **Nested con H3** (PERFORMANCE_OPTIMIZATION_PLAN): `### 1.1 — bcrypt sync → asyncio.to_thread` raggruppa sotto-bullet. Ogni H3 è l'unità; i sotto-bullet sono checklist interna.
- **Ibrido**: rari, ma possibili. Tratta l'H3 come unità se ha più di un sotto-bullet; altrimenti tratta il checkbox come flat.

Dettagli in `references/plan-parsers.md`. In sintesi: **leggi l'intestazione H3 più vicina alla riga per capire se sei dentro un item composto**.

Se l'item ha sotto-task:
- Se sono tutti semplici (1-2 righe di checklist interna) e fanno parte dello stesso cambiamento → implementali tutti, spunta tutto.
- Se sono complessi (cambiano file diversi, sono logicamente separati) → chiedi all'utente se fare l'intero item o solo il primo sotto-task.

## Fase 3 — Pianifica (mostra e attendi conferma)

Presenta un piano d'azione conciso, anche per item semplici. L'utente deve poter correggere il tiro prima che tu scriva codice.

Template del piano (mostra in chat, non scrivere su file):

```
## Piano per <ID> — <titolo>

**Contesto**: <1-2 frasi dal blocco Description, con i file:line rilevanti>

**File da modificare**:
- `path/al/file.py:line-range` — <cosa cambia>
- `path/altro/file.py` — <nuovo file/cosa fa>

**Test da aggiungere**:
- `tests/unit/test_<file>.py::Test<Scenario>` — <cosa copre>
- `tests/integration/test_<file>.py::Test<Flusso>` — <cosa copre>
- (frontend) `frontend/tests/<file>.test.ts` o `frontend/e2e/flows/<flusso>.spec.ts`

**Verifica**:
- <comando pytest mirato>
- <comando npm test mirato>
- `ruff check <path>`, `mypy <path>`, `ruff format <path>`

**Rischi / side-effect**:
- <migration schema / breaking change / impatto su altri moduli>

**Sub-task annidati** (se presenti):
- [ ] <sotto-task 1>
- [ ] <sotto-task 2>

Procedo? [sì / modifica: ... / salta]
```

**Casi speciali**:
- Se la voce non ha un blocco `**Fix**` chiaro (succede in CONFORMANCE), deriva il piano dalla `**Description**` + da `**Location**` + dallo standard di mercato/protocollo menzionato. Presenta il piano comunque, ma con nota esplicita: "Nessun `**Fix**` prescritto — piano derivato da description, conferma o correggi".
- Se la voce richiede decisioni di design non banali (es. scelta di libreria, breaking change API), fermati e chiedi.

## Fase 4 — Sviluppa

Segui le convenzioni di `references/conventions.md` e di `AGENTS.md`. Punti non ovvi:

- **Repository pattern**: se tocchi un service che ha già un Protocol/repository, NON aggiungere accesso diretto al filesystem. Vai attraverso il repository o creane uno nuovo seguendo il pattern (vedi ARCHITECTURE.md via AGENTS.md).
- **Lock**: se il codice tocca operazioni multi-entity (es. User + EmailIndex), usa `named_lock()` da `authglow.core.concurrency`. Le factory dei repository vanno chiamate con `settings=self.settings` per bypassare lru_cache (vedi AGENTS.md "Lru_cache bypass pattern").
- **Log**: usa `structlog.get_logger("authglow.audit")` (o il logger di dominio appropriato), MAI `print()`.
- **Segreti nei test**: riusa fixtures da `backend/tests/conftest.py` o genera con `secrets.token_urlsafe()`. Mai hardcoded.
- **Update services**: NO `hasattr` / `setattr` alla cieca — usa una whitelist esplicita di campi mutabili (anti-pattern VAPT-102/103).
- **Confronto credenziali**: usa `secrets.compare_digest` o `bcrypt.checkpw`, mai `==` o `!=` su secret/hash.

Scrivi il codice, poi fermati. Non passare ai test se non hai completato l'implementazione.

## Fase 5 — Testa

Scegli il tipo di test in base all'area toccata (vedi `references/frontend-testing.md` per il frontend):

| Area toccata | Test minimo |
|---|---|
| `authglow/services/<x>.py` | `pytest tests/unit/test_<x>.py -q --tb=line` |
| `authglow/api/<x>.py` (nuovo endpoint) | `pytest tests/integration/test_<x>.py -q --tb=line` |
| `authglow/core/<x>.py` | Suite completa mirata: `pytest -q --tb=line -n auto` SOLO se cambi `core/` |
| `authglow/repositories/file/<x>.py` | `pytest tests/unit/repositories/file/test_<x>.py -q --tb=line` + conformance `tests/unit/repositories/test_protocols.py` |
| `frontend/src/components/<X>.tsx` | `npm test -- <path>` |
| `frontend/src/pages/<X>.tsx` | `npm test -- <path>` + Playwright solo se flusso cross-cutting (login, OAuth, MFA) |
| `frontend/src/lib/api.ts` o store | Vitest sul modulo + almeno 1 Playwright sul flusso che lo usa |
| `frontend/src/stores/<x>.ts` | `npm test -- <path>` |

**Regole anti-regressione** (da AGENTS.md):
- MAI lanciare la suite completa per ogni item. Solo l'area toccata.
- Per modifiche a `core/`, ok lanciare `-n auto` ma solo sui file rilevanti.
- Mostra solo failures + warning summary, mai full traceback.

**Separazione fallimenti**:
- Dopo ogni test run, dividi in due bucket:
  - **(a) file che hai toccato** → fix immediato, non andare avanti finché non passano.
  - **(b) file non toccati** → riportali in chat con path + errore, chiedi se indagare. Non fixare automaticamente.

**Lint e typecheck** (dopo che i test passano):
- Backend: `ruff check <path>`, `ruff format <path>`, `mypy <path>`
- Frontend: `npm run lint` (solo sui file toccati se il progetto lo permette, altrimenti full)

**Test aggiunti**:
- Per implementazioni nuove: ALMENO un test che fallisce senza la modifica (regression protection).
- Per fix di bug: il test riproduce il bug originale, poi passa con la fix.

## Fase 6 — Aggiorna il piano e proponi il prossimo

Dopo che test, lint, typecheck sono tutti verdi:

1. **Aggiorna il file del piano**:
   - Cambia `- [ ]` → `- [x]` sulla riga della voce completata.
   - Se ci sono sub-bullet, spunta quelli completati; lascia `- [ ]` su eventuali sotto-task non completati.
   - **NON** riscrivere `**Fix**` o `**Description**`. Aggiungi solo una riga di chiusura:
     ```
       - **Done**: <1 riga, es. "implemented bcrypt_rounds config + re-hash on login (commit abc1234)" o "deferred — accettato rischio, documentato in ARCHITECTURE.md">
     ```
   - Se il piano ha un status block per workstream (CONFORMANCE: `> **Stato**: ... 12/12 task chiusi.`), aggiorna il conteggio.

2. **NON fare commit**. Mostra il diff del file di piano e fermati. L'utente decide se committare e quando.

3. **Suggerisci il prossimo**:
   ```
   ## Prossima voce: <ID> — <titolo>
   > Location: <file:line>
   > Description: <1 riga>
   
   Vuoi che proceda? [sì / fai un altro / pausa]
   ```
   
   Se hai finito l'intero piano:
   ```
   ## Piano <NOME> completato
   Tutte le <N> voci sono state spuntate. Suggerimenti:
   - Aggiungere un header `> **Status**: completed <data>` in cima al piano
   - Creare un follow-up PLAN con i "Done: deferred — ..." se ce ne sono
   - Commit di tutte le modifiche (separato per voce, o un commit unico)
   ```

## Comportamenti da evitare

- **Non committare mai** senza che l'utente lo chieda esplicitamente. Mostra il diff e basta.
- **Non fixare fallimenti pre-esistenti** (file non toccati in questa sessione) senza conferma.
- **Non lanciare la suite completa** a ogni item. Sprecando token e tempo.
- **Non inventare ID**: se l'utente chiede `VAPT-999` e non esiste, dillo invece di procedere col primo libero.
- **Non riscrivere il `**Fix**` prescritto** se è chiaro. Implementa quello, anche se pensi che ci sia un modo migliore — annota il dubbio in un commento o in chat, ma rispetta la prescrizione del piano.
- **Non saltare i test**: anche per modifiche "triviali", almeno un test di non-regressione.

## Note operative

- La skill è progettata per essere eseguita in modo iterativo. Ogni invocazione lavora UNA voce, poi si ferma. L'utente decide se continuare, saltare, o prendersi una pausa.
- Se l'utente dice "prosegui automaticamente", ok — ma fermati comunque alla fine di ogni item per far vedere il diff del piano e il prossimo suggerito. Non chiudere più voci in un colpo solo senza far vedere l'update del piano tra una e l'altra.
- Se una voce si rivela molto più complessa del previsto (es. richiede riscrittura di un intero modulo), fermati al primo ostacolo significativo e proponi di spezzarla in sotto-voci da aggiungere al piano.

## Riferimenti

- `references/conventions.md` — regole di codice, comandi test/lint/typecheck, anti-pattern
- `references/plan-parsers.md` — strategia di parsing per i 3 formati di piano osservati (VAPT, CONFORMANCE, PERFORMANCE)
- `references/frontend-testing.md` — quando usare vitest vs Playwright, helpers, anti-pattern
