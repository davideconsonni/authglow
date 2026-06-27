# Plan Parsers

Strategia di parsing per i 3 formati di piano osservati in `docs/plans/`. Da usare nella Fase 1 della skill per identificare voce, ID, e struttura nested.

## Formato 1 — VAPT (flat con blocchi strutturati)

File esempio: `docs/plans/VAPT_FIX_PLAN.md`.

### Struttura

```markdown
# <Titolo piano>

> **Status**: ...
> **Source**: ...
> ...

## Severity summary

| Severity | Count | Fixed | Remaining | Action |
|---|---|---|---|---|

## CRITICAL (11)

### Token storage and bearer credentials

- [x] **VAPT-001** — JWT access + refresh tokens stored in `localStorage` (XSS-stealable)
  - **Location**: `frontend/src/stores/authStore.ts:39-110`; `frontend/src/lib/api.ts:21-34`
  - **Description**: Zustand `persist` middleware writes both tokens to `localStorage`...
  - **Fix**: Move tokens to `httpOnly` cookies set by the backend...

- [ ] **VAPT-002** — Refresh tokens stored in plaintext on disk
  - **Location**: ...
  - **Description**: ...
  - **Fix**: ...
```

### Rilevamento formato

- Header H2 di categoria (es. `## CRITICAL (11)`, `## HIGH (26)`, `## MEDIUM (53)`)
- Liste `- [x]` / `- [ ]` con ID `VAPT-NNN` o `VAPT-INFO-NNN`
- Blocchi sub-bullet con `**Location**`, `**Description**`, `**Fix**` (a volte solo Description + Fix)
- Sezione finale `## Suggested fix order (for the next N sessions)` con elenco numerato — **usare come override** dell'ordine del documento

### Regex per item

```python
# Match di un singolo item
import re

item_pattern = re.compile(
    r'^- \[([ x])\] \*\*([A-Z]+-\d+|VAPT-INFO-\d+)\*\* — (.+?)$',
    re.MULTILINE
)

# Estrazione blocco sub-bullet (Location/Description/Fix)
sub_pattern = re.compile(
    r'  - \*\*(Location|Description|Fix)\*\*: (.+?)(?=\n  - \*\*|\n- \[|\n## |\Z)',
    re.DOTALL
)
```

### Sezione "Suggested fix order"

Cerca l'header `## Suggested fix order` (o varianti `## Roadmap`, `## Ordine di esecuzione`). Sotto, un elenco numerato:

```markdown
## Suggested fix order (for the next N sessions)

1. **VAPT-001 (CRITICAL)** — Move tokens out of `localStorage` to `httpOnly` cookies.
2. **VAPT-006 / VAPT-007 / VAPT-008 (CRITICAL)** — ...
```

Estrai gli ID con regex: `r'\*\*([A-Z]+-\d+(?:\s*/\s*[A-Z]+-\d+)*)\*\*'`.

## Formato 2 — CONFORMANCE (flat con status block e [file:line])

File esempio: `docs/plans/CONFORMANCE_REMEDIATION_PLAN.md`.

### Struttura

```markdown
# AuthGlow — OAuth 2.0 / OIDC Conformance Remediation Plan

> **Origine**: assessment read-only del 2026-06-13...

## Legenda

- 🔴 **P0** — ...
- 🟠 **P1** — ...
- 🟢 **DONE** — Spuntare quando completato e testato

## Workstream A — Security: JWT Audience Validation 🟢

L'audience non è mai verificato...

> **Stato**: completato 2026-06-14. 12/12 task chiusi. 154 test passati, ruff+mypy clean.

- [x] **A.1** Aggiungere campo `aud` (claim singolo) e `azp` agli access token OAuth2 in `services/jwt.py:175-188` quando emessi per un client OAuth2 (non per il flow cookie-first). [services/jwt.py:175-188]
- [x] **A.2** ...
- [ ] **A.3** Modificare `create_id_token()` per richiedere `aud=client_id` e impostare `azp=client_id`...
```

### Rilevamento formato

- Header H2 `## Workstream <lettera> — <titolo> <emoji stato>`
- Emoji stato: 🔴 P0, 🟠 P1, 🟡 P2, 🟢 DONE
- Status block con `> **Stato**: completato <data>. N/N task chiusi. <test count>.`
- Liste `- [x]` / `- [ ]` con ID `<lettera>.<numero>` (es. `A.1`, `B.3`)
- Riferimenti `[file:line]` alla fine della riga
- Spesso **NO blocco `**Fix**`** — solo descrizione del cambiamento richiesto → in questo caso derivare il piano dalla descrizione + standard di mercato/protocollo citato

### Regex per item

```python
item_pattern = re.compile(
    r'^- \[([ x])\] \*\*([A-Z]\.\d+)\*\* (.+?)$',
    re.MULTILINE
)

# Estrai riferimenti [file:line] dalla fine della riga
ref_pattern = re.compile(r'\[([^\]]+:\d+(?:-\d+)?)\]\s*$')
```

### Status block

Per workstream `🟢 DONE` con status block "completato", salta tutti gli item `- [x]` e proponi il prossimo workstream non-DONE. Per workstream ancora attivi (`🔴`/`🟠`/`🟡`), procedi normalmente.

## Formato 3 — PERFORMANCE (nested con H3)

File esempio: `docs/plans/PERFORMANCE_OPTIMIZATION_PLAN.md`.

### Struttura

```markdown
## Tier 1 — Quick wins cross-platform, no new dependencies

**Tempo stimato**: ~2 ore
**Impatto atteso**: ×3-5x throughput
**Rischio**: basso

### 1.1 — bcrypt sync → `asyncio.to_thread`

- [x] **`services/password.py:90-108`** — wrappare `bcrypt.hashpw` e `bcrypt.checkpw` in
  `async def hash_password_async()` / `async def verify_password_async()` con
  `asyncio.to_thread`. ...
- [x] **Aggiornare call site in `services/refresh_token.py:87, 139`** per usare `_async`.
- [x] **Test**: `pytest tests/unit/test_password.py ...` deve passare.
- [x] **Estensione scope** (uniformità): convertiti anche `api/admin.py:260,650`, ...
- [x] **Nuova suite** `tests/performance/test_bcrypt_async.py` (12 test: ...)

### 1.2 — Singleton `JWTService` in `api/*`

- [x] **`api/auth.py:107-114`** — `get_jwt_service` con lazy-async singleton come
  `core/permissions.py:14-21`. ...
```

### Rilevamento formato

- Header H2 `## Tier N — <titolo>`
- Header H3 `### N.M — <titolo>` dove `N.M` è l'ID
- Sotto H3, lista di checkbox `- [x]` / `- [ ]` — **MA l'unità di lavoro è l'H3**, non il singolo checkbox
- Ogni checkbox sotto H3 è un sub-task (locazione + descrizione di una modifica specifica)

### Strategia di parsing

1. Identifica tutti gli H3: `r'^### (\d+\.\d+) — (.+?)$'`
2. Per ogni H3, conta i sub-task `- [ ]` annidati
3. Un H3 è **completato** se tutti i sub-task sono `- [x]`. È **aperto** se almeno uno è `- [ ]`.
4. Il prossimo H3 da lavorare è il primo con sub-task `- [ ]`.

```python
# Pseudo-codice
sections = parse_h3_sections(plan_md)
for h3 in sections:
    if h3.has_open_subtask:
        return h3
```

### Gestione sub-task

Quando presenti l'item all'utente, elenca TUTTI i sub-task. Se l'utente dice "faccio tutto", implementa tutti; altrimenti chiedi conferma sul primo e procedi uno alla volta.

Quando spunti l'item:
- Spunta tutti i sub-task completati
- Lascia `- [ ]` su eventuali sub-task non completati (succede se l'utente ha chiesto split)
- Aggiungi la nota `Done:` dopo l'ultimo sub-task (o in coda all'H3 se la piattaforma lo supporta)

## Caso ibrido

Se un piano ha H3 + checkbox flat (senza sub-bullet sotto H3), trattalo come **flat**: ogni checkbox è un'unità. Esempio:

```markdown
### Item 1
- [ ] task A
- [ ] task B
```

Se `A` e `B` sono indipendenti (file diversi, no dipendenza), trattali come 2 unità. Se sono parte dello stesso cambiamento, chiedi all'utente.

## Edge case comuni

- **Item già `[x]`** con sub-bullet non `[x]` → ambiguità. Salta, prendi il prossimo aperto, o chiedi.
- **Item senza `**Fix**`** → derivare piano dalla Description, presentare esplicitamente come "piano proposto, conferma".
- **Item con più `**Location**`** punti (es. backend + frontend) → unità跨界, fare scaling plan più ampio.
- **Item "verified safe"** (sezione "Verified safe" di VAPT_FIX_PLAN) → non implementare, sono positive findings.
- **Item di status "DONE"** nel titolo (CONFORMANCE: `🟢`) → workstream già chiuso, salta a workstream successivo non-DONE.

## Algoritmo di selezione "prossima voce aperta"

```python
def find_next_open(plan_path: str, item_id: str | None = None) -> Item:
    md = read(plan_path)
    fmt = detect_format(plan_path, md)  # 'vapt' | 'conformance' | 'performance'

    if item_id:
        return find_by_id(md, fmt, item_id)

    if fmt == 'performance':
        # Trova primo H3 con sub-task aperti
        return next_h3_with_open_subtask(md)

    # Flat (VAPT, CONFORMANCE): primo - [ ]
    items = parse_items(md, fmt)
    return next(i for i in items if i.status == 'open')

def detect_format(plan_path: str, md: str) -> str:
    name = plan_path.lower()
    if 'vapt' in name: return 'vapt'
    if 'conformance' in name: return 'conformance'
    if 'performance' in name: return 'performance'
    # Fallback: cerca marker caratteristici nel contenuto
    if re.search(r'^- \[.\] \*\*VAPT-\d+', md, re.M): return 'vapt'
    if re.search(r'^- \[.\] \*\*[A-Z]\.\d+', md, re.M): return 'conformance'
    if re.search(r'^### \d+\.\d+', md, re.M): return 'performance'
    raise ValueError(f"Cannot detect plan format for {plan_path}")
```

## Aggiornamento del piano dopo il completamento

Per il formato flat (VAPT, CONFORMANCE):

```python
def tick_done(plan_md: str, item_id: str, note: str) -> str:
    # Cambia [ ] in [x] sulla riga dell'item
    # Aggiungi "  - **Done**: {note}" come sub-bullet (o modifica Done esistente)
    # NON toccare Location/Description/Fix
```

Per il formato nested (PERFORMANCE):

```python
def tick_h3_done(plan_md: str, h3_id: str, note: str) -> str:
    # Spunta tutti i sub-task [ ] → [x] sotto l'H3
    # Aggiungi nota "**Done**: {note}" come ultima riga dell'H3
    # Se l'H3 aveva solo sub-task parzialmente chiusi, lascia [ ] su quelli aperti
```

Per workstream CONFORMANCE `🟢 DONE` con status block, aggiorna il conteggio: `> **Stato**: completato <data>. N/N task chiusi. <test count>.`

## Test del parser

Prima di fidarti, valida il parser su tutti e 3 i file di piano attuali. Casi di test minimi:

- VAPT_FIX_PLAN.md: contare 126 item (37 done, 89 aperti al 2026-06-04)
- CONFORMANCE_REMEDIATION_PLAN.md: contare workstream A-F, trovare primo A.x o B.x ancora aperto
- PERFORMANCE_OPTIMIZATION_PLAN.md: contare Tier 1-4, trovare primo H3 con sub-task aperti

Se i conteggi non tornano, il pattern regex è sbagliato — correggi prima di usarlo.
