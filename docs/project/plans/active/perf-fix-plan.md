---
type: plan
status: active
ids: PERF-NNN
---

# Performance Fix Plan — Alto Carico (2026-09-12)

> **Status**: findings da static code review, non ancora triagiati/discussi punto per punto.
> **Source**: assessment statico su `davideconsonni/authglow` (nessun load test eseguito — vedi PERF-011).
> **Findings**: 10 item architetturali + 1 item di processo (baseline di load test mancante).

## Come usare questo file

Ogni finding ha un ID stabile `PERF-NNN`. Durante la discussione punto per punto, per ogni item:
1. Leggere **Location** + **Descrizione** insieme.
2. Decidere in **Decisione**: `fix ora` / `fix pianificato (sprint/rilascio)` / `accettato come rischio (motivare)` / `bisogno di dati reali prima di agire` (tipicamente per gli item che dipendono da PERF-011).
3. Quando l'item è implementato: spuntare `[x]`, annotare commit/PR in **Fix** e chiudere.

Severità = impatto atteso sotto carico sostenuto, non urgenza di sicurezza: **CRITICAL = collo di bottiglia che degrada con la concorrenza, HIGH = limita lo scale-out orizzontale, MEDIUM = degrado lento/long-running, STRATEGIC = decisione architetturale di più ampio respiro, PROCESS = manca la misura, non il fix**.

## Severity summary

| Severità | Count | Fixed | Remaining |
|---|---|---|---|
| CRITICAL | 4 | 0 | 4 |
| HIGH | 4 | 0 | 4 |
| MEDIUM | 1 | 0 | 1 |
| STRATEGIC | 1 | 0 | 1 |
| PROCESS | 1 | 0 | 1 |
| **Total** | **11** | **0** | **11** |

---

## CRITICAL (4)

### Concorrenza e caching sul percorso caldo (login / refresh)

- [ ] **PERF-001** — Lock CAS globale di processo serializza tutte le scritture ottimistiche
  - **Location**: `backend/authglow/core/async_io.py:31` (`_cas_write_lock`); usata da refresh-token rotation e redemption dei codici di autorizzazione (`repositories/file/base.py:27-30`)
  - **Descrizione**: `_cas_write_lock` è un singolo `threading.Lock()` di modulo condiviso da **ogni** `write_json_versioned`, indipendentemente dal path scritto. La rotazione del refresh token dell'utente A attende quella dell'utente B. Aggravante: `cache_refresh_token_ttl` è 60s (`core/config.py:402`), quindi sotto carico sostenuto la maggior parte dei refresh bypassa la cache e finisce su questa lock.
  - **Fix proposto**: sostituire con una lock per-path, riusando `AsyncNamedLock` (`core/concurrency.py`) già presente e già corretto nel resto del codice — non serve una primitiva nuova, solo applicarla qui.
  - **Decisione**: _da discutere_

- [ ] **PERF-002** — Repository ricreate a ogni richiesta → cache dell'indice email di fatto inesistente
  - **Location**: `backend/authglow/api/auth.py:482` (`get_user_storage`, nessun `@lru_cache`/singleton); `backend/authglow/repositories/file/email_index.py` (cache in-memory che vive quanto la request)
  - **Descrizione**: `Depends(get_user_storage)` istanzia `UserStorage()` (e a cascata `FileEmailIndexRepository()`) a ogni richiesta HTTP. Ogni cache-miss sul layer superiore (`user_cache`, TTL 300s / maxsize 2000, `core/config.py:403-404`) forza una rilettura+parsing dell'**intero** `email_index.json`, costo che cresce con il numero totale di utenti.
  - **Fix proposto**: applicare lo stesso pattern già usato per il keyring JWT — singleton di processo con staleness probe multi-replica (`core/jwt_singleton.py` è il riferimento diretto da copiare).
  - **Decisione**: _da discutere_
  - **Dipendenze**: se si adotta Redis per le cache (PERF-005), la staleness probe può appoggiarsi allo stesso backend invece che a un probe custom su file — da valutare insieme.

- [ ] **PERF-003** — Thread pool condiviso fra I/O bloccante su file e bcrypt
  - **Location**: `backend/authglow/core/async_io.py` (ogni operazione file passa da `asyncio.to_thread`); `backend/authglow/services/password.py:219,230` (bcrypt async, correttamente offloadato ma sullo stesso pool)
  - **Descrizione**: nessun `ThreadPoolExecutor` dedicato configurato in produzione — tutto condivide il pool di default di asyncio (`min(32, cpu_count + 4)`). Sotto carico misto, bcrypt cost-12 (CPU-bound, ~200-300ms) e centinaia di letture/scritture file (I/O-bound) competono per lo stesso pool ristretto.
  - **Fix proposto**: due executor separati — uno per bcrypt (dimensionato sul numero di core), uno per I/O file (dimensionato più largo, essendo I/O-bound).
  - **Decisione**: _da discutere_

### Deployment

- [ ] **PERF-004** — Nessuna configurazione multi-worker di default
  - **Location**: `backend/Dockerfile` (`CMD uvicorn main:app --host 0.0.0.0 --port ${PORT}`, senza `--workers`)
  - **Descrizione**: di default gira un solo processo Python / un solo event loop. Va bene se l'orchestratore a valle gestisce le repliche, ma non è esplicito né documentato — rischio che un deploy "semplice" (es. singolo container PaaS) resti single-process senza che sia una scelta consapevole.
  - **Fix proposto**: aggiungere `--workers N` configurabile via env, oppure documentare esplicitamente nel README la responsabilità di scalare a livello di orchestratore (k8s replicas, ecc.) — scelta da discutere insieme, non è solo tecnica.
  - **Decisione**: _da discutere_

---

## HIGH (4)

### Scale-out orizzontale (più repliche)

- [ ] **PERF-005** — Cache locali non condivise tra istanze (default `CACHE_BACKEND=memory`)
  - **Location**: `backend/authglow/core/cache.py` (`RedisCacheBackend` già implementata ma non attiva di default)
  - **Descrizione**: `user_cache`, `user_by_id_cache`, `refresh_token_cache`, `oauth_client_cache`, `api_key_cache`, `jti_cache` sono `TTLCache` in-process. Con N repliche dietro un load balancer, ogni replica ha una cache indipendente: nessuna invalidazione condivisa, ogni replica riparte fredda.
  - **Fix proposto**: nessun codice nuovo — attivare `CACHE_BACKEND=redis` nella configurazione di produzione multi-replica; l'interfaccia è già pronta.
  - **Decisione**: _da discutere_

- [ ] **PERF-006** — Rate limiter in-memory non condiviso tra repliche
  - **Location**: `backend/authglow/core/rate_limit.py` (`Limiter(key_func=get_remote_address)` senza `storage_uri`)
  - **Descrizione**: di default `slowapi` usa storage in-memory per processo. Con N repliche il limite effettivo per un client diventa "N × limite configurato" — proprio nello scenario (alto traffico, più istanze) in cui la protezione serve di più.
  - **Fix proposto**: passare uno `storage_uri` Redis al `Limiter` (supportato nativamente da slowapi).
  - **Decisione**: _da discutere_
  - **Dipendenze**: stesso Redis di PERF-005, valutare come un'unica voce di infrastruttura in un'unica discussione.

### Scrittura e pulizia dati

- [ ] **PERF-007** — `email_index.json`: file singolo riscritto per intero a ogni signup/cambio email
  - **Location**: `backend/authglow/repositories/file/email_index.py:104-118` (`insert`/`remove` → `_write_json_atomic` sull'intero indice); serializzato anche da `named_lock("email_index")` nel service layer
  - **Descrizione**: costo O(numero totale utenti) per ogni singola registrazione, non O(1). Su una base utenti grande pone un tetto rigido al throughput di registrazione indipendentemente da CPU/rete disponibili.
  - **Fix proposto**: da discutere — opzioni possibili sono shardare l'indice, oppure (più semplice) trattarlo come motivazione aggiuntiva per PERF-010 (backend Postgres) se la crescita utenti è attesa importante.
  - **Decisione**: _da discutere_

- [ ] **PERF-008** — Token blacklist: scansione a glob dell'intera directory + operazioni sincrone nell'event loop
  - **Location**: `backend/authglow/repositories/file/token_blacklist.py` — `load_all()`/`cleanup_expired()` (glob completo, righe 110/135); `exists()`/`delete()` sincrone (`os.path.isfile`/`os.remove`, righe 150-183) chiamate direttamente nell'event loop
  - **Descrizione**: il costo dello scan cresce con il numero di token mai revocati e non ancora ripuliti, se il cleanup periodico non è schedulato in modo garantito. Le chiamate sync sono accettabili su disco locale veloce ma rischiose se `storage_backend` è di rete/cloud (S3/GCS/ABFS, già supportati).
  - **Fix proposto**: (a) schedulare `cleanup_expired()` con frequenza garantita e non opzionale; (b) valutare se avvolgere `exists()`/`delete()` in `asyncio.to_thread` quando il backend non è `file` locale.
  - **Decisione**: _da discutere_

---

## MEDIUM (1)

- [ ] **PERF-009** — `AsyncNamedLock` non fa mai eviction delle chiavi
  - **Location**: `backend/authglow/core/concurrency.py:41-44`
  - **Descrizione**: il dizionario di lock per-chiave cresce senza mai essere ripulito. Non è un problema acuto a breve termine, ma su un processo long-running ad alto traffico prolungato è un lento leak di memoria (una chiave per ogni utente/token/code mai visto dal processo).
  - **Fix proposto**: eviction opportunistica (es. rimuovere una entry quando la lock non è `locked()` e non ha waiter, con TTL o LRU-bound) — da dimensionare insieme, priorità bassa rispetto al resto.
  - **Decisione**: _da discutere_

---

## STRATEGIC (1)

- [ ] **PERF-010** — Backend Postgres è solo uno stub vuoto
  - **Location**: `backend/authglow/repositories/postgres/__init__.py` (~630 byte, nessuna implementazione concreta)
  - **Descrizione**: oggi l'unico backend di storage realmente funzionante è quello file-JSON-per-record. Molti dei finding sopra (PERF-001, 002, 007, 008) sono sintomi diretti di questa scelta architetturale, non bug isolati. Se il target di carico reale implica molte migliaia di utenti o scritture concorrenti sostenute, è la leva con l'impatto più alto — ma anche lo sforzo più alto.
  - **Fix proposto**: nessuno immediato — item da posizionare in roadmap, non da "fixare" in uno sprint. Utile discuterlo per primo, perché la decisione (investire su Postgres vs. ottimizzare il layer file) condiziona la priorità di PERF-001/002/007.
  - **Decisione**: _da discutere_

---

## PROCESS (1)

- [ ] **PERF-011** — Manca una baseline di load test
  - **Location**: n/a — nessuno script locust/k6/wrk nel repo (`backend/scripts/` contiene solo tool di migrazione/diagnostica)
  - **Descrizione**: tutti i finding sopra derivano da code review statica, non da numeri misurati. Senza una baseline (RPS massimo, p50/p95/p99 su login e refresh concorrenti) non è possibile validare l'impatto reale di un fix né stabilire priorità con dati oggettivi.
  - **Fix proposto**: scrivere uno scenario locust/k6 che eserciti login concorrenti + refresh-token concorrenti (i due percorsi dove PERF-001/002/003 si sommano) contro un'istanza di staging, **prima** di iniziare a implementare i fix sopra — dà i numeri "prima" da confrontare con "dopo".
  - **Decisione**: _da discutere — probabilmente il primo item da chiudere, condiziona tutto il resto_

---

## Note per l'implementazione in sessioni successive

- Ogni item è indipendente a livello di codice tranne le dipendenze esplicitate (PERF-002↔005, PERF-005↔006). Possono essere implementati in qualsiasi ordine una volta presa la decisione.
- Il pattern di riferimento da riusare per PERF-001 e PERF-002 esiste già nel codebase (`AsyncNamedLock` e `core/jwt_singleton.py` rispettivamente) — non richiede progettazione da zero, solo applicazione coerente.
- Consigliato chiudere PERF-011 per primo se possibile, per avere numeri reali da citare quando si discute priorità/sforzo degli altri item.
