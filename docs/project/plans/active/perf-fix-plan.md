---
type: plan
status: active
ids: PERF-NNN
---

# Performance Fix Plan — Alto Carico (2026-09-12)

> **Status**: PERF-001/002/003/008/011 decisi e implementati; il resto è _da discutere_. Tutte le voci rivalidate contro il codice su disk il 2026-11-07/08 (note **Verifica** per item); la baseline PERF-011 ha fatto emergere un nuovo finding (PERF-012, CRITICAL, in coda alla sezione concurrence).
> **Source**: assessment statico su `davideconsonni/authglow` + **baseline load test eseguita 2026-11-08** (`backend/tests/load/`, numeri sotto in PERF-011).
> **Findings**: 11 item architetturali (10 originali + PERF-012) + 1 item di processo (baseline, ora chiusa).

## Come usare questo file

Ogni finding ha un ID stabile `PERF-NNN`. Durante la discussione punto per punto, per ogni item:
1. Leggere **Location** + **Descrizione** insieme.
2. Decidere in **Decisione**: `fix ora` / `fix pianificato (sprint/rilascio)` / `accettato come rischio (motivare)` / `bisogno di dati reali prima di agire` (tipicamente per gli item che dipendono da PERF-011).
3. Quando l'item è implementato: spuntare `[x]`, annotare commit/PR in **Fix** e chiudere.

Severità = impatto atteso sotto carico sostenuto, non urgenza di sicurezza: **CRITICAL = collo di bottiglia che degrada con la concorrenza, HIGH = limita lo scale-out orizzontale, MEDIUM = degrado lento/long-running, STRATEGIC = decisione architetturale di più ampio respiro, PROCESS = manca la misura, non il fix**.

## Severity summary

| Severità | Count | Fixed | Remaining |
|---|---|---|---|
| CRITICAL | 5 | 3 | 2 |
| HIGH | 4 | 1 | 3 |
| MEDIUM | 1 | 0 | 1 |
| STRATEGIC | 1 | 0 | 1 |
| PROCESS | 1 | 1 | 0 |
| **Total** | **12** | **5** | **7** |

---

## CRITICAL (4)

### Concorrenza e caching sul percorso caldo (login / refresh)

- [x] **PERF-001** — Lock CAS globale di processo serializza tutte le scritture ottimistiche
  - **Location**: `backend/authglow/core/async_io.py:31` (`_cas_write_lock`); usata da refresh-token rotation e redemption dei codici di autorizzazione (`repositories/file/base.py:27-30`)
  - **Descrizione**: `_cas_write_lock` è un singolo `threading.Lock()` di modulo condiviso da **ogni** `write_json_versioned`, indipendentemente dal path scritto. La rotazione del refresh token dell'utente A attende quella dell'utente B. Aggravante: `cache_refresh_token_ttl` è 60s (`core/config.py:402`), quindi sotto carico sostenuto la maggior parte dei refresh bypassa la cache e finisce su questa lock.
  - **Fix proposto**: sostituire con una lock per-path, riusando `AsyncNamedLock` (`core/concurrency.py`) già presente e già corretto nel resto del codice — non serve una primitiva nuova, solo applicarla qui.
  - **Decisione**: fix ora (2026-11-07). Per-path sì, `AsyncNamedLock` no: è un `asyncio.Lock`, si lega al primo event loop in cui entra in contesa (verificato: al secondo `asyncio.run` solleva `RuntimeError: ... bound to a different event loop`) e verrebbe rilasciato alla cancellazione della coroutine mentre il worker sta ancora scrivendo. La sezione CAS gira in `asyncio.to_thread`, quindi serve una primitiva thread-side.
  - **Fix**: nuovo `ThreadNamedLock` in `core/concurrency.py` — lock `threading` per chiave, con eviction quando l'ultimo thread holding/waiting esce (nessun dizionario illimitato, a differenza di PERF-009). `write_json_versioned` acquisisce la lock sul `path` dentro il worker: refresh e redemption di record diversi procedono in parallelo. Test in `tests/unit/test_concurrency.py`: overlap su path diversi, serializzazione sullo stesso path, due `asyncio.run()` consecutivi sullo stesso path.

- [x] **PERF-002** — Repository ricreate a ogni richiesta → cache dell'indice email di fatto inesistente
  - **Location**: `backend/authglow/api/auth.py:482` (`get_user_storage`, nessun `@lru_cache`/singleton); `backend/authglow/repositories/file/email_index.py` (cache in-memory che vive quanto la request)
  - **Descrizione**: `Depends(get_user_storage)` istanzia `UserStorage()` (e a cascata `FileEmailIndexRepository()`) a ogni richiesta HTTP. Ogni cache-miss sul layer superiore (`user_cache`, TTL 300s / maxsize 2000, `core/config.py:403-404`) forza una rilettura+parsing dell'**intero** `email_index.json`, costo che cresce con il numero totale di utenti.
  - **Fix proposto**: applicare lo stesso pattern già usato per il keyring JWT — singleton di processo con staleness probe multi-replica (`core/jwt_singleton.py` è il riferimento diretto da copiare).
  - **Decisione**: fix ora (2026-11-07), con scope allargato a `federated_identity` (stesso pattern di costo, peggio: senza alcuna cache — ogni login federato riparsava l'intero file). Singleton applicato al **repository dell'indice**, non a `UserService`: il costo dominante è il re-parse, e `UserService` è costruito in 11 punti fra router e service layer.
  - **Fix**: nuova base `CachedRootIndexRepository` (`repositories/file/root_index.py`) — cache in-memory condivisa di processo con staleness probe a intervallo fisso (nuovo setting `storage_index_refresh_seconds`, default 60, `0` = disabilitato), ricalcando `jwt_singleton.py` ma senza `asyncio.Lock` (lezione PERF-001: primitive legate all'event loop); percorso di scrittura (insert/remove/link/unlink) sempre fresh-read-before-write così le scritture di altre repliche non si perdono mai. Registry di processo `repositories/file/index_registry.py` chiave `(entity, storage_backend, storage_path)`; le factory `get_email_index_repository`/`get_federated_identity_repository` deviano all'istanza condivisa sul backend file (zero modifiche ai router, coperte anche le costruzioni dirette). Reset fixture autouse nel conftest. Freschezza cross-replica limitata a 60s (oggi era immediata perché si rileggeva sempre): baratto documentato, identico al keyring JWT. Test in `tests/unit/repositories/file/test_email_index.py` e `test_federated_identity.py`: istanza condivisa via factory, letture servite da cache senza disco, probe che intercetta scritture esterne, `0` disabilita il probe, merge delle scritture concorrenti, errore probe non blocca le letture.

- [x] **PERF-003** — Thread pool condiviso fra I/O bloccante su file e bcrypt
  - **Location**: `backend/authglow/core/async_io.py` (ogni operazione file passa da `asyncio.to_thread`); `backend/authglow/services/password.py:219,230,242` (bcrypt async, correttamente offloadato ma sullo stesso pool); `backend/main.py:62,96-98`
  - **Descrizione**: ~~nessun `ThreadPoolExecutor` dedicato configurato in produzione — tutto condivide il pool di default di asyncio (`min(32, cpu_count + 4)`)~~ — la parte di sizing è già stata affrontata (vedi Verifica); resta che bcrypt e I/O file condividono **lo stesso** pool. Sotto carico misto, bcrypt cost-12 (CPU-bound, ~200-300ms) e centinaia di letture/scritture file (I/O-bound) competono per gli stessi worker.
  - **Fix proposto**: due executor separati — uno per bcrypt (dimensionato sul numero di core), uno per I/O file (dimensionato più largo, essendo I/O-bound).
  - **Decisione**: fix ora (2026-11-08), con scope allargato al gap emerso in verifica: prima l'offload mancante (bcrypt che girava direttamente sull'event loop), poi la separazione dei pool.
  - **Verifica (2026-11-07)**: **aperto**, con un punto obsoleto e un gap nuovo. (a) Il pool di default è già stato allargato a `min(32, cpu*4)` nel lifespan (`main.py:62,96-98`, Tier 2.1, con benchmark in `tests/performance/test_threadpool.py` e test in `tests/unit/test_main_lifespan.py`) — il mitigava il sintomo "pool ristretto" ma non separa nulla: bcrypt (password.py, api_key.py:266,328, mfa.py:207, refresh_token.py:126, oauth_client.py:77,186) e I/O file (tutta `AsyncFileSystem`) condividono sempre lo stesso executor. (b) Gap nuovo — bcrypt **direttamente sull'event loop**, fuori da qualunque pool: `services/password_reset.py:171` (`create_reset_token` → `_generate_token` → `bcrypt.hashpw`) e `:205` (`verify_token` → `bcrypt.checkpw`), `services/api_key.py:163` (`create_key`) e `:551` (rotazione) — entrambi chiamano `_generate_api_key()` che fa `hash_password` sincrono. ~200-300ms di loop bloccato per richiesta, peggio della condivisione del pool. Da includere nello scope del fix (offload obbligatorio prima della separazione).
  - **Fix**: nuovo modulo `core/executors.py` — `run_cpu_bound()` su singleton `ThreadPoolExecutor` di processo (1 worker per core, `thread_name_prefix=authglow-cpu`), senza affinità di loop (lezione della CAS lock di PERF-001); lo shutdown è delegato all'interprete (`concurrent.futures` atexit), niente wiring nel lifespan. Offload gap: `password_reset.py` (`create_reset_token`, `verify_token`) e `api_key.py` (`create_key`, rotazione) ora dispatchano; separazione: i wrapper di `services/password.py` e i chiamanti `to_thread` bcrypt di `api_key.py`, `mfa.py`, `refresh_token.py` passano a `run_cpu_bound`, l'I/O file resta sul pool di default allargato (invariato). Bonus correlato (chiuso insieme, vedi VAPT-050 nel plan security): dummy bcrypt su `authorize_post`/`change_expired_password` usa lo stesso pool. Test: `tests/unit/test_executors.py` (10: thread dedicati, non-coda dietro il pool I/O, singleton attraverso due `asyncio.run`, wrapper instradati via CPU pool), suite esistente invariata (3277 unit+integration verdi, 12 performance bcrypt verdi).

### Integrità degli indici refresh-token (emerso dalla baseline PERF-011, 2026-11-08)

- [ ] **PERF-012** — I file indice dei refresh token sono scritti in modo non atomico e non serializzato: 500 e token persi sotto concorrenza
  - **Location**: `backend/authglow/repositories/file/refresh_token.py:287-322` (helper `add_to_*`/`remove_from_*` = read-modify-write senza lock su `_id_index_path`/`_active_index_path`), `:96-135` (`_save_id_index_dict`/`_save_active_index_list` usano `base.py:358 _write_text` — scrittura semplice, no tmp+`os.replace`); `core/crypto.py:244` (`decrypt_index_value` solleva `cryptography.exceptions.InvalidTag`, che NON è in `(ValueError, TypeError, JSONDecodeError)` intercettato dai `_load_*`, il cui docstring dichiara "empty if missing/corrupt")
  - **Descrizione**: la rotatione di un refresh token tocca i due indici cifrati con RMW non protetti. Sotto concorrenza accadono due cose, entrambe osservate nei run di baseline: (a) un lettore legge ciphertext a metà scrittura → `InvalidTag` non intercettato → **500 su `/oauth2/token`** (614 traceback in un run 30u; 134 nel run ufficiale 30u; 226 nel 50u); (b) lost update: due `add_to_id_index` concorrenti si sovrascrivono → l'entry del token appena emesso scompare → `get_refresh_token` non risolve un token **legittimo** → 401 `invalid_grant: Invalid refresh token` (25/159 rotazioni nel run 10u, 115/342 nel 30u). (b) è più insidioso di (a): fallisce silenziosamente e invalidate sessioni valide.
  - **Fix proposto**: (1) scrittura atomica dei due indici (tmp + `os.replace`, come `_write_json_atomic`); (2) `InvalidTag` nei due tuple `except` dei `_load_*` — tolleranza "corrupt→vuoto" che diventa sicura solo dopo (1), altrimenti un read a metà scrittura svuoterebbe l'indice alla prima save; (3) `named_lock` sull'RMW dei due indici (chiave = path) per eliminare le lost update. Test: unit concurrency (N writer su `add_to_active_index`, assert N entries tutte presenti), regression `_load_*` con payload `agk1:` corrotto (→ vuoto, non eccezione), integration rotazione concorrente senza 500 né voci perse.
  - **Decisione**: _da discutere_ — raccomandazione **fix ora** (CRITICAL: 500 sul percorso caldo di autenticazione + revoca silenziosa di token validi)

### Deployment

- [ ] **PERF-004** — Nessuna configurazione multi-worker di default
  - **Location**: `backend/Dockerfile` (`CMD uvicorn main:app --host 0.0.0.0 --port ${PORT}`, senza `--workers`)
  - **Descrizione**: di default gira un solo processo Python / un solo event loop. Va bene se l'orchestratore a valle gestisce le repliche, ma non è esplicito né documentato — rischio che un deploy "semplice" (es. singolo container PaaS) resti single-process senza che sia una scelta consapevole.
  - **Fix proposto**: aggiungere `--workers N` configurabile via env, oppure documentare esplicitamente nel README la responsabilità di scalare a livello di orchestratore (k8s replicas, ecc.) — scelta da discutere insieme, non è solo tecnica.
  - **Decisione**: _da discutere_
  - **Verifica (2026-11-07)**: **aperto** — `Dockerfile:24` immutato, nessun `--workers`/`UVICORN_WORKERS` nel repo; `docs/internals/architecture/deployment.md` non tratta la scalabilità del processo. Nota: moltiplicare i worker moltiplica anche i problemi dei singleton di processo (PERF-001/002, cache PERF-005, limiter PERF-006) — da decidere insieme a loro.

---

## HIGH (4)

### Scale-out orizzontale (più repliche)

- [ ] **PERF-005** — Cache locali non condivise tra istanze (default `CACHE_BACKEND=memory`)
  - **Location**: `backend/authglow/core/cache.py` (`RedisCacheBackend` già implementata ma non attiva di default)
  - **Descrizione**: `user_cache`, `user_by_id_cache`, `refresh_token_cache`, `oauth_client_cache`, `api_key_cache`, `jti_cache` sono `TTLCache` in-process. Con N repliche dietro un load balancer, ogni replica ha una cache indipendente: nessuna invalidazione condivisa, ogni replica riparte fredda.
  - **Fix proposto**: nessun codice nuovo — attivare `CACHE_BACKEND=redis` nella configurazione di produzione multi-replica; l'interfaccia è già pronta.
  - **Decisione**: _da discutere_
  - **Verifica (2026-11-07)**: **aperto** — default `cache_backend: str = "memory"` invariato (`core/config.py:405`), backend Redis pronto e selettore in `core/cache.py:151-165`; `.env.example:133` e `deployment.md:44` documentano l'interruttore ma non lo attivano.

- [ ] **PERF-006** — Rate limiter in-memory non condiviso tra repliche
  - **Location**: `backend/authglow/core/rate_limit.py` (`Limiter(key_func=get_remote_address)` senza `storage_uri`)
  - **Descrizione**: di default `slowapi` usa storage in-memory per processo. Con N repliche il limite effettivo per un client diventa "N × limite configurato" — proprio nello scenario (alto traffico, più istanze) in cui la protezione serve di più.
  - **Fix proposto**: passare uno `storage_uri` Redis al `Limiter` (supportato nativamente da slowapi).
  - **Decisione**: _da discutere_
  - **Dipendenze**: stesso Redis di PERF-005, valutare come un'unica voce di infrastruttura in un'unica discussione.
  - **Verifica (2026-11-07)**: **aperto** — `core/rate_limit.py:10` è ancora `Limiter(key_func=get_remote_address)` senza `storage_uri`; nessun riferimento a storage Redis per il limiter nel repo. Il `RateLimitConfigService` gestisce abilitazione/soglie per rotta, non il backend di conteggio.

### Scrittura e pulizia dati

- [ ] **PERF-007** — `email_index.json`: file singolo riscritto per intero a ogni signup/cambio email
  - **Location**: `backend/authglow/repositories/file/email_index.py:80-105` (`insert`/`remove` → `_write_index` sull'intero indice, base `root_index.py`); serializzato anche dal service layer (`services/user.py:136,150,179` — `self._lock("email_index")`)
  - **Descrizione**: costo O(numero totale utenti) per ogni singola registrazione, non O(1). Su una base utenti grande pone un tetto rigido al throughput di registrazione indipendentemente da CPU/rete disponibili.
  - **Fix proposto**: da discutere — opzioni possibili sono shardare l'indice, oppure (più semplice) trattarlo come motivazione aggiuntiva per PERF-010 (backend Postgres) se la crescita utenti è attesa importante.
  - **Decisione**: _da discutere_
  - **Verifica (2026-11-07)**: **aperto** — il fix PERF-002 ha eliminato il costo di **lettura** (cache di processo), ma la scrittura è rimasta full-file rewrite: `insert`/`remove` rileggono tutto, mutano il dict, riscrivono l'intero JSON. Linee del piano (104-118) corrette con la nuova geometria del file.

- [x] **PERF-008** — Token blacklist: scansione a glob dell'intera directory + operazioni sincrone nell'event loop
  - **Location**: `backend/authglow/repositories/file/token_blacklist.py` — `load_all()`/`cleanup_expired()` (glob completo, righe 110/135); `exists()`/`delete()` sincrone (`os.path.isfile`/`os.remove`, righe 150-183) chiamate direttamente nell'event loop
  - **Descrizione**: il costo dello scan cresce con il numero di token mai revocati e non ancora ripuliti, se il cleanup periodico non è schedulato in modo garantito. Le chiamate sync sono accettabili su disco locale veloce ma rischiose se `storage_backend` è di rete/cloud (S3/GCS/ABFS, già supportati).
  - **Fix proposto**: (a) schedulare `cleanup_expired()` con frequenza garantita e non opzionale; (b) valutare se avvolgere `exists()`/`delete()` in `asyncio.to_thread` quando il backend non è `file` locale.
  - **Decisione**: fix (a) ora (2026-11-08); (b) **accettato come rischio** con motivazione: le primitive sync sono comportamento di protocollo documentato (`protocols.py:434-448`), sicure su storage locale (una `stat()` per cache-miss, fenomeno raro dopo il riscaldamento); async-ificarle cambierebbe la firma del contratto e il percorso di verifica JWT su ogni richiesta. Da rivedere con i numeri di PERF-011 o al primo deploy con `storage_backend` di rete.
  - **Verifica (2026-11-07)**: **aperto, aggravato** — confermato che `cleanup_expired()` **non ha alcun chiamante in produzione**: il lifespan chiama solo `startup_hydrate()` (`main.py:99`) e `_sweep()` del service (`services/auth/token_blacklist.py:140-147`) pulisce solo il dict in memoria, mai il disco. Il punto (a) del fix passa da "valutare" a "necessario": senza schedula, i file restano finché la cache non arriva a `MAX_ENTRIES` (10 000). Hot path confermata: `is_revoked` è sync su ogni richiesta autenticata (`services/jwt.py:510`, `api/oauth2_advanced.py:300`) con `exists`/`delete` `os.path` dentro l'event loop — scelta esplicita del protocollo (`repositories/protocols.py:434-448`) accettabile solo per backend file locali.
  - **Fix**: metodo `TokenBlacklist.cleanup_expired()` (sweep del repository + potatura cache in memoria, idempotente, sicuro su N repliche) + task background `_token_blacklist_sweeper` nel lifespan con nuovo setting `token_blacklist_cleanup_seconds` (default 900, `0` = disabilitato), pattern ricalcato su `_admin_config_refresher` (errore loggato e inghiottito, cancellazione allo shutdown, task esposto su `app.state` per i test). Setting NON esposto all'admin UI (binding all'avvio, l'override sarebbe inerte fino al restart — stessa rationale di `admin_config_refresh_seconds` nella whitelist del test guardiano). I file scaduti restano al più 900s su disco, già inerti in memoria. Test: `tests/unit/repositories/file/test_token_blacklist.py` (cancella scaduti + pota memoria; idempotenza a zero scaduti), `tests/unit/test_main_lifespan.py` (task creato e cancellato allo shutdown; assente con `0`).

---

## MEDIUM (1)

- [ ] **PERF-009** — `AsyncNamedLock` non fa mai eviction delle chiavi
  - **Location**: `backend/authglow/core/concurrency.py:54-65` (`AsyncNamedLock.__call__` — le entry non vengono mai rimosse)
  - **Descrizione**: il dizionario di lock per-chiave cresce senza mai essere ripulito. Non è un problema acuto a breve termine, ma su un processo long-running ad alto traffico prolungato è un lento leak di memoria (una chiave per ogni utente/token/code mai visto dal processo).
  - **Fix proposto**: eviction opportunistica (es. rimuovere una entry quando la lock non è `locked()` e non ha waiter, con TTL o LRU-bound) — da dimensionare insieme, priorità bassa rispetto al resto.
  - **Decisione**: _da discutere_
  - **Verifica (2026-11-07)**: **aperto** — invariato, nessuna eviction (linee del piano 41-44 → ora 54-65). Nota per il fix: `ThreadNamedLock` (introdotto con PERF-001, `concurrency.py:83-128` fa già eviction con contatore di utenti sotto guard lock, ma lo schema non è replicabile su `asyncio.Lock` (nessun modo pubblico di contare i waiter): lì serve TTL/LRU, come già ipotizzato.

---

## STRATEGIC (1)

- [ ] **PERF-010** — Backend Postgres è solo uno stub vuoto
  - **Location**: `backend/authglow/repositories/postgres/__init__.py` (~630 byte, nessuna implementazione concreta)
  - **Descrizione**: oggi l'unico backend di storage realmente funzionante è quello file-JSON-per-record. Molti dei finding sopra (PERF-001, 002, 007, 008) sono sintomi diretti di questa scelta architetturale, non bug isolati. Se il target di carico reale implica molte migliaia di utenti o scritture concorrenti sostenute, è la leva con l'impatto più alto — ma anche lo sforzo più alto.
  - **Fix proposto**: nessuno immediato — item da posizionare in roadmap, non da "fixare" in uno sprint. Utile discuterlo per primo, perché la decisione (investire su Postgres vs. ottimizzare il layer file) condiziona la priorità di PERF-001/002/007.
  - **Decisione**: _da discutere_
  - **Verifica (2026-11-07)**: **aperto** — `repositories/postgres/__init__.py` è sempre solo il docstring di placeholder (15 righe): backend non registrato, `Settings(repository_backend="postgres")` fallisce fast. Nessuna implementazione concreta.

---

## PROCESS (1)

- [x] **PERF-011** — Manca una baseline di load test
  - **Location**: n/a — nessuno script locust/k6/wrk nel repo (`backend/scripts/` contiene solo tool di migrazione/diagnostica)
  - **Descrizione**: tutti i finding sopra derivano da code review statica, non da numeri misurati. Senza una baseline (RPS massimo, p50/p95/p99 su login e refresh concorrenti) non è possibile validare l'impatto reale di un fix né stabilire priorità con dati oggettivi.
  - **Fix proposto**: scrivere uno scenario locust/k6 che eserciti login concorrenti + refresh-token concorrenti (i due percorsi dove PERF-001/002/003 si sommano) contro un'istanza di staging, **prima** di iniziare a implementare i fix sopra — dà i numeri "prima" da confrontare con "dopo".
  - **Decisione**: fix ora (2026-11-08).
  - **Verifica (2026-11-07)**: **aperto** — nessun locustfile/k6/wrk nel repo; `backend/scripts/` contiene sempre solo migrazione/diagnostica. Esiste però `tests/performance/` (pytest marcati `-m performance`: `test_threadpool.py` Tier 2.1, `test_bcrypt_async.py`, singleton jwt/httpx, cache oauth2) che il suo stesso README esclude come sostituto del load test (`tests/performance/README.md:10-12`); la directory `tests/load/` citata dal README non esiste.
  - **Fix**: harness locust in `backend/tests/load/` (branch `chore/load-test-baseline`): `run_baseline.py` one-shot (uvicorn usa-e-getta su storage temporaneo, seed admin+utenti via API, limiter disabilitato via config pre-seedata, CSV + `summary.md` con p50/p95/p99), `locustfile.py` (`LoginUser` cerimonia completa authorize→token, `RefreshUser` catena di rotazione per sessione, pesi 1:3, account dedicato per VU — la condivisione causava falsi 401 da theft-detection), `authflow.py` (flow in `requests` puro condiviso tra seed e scenario), `requirements-load.txt` (locust 2.47, fuori dal lockfile app). Baseline — **server = v0.2.2**, worker singolo, file storage, bcrypt 12, laptop dev 24 core, 60s/run:

    | concurrency | login e2e p50/p95 | authorize p50/p95 | refresh p50/p95 | logins/s | refresh/s | 500 | 401 |
    |---|---|---|---|---|---|---|---|
    | 10 | 580/930 ms | 250/320 ms | 500/700 ms | 1.14 | 2.71 | 0 | 25 (16%) |
    | 30 | 920/1500 ms | 310/700 ms | 530/840 ms | 1.71 | 5.74 | 134 | 115 (34%) |
    | 50 | 2600/3400 ms | * | * | 0.79 | 5.80 | 226 | 283 (82%) |

    *\*50u: percentili fuori tabella perché il 76% delle authorize fallisce (500) e l'82% delle refresh è 401 a risposta rapida — le code distorcono qualsiasi percentile: a 50u il sistema è in collasso, non "lento". Lettura: il throughput login a 1 worker è ~1.7/s già a 30u e il teto NON è bcrypt (che scala sul pool CPU a 24 core: authorize resta ~300ms mediana): è PERF-012 — gli indici refresh-token corrotti generano 500/lost-update che mascherano il throughput reale. Dopo il fix di PERF-012 la baseline va rimisurata (numeri "vera capacità"), poi PERF-004 (`--workers`, già supportato dal driver) e Redis (PERF-005/006) hanno numeri su cui decidere. Riproduzione: `python tests/load/run_baseline.py --users 30 --duration 60s` (README per opzioni/staging).

---

## Note per l'implementazione in sessioni successive

- Ogni item è indipendente a livello di codice tranne le dipendenze esplicitate (PERF-002↔005, PERF-005↔006). Possono essere implementati in qualsiasi ordine una volta presa la decisione.
- Il pattern di riferimento da riusare per PERF-001 e PERF-002 esiste già nel codebase (`AsyncNamedLock` e `core/jwt_singleton.py` rispettivamente) — non richiede progettazione da zero, solo applicazione coerente.
- PERF-003 dopo la rivalidazione 2026-11-07 ha due scope distinti: offload mancante di bcrypt sull'event loop (`password_reset.py:171,205`, `api_key.py:163,551` — fix necessario e indipendente) e separazione dei due executor (bcrypt vs I/O) — il sizing del pool di default è già stato fatto (Tier 2.1, `main.py:96-98`).
- Consigliato chiudere PERF-011 per primo se possibile, per avere numeri reali da citare quando si discute priorità/sforzo degli altri item.
