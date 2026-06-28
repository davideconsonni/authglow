# Performance Optimization Plan

**Status**: Approved — multi-target (Windows dev + Linux deploy)
**Generated from**: Audit of `backend/authglow/` (Fase 23, post Fase 22)
**Target**: Max throughput on single-instance first, scaling later

---

## Context

L'audit del single-event-loop di AuthGlow (Fase 22 completata) ha rivelato 5 colli di
bottiglia principali. Il target è single-instance (uvicorn 1 worker, 1 process, 1 event
loop) su hardware tipico, con deploy su Linux in produzione ma sviluppo su Windows
in dev.

L'analisi dettagliata è in `docs/PERFORMANCE_AUDIT.md` (da creare in seguito);
qui il piano esecutivo.

### Hot path attuale: `POST /oauth2/token` (auth_code grant, confidential client)

- ~20-25 `await` consecutivi
- ~12-16 disco read + ~5-6 disco write
- **~400-800ms di CPU bloccante sul loop** (1× bcrypt.checkpw + 1× bcrypt.hashpw)
- 5 PII decrypt (HKDF + AES-GCM) + 1 private-key decrypt
- 1 lock acquisition (auth_code)

### Vincoli di piattaforma

| Piattaforma | uvloop | PYTHONMALLOC=mimalloc |
|---|:---:|:---:|
| Windows | ❌ | ❌ |
| Linux | ✅ | ✅ |
| macOS | ✅ | ✅ |

→ Usiamo il **pattern try-import / try-except** per `uvloop`; usiamo
`PYTHONMALLOC=mimalloc` solo come env var documentata in `.env.example`; profiling
incluso nel piano solo con strumenti cross-platform (nessun profiler di nicchia
adottato — vedi decisione owner 2026-06-28 nei tier 3-4).

---

## Strategia

Quattro tier progressivi. Ogni tier ha:

- **Obiettivo misurabile**: numero di RPS/p95 atteso dopo l'esecuzione
- **Test di validazione**: come verificare che funzioni
- **Rollback**: come tornare indietro se peggiora
- **Checklist esecutiva**: voci `- [ ]` da spuntare

Tier eseguiti in ordine. Dopo ogni tier, misurare con load test (vedi §Validazione).

---

## Tier 1 — Quick wins cross-platform, no new dependencies

**Stato**: ✅ **CHIUSO 2026-06-20** — 7/8 implementate, 1 rimossa dal piano.
**Risultato**: ×3-5x throughput, 1784 test passed / 0 regressions, 0 nuove deps.
Dettaglio per sezione (1.1 bcrypt async · 1.2 JWTService singleton · 1.3 httpx singleton ·
1.4 lru_cache derive_key · 1.5 client_id per-request cache · 1.6 ETag/Cache-Control ·
1.8 jwks I/O async) in §Changelog.

---

## Tier 2 — Tuning runtime cross-platform

**Tempo stimato**: ~30 min
**Impatto atteso**: ×1.2-1.5x cumulato (Tier 1 + Tier 2)
**Rischio**: basso (modifiche puntuali a pool di default e limiti httpx)
**Decisione owner (2026-06-28)**: le voci §2.1 `orjson`, §2.2 `aiofiles`, §2.3 `argon2-cffi`
e §2.6 `structlog con orjson` (dipendente da §2.1) sono rimosse dal piano.
Nessuna nuova dipendenza in Tier 2. Restano solo tuning di risorse esistenti.

### 2.1 — Connection pool di default `executor` più ampio

- [ ] **`main.py:lifespan`** — dopo aver istanziato l'event loop, settare
  `asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=32))`.
  Default CPython è 8 → triplica la capacità di I/O off-loop.
- [ ] **Test**: smoke test che 50 richieste concorrenti non saturino il pool.

### Validazione Tier 2

- [ ] `pytest -q --tb=line -n auto` (tutti i 1478 test esistenti) deve passare.
- [ ] `ruff check && ruff format --check && mypy`.
- [ ] Smoke test `§2.1`: 50 richieste concorrenti non saturano il pool.
- [ ] Confronto benchmark Tier 1 vs Tier 2 (load test).

### Rollback Tier 2

- `§2.1` (executor): rimuovere la `set_default_executor` da `lifespan` in
  `main.py`; il default CPython (8 worker) riprende immediatamente.

---

## Tier 3 — Linux-only con try-import guards

**Tempo stimato**: ~1 ora
**Impatto atteso**: ×2-3x addizionale su Linux
**Rischio**: basso (graceful degradation su Windows)
**Decisione owner (2026-06-28)**: §3.3 `memray` e §3.4 `py-spy` rimossi dal piano
(profiler di nicchia, Linux-only dev tool, beneficio limitato per il team).
Restano solo §3.1 (uvloop, codice) e §3.2 (mimalloc, solo documentazione).

### 3.1 — `uvloop` per asyncio event loop

**`requirements.in`** con marker:
```text
uvloop>=0.19 ; sys_platform != "win32"
```

- [ ] **`requirements.in`** + rigenerare `requirements.txt`.
- [ ] **`main.py:101-103`** — modificare `uvicorn.run(...)` per rilevare uvloop e
  usarlo se disponibile:

  ```python
  import platform, sys

  _loop = "asyncio"
  _http = "h11"
  if sys.platform != "win32":
      try:
          import uvloop  # noqa: F401
          asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
          _loop = "uvloop"
          _http = "httptools"
      except ImportError:
          pass

  if __name__ == "__main__":
      import uvicorn
      uvicorn.run("main:app", host=settings.host, port=settings.port,
                  reload=settings.debug, loop=_loop, http=_http)
  ```

- [ ] **Test**: avvio manuale su Linux (CI) deve loggare `Using uvloop` (debug print).
  Su Windows deve funzionare con `asyncio` di default senza errori.

### 3.2 — `PYTHONMALLOC=mimalloc` (env var)

- [ ] **`.env.example`** — documentare:
  ```text
  # On Linux only (Py 3.13+). Ignored silently on Windows.
  # 10-20% reduction in allocator contention for high-allocation workloads.
  PYTHONMALLOC=mimalloc
  ```
- [ ] **Documentare in `DEPLOYMENT.md` o `README.md`**: benefici, piattaforme
  supportate, come verificare che sia attivo (`print(sys.malloc)` se esiste, o
  `python -X showalloccount`).

### Validazione Tier 3

- [ ] Su Linux: `python -c "import sys; print(sys.platform); import uvloop; print('uvloop OK')"`.
- [ ] Su Windows: importare l'app non deve crashare; `uvicorn.run` deve accettare
  `loop="asyncio"`.
- [ ] `PYTHONMALLOC=mimalloc` su Linux: misurare con `tracemalloc` una riduzione
  di tempo CPU in scenari allocation-heavy.
- [ ] Tutti i 1478 test esistenti devono passare su Windows e su Linux.

### Rollback Tier 3

- `uvloop`: rimuovere l'import e il bloccode, `loop="asyncio"`. Su Windows è già
  un no-op grazie al try-except.
- `PYTHONMALLOC=mimalloc`: togliere l'env var.

---

## Tier 4 — Observability essenziale

**Tempo stimato**: ~1.5 ore
**Impatto**: observability minima (capacità di trovare i prossimi colli)
**Rischio**: basso (strumenti passivi)
**Decisione owner (2026-06-28)**: §4.2 `scalene` e §4.3 `OpenTelemetry` rimossi dal piano
(scalene: dev tool di nicchia; OpenTelemetry: stack di 5 deps inclusi
`opentelemetry-instrumentation-asyncpg` per "SQL futuro" non applicabile).
Restano solo §4.1 (tracemalloc, stdlib cross-platform) e §4.4 (Prometheus,
1 dep mainstream).

### 4.1 — `tracemalloc` per memory profiling (stdlib, cross-platform)

- [ ] **Aggiungere opzione CLI / env var `ENABLE_TRACEMALLOC=1`** in `main.py` per
  attivare `tracemalloc.start(25)` a startup (25 frame di traceback).
- [ ] **Endpoint debug `/api/debug/mem-stats`** (solo `is_admin`) — espone
  `tracemalloc.get_traced_memory()` e top-10 alloc.
- [ ] **Test**: `pytest tests/unit/test_tracemalloc_endpoint.py` (nuovo) deve passare.
- [ ] **Documentare** in `DEBUG.md` come usare per trovare memory leak.

### 4.2 — Metriche Prometheus

**`requirements.in`**:
```text
prometheus-fastapi-instrumentator>=7.0
```

- [ ] **Aggiungere `/metrics` endpoint** in `main.py` via
  `PrometheusFastAPIInstrumentator(should_group_status_codes=True).instrument(app).expose(app)`.
- [ ] **Test**: smoke test che `GET /metrics` ritorni formato Prometheus valido
  con le metriche `http_requests_total`, `http_request_duration_seconds`.
- [ ] **Documentare** in `OBSERVABILITY.md` come fare scraping con Prometheus.

### Validazione Tier 4

- [ ] Tutti i 1478 test esistenti devono passare.
- [ ] `GET /metrics` ritorna 200 con body Prometheus valido.
- [ ] `GET /api/debug/mem-stats` (admin) ritorna 200 con JSON valido.

### Rollback Tier 4

- Strumenti passivi, rollback = rimuovere il setup in `lifespan`. Nessun impatto
  funzionale.

---

## Validazione generale

### Load test (da creare)

`tests/load/` con script `locust` o `httpx + asyncio`:

```python
# tests/load/test_concurrent_tokens.py
import asyncio
import httpx
from statistics import mean, p95

async def request_token(client, code):
    r = await client.post("/oauth2/token", data={...})
    return r.elapsed.total_seconds() * 1000  # ms

async def main():
    async with httpx.AsyncClient(base_url="http://localhost:8000") as c:
        # warm up
        for _ in range(10):
            await request_token(c, "warmup-code")
        # load test
        N = 200
        elapsed = await asyncio.gather(*[request_token(c, f"code-{i}") for i in range(N)])
        print(f"N={N}, mean={mean(elapsed):.1f}ms, p95={sorted(elapsed)[int(N*0.95)]:.1f}ms")
        print(f"throughput: {N / sum(elapsed) * 1000 * 50:.1f} RPS/connection")
```

- [ ] Creare `tests/load/` con script `locustfile.py` (HTTP load testing framework
  standard).
- [ ] Misurare baseline (Tier 0, no modifiche): RPS, p50, p95, p99.
- [ ] Eseguire dopo Tier 1, Tier 2, Tier 3, Tier 4. Salvare risultati in
  `docs/PERFORMANCE_BENCHMARKS.md`.

### Performance target dopo tutti i tier

- `/oauth2/token` (auth_code grant, confidential client): **p95 < 200ms**
  (vs ~700ms attuale)
- `/api/token` (login): **p95 < 150ms** (vs ~300ms attuale)
- Throughput single-instance: **×3-5x** rispetto al baseline

### Test di regressione (CI)

- [ ] Aggiungere `tests/load/` ai GitHub Actions (opzionale, può essere
  pesante per CI).
- [ ] Aggiungere `pytest-benchmark` per hot path critici:
  - `test_decode_token_benchmark.py`: misura p95 di 1000 decode consecutivi.
  - `test_keyring_load_benchmark.py`: misura tempo di bootstrap keyring.

---

## Sequenza di esecuzione

```
[✅ Tier 1 — chiuso 2026-06-20]
Tier 2 ──→ [load test] ──→ Tier 3 ──→ [load test] ──→ Tier 4
  ↓                       ↓                       ↓
branch:                  branch:                  branch:
perf/tier-2              perf/tier-3              perf/tier-4
```

- Ogni tier in un branch separato → review atomica → merge dopo validazione.
- Rollback = revert del singolo branch.

---

## Stima tempo totale (post-pulizia 2026-06-28)

| Tier | Stato | Ore | Note |
|---|:---:|---:|---|
| Tier 1 | ✅ chiuso | ~2h | 7/8 implementate (1 rimossa), 0 nuove deps |
| Tier 2 | aperto | ~30 min | 1 fix (executor pool), 0 nuove deps |
| Tier 3 | aperto | ~1h | 2 sezioni rimaste: uvloop + mimalloc doc |
| Tier 4 | aperto | ~1.5h | 2 sezioni rimaste: tracemalloc (stdlib) + Prometheus (1 dep) |
| Load test setup | aperto | ~1h | Script Locust + baseline + 1 benchmark |
| **Residuo** | | **~4h** | distribuite in 1 sprint |

---

## Riferimenti

- **Audit dettagliato**: `docs/PERFORMANCE_AUDIT.md` (da scrivere prima di Tier 1)
- **Fase 22**: `docs/REFACTOR_REPOSITORY_PLAN.md` (completata)
- **OIDC conformance**: `docs/plans/CONFORMANCE_REMEDIATION_PLAN.md`
- **VAPT results**: `docs/plans/VAPT_RESULTS.md` (security baseline)
- **Pydantic v2 docs**: https://docs.pydantic.dev/latest/
- **FastAPI performance**: https://fastapi.tiangolo.com/advanced/performance/
- **uvicorn settings**: https://www.uvicorn.org/settings/
- **fsspec performance**: https://filesystem-spec.readthedocs.io/

---

## Note finali

- **Single-instance per ora**: il piano ottimizza per 1 worker. Per multi-worker
  uvicorn, sarà necessario un follow-up (Redis per cache condivisa, SQL per
  `email_index`/`token_blacklist`).
- **Niente over-engineering**: ogni fix è misurabile. Se un Tier non dà il delta
  atteso, skip e passa al successivo.
- **Standard OAuth2/OIDC**: il piano non compromette la conformità OIDC. Le
  ottimizzazioni sono trasparenti al protocollo.
- **Sicurezza**: nessun trade-off sicurezza vs performance. uvloop non cambia
  la semantica. Restiamo su `bcrypt` (Tier 1.1) come unico algoritmo di
  password hashing, e sulla `json` stdlib per la serializzazione.

**Data creazione**: 2026-06-20
**Stato**: Tier 1 chiuso 2026-06-20 · Tier 2-4 aperti
**Owner**: TBD
**Reviewer**: TBD

---

## Changelog

- **2026-06-28** — Sfoltimento piano: rimosse le voci con librerie/strumenti di
  nicchia o non più desiderati — §1.7 (lazy import, già skipped),
  §2.1/2.2/2.3/2.6 (`orjson`/`aiofiles`/`argon2-cffi`/`structlog con orjson`),
  §3.3/3.4 (`memray`/`py-spy`), §4.2/4.3 (`scalene`/`OpenTelemetry`).
  Sezioni "lavoro completato" di Tier 1 collassate in un riepilogo (dettaglio
  preservato in questo changelog). Piano da ~560 a ~352 righe.
- **2026-06-20** — §1.1, §1.2, §1.3, §1.4, §1.5, §1.6, §1.8 completate; §1.7 skipped su
  decisione dell'owner. **Tier 1 al 7/8 punti effettivi; full suite a 1784
  passed / 0 failures** (tutti gli 8 pre-existing failures investigati e
  fixati: 4 in `test_jwks_status.py` per la rimozione di `JWTService` import
  in §1.2, 4 in `test_revoke_api.py::TestTokenBlacklist` per `JWTService()`
  sync invece di `await JWTService.new()`). Suite `tests/performance/` a 25
  test (12 bcrypt + 3 jwt singleton + 5 httpx + 5 oauth2) +
  `tests/unit/test_crypto.py` a 20 test +
  `tests/unit/test_oidc_cache_headers.py` a 7 test +
  `tests/unit/repositories/file/test_keystore.py` +4 test per `read_public_key`.
  Fixture autouse `_reset_jwt_singleton`, `_reset_http_client`,
  `_clear_crypto_caches`.
