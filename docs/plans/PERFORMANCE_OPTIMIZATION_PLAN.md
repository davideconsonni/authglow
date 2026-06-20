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

| Piattaforma | uvloop | PYTHONMALLOC=mimalloc | memray | py-spy live |
|---|:---:|:---:|:---:|:---:|
| Windows | ❌ | ❌ | ❌ | ❌ |
| Linux | ✅ | ✅ | ✅ | ✅ |
| macOS | ✅ | ✅ | ✅ | ✅ |

→ Usiamo il **pattern try-import / try-except** per `uvloop`; usiamo
`PYTHONMALLOC=mimalloc` solo come env var documentata in `.env.example`; profiling solo
con strumenti cross-platform (`tracemalloc`, `scalene`, `opentelemetry`).

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

**Tempo stimato**: ~2 ore
**Impatto atteso**: ×3-5x throughput
**Rischio**: basso (modifiche localizzate, pattern esistenti nel codice)

### 1.1 — bcrypt sync → `asyncio.to_thread`

- [x] **`services/password.py:90-108`** — wrappare `bcrypt.hashpw` e `bcrypt.checkpw` in
  `async def hash_password_async()` / `async def verify_password_async()` con
  `asyncio.to_thread`. Mantenere le versioni sync come wrapper che chiamano `asyncio.run`
  per retro-compat (per gli script CLI e i job fuori dal request loop).
- [x] **Aggiornare call site in `services/refresh_token.py:87, 139`** per usare
  `_async`.
- [x] **Aggiornare call site in `services/mfa.py:125-132`** (backup code verify).
- [x] **Aggiornare call site in `services/api_key.py:76, 83`** (hash + verify).
- [x] **Aggiornare call site in `services/oauth_client.py:103`** (`verify_password`).
- [x] **Aggiornare call site in `api/auth.py:1007`** (login password verify).
- [x] **Aggiornare call site in `api/auth.py:491`** (OAuth2 authorize password).
- [x] **Aggiornare call site in `api/oidc.py:694`** (DCR client_secret verify).
- [x] **Aggiornare call site in `api/user_profile.py:179`** (change password).
- [x] **Aggiornare call site in `api/password_reset.py:236, 259`** (reset/change).
- [x] **Test**: `pytest tests/unit/test_password.py tests/unit/test_api_key.py
  tests/unit/test_refresh_token.py tests/unit/test_admin_users_phase2.py` deve passare.
- [x] **Estensione scope** (uniformità): convertiti anche `api/admin.py:260,650`,
  `api/federation.py:316`, `api/setup.py:114`, `api/auth.py:1319,1511` e
  i call site `hash` in `api/password_reset.py:183,266` e `services/user_profile.py:145,149,231`
  + `services/oauth_client.py:72,162`. Refactor di `services/{refresh_token,mfa,api_key}.py`
  per delega a `services/password.py` (rimozione `import bcrypt` diretto).
- [x] **Nuova suite** `tests/performance/test_bcrypt_async.py` (12 test: correttezza
  + concorrenza + micro-benchmark) con marker `performance` in `pyproject.toml`.

### 1.2 — Singleton `JWTService` in `api/*`

- [x] **`api/auth.py:107-114`** — `get_jwt_service` con lazy-async singleton come
  `core/permissions.py:14-21`. Cache invalida su `rotate_keys` (admin-only).
- [x] **`api/mfa.py:47-49`** — stesso pattern.
- [x] **`api/passkey.py:66-68`** — stesso pattern.
- [x] **`api/oauth2_advanced.py:30-32`** — stesso pattern.
- [x] **Estensione scope** (uniformità): consolidato tutto in un unico modulo
  `core/jwt_singleton.py` con `get_jwt_service()` + `reset_jwt_singleton()`,
  `asyncio.Lock` + double-checked locking. Hook su `JWTService.rotate_keys` e
  `revoke_key`. Convertiti anche i call site diretti in `api/admin.py:1491,1534,1561`,
  `api/oidc.py:133,190,225,299,451`, `api/password_reset.py:284`, `api/federation.py:346`,
  `api/auth.py:349,397` (16 call site totali → 1 singleton).
- [x] **Test isolation**: fixture autouse `_reset_jwt_singleton` in `tests/conftest.py`.
- [x] **Test**: `pytest tests/unit/test_jwt.py tests/unit/test_admin.py
  tests/unit/test_id_token_*.py` deve passare; test_oidc_logout, test_logout_redirect,
  test_permissions. Aggiornati i mock in `test_logout_redirect.py`,
  `test_id_token_hint.py`, `test_federation.py` per il nuovo pattern.
  Nuova suite `tests/performance/test_jwt_singleton.py` (3 test: reuse, concorrenza,
  invalidation su rotate).

### 1.3 — `httpx.AsyncClient` singleton in `federation.py`

- [ ] **`services/federation.py:122, 178, 195`** — estrarre il `with
  httpx.AsyncClient(...) as client:` in un singleton module-level con
  `httpx.Limits(max_connections=50, max_keepalive_connections=20)`. Init lazy
  dentro un async lock.
- [ ] **Test**: `pytest tests/integration/test_federation*.py
  tests/unit/test_federation_*.py` deve passare.

### 1.4 — `lru_cache` su `_derive_key`

- [ ] **`core/crypto.py:33-40`** — wrappare `_derive_key` con
  `@functools.lru_cache(maxsize=8)`. La funzione è deterministica in
  `(secret_key, info)` → sicuro cachare.
- [ ] **Test**: `pytest tests/unit/test_crypto.py` (se esiste) o smoke test in
  `tests/unit/test_admin_users_phase2.py` (cambio password).

### 1.5 — Cache `client_id` per-request in `OAuth2Service`

- [ ] **`services/oauth2.py:152, 179, 221`** — accettare `client_id_cache: dict[str,
  OAuth2Client] | None = None` come parametro, oppure cachare per-request via
  `contextvars.ContextVar`. Popolato al primo lookup, rimosso a fine request.
- [ ] **Test**: `pytest tests/integration/test_oauth2*.py` deve passare.

### 1.6 — ETag + Cache-Control su endpoint statici

- [ ] **`api/oidc.py:30`** (`openid_configuration`) — aggiungere
  `response.headers["Cache-Control"] = "public, max-age=3600"`.
- [ ] **`api/oidc.py:123`** (`jwks`) — aggiungere
  `response.headers["Cache-Control"] = "public, max-age=300"` + ETag basato su
  `keyring.json` mtime + content hash.
- [ ] **`api/oidc.py:210`** (`userinfo`) — `private, max-age=0, no-cache`.
- [ ] **Test**: `pytest tests/unit/test_oidc.py tests/unit/test_discovery.py` deve passare.

### 1.7 — Lazy import moduli pesanti

- [ ] **Spostare `import pyotp`**, **`import qrcode`**, **`import webauthn`** dentro le
  rispettive funzioni (vedi `services/mfa.py`, `services/passkey.py`).
- [ ] **Test**: `pytest tests/unit/test_mfa.py tests/unit/test_passkey.py` deve passare.

### 1.8 — Rimuovere I/O sync in `jwks`

- [ ] **`api/oidc.py:149-155`** — rimuovere `os.path.exists` + `open(..., "rb")` +
  `serialization.load_pem_public_key` sync. Usare
  `await self._repository._afs.read_bytes(...)` e parse async-safe
  (`asyncio.to_thread` per il parse RSA che è CPU-bound).
- [ ] **Test**: `pytest tests/unit/test_oidc.py` deve passare.

### Validazione Tier 1

- [x] `pytest -q --tb=line -n auto` deve passare (zero regressions). — **1735 passed, 8 pre-existing failures (JWT su Py 3.13, vedi AGENTS.md), 0 regressioni**.
- [x] `ruff check authglow/ && ruff format --check authglow/ && mypy authglow/`. — ruff/format puliti; mypy: 2 errori pre-esistenti (`oidc.py:553`, `federation.py:636`).
- [ ] Misurare throughput: prima/dopo con load test (vedi §Validazione). — da fare in Tier 2 / fine-piano.

### Rollback Tier 1

Ogni fix è indipendente: revert del singolo file. Conserva le firme async come
wrapper delle sync originali (no API break).

---

## Tier 2 — Nuove librerie cross-platform

**Tempo stimato**: ~3 ore
**Impatto atteso**: ×4-10x cumulato (Tier 1 + Tier 2)
**Rischio**: medio (richiede test approfonditi di compat Pydantic)

### 2.1 — `orjson` per JSON

**`requirements.in`** (cross-platform ✓):
```text
orjson>=3.10
```

- [ ] **`requirements.in`** + `requirements.txt` (rigenerare via `uv pip compile`).
- [ ] **`core/async_io.py:42-48`** (`read_json`) — usare `orjson.loads` invece di
  `json.load`. Wrappare in `asyncio.to_thread` solo per il file I/O; il parsing è veloce.
- [ ] **`core/async_io.py:49-56`** (`write_json`) — usare `orjson.dumps`, convertire
  bytes → write bytes. Gestire `default=` callback per `datetime`/`UUID` se
  Pydantic non le gestisce già.
- [ ] **Verifica compat Pydantic v2**: Pydantic v2 `model_dump_json()` è già
  veloce ma usa `orjson` opzionalmente tramite `model_dump(mode="json")` +
  `orjson.dumps`. Per FastAPI response: configurare `ORJSONResponse` come
  default in `main.py:43` (`default_response_class=ORJSONResponse`).
- [ ] **`services/passkey.py:195, 227, 265, 334`** — sostituire `json.dumps`/`json.loads`
  con `orjson`.
- [ ] **`services/email/file_storage.py:32`** — `json.dump` con `orjson`.
- [ ] **`services/auth/token_blacklist.py:109`** — `json.load` con `orjson`.
- [ ] **Configurare `structlog` renderer** per usare `orjson.dumps` in
  `main.py` (opzionale, vedi §2.6).
- [ ] **Test**: `pytest -q --tb=line -n auto` deve passare (in particolare i test
  JSON-schema che asseriscono presenza di keys).

### 2.2 — `aiofiles` per `storage_backend="file"` (bypass `to_thread`)

**`requirements.in`**:
```text
aiofiles>=23.0
```

- [ ] **`requirements.in`** + rigenerare `requirements.txt`.
- [ ] **`repositories/file/base.py:67-115`** — aggiungere parametro `async_io:
  Literal["asyncio", "fsspec", "aiofiles"] = "fsspec"`. Quando `storage_backend == "file"`,
  usare `aiofiles` invece di `fsspec` + `asyncio.to_thread`. I file locali non hanno
  il bisogno dell'astrazione fsspec, e `aiofiles` è un thin wrapper sopra
  `os.read`/`os.write` event-driven.
- [ ] **Test**: `pytest tests/unit/repositories/ -n auto` deve passare; in
  particolare `test_protocols.py` (39 test conformance) e
  `test_keystore_shared_backend.py`.
- [ ] **Benchmark**: scrivere micro-benchmark con `pytest-benchmark` per misurare
  il delta su I/O locale. Target: <50μs per `read_json` invece di ~200μs.

### 2.3 — `argon2-cffi` al posto di `bcrypt` con graceful re-hash

**`requirements.in`**:
```text
argon2-cffi>=23.0
```

- [ ] **`requirements.in`** + `requirements.txt`.
- [ ] **`services/password.py`** — aggiungere `Argon2Hasher` con i parametri
  OWASP-recommended (t=3, m=64MB, p=4). Algoritmo di identificazione: controllare
  il prefisso dell'hash (`$argon2id$` vs `$2b$`).
- [ ] **`services/password.py:hash_password`** — se algoritmo scelto è argon2id,
  usa `Argon2Hasher().hash()`. Se `bcrypt`, fallback.
- [ ] **`services/password.py:verify_password`** — usa `phcrypt.verify(stored,
  plain)` (dalla lib `pwdlib` o `passlib`) che identifica automaticamente.
- [ ] **Aggiungere re-hash lazy**: in `services/user.py:update_password` (o dove
  l'utente cambia password), dopo `verify_password` se l'hash era bcrypt,
  ri-hashare con argon2. Aggiungere una colonna `password_algo` nel User (se
  si vuole esplicito) o usare il prefisso hash.
- [ ] **Migration strategy**: nessuna migrazione forzata. Vecchi utenti bcrypt
  rimangono bcrypt fino al prossimo login o change-password. Documentare in
  `SECURITY.md`.
- [ ] **Test**: `pytest tests/unit/test_password.py
  tests/unit/test_admin_users_phase2.py` deve passare. Aggiungere test che
  verifica un hash bcrypt si autentica e viene re-hashed a argon2 al primo
  cambio password.
- [ ] **Documentare in `SECURITY.md`**: parametri OWASP, motivazione, piano di
  deprecazione bcrypt.

### 2.4 — `httpx.AsyncClient` singleton (multi-target, già in Tier 1.3 ma
qui rafforzato con `Limits` tuning)

Vedi §1.3.

### 2.5 — Connection pool di default `executor` più ampio

- [ ] **`main.py:lifespan`** — dopo aver istanziato l'event loop, settare
  `asyncio.get_running_loop().set_default_executor(ThreadPoolExecutor(max_workers=32))`.
  Default CPython è 8 → triplica la capacità di I/O off-loop.
- [ ] **Test**: smoke test che 50 richieste concorrenti non saturino il pool.

### 2.6 — structlog con `orjson` per JSON rendering

- [ ] **`main.py`** (dove si configura structlog) — usare
  `structlog.processors.JSONRenderer(orjson.dumps)` invece del default
  `json.dumps`. Richiede `orjson` (già in §2.1).
- [ ] **Test**: i test esistenti che asseriscono formato log devono passare.

### Validazione Tier 2

- [ ] `pytest -q --tb=line -n auto` (tutti i 1478 test esistenti) deve passare.
- [ ] `ruff check && ruff format --check && mypy`.
- [ ] Confronto benchmark Tier 1 vs Tier 2 (load test).

### Rollback Tier 2

- `orjson`: revert a `json` (basta togliere la sostituzione, API quasi identica).
  Attenzione a `default=` callback per datetime/UUID.
- `aiofiles`: revert a fsspec (mantenere la signature `async_io` con default
  "fsspec").
- `argon2-cffi`: tenere bcrypt come fallback, basta disattivare la scelta
  argon2 se emergono bug.

---

## Tier 3 — Linux-only con try-import guards

**Tempo stimato**: ~1 ora
**Impatto atteso**: ×2-3x addizionale su Linux
**Rischio**: basso (graceful degradation su Windows)

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

### 3.3 — `memray` come dev tool (opzionale)

**`pyproject.toml` optional-dependencies**:
```toml
[project.optional-dependencies]
dev = [
    "memray>=1.18; sys_platform != 'win32'",
    "py-spy>=0.4; sys_platform != 'win32'",
    "scalene>=1.5",
    "opentelemetry-instrumentation-fastapi>=0.50b0",
]
```

- [ ] **`pyproject.toml`** — aggiungere gruppo dev come sopra.
- [ ] **Documentare in `DEVELOPMENT.md`** (o `README.md` sezione Dev Tools): come
  usare `memray run -o output.bin -m uvicorn main:app` e `memray flamegraph
  output.bin`. Notare che **memray non funziona su Windows**.
- [ ] **Test**: nessun test automatico (è un dev tool). Documentare che
  `pip install -e .[dev]` su Windows installa solo `scalene` e
  `opentelemetry-*` (gli altri sono skippati via marker).

### 3.4 — `py-spy` in dev/prod Linux

- [ ] **Documentare in `DEPLOYMENT.md`**: come profilare un processo in produzione
  (`py-spy dump --pid <pid>` e `py-spy record -o profile.svg -- python main.py`).
  Specificare: **richiede ptrace**, Linux/macOS solo.
- [ ] **CI**: opzionalmente, su GitHub Actions Linux, eseguire `py-spy record`
  su un smoke test e pubblicare il flamegraph come artifact.

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
- `memray`/`py-spy`: solo dev tools, basta non installarli.

---

## Tier 4 — Profilazione cross-platform

**Tempo stimato**: ~2 ore
**Impatto**: observability (capacità di trovare i prossimi colli)
**Rischio**: basso (strumenti passivi)

### 4.1 — `tracemalloc` per memory profiling (stdlib, cross-platform)

- [ ] **Aggiungere opzione CLI / env var `ENABLE_TRACEMALLOC=1`** in `main.py` per
  attivare `tracemalloc.start(25)` a startup (25 frame di traceback).
- [ ] **Endpoint debug `/api/debug/mem-stats`** (solo `is_admin`) — espone
  `tracemalloc.get_traced_memory()` e top-10 alloc.
- [ ] **Test**: `pytest tests/unit/test_tracemalloc_endpoint.py` (nuovo) deve passare.
- [ ] **Documentare** in `DEBUG.md` come usare per trovare memory leak.

### 4.2 — `scalene` per CPU+memory profiling (dev tool, cross-platform)

- [ ] **`pyproject.toml` optional-dependencies dev**: aggiungere `scalene>=1.5`.
- [ ] **Documentare in `DEVELOPMENT.md`**: come usare `scalene main.py` per
  profiling line-level (identifica esattamente quali linee allocano di più).
  Cross-platform, funziona su Windows.

### 4.3 — `opentelemetry-instrumentation-fastapi` per distributed tracing

**`requirements.in`**:
```text
opentelemetry-instrumentation-fastapi>=0.50b0
opentelemetry-instrumentation-asyncpg>=0.50b0  # futuro, per quando migreremo a SQL
opentelemetry-exporter-otlp-proto-grpc>=1.27
opentelemetry-sdk>=1.27
```

- [ ] **`requirements.in`** + rigenerare.
- [ ] **`main.py:lifespan`** — aggiungere setup OpenTelemetry tracer provider se
  `OTEL_EXPORTER_OTLP_ENDPOINT` env var è settata. Setup idempotente.
- [ ] **Auto-instrument FastAPI**: `FastAPIInstrumentor.instrument_app(app)`.
- [ ] **Auto-instrument httpx**: `HTTPXClientInstrumentor().instrument()`.
- [ ] **Auto-instrument bcrypt / argon2**: opzionale, con `BcryptInstrumentor`.
- [ ] **Test**: smoke test che l'app si avvii senza `OTEL_EXPORTER_OTLP_ENDPOINT`
  (deve essere no-op).
- [ ] **Documentare in `OBSERVABILITY.md`**: come configurare un collector locale
  (es. `docker run -p 4317:4317 otel/opentelemetry-collector`), come visualizzare
  in Jaeger / Tempo / Grafana.

### 4.4 — Metriche Prometheus

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
- [ ] Con OpenTelemetry collector attivo, le trace arrivano.

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
Tier 1 ──→ [load test] ──→ Tier 2 ──→ [load test] ──→ Tier 3 ──→ [load test] ──→ Tier 4
  ↓                       ↓                       ↓                       ↓
branch:                  branch:                  branch:                  branch:
perf/tier-1              perf/tier-2              perf/tier-3              perf/tier-4
```

- Ogni tier in un branch separato → review atomica → merge dopo validazione.
- Rollback = revert del singolo branch.

---

## Stima tempo totale

| Tier | Ore | Note |
|---|---:|---|
| Tier 1 | ~2h | 8 fix, no nuove deps |
| Tier 2 | ~3h | 6 fix + 3 nuove deps, test approfonditi |
| Tier 3 | ~1h | 4 fix con try-import guards |
| Tier 4 | ~2h | 4 fix, strumenti observability |
| Load test setup | ~1h | Script Locust + baseline |
| **Totale** | **~9h** | distribuite in 1-2 sprint |

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
- **Sicurezza**: argon2 è memory-hard e più robusto di bcrypt. uvloop non
  cambia la semantica. orjson è spec-compliant (rifiuta JSON invalido). Nessun
  trade-off sicurezza vs performance.

**Data creazione**: 2026-06-20
**Stato**: pronto per esecuzione
**Owner**: TBD
**Reviewer**: TBD

---

## Changelog

- **2026-06-20** — §1.1 e §1.2 completate. Tier 1 al 2/8 punti. Suite `tests/performance/`
  istituita (15 test totali: 12 bcrypt + 3 jwt singleton). Fixture autouse
  `_reset_jwt_singleton` aggiunta a `tests/conftest.py`.
