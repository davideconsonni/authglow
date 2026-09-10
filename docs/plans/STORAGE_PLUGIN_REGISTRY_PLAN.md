# Storage Plugin Registry — Piano di implementazione

> Workflow: plan-grill-implement. Un item alla volta, ogni step richiede approvazione esplicita.
> Stato workflow: `[x] Step 1 Plan` → `[x] Step 2 Grill` → `[x] Step 3 Implement` → `[x] Step 4 Test` → `[x] Step 5 Mark Done`

## - [x] 1. Contesto (current vs desired)

**Current state (verificato su disco):**
- `backend/authglow/repositories/protocols.py` (1307 righe): ~35 `Protocol` `runtime_checkable` — contratto domain-shaped, async-only, Pydantic round-trip. Astrazione già pronta.
- `backend/authglow/repositories/dependencies.py` (731 righe): 35x `get_<entity>_repository()` (righe 52–731) cablate a mano su `File*Repository`. Docstring righe 1–7 promette "a new storage backend only adds a new repositories/<backend>/ implementation".
- Solo ~13 factory accettano `settings=` (phone:135, refresh_token:298, login_history:371, email_index:429, federated_identity:454, user:479, user_preferences:502, federation_provider:528, keystore:554, device_authorization:583, claim_policy:601, api_key_claim_policy:627, webhook:652, webhook_delivery:669, rate_limit_config:686, settings_override:710); le altre ~20 non lo accettano → inconsistenza `lru_cache` bypass (cfr. AGENTS.md).
- `backend/authglow/core/config.py:249` — `storage_backend: str = "file"` è il selettore **fsspec** (`file/s3/gcs/abfs`, cfr. `get_storage_options()` righe 816–840), NON il selettore DB. Non riusabile.
- Rete di sicurezza esistente: `backend/tests/unit/repositories/test_protocols.py` (conformance Protocol×impl via `_IMPL_TABLE`) + `test_in_memory.py` + `file/test_*.py` (30+ file).

**Desired state (intesa grilling confermata):**
1. Tutte le 35 factory migrate a thin wrapper sopra `_resolve()`, solo backend `file` — nessun cambio di comportamento.
2. Registro interno: `_REGISTRY + register_backend() + _resolve()` in `dependencies.py`.
3. Nuovo setting globale `repository_backend: Literal["file"] = "file"` (env `REPOSITORY_BACKEND`).
4. `settings=` propagato a tutte le 35 factory (stesso pattern bypass già usato per phone/user/refresh).
5. Fail-fast `ValueError` su backend sconosciuto (niente fallback silenzioso).

**Fuori scopo (non aprire):** `UserService` lock cross-entity (`user+email_index+federated_identity`), `FileKeyStoreRepository._write_json_versioned`, `core/` (jwt/crypto/concurrency/PII audit), middleware security. Nessuna impl `repositories/postgres/` in questo passo (solo stub/dir + doc) — il valore `postgres` resta volutamente non registrato.

## - [x] 2. File da creare/modificare (con righe)

| # | File | Azione |
|---|------|--------|
| 1 | `backend/authglow/core/config.py` (~riga 248–250) | Aggiungere `repository_backend: Literal["file"] = "file"` dopo `storage_path`, con `Field(description=...)`. Verificare import `Literal` (già `typing`?). |
| 2 | `backend/authglow/repositories/dependencies.py` (righe 1–731) | Aggiungere `_REGISTRY`, `register_backend()`, `_resolve(entity, settings)`; precaricare mapping `file` → 35 `File*Repository`; convertire tutte le 35 `get_*` in wrapper; aggiungere `settings=None` alle ~20 mancanti. Aggiornare docstring modulo. |
| 3 | `backend/authglow/repositories/postgres/__init__.py` | Stub documentato: "placeholder, non registrato — fail-fast finché non implementato". |
| 4 | `backend/tests/unit/repositories/test_registry.py` (nuovo) | Test registro: default=file, `settings=` propagato, backend sconosciuto→`ValueError`, `register_backend()` custom (fake in-memory) risolto via `_resolve`. |
| 5 | `ARCHITECTURE.md` | Aggiornare mappa `repositories/` + nota selettore config-driven (obbligo AGENTS.md). |

## - [x] 3. Strategia di test

- **Unit (nuovi):** `test_registry.py` — 4 casi: (a) ogni `get_*` ritorna `File*` di default; (b) `settings=Settings(repository_backend="file")` propagato (mock `lru_cache` bypass); (c) `repository_backend="postgres"` → `ValueError` con messaggio con backend disponibile; (d) `register_backend("fake", {...})` + resolve → istanza fake.
- **Regressione esistente:** `pytest backend/tests/unit/repositories/ -q` (conformance + file impl) — deve restare verde; per AGENTS.md solo file dell'area toccata, non full suite (full `-n auto` solo prima del commit).
- **Edge:** typo env (`REPOSITORY_BACKEND=File` maiuscolo → fail-fast o normalizzazione? proposta: case-sensitive strict, documentato); `settings=None` → `get_settings()` singleton; import circolari (`dependencies.py` importa `File*` lazy dentro le funzioni — mantenere lazy anche nel precaricamento via lambda/factory, MAI import top-level).
- **Lint/type:** `ruff check authglow/` + `ruff format --check`, `mypy authglow/repositories/ authglow/core/config.py`.

## - [x] 4. Rischi e compatibilità

| Rischio | Mitigazione |
|---------|-------------|
| Import circolari se il precaricamento importa `File*` a top-level | Mapping con factory lazy (`lambda settings: FileX(settings)`) o import dentro `_resolve`; verificare con `pytest --collect-only` |
| Cambio firma `get_*()` rompe `Depends()` / mock nei test | Solo aggiunta kwarg opzionale `settings=None`; ritorno stesso tipo. Nessun cambio per chiamanti senza arg |
| `Literal["file"]` rifiuta `postgres` a livello Pydantic prima del fail-fast custom | Voluto in questo passo; allargare a `Literal["file","postgres"]` solo quando l'impl postgres esiste |
| Collisione concettuale `storage_backend` vs `repository_backend` | Nomi + docstring distinti; `storage_backend` resta fsspec, `repository_backend` è DB/entità |
| Stati misti user/postgres + email_index/file | Impossibile per design: selettore globale singolo (deciso Q3) |
| Pre-esistenti noti (event loop 3.13, CSP, `setup_page`) | Non toccare senza chiedere; bucket (b) per AGENTS.md |

## - [x] 5. Stima scopo

- **File toccati:** 2 modificati (config, dependencies) + 1 stub + 1 test nuovo + 1 doc = 5 file.
- **Complessità:** media-bassa. `dependencies.py` è meccanico (35 wrapper), ma richiede disciplina su lazy-import + `settings=` uniforme. Test nuovi piccoli. Nessuna logica di business toccata.
- **Righe stimate:** ~+120 (registro+wrapper) / ~+80 test / ~+10 config / doc.

---
*Gate: attendere approvazione Step 1 prima di passare allo Step 2 (Grill).*

## Completamento (Step 5 — approvato dall'utente)

- Implementato: `repository_backend` in `Settings`, `_REGISTRY`/`register_backend()`/`_resolve()` in `dependencies.py` (35 factory → wrapper con `settings=`), stub `repositories/postgres/`, `test_registry.py` (9 test), `REPOSITORY_BACKEND` in `.env.example`, `ARCHITECTURE.md` aggiornato. Extra: `_resolve` tipizzato con generico `_T` per mypy strict.
- Test: `tests/unit/repositories/` 728 passed; `test_registry + test_config` 66 passed; `ruff check`/`ruff format`/`mypy` puliti.
- Follow-up dalla full suite (stesso item): (a) `repository_backend` aggiunto a `_FIELD_META` in `api/admin_settings.py` (il test di copertura config lo richiede); (b) `_resolve_backend_name` tollera Settings mockati (non-string → `"file"`, settings inoltrato intatto — preserva i test JWT con `MagicMock`); (c) `REPOSITORY_BACKEND=file` in `.env.example`.
- Full suite finale: **2716 passed** (`pytest -q --tb=line -n auto`, Python 3.13).
- Post-item (su richiesta): fixati i 2 errori mypy in `api/admin.py:1180,1193` (`bulk_user_operation`: `user.email if 'user' in locals()` → `_last_user = locals().get("user")` + `isinstance(..., User)` — stessa semantica, narrowing corretto). mypy pulito su tutti i file toccati; test `test_admin_users_update + test_admin_jwk_revoke` 20 passed; diff minimo (8+/2-, senza reformat di hunk non correlati).
- Stato git: registry committato in `d61e82c`/`2d1c49f`; fix `admin.py` non committato (nessuna richiesta di commit).
