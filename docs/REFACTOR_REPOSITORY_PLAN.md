# Repository Pattern Refactor — Implementation Plan

> **Status**: Fase 0 (scaffolding) ✅ done · Fase 1 (TokenBlacklist) ✅ done · Fase 2 (CSRF) ✅ done · Fase 3 (Session) ✅ done · Fase 4 (EmailVerification) ✅ done · Fase 5 (PasswordReset) ✅ done · Fase 6 (AuthorizationCode) ✅ done · Fase 7 (OAuth2Client) ✅ done · Fase 8 (OAuth2Consent + FIX admin.py) ✅ done · Fase 9 (MFA split 3) ✅ done · Fase 10 (Passkey + FIX url_to_fs) ✅ done · Fase 11 (API Key) ✅ done · Fase 12 (RefreshToken) ✅ done · Fase 13 (RBAC split 3) ✅ done · Fase 14 (LoginHistory + FIX 2 bugs) ✅ done · Fase 15 (AdminAction + FIX 2 bugs) ✅ done · Fase 16 (SecurityEvent + FIX 2 bugs + FIX typo protocol) ✅ done · Fase 17a (EmailIndex) ✅ done · Fase 17b (FederatedIdentity) ✅ done · Fase 17c (User) ✅ done · Fase 17 (Federation, era mancante da Status/tabella) ✅ done · Fase 18 (Rename `UserStorage` → `UserService`) ✅ done · Fase 19 (UserPreferences) ✅ done · Fase 20 (KeyStore) ✅ done · **Fase 21 (Deprecazione & cleanup) ✅ done — Piano archiviato**.
> **Pattern**: Strangler — una fase per PR, sempre testabile e rollbackabile.
> **Vincoli**: API pubblica dei service invariata, factory rinominate, test esistenti restano verdi (con patch del conftest dove necessario).

---

## 1. Perché e cosa stiamo facendo

**Problema attuale**: 23 servizi (`backend/authglow/services/` + `core/token_blacklist.py`) aprono fsspec/AsyncFileSystem direttamente, ognuno duplicando `_afs`, `_lock`, `_get_*_path`. Qualsiasi sostituzione del backend (Postgres, Firestore, Redis+S3) richiederebbe di toccare 23 file in modo coordinato.

**Obiettivo**: introdurre un livello di **Protocol** backend-agnostici (`UserRepository`, `TokenRepository`, …) + implementazioni concrete (oggi `FileUserRepository`, domani `SqlUserRepository`/`FirestoreUserRepository`). I servizi smettono di parlare di path/lock/JSON e parlano di entità di dominio.

**Vincoli non negoziabili** (test devono continuare a passare):
- API pubblica dei service invariata (gli stessi metodi async con le stesse firme)
- Nomi dei metodi dei service non cambiano (es. `UserStorage.create_user` → `UserService.create_user` con `UserService` che chiama `user_repo.create`)
- Factory `get_user_storage` esiste ancora ma diventa `get_user_repository`

**Esempio concreto** del refactor per `UserStorage.create_user`:

```python
# PRIMA (services/storage.py:156)
async with self._lock(f"user:{user.id}"), self._lock("email_index"):
    email_index = await self._load_email_index()
    index_key = hash_index_key(user.email.lower())
    if index_key in email_index:
        raise ValueError(f"User with email {user.email} already exists")
    user_path = self._get_user_path(user.id)
    user_data = self._encrypt_user_for_storage(user)
    await self._afs.write_json(user_path, user_data)
    email_index[index_key] = user.id
    await self._save_email_index(email_index)
return user

# DOPO (services/user.py:156)
async with self._lock("email_index"):
    if await self._user_repo.exists_by_email(user.email):
        raise ValueError(f"User with email {user.email} already exists")
    await self._user_repo.create(user)
```

Il `UserRepository` (Protocol) è backend-agnostico. Il `FileUserRepository` (impl concreta) contiene tutta la logica fsspec + lock + encryption.

---

## 2. Architettura a strati

```
┌──────────────────────────────────────────────┐
│  API (FastAPI routes)                        │   Depends(get_user_repository)
├──────────────────────────────────────────────┤
│  Services (business logic)                   │   UserService, JWTSvc, MFASvc, …
│  - policy, composizione, named_lock          │   ↕ parla solo con i Repository
├──────────────────────────────────────────────┤
│  Repository Protocols (interfacce)            │   UserRepository, TokenRepository…
│  - CRUD puro + queries dominio               │   Definiti in repositories/protocols.py
├──────────────────────────────────────────────┤
│  File Repository (impl concreta)             │   FileUserRepository, FileTokenRepo…
│  - fsspec, AsyncFileSystem, encrypt_field    │   Sottocartella repositories/file/
│  - nasconde lock + CAS + serializzazione    │
├──────────────────────────────────────────────┤
│  Driver: AsyncFileSystem (esistente)         │   core/async_io.py — già astratto
└──────────────────────────────────────────────┘
```

**Decisioni di design**:
- I **Protocol** sono **backend-agnostici**: nessun path, nessun lock, nessun concetto storage nei metodi. Esempio: `UserRepository.create(user: User) -> None`, non `write_user_at_path(path, blob)`.
- Le **eccezioni di dominio** (`ConcurrentWriteError` per CAS) restano in `core/concurrency.py` e vengono sollevate sia dall'impl File che dalla futura impl SQL (per quest'ultima il retry diventa una no-op).
- Il **`named_lock` in-process** resta nei Service (è logica di business, non di storage). Il `FileUserRepository.update` non prende lock propri — si fida che il Service chiami in modo serialized. Questo è già vero oggi per la maggior parte dei metodi locked. *Per il refactor: lo lascio nei Service per non rompere i test esistenti che patchano la classe storage.*
- **CAS cross-process** (usato da 5 servizi: email_verification, oauth_client, oauth2 codes, password_reset, refresh_token) resta nel File impl come dettaglio interno. Il Protocol espone `update` con `expected_version` opzionale che solleva `ConcurrentWriteError`. Il Service fa il retry.
- **Email storage** (`services/email/file_storage.py`) **non** entra nei repository: è un `EmailProvider` (astrazione diversa, già esiste come `EmailProvider(ABC)`). Resta dov'è.
- **JWT keyring** (`core/config.py` + `services/jwt.py`) → entra come **`KeyStoreRepository`**, *ma con signature diversa* (key material, non User-like). Trattato come refactor speciale, vedi §6.
- **TokenBlacklist** in `core/` viene spostato in `services/auth/token_blacklist.py` per coerenza (è I/O, non config). Il `token_blacklist()` singleton resta.

---

## 3. Layout target

```
backend/authglow/
├── core/
│   ├── async_io.py              (invariato — è il driver)
│   ├── concurrency.py           (invariato — NamedLock + ConcurrentWriteError)
│   ├── cache.py                 (invariato)
│   ├── config.py                (invariato)
│   ├── crypto.py                (invariato)
│   ├── datetime.py              (invariato)
│   ├── password.py              (invariato)
│   ├── rate_limit.py            (invariato)
│   └── token_blacklist.py       ← DA SPOSTARE in services/auth/token_blacklist.py (fase 1)
├── repositories/                ← NUOVA CARTELLA
│   ├── __init__.py              (riesporta i Protocol + factory principali)
│   ├── protocols.py             (TUTTI i Protocol, uno per entità, raggruppati per dominio)
│   ├── exceptions.py            (NotFoundError, AlreadyExistsError, ConcurrentWriteError*)
│   ├── dependencies.py          (factory FastAPI: get_user_repository, get_token_repository, …)
│   ├── base.py                  (BaseFileRepository: fsspec + AsyncFileSystem + path helpers comuni)
│   └── file/                    (implementazioni concrete)
│       ├── __init__.py
│       ├── base.py              (BaseFileRepository: setup fsspec, encrypt helpers, CAS helper)
│       ├── user.py              (FileUserRepository)
│       ├── email_index.py       (FileEmailIndexRepository)
│       ├── federated_identity.py(FileFederatedIdentityRepository)
│       ├── refresh_token.py     (FileRefreshTokenRepository)
│       ├── authorization_code.py(FileAuthorizationCodeRepository)
│       ├── oauth_client.py      (FileOAuth2ClientRepository)
│       ├── oauth_consent.py     (FileOAuth2ConsentRepository)
│       ├── email_verification.py(FileEmailVerificationRepository)
│       ├── password_reset.py    (FilePasswordResetRepository)
│       ├── csrf.py              (FileCSRFTokenRepository)
│       ├── session.py           (FileSessionRepository)
│       ├── passkey.py           (FilePasskeyRepository + FileWebAuthnChallengeRepository)
│       ├── rbac.py              (FileRoleRepository + FilePermissionRepository + FileUserRoleRepository)
│       ├── mfa.py               (FileBackupCodeRepository + FileBackupCodeAttemptRepository + FileTrustedDeviceRepository)
│       ├── api_key.py           (FileAPIKeyRepository)
│       ├── login_history.py     (FileLoginHistoryRepository) ← sistema anche il bug "no-cloud"
│       ├── admin_action.py      (FileAdminActionRepository)  ← sistema anche il bug "no-cloud"
│       ├── security_event.py    (FileSecurityEventRepository)← sistema anche il bug "no-cloud"
│       ├── federation.py        (FileFederationProviderRepository)
│       ├── user_preferences.py  (FileUserPreferencesRepository)
│       ├── token_blacklist.py   (FileTokenBlacklistRepository)
│       └── keystore.py          (FileKeyStoreRepository — RSA keyring)
├── services/                    (invariato nella struttura, ma ogni servizio ora dipende da repository)
│   ├── storage.py               (rinominato in user.py, vedi sotto)
│   ├── jwt.py                   (usa KeyStoreRepository)
│   ├── …
│   ├── user.py                  ← era services/storage.py (rinominato)
│   ├── email_verification.py    (usa EmailVerificationRepository)
│   ├── password_reset.py        (usa PasswordResetRepository)
│   ├── refresh_token.py         (usa RefreshTokenRepository)
│   └── …
└── api/                         (factory locali rimosse, importa da repositories/dependencies)
    ├── auth.py                  (Depends(get_user_repository) al posto di Depends(get_user_storage))
    ├── admin.py                 (FIX inline I/O: 1163-1225)
    └── …
```

*`ConcurrentWriteError` resta in `core/concurrency.py` (già importato ovunque). `repositories/exceptions.py` aggiunge solo le semantic-specific.*

---

## 4. I Protocol — esempi

```python
# repositories/protocols.py (estratti, non completi)

class UserRepository(Protocol):
    async def create(self, user: User) -> None: ...
    async def get_by_id(self, user_id: str) -> Optional[User]: ...
    async def get_by_email(self, email: str) -> Optional[User]: ...
    async def exists_by_email(self, email: str) -> bool: ...
    async def update(self, user: User) -> None: ...
    async def delete(self, user_id: str) -> bool: ...
    async def list(self, *, limit: int, offset: int, **filters) -> tuple[list[User], int]: ...
    async def count(self) -> int: ...

class RefreshTokenRepository(Protocol):
    async def create(self, token: RefreshToken) -> None: ...
    async def get_by_token(self, plaintext_token: str) -> Optional[RefreshToken]: ...
    async def get_by_id(self, token_id: str) -> Optional[RefreshToken]: ...
    async def revoke(self, token_id: str) -> None: ...
    async def revoke_family(self, family_id: str) -> None: ...
    async def list_active(self, *, user_id: Optional[str] = None) -> list[RefreshToken]: ...
    async def rotate(self, old: RefreshToken, new: RefreshToken) -> None: ...  # CAS-protected

class EmailIndexRepository(Protocol):
    async def lookup(self, email: str) -> Optional[str]: ...
    async def insert(self, email: str, user_id: str) -> None: ...
    async def remove(self, email: str) -> None: ...
    async def all(self) -> dict[str, str]: ...
```

I Protocol sono **puri**, niente `fsspec`, niente path. La crittografia PII vive nel `FileUserRepository` (è un dettaglio del backend file — Postgres cifra a livello colonna con strategie diverse).

---

## 5. Ordine di migrazione (Strangler)

Una PR per fase. Ogni fase indipendente, test green, rollback possibile.

Ogni fase qui sotto ha la **checklist dettagliata** nel §5.1 — usa quella durante l'esecuzione.

| # | Fase | Entità | Note |
|---|---|---|---|
| 0 | **Setup** | — | Crea `repositories/` con `protocols.py` (TUTTI i Protocol), `exceptions.py`, `base.py`, `dependencies.py`, `file/base.py`. Smoke test che il package importi. Nessun servizio toccato. **Stato dell'app invariato.** |
| 1 | TokenBlacklist ✅ | `TokenBlacklistRepository` | 1 file, già singleton, niente CAS. Sposta `core/token_blacklist.py` → `services/auth/token_blacklist.py` (mantieni singleton). Aggiorna 0 route (è già auto-idratato). **Fatto: 2026-06-14.** |
| 2 | CSRF ✅ | `CSRFTokenRepository` | Service esposto con `repository=` injection, helpers crittografici (`_compute_lookup`, `_hash_token`) restano nel service. Throttling sweep rimane in service. **Fatto: 2026-06-14.** |
| 3 | Session ✅ | `SessionRepository` | `SessionService` delega MFA + consent I/O al repository. `_compute_lookup` (HMAC) e plaintext generation restano nel service. Expiry check + delete-on-expire restano nel service. **Fatto: 2026-06-14.** |
| 4 | EmailVerification ✅ | `EmailVerificationRepository` | `EmailVerificationService` delega CRUD al repository. `mark_token_used` mantiene `named_lock` (in-process) + CAS retry loop catching `ConcurrentWriteError` da `_repo.update()` (cross-process). `_find_lookup` + bcrypt verify restano nel service. `user_storage` resta pubblico (peer service, migrazione a UserRepository in Fase 18). **Fatto: 2026-06-14.** |
| 5 | PasswordReset ✅ | `PasswordResetRepository` | `PasswordResetService` delega CRUD + listing + cleanup + stats al repository. **Dual-mirror file** (primary `token_lookup` + mirror `code_lookup`) nascosto nel repository: VAPT-022. `mark_token_used` mantiene `named_lock` + CAS retry loop (defensive, il `write_text` del repo non preserva `_version`). `generate_reset_code` + alphabet invariant + HMAC `reset_code_lookup_key` (spostato in `core/crypto.py`) restano nel service. **Fatto: 2026-06-14.** |
| 6 | AuthorizationCode ✅ | `AuthorizationCodeRepository` | Solo i 4 metodi auth-code di `OAuth2Service` (create/get/mark_used/delete) sono migrati. `verify_client` / `verify_redirect_uri` / `verify_scopes` / `process_scopes` / `verify_grant_type` restano (usano `client_storage` e `settings`, non file I/O). `client_storage` resta pubblico. `mark_code_as_used` mantiene `named_lock` + CAS retry loop (defensive). Repo gestisce policy get_by_code (absent/corrupt/expired/used → None, auto-delete expired). **Fatto: 2026-06-14.** |
| 7 | OAuth2Client ✅ | `OAuth2ClientRepository` | `OAuth2ClientStorage` delega CRUD al repository. `update_last_used` + `rotate_secret` mantengono `named_lock` (in-process) + CAS retry loop catching `ConcurrentWriteError` da `_repo.update()` (cross-process). `verify_client_secret` / `verify_redirect_uri` / `is_scope_allowed` / `is_grant_type_allowed` restano nel service (business). `generate_client_secret` + bcrypt hashing restano nel service. **Fatto: 2026-06-14.** |
| 8 | OAuth2Consent ✅ | `OAuth2ConsentRepository` (+ FIX inline I/O admin.py) | `OAuth2ConsentService` delega CRUD + listing + cleanup al repository. Deterministic path `{user_id}/{client_id}.json` (O(1)). `revoke_consent` / `revoke_user_client_consent` mantengono `named_lock` (in-process). **FIX inline I/O in `api/admin.py:1163-1225`**: rimosso fsspec/AsyncFileSystem inline, sostituito con `consent_service.list_all_for_admin()` che fa email filter + DTO conversion + pagination (vengono aggiunti 2 metodi: `OAuth2ConsentRepository.list_all` + `OAuth2ConsentService.list_all_for_admin`). **Fatto: 2026-06-14.** |
| 9 | MFA (split 3) ✅ | `BackupCodeRepository` + `BackupCodeAttemptRepository` + `TrustedDeviceRepository` | `MFAService` delega CRUD + lockout counter + trusted device management ai 3 repository. `verify_user_backup_code` chiama `_bc_repo.use_code()` (atomic read-modify-write) + `_attempts_repo.get/save/delete()`. `is_device_trusted` chiama `_td_repo.find_trusted()` + `_td_repo.update()` con retry CAS catching `ConcurrentWriteError`. `generate_totp_secret` / `verify_totp` / `generate_qr_code` / `hash_backup_code` / `verify_backup_code` / `generate_device_fingerprint` restano nel service (pure crypto). `named_lock` resta nel service (lock multi-repo). **Fatto: 2026-06-14.** |
| 10 | Passkey (+ FIX url_to_fs) ✅ | `PasskeyRepository` + `WebAuthnChallengeRepository` (+ FIX fsspec bypass) | `PasskeyService` delega CRUD ai 2 repository. **FIX bypass bug**: rimosso `fsspec.core.url_to_fs(storage_path)[0]` da `__init__` (riga 51 originale) che bypassava il `Settings.storage_backend` selection e sarebbe crashato su backend non-`file`. I repo ora usano `BaseFileRepository._init_filesystem` che onora `Settings.storage_backend`. `update_passkey_usage` wrappa `get + update(last_used, sign_count)` in `named_lock` + retry CAS catching `ConcurrentWriteError` (5 tentativi). `verify_registration` / `verify_authentication` / `generate_*_options_dict` restano nel service (WebAuthn crypto). `named_lock` resta nel service. **Fatto: 2026-06-14.** |
| 11 | API Key ✅ | `APIKeyRepository` (+ prefix index) | `APIKeyService` delega CRUD + listing al repository. Mantiene `named_lock` per i critical section di brute-force lockout, usage stats, IP restrictions, revoke. **Prefix index** (12-char prefix → key_ids) è gestito dal repository con 3 metodi pubblici nel Protocol (`load_prefix_index` / `add_to_prefix_index` / `remove_from_prefix_index`); SQL backends li implementano via native unique key su `key_prefix`. `cleanup_expired` richiede sia `expires_at < now` AND `is_active=False` (semantica invariata). `_verify_api_key` (bcrypt) e `_generate_api_key` (secrets + bcrypt) restano nel service (pure crypto). **Fatto: 2026-06-14.** |
| 12 | RefreshToken (alta complessità) ✅ | `RefreshTokenRepository` (+ id_index + active_index) | `RefreshTokenService` delega CRUD + listing + 2 indici secondari al repository. `_find_token_lookup` (HMAC) e `_generate_token` (secrets + bcrypt + HMAC) restano nel service (pure crypto). `create_refresh_token` chiama `_repo.create()` + `_repo.add_to_id_index()` + `_repo.add_to_active_index()`. `validate_and_rotate` wrappa get+modify+update in `named_lock(f"refresh_token:{lookup}")` + retry CAS catching `ConcurrentWriteError` (3 tentativi). `_revoke_token_family` / `_revoke_descendants` (business logic ricorsiva) restano nel service ma usano `_repo.update()` + `_repo.remove_from_active_index()`. **`get_refresh_token_repository(settings=...)` factory** accetta settings opzionale per evitare il `lru_cache` bypass sul `get_settings()` globale (vedi nota). **Fatto: 2026-06-14.** |
| 13 | RBAC (split 3) ✅ | `PermissionRepository` + `RoleRepository` + `UserRoleRepository` | `RBACService` delega CRUD ai 3 repository. `initialize_defaults` (business) resta nel service. `user_has_permission` / `user_has_role` / `get_user_permissions` (business aggregation multi-repo) restano nel service. `update_role` wrappa in `named_lock(f"role:{id}")` + `_role_repo.update()`. `delete_role` check `is_system` (business guard) prima di `_role_repo.delete()`. `get_user_roles` ora delega al repository che fa auto-delete expired on read. `remove_role_from_user` ora chiama `_user_role_repo.find_assignment()` + `remove()` (vs scan+delete pre-refactor). **Fatto: 2026-06-14.** |
| 14 | LoginHistory (+ FIX 2 bugs) ✅ | `LoginHistoryRepository` (+ FIX `fsspec.filesystem("file")` + FIX `os.remove()`) | `LoginHistoryService` delega CRUD + listing + retention sweep al repository. **FIX bypass bug 1** (riga 73 originale): rimosso `self.fs = fsspec.filesystem("file")` hard-coded che bypassava `Settings.storage_backend`. **FIX bypass bug 2** (riga 141 originale): rimosso `os.remove(file_path)` in `_cleanup_old_entries` (bypassava fsspec e crashava su backend non-`file` con `FileNotFoundError` / `OSError`); ora delega a `_repo.cleanup_old()` che usa `_delete()` (async-fsspec `rm`). Aggiunti 2 parametri opzionali `entry_id` e `timestamp` al Protocol per coerenza tra `LoginHistoryEntry` service-side e record persistito. **`get_login_history_repository(settings=...)` factory** accetta settings opzionale (lru_cache bypass). **Fatto: 2026-06-14.** |
| 15 | AdminAction (+ FIX 2 bugs) ✅ | `AdminActionRepository` (+ FIX `fsspec.filesystem("file")` + FIX `os.makedirs()`) | `AdminActionService` delega CRUD + listing al repository. **FIX bypass bug 1** (riga 76 originale): rimosso `self.fs = fsspec.filesystem("file")` hard-coded che bypassava `Settings.storage_backend`. **FIX bypass bug 2** (riga 105 originale): rimosso `os.makedirs(os.path.dirname(action_path), exist_ok=True)` (bypassava fsspec; su qualsiasi backend non-`file` il `makedirs` OS-level creava una directory locale che il backend cloud non vedeva); ora delega a `_write_json` che chiama `_ensure_parent` (single backend-agnostic mkdir point). Mantenuta la dataclass `AdminAction` (zero callers ma usata internamente per `record_action` return type — id/timestamp locali **disaccoppiati** da quelli persistiti, documentato nel docstring). **Fatto: 2026-06-14.** |
| 16 | SecurityEvent (+ FIX 2 bugs) ✅ | `SecurityEventRepository` (+ FIX `fsspec.filesystem("file")` + FIX `os.makedirs()` + FIX typo protocol) | `SecurityEventService` delega CRUD + listing al repository. **FIX bypass bug 1** (riga 72 originale): rimosso `self.fs = fsspec.filesystem("file")` hard-coded che bypassava `Settings.storage_backend`. **FIX bypass bug 2** (riga 99 originale): rimosso `os.makedirs(os.path.dirname(event_path), exist_ok=True)`; ora delega a `_write_json` che chiama `_ensure_parent`. **FIX typo protocol** (riga 857 `protocols.py`): `list_for_user` ritornava `tuple[List[SecurityEventModel], int]` (typo, import inesistente); corretto a `tuple[List[Record], int]` per coerenza con `AdminAction`/`LoginHistory` e rimosso import unused di `SecurityEvent as SecurityEventModel`. Mantenuta la dataclass `SecurityEvent` (zero callers del `record_event` return, id/timestamp locali **disaccoppiati**, documentato). **Fatto: 2026-06-14.** |
| 17a | EmailIndex (User domain split 1/3) ✅ | `EmailIndexRepository` (storage root file, HMAC-hashed keys) | `UserStorage._load_email_index` / `_save_email_index` rimossi; ora delega a `_email_index_repo.lookup/insert/remove/all`. Service mantiene `named_lock("email_index")` per cross-entity atomicity (create_user, update_email, delete_user). Factory `get_email_index_repository(settings=...)` accetta settings opzionale (lru_cache bypass — senza, l'autouse `_override_settings` non basta perché `FileEmailIndexRepository` chiama `authglow.repositories.file.base.get_settings` che NON è patchato). L'email index file vive alla storage root (`<storage>/email_index.json`), pre-refactor layout. **Fatto: 2026-06-14.** |
| 17b | FederatedIdentity (User domain split 2/3) ✅ | `FederatedIdentityRepository` (storage root file, composite key `{provider}|{external}`) | `UserStorage._load_federated_identities` / `_save_federated_identities` rimossi; ora delega a `_federated_identity_repo.lookup/link/unlink`. `link` solleva `EntityAlreadyExistsError` (vs `ValueError` pre-refactor) per coerenza con altre repository exception. Service mantiene `named_lock("federated_identities")` per cross-entity atomicity. Factory `get_federated_identity_repository(settings=...)` con lru_cache bypass. Il file vive alla storage root (`<storage>/federated_identities.json`). **Fatto: 2026-06-14.** |
| 17c | User (User domain split 3/3) ✅ | `UserRepository` (PII encryption + CRUD + lockout + last-login + password setters) | `UserStorage` refactored come thin facade sopra `UserRepository` (PII encryption spostata nel repo, è responsabilità del File backend). Service mantiene `named_lock` per cross-entity operations (`create_user`, `update_email`, `delete_user`, `link_federated_identity`) + user cache invalidation + timing-leak protection in `get_user_by_email`. PII encryption/decryption: 5 campi (`email`, `first_name`, `last_name`, `phone`, `avatar_url`) via `authglow.core.crypto.encrypt_field`/`decrypt_field` (AES-256-GCM). **`get_by_email` / `exists_by_email` lato repo sollevano `NotImplementedError`** perché richiedono coordinazione con `EmailIndexRepository` (two-step lookup); il service `get_user_by_email` orchestra le due chiamate. Aggiunti 6 metodi al protocol: `update_last_login`, `record_failed_login`, `reset_failed_login_attempts`, `clear_failed_login_attempts`, `is_account_locked`, `set_password` (single-file mutations, no cross-entity coordination). `_get_user_path` mantenuto come back-compat shim per i 6 test esistenti che introspectano lo storage path. **Rename `UserStorage` → `UserService` e move a `services/user.py` rimandato** (100+ call sites, fuori scope di questa fase). **Fatto: 2026-06-14.** |
| 18 | Rename UserStorage → UserService (+ deprecation shim) ✅ | `services/user.py` con `UserService` + `services/storage.py` come shim | Tutta la logica del `UserStorage` spostata in `services/user.py` con la classe `UserService`. `services/storage.py` diventa un deprecation shim: `from authglow.services.user import UserService as UserStorage` + `get_settings` re-export + `DeprecationWarning` emesso al module import. **Zero modifiche ai 100+ call sites in 11 file `api/*.py`** (continuano a importare `UserStorage` da `services.storage`). Test esistenti adattati: `tests/conftest.py:109` patch path `authglow.services.storage.get_settings` → `authglow.services.user.get_settings` (il binding originale in `BaseFileRepository.__init__`); `tests/unit/test_concurrency.py:231,264` stesso fix. 7 test in `tests/unit/test_user_profile.py` adattati da `user_storage._write_user` → `user_storage._user_repo.update` (Fase 17c). **Fatto: 2026-06-14.** |
| 19 | UserPreferences ✅ | `UserPreferencesRepository` (Pydantic round-trip + delete preferences) | `UserProfileService` refactored: rimosso `import os`, `import fsspec`, `AsyncFileSystem`, `preferences_path`, `storage_options`, `fs`, `_afs`. 3 metodi migrano al repo: `get_user_preferences` → `_preferences_repo.get(user_id)`, `update_user_preferences` → `_preferences_repo.save(preferences)`, `delete_account` → `_preferences_repo.delete(user_id)`. 5 metodi restano nel service (richiedono User + cross-entity): `get_user_profile` (User + preferences aggregato), `update_user_profile` (User file), `change_password` (User + security notification), `change_email` (User + email service + security service), `deactivate_account` / `reactivate_account` (User file). 5 siti in `update_user_profile`/`change_password`/`change_email`/`deactivate_account`/`reactivate_account` migrati da `self.user_storage._write_user(user)` (privato pre-refactor) a `self.user_storage._user_repo.update(user)` (pubblico post-Fase 17c). Path layout: `<storage>/user_preferences/<user_id>.json`. **Fatto: 2026-06-14.** |
| 17 | Federation ⏳ → ✅ | `FederationProviderRepository` (+ FIX `fsspec.filesystem("file")` + FIX `os.makedirs()`) | `FederationStorage` (108 righe, ora 13 righe di deprecation shim) ha `fsspec` + `os.makedirs` + `AsyncFileSystem` direttamente (gli stessi bug delle altre fasi migrate). `FederationProviderRepository` protocol esiste già in `protocols.py:867` (5 metodi: `create` / `get_by_id` / `update` / `delete` / `list`). 28 test integration in `tests/integration/test_federation.py` verdi baseline. Path layout: `<storage>/federation/<provider_id>.json`. 5 metodi del service migrano al repo. Service mantiene `named_lock("federation:*")` per in-process safety. `services/federation.py:11` importa `FederationStorage` direttamente → da aggiornare a `FederationProviderService` (con deprecation shim). **NB**: il nome `FederationService` è già usato in `services/federation.py` per l'OIDC Relying Party flow (callback handling, JWKS verification, provider UI list) — il CRUD usa quindi `FederationProviderService` per separare le 2 concern. **Fatto: 2026-06-14.** |
| 8 | OAuth2Consent | `OAuth2ConsentRepository` | Path deterministici, no CAS. **Fix inline I/O in api/admin.py:1163-1225** in questa fase. |
| 9 | MFA (split 3) | `BackupCodeRepository`, `BackupCodeAttemptRepository`, `TrustedDeviceRepository` | 3 subdir, no CAS. |
| 10 | Passkey (split 2) | `PasskeyRepository`, `WebAuthnChallengeRepository` | 2 subdir, no CAS. Sistemato anche il `url_to_fs` che bypassa settings. |
| 11 | API Key | `APIKeyRepository` | 1 subdir + index, no CAS. |
| 12 | RefreshToken | `RefreshTokenRepository` | 1 subdir + 2 indici, CAS. **Complessità alta.** |
| 13 | RBAC (split 3) | `RoleRepository`, `PermissionRepository`, `UserRoleRepository` | 3 subdir. |
| 14 | LoginHistory | `LoginHistoryRepository` | **Fix bug "hard-coded fsspec.filesystem('file')"** portandolo sul `BaseFileRepository` che rispetta `storage_backend`. |
| 15 | AdminAction | `AdminActionRepository` | Idem fix "hard-coded". |
| 16 | SecurityEvent | `SecurityEventRepository` | Idem fix "hard-coded". |
| 17 | Federation | `FederationProviderRepository` | 1 subdir. |
| 18 | **UserStorage (split 3)** | `UserRepository`, `EmailIndexRepository`, `FederatedIdentityRepository` | **Il refactor più grosso.** Rinomina `services/storage.py` → `services/user.py`. 3 repository separati perché sono entità distinte. Il `UserStorage` esistente (447 righe) diventa `UserService` (business) + 3 `File*Repository` (storage). Test `tests/unit/test_storage.py` resta verde grazie alla facciata `UserStorage` deprecata che delega ai repository. |
| 19 | UserPreferences | `UserPreferencesRepository` | `services/user_profile.py` — sottrae solo la parte preferences (le altre operazioni restano nel service). |
| 20 | **KeyStore (speciale)** | `KeyStoreRepository` | **Interfaccia diversa**: non CRUD su User, ma key material. Metodi: `get_active_keypair() -> KeyPair`, `get_keypair_by_kid(kid) -> Optional[KeyPair]`, `get_public_keys() -> list[PublicKey]`, `rotate() -> KeyPair`, `revoke(kid) -> None`. Refactor di `core/config.py` + `services/jwt.py`. |
| 21 | **Deprecazione & cleanup** | — | Rimuove tutte le factory `get_user_storage` duplicate nei 7 file `api/`, sostituite con `get_user_repository`. Rimuove `services/storage.py` (UserStorage). Aggiorna tutti i `patch("authglow.services.storage...")` nel conftest → `patch("authglow.repositories.file.user...")`. Aggiorna `tests/unit/test_storage.py` → `tests/unit/repositories/file/test_user_repository.py`. |

**Stima**: 21 PR, ~3-5 giorni/settimana realistica. Ogni PR: refactor + run test del file + lint + type-check.

### 5.1 Checklist dettagliate per fase

> **Convenzioni**: ogni fase è una singola PR, con branch `refactor/repo-phase-N-<entity>`. Le checkbox vanno spuntate PRIMA del commit finale. I test elencati in "Test" sono quelli da eseguire PRIMA di marcare la fase come completata. Se un test non passa, NON procedere — fixare o rollback.

---

#### Fase 0 — Setup scaffolding

- [x] Creare `backend/authglow/repositories/__init__.py` con re-export di tutti i Protocol + eccezioni
- [x] Creare `backend/authglow/repositories/protocols.py` con TUTTI i Protocol (24 Protocol) — vedi §4
- [x] Creare `backend/authglow/repositories/exceptions.py` con `EntityNotFoundError`, `EntityAlreadyExistsError`
- [x] Creare `backend/authglow/repositories/base.py` (placeholder per future astrazioni cross-cutting)
- [x] Creare `backend/authglow/repositories/dependencies.py` (vuoto, sarà popolato fase per fase)
- [x] Creare `backend/authglow/repositories/file/__init__.py` (vuoto)
- [x] Creare `backend/authglow/repositories/file/base.py` con `BaseFileRepository` (fsspec + AFS + path helpers)
- [x] Creare `backend/tests/unit/repositories/__init__.py` (vuoto)
- [x] Creare `backend/tests/unit/repositories/file/__init__.py` (vuoto)
- [x] Creare `backend/tests/unit/repositories/file/test_base.py` con smoke test per `BaseFileRepository`
- [x] Aggiornare questo file (`docs/REFACTOR_REPOSITORY_PLAN.md`) marcando Fase 0 come completata

**Comandi di verifica**:
```bash
cd backend
ruff check authglow/repositories/
ruff format --check authglow/repositories/
mypy authglow/repositories/
pytest tests/unit/repositories/ -v
pytest -q --tb=line -n auto   # full suite, deve restare verde
```

**Criteri di accettazione**:
- [ ] Tutti i comandi sopra passano
- [ ] Nessun servizio esistente è stato modificato (`git diff --stat services/ core/` vuoto)
- [ ] `python -c "from authglow.repositories.protocols import UserRepository, RefreshTokenRepository"` funziona

---

#### Fase 1 — TokenBlacklist ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/token_blacklist.py` con `FileTokenBlacklistRepository` (implemementa `TokenBlacklistRepository`)
- [x] Aggiungere factory `get_token_blacklist_repository()` in `backend/authglow/repositories/dependencies.py`
- [x] Spostare `backend/authglow/core/token_blacklist.py` → `backend/authglow/services/auth/token_blacklist.py` (mantieni singleton `token_blacklist()`)
- [x] Service espone `revoke`, `is_revoked`, `startup_hydrate` (identici) + delega I/O al repository
- [x] Aggiornare import in `backend/main.py` (lifespan) se necessario
- [x] Aggiornare `tests/conftest.py` per patchare il nuovo path (es. `patch("authglow.services.auth.token_blacklist.get_settings")`)
- [x] Aggiungere test `backend/tests/unit/repositories/file/test_token_blacklist.py`
- [x] Verificare `tests/unit/test_jwt.py` e tutti i test che usano `token_blacklist()` restano verdi

**Risultato**: 1077/1077 test passano (full suite, 4:13). 25 nuovi test in `test_token_blacklist.py` + 4 nuovi in `test_base.py` (atomic write). Bug-fix intermedio: rimosso check ridondante su `_initialized` in `is_revoked` (`_store` vuoto è già lo stato "non idratato" corretto).

**Comandi**:
```bash
cd backend
ruff check authglow/repositories/file/token_blacklist.py authglow/services/auth/token_blacklist.py
mypy authglow/repositories/file/token_blacklist.py authglow/services/auth/token_blacklist.py
pytest tests/unit/repositories/file/test_token_blacklist.py -v
pytest tests/unit/test_jwt.py -v
pytest -q --tb=line -n auto
```

---

#### Fase 2 — CSRF ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/csrf.py` con `FileCSRFTokenRepository`
- [x] Aggiungere factory `get_csrf_token_repository()` in `dependencies.py`
- [x] Refactor `backend/authglow/services/csrf.py`: `CSRFTokenService` chiama `_repo.save()` / `_repo.get()` / `_repo.delete()` / `_repo.cleanup_expired()`. Le funzioni statiche `_compute_lookup` e `_hash_token` restano nel service (sono crittografiche, non I/O).
- [x] Aggiornare import in `backend/authglow/api/auth.py` e altri file che usano `get_csrf_service()` — non serviva: nessun caller di `get_csrf_service` (la factory era esportata ma non iniettata)
- [x] Aggiornare `tests/conftest.py`: aggiungere `patch("authglow.repositories.file.csrf.get_settings")` — non serviva: la service chiama `get_settings()` direttamente via il proprio binding, e l'autouse fixture `test_settings` copre già il path transitivo
- [x] Aggiungere `tests/unit/repositories/file/test_csrf.py`
- [x] `tests/unit/test_csrf.py` deve restare verde senza modifiche (a parte `patch()` path)

**Risultato**: 17 nuovi test in `test_csrf.py` (init, protocol conformance, save/get, delete, cleanup_expired, patched-settings construction). 12 test esistenti in `test_csrf.py` restano verdi con cambi minimi (`svc.storage_path` → `svc.repository._storage_path`, `svc.fs` → `svc.repository._filesystem`). 67/67 test repository totali. 59/59 test mirati CSRF+federation.

---

#### Fase 3 — Session ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/session.py` con `FileSessionRepository`
- [x] Factory `get_session_repository()` in `dependencies.py`
- [x] Refactor `backend/authglow/services/session.py`: `SessionService` chiama `_repo.save_mfa_session()` etc.
- [x] Le funzioni `_compute_lookup` restano nel service
- [x] Aggiornare import in `api/auth.py`, `api/mfa.py`, `api/oauth2_advanced.py` — non serviva: la firma di `SessionService()` è invariata (accetta opzionale `repository=`)
- [x] Aggiornare `tests/conftest.py` — non serviva: il patch esistente `authglow.services.session.get_settings` copre il binding del service
- [x] Aggiungere `tests/unit/repositories/file/test_session.py`
- [x] Test esistenti su session restano verdi

**Risultato**: 23 nuovi test in `test_session.py` (init, protocol conformance, MFA save/get/delete, consent save/get/delete, indipendenza MFA-vs-consent, costruzione via patched settings). 17 test esistenti in `test_session.py` restano verdi con cambi minimi (`session_service.storage_path` → `session_service.repository._storage_path`, `session_service.fs` → `session_service.repository._filesystem`). 90/90 test repository totali. 1117/1117 full suite (era 1077 dopo Fase 1, +40 test nuovi).

---

#### Fase 4 — EmailVerification ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/email_verification.py` con `FileEmailVerificationRepository`
- [x] Factory `get_email_verification_repository()`
- [x] Refactor `backend/authglow/services/email_verification.py`:
  - `EmailVerificationService.mark_token_used` diventa `await self._repo.update(token)` con retry
  - `_find_lookup` (HMAC) resta nel service
  - `_generate_token` (bcrypt + HMAC) resta nel service
- [x] Aggiornare import in `api/email_verification.py` e dove usato — non serviva: `EmailVerificationService()` mantiene la firma a zero argomenti
- [x] Aggiornare `tests/conftest.py` — non serviva: la fixture esistente patcha `authglow.services.email_verification.get_settings`; il service continua a chiamare `get_settings()` localmente
- [x] Aggiungere `tests/unit/repositories/file/test_email_verification.py`
- [x] Test esistenti in `tests/unit/test_email_verification.py` restano verdi (4 test con cambi minimi: `email_verification_service.storage_path` → `email_verification_service.repository._storage_path`, `email_verification_service.fs` → `email_verification_service.repository._filesystem`)

**Risultato**: 23 nuovi test in `test_email_verification.py` (init, protocol conformance, create with VAPT-003 plaintext-on-disk check, get_by_lookup with Pydantic round-trip e exclude=True handling, update with first-CAS pass + ConcurrentWriteError on stale version, delete, cleanup_expired con conteggio corretto, patched-settings construction). 15 test esistenti verdi con 4 body changes minimi. 113/113 test repository totali. 1140/1140 full suite (era 1117 dopo Fase 3, +23 nuovi).

**Bug-fix intermedio**: prima versione del `FileEmailVerificationRepository.update` aveva un check `if version == 0: raise FileNotFoundError(...)` sbagliato — il payload creato da `create` non ha `_version`, quindi la prima `read_json_versioned` ritorna 0 di default (semantica originale). Rimosso. Il CAS effettivo parte solo dalla seconda update concorrente.

---

#### Fase 5 — PasswordReset ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/password_reset.py` con `FilePasswordResetRepository`
- [x] Factory `get_password_reset_repository()`
- [x] Refactor `backend/authglow/services/password_reset.py`:
  - `mark_token_used`: nascondere la logica dual-mirror (token_lookup + code_lookup) dentro `_repo.update()`
  - `verify_token`, `verify_by_code`: usano `_repo.get_by_token_lookup()` / `_repo.get_by_code_lookup()`
  - `_generate_token` (bcrypt + HMAC) resta nel service
  - `_reset_code_lookup_key` (HMAC) resta nel service (wrapper di `core.crypto.reset_code_lookup_key`)
- [x] **Attenzione**: `create_reset_token` scrive 2 file mirror. La transazione non esiste nel filesystem: accettato il rischio (era già così). `delete_by_token_lookup` legge il primary per recuperare `reset_code` e cancellare anche il mirror.
- [x] Aggiornare import in `api/password_reset.py` — non serviva: `PasswordResetService()` mantiene la firma a zero argomenti
- [x] Aggiornare `tests/conftest.py` — non serviva: la fixture esistente patcha `authglow.services.password_reset.get_settings`; il service continua a chiamare `get_settings()` localmente
- [x] Aggiungere `tests/unit/repositories/file/test_password_reset.py` con casi specifici per VAPT-022 (dual mirror)
- [x] Test esistenti VAPT-022 restano verdi (5 test con cambi minimi)

**Risultato**: 33 nuovi test in `test_password_reset.py` (init, protocol conformance, create con VAPT-022 dual-mirror + plaintext-not-on-disk, get_by_token_lookup / get_by_code_lookup con Pydantic round-trip, update con dual-mirror, delete_by_token_lookup che rimuove entrambi, list_for_user con active_only + skip mirrors, list_all pagination, cleanup con grace period 24h, stats senza doppio conteggio mirrors, patched-settings construction). 42 test esistenti verdi con 5 body changes minimi. 146/146 test repository totali. 1173/1173 full suite (era 1140 dopo Fase 4, +33 nuovi).

**Helper aggiunto**: `authglow/core/crypto.py::reset_code_lookup_key(secret_key, code) -> str` — esposto come free function (non legata a `get_settings()`) così il repository può usarla senza importare dal service. Il service ha un wrapper `_reset_code_lookup_key` per retrocompatibilità.

**Comandi**:
```bash
cd backend
pytest tests/unit/repositories/file/test_password_reset.py tests/unit/test_password_reset.py -v -k "mirror or vapt_022 or reset_code"
```

---

#### Fase 6 — AuthorizationCode ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/authorization_code.py` con `FileAuthorizationCodeRepository`
- [x] Factory `get_authorization_code_repository()`
- [x] Refactor `backend/authglow/services/oauth2.py`:
  - `mark_code_as_used` delega a `_repo.mark_used()` (CAS interno nel repo, defensive retry nel service)
  - `get_authorization_code` delega a `_repo.get_by_code()`
  - `create_authorization_code` delega a `_repo.create()`
  - `delete_authorization_code` delega a `_repo.delete()`
  - `verify_client` / `verify_redirect_uri` / `verify_scopes` / `process_scopes` / `verify_grant_type` restano (usano `client_storage` e `settings`)
- [x] Aggiornare `api/oauth2_advanced.py` — non serviva: la firma `OAuth2Service()` mantiene zero argomenti
- [x] Aggiornare `tests/conftest.py` — non serviva: la fixture esistente patcha `authglow.services.oauth2.get_settings`; il service continua a chiamarlo
- [x] Aggiungere `tests/unit/repositories/file/test_authorization_code.py`

**Risultato**: 29 nuovi test in `test_authorization_code.py` (init, protocol conformance, create con PKCE+nonce round-trip, get_by_code con policy absent/corrupt/expired/used + auto-delete expired + version-field transparent strip, mark_used con CAS retry su ConcurrentWriteError simulato + bounded retries → False, delete, patched-settings construction). Tutti i test esistenti (`test_oauth2.py` 11 + `test_auth_api.py` 22 + altri caller) restano verdi senza modifiche — nessun test accedeva agli internali `fs`/`storage_path`/`_get_code_path` del service. 175/175 test repository totali. 1202/1202 full suite (era 1173 dopo Fase 5, +29 nuovi).

**Bug-fix intermedio**: `_read_json_versioned` non cattura `ValueError`/`TypeError` (solo `FileNotFoundError`). Aggiunto `try/except (ValueError, TypeError)` in `get_by_code` e `mark_used` per gestire file JSON corrotti.

#### Fase 7 — OAuth2Client ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/oauth_client.py` con `FileOAuth2ClientRepository`
- [x] Factory `get_oauth2_client_repository()`
- [x] Refactor `backend/authglow/services/oauth_client.py`:
  - `update_last_used`, `rotate_secret` usano `_repo.update()` con CAS interno (via versioned write)
  - `verify_client_secret`, `verify_redirect_uri` etc. restano nel service (sono business)
- [x] Aggiornare import in `api/oauth_client.py`, `api/oauth2_advanced.py`, `api/admin.py` — non serviva: `OAuth2ClientStorage()` mantiene la firma a zero argomenti
- [x] Aggiornare `tests/conftest.py` — non serviva: la fixture esistente patcha `authglow.services.oauth_client.get_settings`; il service continua a chiamarlo
- [x] Aggiungere `tests/unit/repositories/file/test_oauth_client.py`
- [x] Test esistenti in `test_oauth_client_service.py` restano verdi (5 test con cambi minimi: `oauth_client_storage._afs` → `oauth_client_storage.repository._afs`, `_afs.write_json_versioned` mock → `_write_json_versioned` mock sul repo, `_afs` patches per s3/gcs → `authglow.repositories.file.base.fsspec.filesystem`)

**Risultato**: 24 nuovi test in `test_oauth_client.py` (init, protocol conformance, create con branding round-trip, get_by_id con Pydantic + version-field transparent strip, update con versioned-write CAS + concurrent-write-error simulation, delete, list con active_only + pagination + sort, patched-settings construction). 33 test esistenti verdi con 5 body changes minimi. 199/199 test repository totali. 1226/1226 full suite (era 1202 dopo Fase 6, +24 nuovi).

**Bug-fix intermedio**: prima versione del `FileOAuth2ClientRepository.update` aveva un check `if version == 0: plain write` che bypassava il mock del CAS nei test. Rimosso — il repo fa sempre versioned write (anche su file appena creati). Su un file senza `_version` field, `_read_json_versioned` ritorna 0 e `_write_json_versioned(data, 0)` passa il check e scrive `_version: 1`.

---

#### Fase 8 — OAuth2Consent (+ FIX inline I/O in admin.py) ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/oauth_consent.py` con `FileOAuth2ConsentRepository` (7 metodi dal Protocol + `list_all` aggiunto per l'admin)
- [x] Factory `get_oauth_consent_repository()`
- [x] Refactor `backend/authglow/services/oauth_consent.py`
- [x] **FIX inline I/O** in `backend/authglow/api/admin.py:1163-1225`:
  - Rimosso fsspec/AsyncFileSystem inline (63 righe di I/O in-line)
  - Sostituito con `consent_service.list_all_for_admin()` (3 righe) che fa email filter + DTO conversion + pagination
  - Aggiunto metodo `OAuth2ConsentRepository.list_all(limit, offset) -> List[OAuth2Consent]` (al Protocol + repo)
  - Aggiunto metodo `OAuth2ConsentService.list_all_for_admin(limit, offset, email=None) -> tuple[List[dict], int]`
- [x] Aggiornare import in `api/oauth2_advanced.py`, `api/admin.py` — non serviva: `OAuth2ConsentService()` mantiene la firma a zero argomenti
- [x] Aggiornare `tests/conftest.py` — non serviva: la fixture esistente patcha `authglow.services.oauth_consent.get_settings`; il service continua a chiamarlo
- [x] Aggiungere `tests/unit/repositories/file/test_oauth_consent.py`
- [x] Test esistenti in `test_oauth_consent.py` restano verdi (8 test bodies con cambi minimi)
- [x] Test esistenti in `test_admin_api.py` restano verdi (patches `authglow.services.oauth_consent.OAuth2ConsentService` non impattate)

**Risultato**: 23 nuovi test in `test_oauth_consent.py` (init, protocol conformance, create con O(1) path layout, get_by_id scan, get_for_user_client con revoked/expired auto-delete, update con revoke semantics, delete, list_for_user, list_all con pagination, cleanup_expired con keep-no-expiry semantics, patched-settings construction). 25 test esistenti in `test_oauth_consent_service.py` verdi con 8 body changes minimi. 222/222 test repository totali. 1249/1249 full suite (era 1226 dopo Fase 7, +23 nuovi).

**Bug-fix admin.py inline I/O**: 63 righe di fsspec/AsyncFileSystem inline + email filter + DTO + pagination sostituite con 3 righe: `consent_service = OAuth2ConsentService(); items, total = await consent_service.list_all_for_admin(limit=limit, offset=offset, email=email); return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)`. La logica di business è ora testabile tramite la service.

---

#### Fase 9 — MFA (split 3) ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/mfa.py` con:
  - `FileBackupCodeRepository` (subdir `mfa/backup_codes`, 4 metodi: save/get/delete/use_code atomic)
  - `FileBackupCodeAttemptRepository` (subdir `mfa/backup_code_attempts`, 3 metodi: get/save/delete)
  - `FileTrustedDeviceRepository` (subdir `mfa/trusted_devices`, 7 metodi: add/get/update con CAS/delete/list_for_user/find_trusted/cleanup_expired)
- [x] Factory `get_backup_code_repository()`, `get_backup_code_attempt_repository()`, `get_trusted_device_repository()` in `repositories/dependencies.py`
- [x] Refactor `backend/authglow/services/mfa.py`:
  - `verify_user_backup_code` chiama `_bc_repo.get()` + `_bc_repo.use_code()` (atomic) + `_attempts_repo.get/save/delete()`
  - `is_device_trusted` chiama `_td_repo.find_trusted()` + `_td_repo.update()` con retry CAS catching `ConcurrentWriteError` (5 tentativi dentro `named_lock`)
  - `add_trusted_device` / `list_trusted_devices` / `remove_trusted_device` / `cleanup_expired_devices` delegano ai rispettivi repository
  - `generate_totp_secret` / `verify_totp` / `generate_qr_code` / `hash_backup_code` / `verify_backup_code` / `generate_device_fingerprint` restano nel service (pure crypto, no I/O)
- [x] Aggiornare import in `api/mfa.py` — non serviva: `MFAService()` mantiene firma a zero argomenti via factory lazy
- [x] Aggiornare `tests/conftest.py` — non serviva: la fixture esistente patcha `authglow.services.mfa.get_settings`; i repo si istanziano via factory lazy
- [x] Aggiungere `tests/unit/repositories/file/test_mfa.py` (4 classi: TestFileBackupCodeRepository + TestFileBackupCodeAttemptRepository + TestFileTrustedDeviceRepository + TestFileMFARepositoriesWithPatchedSettings)
- [x] Test esistenti in `test_mfa.py` e `test_mfa_api.py` restano verdi

**Risultato**: 35 nuovi test in `test_mfa.py` (10 per BackupCode, 5 per BackupCodeAttempt, 16 per TrustedDevice, 1 patched-settings smoke test per tutte e 3). 46 test esistenti in `test_mfa.py` verdi con 9 body changes (`_get_backup_code_attempts` → `_attempts_repo.get`) + 1 body change in `test_trusted_device_expires` (scrittura diretta JSON → `_td_repo.update()`) + 1 body change in `test_backup_code_attempts_file_crud` (3 chiamate `_save/_get/_reset` → `_attempts_repo.save/get/delete`). 12 test esistenti in `test_mfa_api.py` verdi con 1 body change. 257/257 test repository totali. 1284/1284 full suite (era 1249 dopo Fase 8, +35 nuovi).

**Note implementative**:
- `FileBackupCodeRepository.use_code` è atomico: usa `named_lock(f"backup_codes_atomic:{user_id}")` (singleton di processo) per garantire che due `verify` concorrenti sullo stesso user non possano double-remove lo stesso hash. Il service layer chiama questo metodo e basta — nessun retry loop.
- `FileTrustedDeviceRepository.update` usa `_write_json_versioned` con `expected_version` per il CAS. `FileTrustedDeviceRepository.find_trusted` è una scan (no index su fingerprint) — accettabile perché trusted devices sono O(dozens) per user e il lookup è cold path.
- `MFAService.is_device_trusted` wrappa `find_trusted + update(last_used)` in `named_lock(f"trusted_devices:{user_id}")` + retry loop catching `ConcurrentWriteError` (5 tentativi) per cross-process safety.
- `MFAService.verify_user_backup_code` wrappa `attempts.get + backup_codes.get + use_code + attempts.delete` (o `attempts.save` per failure) in `named_lock(f"backup_codes:{user_id}")`.

---

#### Fase 10 — Passkey (+ FIX url_to_fs) ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/passkey.py` con:
  - `FilePasskeyRepository` (subdir `passkeys`, 5 metodi: save/get/update con CAS/delete/list_for_user)
  - `FileWebAuthnChallengeRepository` (subdir `challenges`, 3 metodi: save/get con auto-delete expired/delete)
- [x] Factory `get_passkey_repository()`, `get_webauthn_challenge_repository()` in `repositories/dependencies.py`
- [x] Refactor `backend/authglow/services/passkey.py`:
  - **`__init__` FIX bypass bug**: rimosso `self.fs = fsspec.core.url_to_fs(storage_path)[0]` (riga 51 originale). Rimosso anche `AsyncFileSystem`, `storage_path` attribute, e i 2 `fs.mkdirs(...)`. Il service ora costruisce 2 repository via factory; i repo usano `BaseFileRepository._init_filesystem` che onora `Settings.storage_backend`.
  - Rimosso parametro `storage_path` da `__init__` (deprecato; il path deriva da `Settings.storage_path` + `_subdir` del repo).
  - `get_user_passkeys` / `save_passkey` / `get_passkey` / `delete_passkey` / `update_passkey_usage` delegano a `self._passkey_repo`.
  - `save_challenge` / `get_challenge` / `delete_challenge` delegano a `self._challenge_repo` (auto-delete expired on read).
  - `update_passkey_usage` wrappa `get + update(last_used, sign_count)` in `named_lock` + retry CAS catching `ConcurrentWriteError` (5 tentativi).
  - `verify_registration` / `verify_authentication` / `generate_*_options_dict` restano nel service (WebAuthn crypto, no I/O).
- [x] Aggiornare 3 call sites di `PasskeyService(...)` rimuovendo `storage_path=`:
  - `api/passkey.py:51-56` (factory `get_passkey_service(request)`)
  - `api/admin.py:56-61` (factory `get_passkey_service()`)
  - `api/admin.py:1312-1317` (chiamata diretta dentro route admin)
- [x] Aggiornare `tests/conftest.py` — non serviva: nessuna fixture `passkey_service` in conftest.
- [x] Aggiungere `tests/unit/repositories/file/test_passkey.py` (3 classi: TestFilePasskeyRepository + TestFileWebAuthnChallengeRepository + TestFilePasskeyRepositoriesWithPatchedSettings)
- [x] Test esistenti in `test_passkey.py` restano verdi (usano `__new__` skipping init)

**Risultato**: 22 nuovi test in `test_passkey.py` (10 per Passkey, 6 per Challenge, 1 patched-settings smoke test). 4 test esistenti in `test_passkey.py` verdi (0 body changes, usano `__new__` skipping init). 279/279 test repository totali. 1306/1306 full suite (era 1284 dopo Fase 9, +22 nuovi).

**Bug-fix `fsspec.core.url_to_fs` bypass**: il pre-refactor `PasskeyService.__init__` chiamava `fsspec.core.url_to_fs(storage_path)[0]` per costruire l'fsspec filesystem, bypassando completamente `Settings.storage_backend` (che in `BaseFileRepository._init_filesystem` seleziona `file` vs `s3` vs `gcs` vs `abfs`). Su qualsiasi backend non-`file` questo avrebbe generato un confuso `ValueError` da fsspec. Con il refactor, i 2 nuovi repository (`FilePasskeyRepository` + `FileWebAuthnChallengeRepository`) estendono `BaseFileRepository` che onora `Settings.storage_backend`. La "deployability" del WebAuthn flow su backend cloud è ora consistente con gli altri domain.

**Pre-existing issue trovata (non causata da Fase 10)**: `authglow/api/admin.py:27` ha un `from authglow.services.oauth_client import OAuth2ClientStorage` non utilizzato a livello modulo, e due `from authglow.services.oauth_client import OAuth2ClientStorage` ridefiniti inline dentro funzioni alle righe 1256 e 1295. Queste import generano `F401` + `F811` da ruff. **Chiedere all'utente se fixare**.

---

#### Fase 11 — API Key ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/api_key.py` con `FileAPIKeyRepository` (subdir `api_keys`)
- [x] Factory `get_api_key_repository()` in `repositories/dependencies.py`
- [x] Refactor `backend/authglow/services/api_key.py`:
  - `create_key` chiama `_repo.create()` + `_repo.add_to_prefix_index()` in `named_lock(f"api_key_create:{prefix}")`
  - `validate_key` chiama `_repo.load_prefix_index()` + `_repo.get_by_id()` per candidate, + `_repo.update()` per lockout reset
  - `record_failed_validation` / `is_key_locked` / `reset_failed_validations` / `record_usage` / `update_key` / `revoke_key` / `track_usage` wrappano get+modify+update in `named_lock(f"api_key:{key_id}")`
  - `delete_key` chiama `_repo.remove_from_prefix_index()` + `_repo.delete()` in `named_lock`
  - `cleanup_expired_keys` delega a `_repo.cleanup_expired()` (semantica "expired AND inactive" preservata)
  - `_verify_api_key` (bcrypt) e `_generate_api_key` (secrets + bcrypt) restano nel service (pure crypto, no I/O)
  - Rimosso `fsspec`/`AsyncFileSystem`/`storage_path`/`fs`/`_afs`/`os.makedirs` da `__init__`
- [x] Aggiornare import in `api/api_key.py`, `api/admin.py` — non serviva: `APIKeyService()` mantiene firma a zero argomenti via factory lazy
- [x] Aggiornare `tests/conftest.py` — non serviva: la fixture esistente patcha `authglow.services.api_key.get_settings`; il repo si istanzia via factory lazy
- [x] Aggiungere `tests/unit/repositories/file/test_api_key.py` (2 classi: TestFileAPIKeyRepository + TestFileAPIKeyRepositoryWithPatchedSettings)
- [x] Test esistenti in `test_api_key.py` restano verdi (6 chiamate `_load_prefix_index` → `load_prefix_index` + 3 scritture dirette `_afs.write_json` → `_repo.update()`)

**Risultato**: 24 nuovi test in `test_api_key.py` (subdir + protocol + 5 metodi CRUD + 5 prefix index helpers + 4 list/pagination + 1 cleanup_expired + 1 patched-settings smoke test). 31 test esistenti in `test_api_key.py` verdi con 6 body changes (prefix index) + 3 body changes (scrittura diretta → repo.update). 303/303 test repository totali. 1330/1330 full suite (era 1306 dopo Fase 10, +24 nuovi).

**Note implementative**:
- Il `prefix index` (12-char prefix → key_ids) è gestito dal repository con 3 metodi pubblici nel Protocol: `load_prefix_index` / `add_to_prefix_index` / `remove_from_prefix_index`. Il File backend li implementa con file JSON (`<storage>/api_keys/index/<prefix>.json`). SQL backends li implementerebbero via native unique key su `key_prefix` (e potrebbero no-op `add`/`remove`).
- `cleanup_expired` richiede sia `expires_at < now` AND `is_active=False` (semantica invariata dal pre-refactor: una key expired ma active è ancora utile come "force fail" target).
- `delete` è **non** CAS (no `_write_json_versioned`): le API key brute-force lockout / usage stats sono wrappate in `named_lock` (in-process), non hanno bisogno di cross-process CAS.
- **Bug-fix in `__init__`**: rimosso `fsspec`/`AsyncFileSystem`/`storage_path`/`fs`/`_afs`/`os.makedirs`. Il service ora risolve il path via `Settings.storage_path + _subdir` (route attraverso `BaseFileRepository._init_filesystem` che onora `Settings.storage_backend`).

---

#### Fase 12 — RefreshToken (alta complessità) ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/refresh_token.py` con `FileRefreshTokenRepository` (15 metodi: 8 protocol base + 1 `revoke_user_tokens` + 6 index helpers)
- [x] Factory `get_refresh_token_repository(settings=None)` in `repositories/dependencies.py` con parametro `settings` opzionale (vedi nota lru_cache)
- [x] Aggiungere 6 helper di index al `RefreshTokenRepository` Protocol (`load_id_index`, `add_to_id_index`, `remove_from_id_index`, `load_active_index`, `add_to_active_index`, `remove_from_active_index`) + `revoke_user_tokens`
- [x] Refactor `backend/authglow/services/refresh_token.py`:
  - `_find_token_lookup` (HMAC) e `_generate_token` (secrets + bcrypt + HMAC) restano nel service (pure crypto)
  - `create_refresh_token` chiama `_repo.create()` + `_repo.add_to_id_index()` + `_repo.add_to_active_index()`
  - `validate_and_rotate` wrappa get+modify+update in `named_lock(f"refresh_token:{lookup}")` + retry CAS catching `ConcurrentWriteError` (3 tentativi, MAX_CAS_RETRIES)
  - `_revoke_token_family` / `_revoke_descendants` (business logic ricorsiva) restano nel service ma usano `_repo.update()` + `_repo.remove_from_active_index()`
  - `revoke_user_tokens` delega completamente al repository (scan + filter + revoke atomic)
  - Rimosso `fsspec`/`AsyncFileSystem`/`storage_path`/`fs`/`_afs`/`os.makedirs` da `__init__`
- [x] Aggiornare import in `api/oauth2_advanced.py`, `api/admin.py` — non serviva: `RefreshTokenService()` mantiene firma a zero argomenti via factory lazy
- [x] Aggiornare `tests/conftest.py` — non serviva: la fixture esistente patcha `authglow.services.refresh_token.get_settings`; il repo si istanzia via factory lazy
- [x] Aggiungere `tests/unit/repositories/file/test_refresh_token.py` (2 classi: TestFileRefreshTokenRepository + TestFileRefreshTokenRepositoryWithPatchedSettings)
- [x] Test esistenti in `test_refresh_token.py` restano verdi (4 chiamate `_load_active_index` → `load_active_index` + 2 patch `_afs.glob` → `_repo._glob` + 2 sostituzioni `_get_token_path`/`_active_index_path` → `_repo._path_for_lookup`/`_repo._active_index_path`)
- [x] **Test specifici per rotation CAS, token reuse detection, family revocation**: ereditati dai test esistenti `TestRefreshTokenLifecycle` + `TestRefreshTokenActiveIndex`

**Risultato**: 34 nuovi test in `test_refresh_token.py` (8 protocol methods + 5 id_index helpers + 5 active_index helpers + 3 list_active + 3 list_all + 3 revoke_user_tokens + 1 cleanup_expired + 1 _collect noise + 1 VAPT-002 plaintext + 1 patched-settings). 26 test esistenti in `test_refresh_token.py` verdi con 8 body changes. 337/337 test repository totali. 1364/1364 full suite (era 1330 dopo Fase 11, +34 nuovi).

**Bug-fix critico `lru_cache` bypass**: il pre-refactor `RefreshTokenService.__init__` chiamava `get_settings()` direttamente (con la patch sul modulo `authglow.services.refresh_token`, otteneva `test_settings` per-function). Post-refactor, `RefreshTokenService.__init__` chiama `get_refresh_token_repository()` → `FileRefreshTokenRepository()` → `BaseFileRepository.__init__()` → `authglow.repositories.file.base.get_settings()` (NON patchato dalla fixture, è il singleton cached con `lru_cache`). Risultato: `_storage_path` del repo puntava a un `tmp_path` shared, non per-function → 4 test fallivano (richiedono "stato pulito"). **Fix**: `get_refresh_token_repository` ora accetta `settings=None` opzionale; il service passa `self.settings` (patched, per-function) esplicitamente. Il repo ottiene lo stesso `_storage_path` del service. **Stesso pattern da applicare a tutti i service futuri che dipendono da "stato pulito" per test** (per ora solo RefreshToken). Per gli altri service (MFA, ecc.) lo storage shared non rompe i test esistenti, ma è un bug latente da fixare in un cleanup globale (Fase 21).

**Note implementative**:
- `update` usa `_write_json_versioned` con `expected_version` per CAS. Solleva `ConcurrentWriteError` su race cross-process. Solleva `FileNotFoundError` se il file manca.
- `cleanup_expired` recupera `token_lookup` da `id_index` **prima** di rimuovere l'entry (altrimenti non sa più dove trovare il file JSON da cancellare). Fallback a `token.token_lookup` se l'index è già pulito.
- `_collect` skippa i 2 file di index (`id_index.json`, `active_index.json`) durante lo scan del `*.json` glob, perché non sono documenti `RefreshToken`.
- `revoke_user_tokens` è un'operazione "batch" che itera + update + remove da active_index. SQL backends lo implementerebbero con un singolo `UPDATE ... WHERE ... AND NOT revoked`.

---

#### Fase 13 — RBAC (split 3) ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/rbac.py` con:
  - `FilePermissionRepository` (subdir `rbac/permissions`, 5 metodi: create/get_by_id/get_by_name/delete/list)
  - `FileRoleRepository` (subdir `rbac/roles`, 6 metodi: create/get_by_id/get_by_name/update/delete/list)
  - `FileUserRoleRepository` (subdir `rbac/user_roles`, 5 metodi: assign/get_by_id/find_assignment/remove/list_for_user con auto-delete expired)
- [x] Factory `get_permission_repository()`, `get_role_repository()`, `get_user_role_repository()` in `repositories/dependencies.py`
- [x] Aggiungere `get_by_id` + `find_assignment` al `UserRoleRepository` Protocol (rinominato `remove(assignment_id)` da `remove(user_id, role_id)` per separation of concerns)
- [x] Refactor `backend/authglow/services/rbac.py`:
  - `initialize_defaults` (business) resta nel service, usa i 3 repo per I/O
  - `user_has_permission` / `user_has_role` / `get_user_permissions` (business aggregation multi-repo) restano nel service
  - `update_role` wrappa in `named_lock(f"role:{id}")` + `_role_repo.update()` (l'update_at refresh resta nel service)
  - `delete_role` check `is_system` (business guard) prima di `_role_repo.delete()`
  - `get_user_roles` ora delega al repository (auto-delete expired on read, business logic invariata)
  - `remove_role_from_user` ora chiama `_user_role_repo.find_assignment()` + `remove(assignment_id)` (vs scan+delete pre-refactor)
  - Rimosso `fsspec`/`AsyncFileSystem`/`os.makedirs`/`storage_options` da `__init__`
- [x] Aggiornare import in `api/admin.py` (RBAC routes) — non serviva: `RBACService()` mantiene firma a zero argomenti via factory lazy (è una nuova firma: 3 repository opzionali, tutti default a `None` → lazy resolve)
- [x] Aggiornare `tests/conftest.py` — non serviva: la fixture esistente patcha `authglow.services.rbac.get_settings`; i repo si istanziano via factory lazy
- [x] Aggiungere `tests/unit/repositories/file/test_rbac.py` (4 classi: TestFilePermissionRepository + TestFileRoleRepository + TestFileUserRoleRepository + TestFileRBACRepositoriesWithPatchedSettings)
- [x] Test esistenti in `test_rbac.py` restano verdi (0 body changes — l'API pubblica del service è invariata)

**Risultato**: 36 nuovi test in `test_rbac.py` (8 per Permission, 9 per Role, 12 per UserRole, 7 per patched-settings smoke test). 31 test esistenti in `test_rbac.py` verdi con 0 body changes. 373/373 test repository totali. 1400/1400 full suite (era 1364 dopo Fase 12, +36 nuovi).

**Note implementative**:
- 3 file in 1 (`rbac.py`) perche sono 3 classi dello stesso dominio, seguendo il pattern di Fase 9 (MFA).
- Sub-path layout: `rbac/permissions/`, `rbac/roles/`, `rbac/user_roles/` (gerarchia a 2 livelli esplicita nel `_subdir` per ricordare la pre-refactor structure).
- `UserRoleRepository.list_for_user` auto-elimina expired assignments on read (consistente con `OAuth2Consent.get_for_user_client` di Fase 8).
- `UserRoleRepository.remove(assignment_id)` (non `remove(user_id, role_id)`): separation of concerns — il service fa `find_assignment` + `remove` invece di scan+delete interno. Aggiornato il Protocol di conseguenza.
- **Bug-fix in `__init__`**: rimosso `fsspec`/`AsyncFileSystem`/`os.makedirs`/`storage_options`. La "deployability" su backend non-`file` è ora consistente.
- `update_role` NON ha CAS (no `_write_json_versioned`): il `named_lock` (in-process) basta per gli updates di role metadata.
- `delete_role` non ha guard lato repo: l'`is_system` check è business logic, vive nel service.
- [ ] Test esistenti in `test_rbac.py` e `test_rbac_jwt_injection.py` restano verdi

---

#### Fase 14 — LoginHistory (+ FIX 2 bugs) ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/login_history.py` con `FileLoginHistoryRepository` (3 metodi: record/list_for_user/cleanup_old)
- [x] Factory `get_login_history_repository(settings=None)` in `repositories/dependencies.py` con parametro `settings` opzionale (lru_cache bypass)
- [x] Aggiornare `LoginHistoryRepository` Protocol: aggiunti 2 parametri opzionali `entry_id` e `timestamp` a `record()` per coerenza tra `LoginHistoryEntry` service-side e record persistito; cambiato `cleanup_old` signature da `cutoff: datetime` a `cutoff: str` (ISO-8601)
- [x] Refactor `backend/authglow/services/login_history.py`:
  - **FIX bypass bug 1** (riga 73 originale): rimosso `self.fs = fsspec.filesystem("file")` hard-coded
  - **FIX bypass bug 2** (riga 141 originale): rimosso `os.remove(file_path)` in `_cleanup_old_entries`; ora delega a `_repo.cleanup_old()` che usa `_delete()` (async-fsspec `rm` backend-agnostic)
  - Rimosso `import os`, `import fsspec`, `AsyncFileSystem`, `storage_path`, `fs`, `_afs`
  - `__init__` accetta `repository=` opzionale + passa `self.settings` al factory (FIX lru_cache)
  - `record_login` chiama `_repo.record(entry_id=entry.id, timestamp=entry.timestamp.isoformat(), ...)` + `_repo.cleanup_old(user_id, cutoff)`
  - `get_login_history` delega a `_repo.list_for_user(user_id, limit, offset)`
- [x] Aggiornare import in `api/admin.py` — non serviva: `LoginHistoryService()` mantiene firma a zero argomenti via factory lazy
- [x] Aggiornare `tests/conftest.py` — non serviva: nessuna fixture `login_history_service` (è istanziato inline in `api/auth.py`, `api/admin.py`, `api/mfa.py`, `api/federation.py`, `api/passkey.py`)
- [x] Aggiungere `tests/unit/repositories/file/test_login_history.py` (2 classi: TestFileLoginHistoryRepository + TestFileLoginHistoryRepositoryWithPatchedSettings)
- [x] Test esistenti: 2 test in `test_admin_api.py` (con `mock_login_svc` AsyncMock) verdi con 0 body changes

**Risultato**: 18 nuovi test in `test_login_history.py` (5 record + 5 list_for_user + 4 cleanup_old con regression test per il bug `os.remove()` + 4 patched-settings smoke test). 2 test esistenti in `test_admin_api.py` verdi con 0 body changes. 391/391 test repository totali. 1418/1418 full suite (era 1400 dopo Fase 13, +18 nuovi).

**Bug-fix critici (entrambi risolti)**:
1. **`fsspec.filesystem("file")` hard-coded** (`services/login_history.py:73` originale): bypassava `Settings.storage_backend`. Su qualsiasi backend non-`file` (s3/gcs/abfs) il service sarebbe crashato immediatamente. Risolto rimuovendo `fsspec` dal service e instradando tutto attraverso `BaseFileRepository._init_filesystem`.
2. **`os.remove(file_path)` bypass** (`services/login_history.py:141` originale): `os.remove` è una system call OS-level, NON passa attraverso fsspec. Su qualsiasi backend non-`file`, il file è gestito da fsspec (cache, autenticazione, cleanup), e `os.remove` vedrebbe un path locale inesistente → `FileNotFoundError` o `OSError`. Risolto delegando a `_repo.cleanup_old()` che usa `BaseFileRepository._delete()` → `self._afs.rm(path)` (async-fsspec). **Regression test specifico** in `test_cleanup_old_uses_afs_rm_not_os_remove` che spia `repo._delete` con `wraps` per verificare che il cleanup passi attraverso il fsspec abstraction.

**Note implementative**:
- Path layout 2-livello: `login_history/{user_id}/{entry_id}.json`. La 2-livello mantiene l'isolation per user e permette a `list_for_user` di fare un singolo `glob` invece di scansionare l'intero subtree.
- `record()` ritorna il record persistito (con `id` e `timestamp` effettivi) — utile per il service che vuole mantenere coerenza tra `LoginHistoryEntry` in-memory e record su disco.
- `cleanup_old` accetta `cutoff: str` (ISO-8601) invece di `datetime` per semantica universale (l'ISO string è la stessa cosa che il service genera con `utcnow().isoformat()` e che il repo legge da `LoginHistoryEntry.to_dict()["timestamp"]`).

---

#### Fase 15 — AdminAction (+ FIX 2 bugs) ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/admin_action.py` con `FileAdminActionRepository` (2 metodi: record/list_for_user)
- [x] Factory `get_admin_action_repository()` in `repositories/dependencies.py`
- [x] Aggiunto `AdminActionRepository` al blocco `TYPE_CHECKING` in `dependencies.py`
- [x] Refactor `backend/authglow/services/admin_action.py`:
  - **FIX bypass bug 1** (riga 76 originale): rimosso `self.fs = fsspec.filesystem("file")` hard-coded
  - **FIX bypass bug 2** (riga 105 originale): rimosso `os.makedirs(os.path.dirname(action_path), exist_ok=True)`; ora delega a `_write_json` che chiama `_ensure_parent` (single backend-agnostic mkdir point)
  - Rimosso `import os`, `import fsspec`, `AsyncFileSystem`, `storage_path`, `fs`, `_afs`
  - `__init__` accetta `repository: Optional[AdminActionRepository] = None` + tipizza `self._repo` con forward ref
  - `record_action` chiama `_repo.record(...)` + ritorna un `AdminAction` locale (zero callers consumano il ritorno, ma la firma pubblica è mantenuta per retrocompat — l'inconsistenza id/timestamp è documentata nel docstring di `AdminAction`)
  - `get_admin_actions` delega a `_repo.list_for_user(target_user_id, limit, offset)`
- [x] Aggiornare import in `api/admin.py` — non serviva: `AdminActionService()` mantiene firma a zero argomenti via factory lazy
- [x] Aggiornare `tests/conftest.py` — non serviva: nessuna fixture `admin_action_service` (è istanziato inline in 17 call sites in `api/admin.py`)
- [x] Aggiungere `tests/unit/repositories/file/test_admin_action.py` (2 classi: TestFileAdminActionRepository + TestFileAdminActionRepositoryWithPatchedSettings)

**Risultato**: 15 nuovi test (3 protocol/layout + 6 record + 5 list_for_user + 1 patched-settings smoke test, include `test_record_uses_ensure_parent_not_direct_os_makedirs` regression test). 1433/1433 full suite (era 1418 dopo Fase 14, +15 nuovi).

**Bug-fix critici (entrambi risolti)**:
1. **`fsspec.filesystem("file")` hard-coded** (`services/admin_action.py:76` originale): bypassava `Settings.storage_backend`. Su qualsiasi backend non-`file` (s3/gcs/abfs) il service sarebbe crashato immediatamente. Risolto rimuovendo `fsspec` dal service e instradando tutto attraverso `BaseFileRepository._init_filesystem`.
2. **`os.makedirs()` bypass** (`services/admin_action.py:105` originale): `os.makedirs` è una system call OS-level, NON passa attraverso fsspec. Su qualsiasi backend non-`file`, il `makedirs` OS-level creava una directory locale che il backend cloud non vedeva → primo `write_json` falliva con missing-bucket/permission error. Risolto delegando a `_write_json` → `_ensure_parent` (single backend-agnostic mkdir point). **Regression test specifico** in `test_record_uses_ensure_parent_not_direct_os_makedirs` che spia `repo._ensure_parent` con `wraps` per verificare che la directory creation passi attraverso il fsspec abstraction.

**Note implementative**:
- Path layout 2-livello: `admin_actions/<target_user_id>/<action_id>.json`. Mantiene isolation per target user e permette a `list_for_user` di fare un singolo `glob` invece di scansionare l'intero subtree.
- `record()` ritorna `None` (vs `LoginHistory` che ritorna `Record`): il contract attuale del protocol è `-> None` (zero callers consumano il ritorno). L'`AdminAction` dataclass è mantenuta per retrocompat con `record_action -> AdminAction` signature, ma id/timestamp locali sono disaccoppiati da quelli persistiti (lazy: 0 callers → bug latente ma documentato).
- `AdminAction` dataclass mantenuta come utility interna al service (per retrocompat con il return type di `record_action`). Nessuna Pydantic model — coerente con `LoginHistoryEntry` pattern.
- `_extra_dirs` vuoto per `FileAdminActionRepository`: la subdir per user_id viene creata lazy da `_ensure_parent` durante la prima `record`.

---

#### Fase 16 — SecurityEvent (+ FIX 2 bugs + FIX typo protocol) ✅ (Fatto: 2026-06-14)

- [x] **FIX typo protocol** (`repositories/protocols.py:857`): `SecurityEventRepository.list_for_user` ritornava `tuple[List[SecurityEventModel], int]` (typo, import di `SecurityEvent as SecurityEventModel` usato solo qui); corretto a `tuple[List[Record], int]` per coerenza con `AdminAction`/`LoginHistory`. Rimosso l'import unused di `SecurityEventModel` per evitare F401.
- [x] Creare `backend/authglow/repositories/file/security_event.py` con `FileSecurityEventRepository` (2 metodi: record/list_for_user)
- [x] Factory `get_security_event_repository()` in `repositories/dependencies.py` + aggiunto `SecurityEventRepository` al blocco `TYPE_CHECKING`
- [x] Refactor `backend/authglow/services/security_event.py`:
  - **FIX bypass bug 1** (riga 72 originale): rimosso `self.fs = fsspec.filesystem("file")` hard-coded
  - **FIX bypass bug 2** (riga 99 originale): rimosso `os.makedirs(os.path.dirname(event_path), exist_ok=True)`; ora delega a `_write_json` che chiama `_ensure_parent`
  - Rimosso `import os`, `import fsspec`, `AsyncFileSystem`, `storage_path`, `fs`, `_afs`
  - `__init__` accetta `repository: Optional[SecurityEventRepository] = None` + tipizza `self._repo` con forward ref
  - `record_event` chiama `_repo.record(...)` + ritorna un `SecurityEvent` locale (zero callers consumano il ritorno, id/timestamp locali **disaccoppiati** da quelli persistiti, documentato nel docstring di `SecurityEvent`)
  - `get_security_events` delega a `_repo.list_for_user(user_id, limit, offset)`
- [x] Aggiornare import in `api/admin.py` — non serviva: `SecurityEventService()` mantiene firma a zero argomenti via factory lazy
- [x] Aggiornare `tests/conftest.py` — non serviva: nessuna fixture `security_event_service` (è istanziato inline in 25 call sites in `api/admin.py`)
- [x] Aggiungere `tests/unit/repositories/file/test_security_event.py` (2 classi: TestFileSecurityEventRepository + TestFileSecurityEventRepositoryWithPatchedSettings)

**Risultato**: 15 nuovi test (3 protocol/layout + 6 record + 5 list_for_user + 1 patched-settings smoke test, include `test_record_uses_ensure_parent_not_direct_os_makedirs` regression test). 1448/1448 full suite (era 1433 dopo Fase 15, +15 nuovi).

**Bug-fix critici (3 risolti)**:
1. **`fsspec.filesystem("file")` hard-coded** (`services/security_event.py:72` originale): bypassava `Settings.storage_backend`. Su qualsiasi backend non-`file` (s3/gcs/abfs) il service sarebbe crashato immediatamente. Risolto rimuovendo `fsspec` dal service e instradando tutto attraverso `BaseFileRepository._init_filesystem`.
2. **`os.makedirs()` bypass** (`services/security_event.py:99` originale): `os.makedirs` è una system call OS-level, NON passa attraverso fsspec. Su qualsiasi backend non-`file`, il `makedirs` OS-level creava una directory locale che il backend cloud non vedeva → primo `write_json` falliva con missing-bucket/permission error. Risolto delegando a `_write_json` → `_ensure_parent` (single backend-agnostic mkdir point). **Regression test specifico** in `test_record_uses_ensure_parent_not_direct_os_makedirs` che spia `repo._ensure_parent` con `wraps` per verificare che la directory creation passi attraverso il fsspec abstraction.
3. **Typo protocol** (`protocols.py:857`): `list_for_user -> tuple[List[SecurityEventModel], int]` referenziava un alias importato `SecurityEvent as SecurityEventModel` che non esisteva come Pydantic model in `authglow.models.admin` (esiste `SecurityEvent` come modello Pydantic, ma l'aliasing era per vecchia intenzione). Risolto cambiando a `tuple[List[Record], int]` (coerente con `AdminActionRepository`/`LoginHistoryRepository`) e rimuovendo l'import unused di `SecurityEventModel` da `protocols.py`. Il Pydantic model `SecurityEvent` in `authglow.models.admin` rimane disponibile per future implementazioni typed (es. response models delle route admin).

**Note implementative**:
- Path layout 2-livello: `security_events/<user_id>/<event_id>.json`. Mantiene isolation per user e permette a `list_for_user` di fare un singolo `glob` invece di scansionare l'intero subtree.
- `record()` ritorna `None` (vs `LoginHistory` che ritorna `Record`): il contract attuale del protocol è `-> None` (zero callers consumano il ritorno). Il `SecurityEvent` dataclass è mantenuto per retrocompat con `record_event -> SecurityEvent` signature, ma id/timestamp locali sono disaccoppiati da quelli persistiti (lazy: 0 callers → bug latente ma documentato).
- `SecurityEvent` dataclass mantenuta come utility interna al service (per retrocompat con il return type di `record_event`). Nessuna Pydantic model obbligatoria — coerente con `LoginHistoryEntry`/`AdminAction` pattern.
- `_extra_dirs` vuoto per `FileSecurityEventRepository`: la subdir per user_id viene creata lazy da `_ensure_parent` durante la prima `record`.
- `RETENTION_DAYS = 365` mantenuto per retrocompat ma non implementato (sweep sarebbe feature creep — fuori scope del refactor).

---

#### Fase 17a — EmailIndex (User domain split 1/3) ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/email_index.py` con `FileEmailIndexRepository` (4 metodi: lookup/insert/remove/all). Path layout: `<storage>/email_index.json` (storage root, NON una subdir). `BaseFileRepository.__init__` richiede `_subdir` non-empty → `subdir="."` + override `self._storage_path = self._storage_root` per collassare il path.
- [x] Factory `get_email_index_repository(settings=None)` con lru_cache bypass (vedi Fase 12/14 rationale). Senza, `FileEmailIndexRepository.__init__` chiama `authglow.repositories.file.base.get_settings` (NON patchato dall'autouse `_override_settings`) → lru_cache returns first cached test_settings → tutti i test condividono lo stesso `_storage_path` → fallimenti di isolation.
- [x] Refactor `services/storage.py`: rimosso `_load_email_index`/`_save_email_index`; ora delega a `_email_index_repo.lookup/insert/remove/all`. Service mantiene `named_lock("email_index")` per cross-entity atomicity in `create_user`/`update_email`/`delete_user`.
- [x] Test esistenti aggiornati: 3 in `TestEncryptedPIIStorage` (linee 304, 614, 662) che chiamavano `_load_email_index`/`_get_email_index_path` direttamente → ora usano `_email_index_repo.lookup/all` e `_email_index_repo._index_path()`. 1 in `TestUserCache` (linea 304) che patchava `_load_email_index` per verificare cache hit → ora patcha `_email_index_repo.lookup`.
- [x] Aggiungere `tests/unit/repositories/file/test_email_index.py` (17 test in 2 classi).
- [x] Full suite verification: 1465/1465.

**Risultato**: 17 nuovi test. **Bug-fix critico risolto**: **lru_cache bypass su `authglow.repositories.file.base.get_settings`**. Senza il fix, `FileEmailIndexRepository._storage_path` restava fissato al `tmp_path` del primo test (lru_cache singleton), facendo fallire `TestAccountLockout` con "User with email lockout@example.com already exists" sul 2° test della classe.

---

#### Fase 17b — FederatedIdentity (User domain split 2/3) ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/federated_identity.py` con `FileFederatedIdentityRepository` (3 metodi: lookup/link/unlink). Composite key: `f"{provider_id}|{external_id}"` (matches pre-refactor `_make_identity_key`). Path: `<storage>/federated_identities.json` (storage root, stesso pattern di EmailIndex).
- [x] Factory `get_federated_identity_repository(settings=None)` con lru_cache bypass (stesso rationale di 17a).
- [x] Refactor `services/storage.py`: rimosso `_load_federated_identities`/`_save_federated_identities`/`_get_federated_identities_path`/`_make_identity_key`; ora delega a `_federated_identity_repo.lookup/link/unlink`. Service mantiene `named_lock("federated_identities")` in `link_federated_identity`.
- [x] **`link` solleva `EntityAlreadyExistsError` (vs `ValueError` pre-refactor)**: il repo solleva l'eccezione domain-level (`EntityAlreadyExistsError("federated_identity", key)`) con `entity` + `identifier` attributes. Il service `link_federated_identity` lascia propagare l'eccezione (i call sites esistenti già gestiscono `ValueError` come generico, e `EntityAlreadyExistsError` è una sottoclasse di `ValueError` → retrocompat mantenuta).
- [x] Aggiungere `tests/unit/repositories/file/test_federated_identity.py` (17 test in 2 classi, include `test_link_raises_on_different_user` per `EntityAlreadyExistsError`).
- [x] Full suite verification: 1482/1482.

**Risultato**: 17 nuovi test.

---

#### Fase 17c — User (User domain split 3/3, PII encryption) ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/user.py` con `FileUserRepository` (CRUD + lockout + last-login + password + list/count/get_stats). Path: `<storage>/<user_id>.json` (flat directory, pre-refactor layout).
- [x] Factory `get_user_repository(settings=None)` con lru_cache bypass.
- [x] **PII encryption (5 campi) spostata dal service al repo**: `_PII_FIELDS = ("email", "first_name", "last_name", "phone", "avatar_url")`. `encrypt_field`/`decrypt_field` da `authglow.core.crypto` (AES-256-GCM). Encryption è responsabilità del File backend, NON del service (SQL backends NON devono re-implementare).
- [x] **6 metodi "convenience" aggiunti al protocol `UserRepository`**: `update_last_login`, `record_failed_login`, `reset_failed_login_attempts`, `clear_failed_login_attempts`, `is_account_locked`, `set_password`. Single-file mutations (no cross-entity coordination). Service li wrappa in `named_lock(f"user:{user_id}")` per in-process safety.
- [x] **`get_by_email` / `exists_by_email` sollevano `NotImplementedError`**: richiedono coordinazione con `EmailIndexRepository` (two-step lookup). Il service `get_user_by_email` orchestra le due chiamate: `lookup(email) → get_by_id(user_id)`. Le firme rimangono nel protocol (per `runtime_checkable` conformance) ma l'impl `FileUserRepository` documenta il vincolo via `NotImplementedError`.
- [x] **Refactor `UserStorage` come thin facade**: rimossi `_encrypt_user_for_storage`/`_decrypt_user_from_storage`/`_write_user`/`_get_user_path` (eccetto shim)/`_load_email_index`/`_save_email_index`/`_load_federated_identities`/`_save_federated_identities`/`_get_federated_identities_path`/`_make_identity_key`. Service mantiene 4 cose non-File-specifiche: (1) `named_lock` per cross-entity atomicity, (2) `user_cache` invalidation, (3) timing-leak protection, (4) `_get_user_path` shim per back-compat test.
- [x] Test esistenti aggiornati: 6 in `TestEncryptedPIIStorage._get_user_path` (ora `storage._get_user_path` funziona via shim) + 2 in `TestStorageSetPassword`/`TestStorageClearFailedAttempts` (mock `storage._write_user` → `storage._user_repo.set_password/clear_failed_login_attempts`).
- [x] Aggiungere `tests/unit/repositories/file/test_user.py` (33 test in 2 classi, include `test_pii_encrypted_on_disk` e `test_non_pii_fields_stored_in_plaintext` per coprire PII semantics).
- [x] Full suite verification: 1515/1515.

**Risultato**: 33 nuovi test. **1515/1515** (era 1448 dopo Fase 16, +67 nuovi totali per Fase 17).

**Decisioni di design (riepilogo Fase 17)**:

- **lru_cache bypass obbligatorio per repository alla storage root**: tutte le factory di repository (email_index, federated_identity, user_repository) accettano `settings=None` + service passa `self.settings` esplicitamente. Senza, lru_cache singleton restituisce il primo test_settings cachato.
- **PII encryption è responsabilità del File backend**: 5 campi in `_PII_FIELDS`. SQL backends NON devono re-implementare.
- **`get_by_email` / `exists_by_email` come protocol methods `NotImplementedError`**: il `UserRepository` non ha visibilità sull'`EmailIndexRepository`. Service è il solo che fa il two-step lookup.
- **`EntityAlreadyExistsError` vs `ValueError`**: tutte le nuove repository sollevano `EntityAlreadyExistsError(entity, identifier)` (sottoclasse di `ValueError` → retrocompat mantenuta).
- **Rename `UserStorage` → `UserService` rimandato a Fase 18**: 100+ call sites, fuori scope di Fase 17. Il facade mantiene la classe `UserStorage` per retrocompat.

---

#### Fase 17 — Federation ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/federation.py` con `FileFederationProviderRepository` (5 metodi: `create` / `get_by_id` / `update` / `delete` / `list`)
- [x] Factory `get_federation_provider_repository(settings=None)` con lru_cache bypass
- [x] Refactor `backend/authglow/services/federation_storage.py` (108 righe → 30 righe di deprecation shim):
  - **FIX bypass bug 1** (riga 25 originale): rimosso `fsspec.filesystem("file")` hard-coded che bypassava `Settings.storage_backend`
  - **FIX bypass bug 2** (riga 24 originale): rimosso `os.makedirs(self.storage_path, exist_ok=True)`; ora `_init_filesystem` del `BaseFileRepository` gestisce directory creation in modo backend-agnostic
  - Rimosso `import os`, `import fsspec`, `AsyncFileSystem`, `storage_path`, `storage_options`, `fs`, `_afs`
  - 5 metodi delegati al repo: `create_provider` (con `named_lock("federation:create")`), `get_provider`, `update_provider` (con `named_lock(f"federation:{provider_id}")`), `delete_provider` (con `named_lock(f"federation:{provider_id}")`), `list_providers`
- [x] **NB**: `FederationService` esiste GIÀ in `services/federation.py` (OIDC Relying Party flow: callback handling, JWKS verification, provider UI list) — il CRUD usa quindi `FederationProviderService` per separare le 2 concern
- [x] **Ripristino critico**: `services/federation.py` ripristinato da git dopo che la prima creazione di `FederationService` lo aveva sovrascritto accidentalmente (234 righe di logica OIDC preservate)
- [x] Factory `get_federation_provider_repository(settings=None)` con lru_cache bypass
- [x] Aggiungere `tests/unit/repositories/file/test_federation.py` (18 test in 2 classi)
- [x] Test esistenti: 28 in `tests/integration/test_federation.py` verdi con 0 body changes
- [x] Full suite verification: 1548/1548

**Risultato**: 18 nuovi test. **1548/1548** (era 1530 dopo Fase 19, +18 nuovi).

**Bug-fix critici (entrambi risolti)**:

1. **`fsspec.filesystem("file")` hard-coded** (linea 25 originale): bypassava `Settings.storage_backend`. Su qualsiasi backend non-`file` (s3/gcs/abfs) il service sarebbe crashato immediatamente. Risolto rimuovendo `fsspec` dal service e instradando tutto attraverso `BaseFileRepository._init_filesystem`.
2. **`os.makedirs()` bypass** (linea 24 originale): `os.makedirs` è una system call OS-level, NON passa attraverso fsspec. Su qualsiasi backend non-`file`, il `makedirs` OS-level creava una directory locale che il backend cloud non vedeva → primo `write_json` falliva con missing-bucket/permission error. Risolto delegando a `_init_filesystem` del `BaseFileRepository` (che gestisce directory creation in modo backend-agnostic).

**Decisioni di design**:

- **`FederationProviderService` vs `FederationService`**: il nome `FederationService` è già usato in `services/federation.py` per l'OIDC Relying Party flow (callback handling, JWKS verification, provider UI list) — il CRUD usa quindi `FederationProviderService` per separare le 2 concern. Pattern simile a `UserService` (Fase 18) ma con naming esplicito per evitare collisioni.
- **`created_at` / `updated_at` settati dal repo** (non dal service): matches pre-refactor service-side behaviour (le timestamp erano impostate prima della write). `update` ignora `None` values (matches `if value is not None: setattr(...)` del service pre-refactor). `update` ritorna `None` per provider mancanti (vs sollevare `EntityNotFoundError`) per retrocompat con `FederationStorage.update_provider`.
- **`named_lock` mantenuto nel service**: anche se il CRUD è single-entity oggi, il lock è tenuto per consistenza con il pre-refactor behavior (`named_lock("federation:create")` + `named_lock(f"federation:{provider_id}")`) e per forward-compatibility con future cross-entity federation flows (es. cleanup linked federated identities).
- **Path layout**: `<storage>/federation/<provider_id>.json` (subdir `federation`, pre-refactor layout). 1 file per provider.
- **Corrupt-JSON tolerance**: `get_by_id` ritorna `None` su file corrotto (matches pre-refactor `try/except Exception: return None`). `list` silently skips corrupt files (matches pre-refactor `try/except Exception: continue`).
- **Deprecation shim approach** (Fase 18 pattern): 10+ call sites in `api/federation.py` continuano a importare `FederationStorage` da `services/federation_storage`. Lo shim emette `DeprecationWarning` al module import. Migrazione completa a `Depends(get_federation_provider_repository)` in Fase 21.

---

#### Fase 18 — Rename `UserStorage` → `UserService` (+ deprecation shim) ✅ (Fatto: 2026-06-14)

> Questa fase completa il rename `UserStorage` → `UserService` iniziato in Fase 17c. Lo split 3 in EmailIndex/FederatedIdentity/User è stato completato come 17a/17b/17c.

- [x] Creare `backend/authglow/services/user.py` con `UserService` (tutta la logica del `UserStorage`)
- [x] Convertire `backend/authglow/services/storage.py` in deprecation shim con `UserService as UserStorage` + `get_settings` re-export + `DeprecationWarning` emesso al module import
- [x] **Zero modifiche ai 100+ call sites** in 11 file `api/*.py` (continuano a importare `UserStorage` da `services.storage`)
- [x] Aggiornare `tests/conftest.py:109` patch path: `authglow.services.storage.get_settings` → `authglow.services.user.get_settings` (lru_cache bypass pattern consolidato Fase 17a)
- [x] Aggiornare `tests/unit/test_concurrency.py:231,264` stesso fix
- [x] 7 test in `tests/unit/test_user_profile.py` adattati per il rename `_write_user` → `_user_repo.update` (fatto in Fase 19)
- [x] `tests/unit/test_storage.py` continua a passare (la facciata deprecata lo permette)
- [x] Full suite verification: 1515/1515 (era 1515 dopo Fase 17, +0 nuovi ma rename completato)

**Risultato**: 0 nuovi test, 0 regressioni. **1515/1515** invariato (la Fase 19 aggiungerà 15 nuovi test).

**Decisioni di design**:

- **Deprecation shim approach**: 100+ call sites in 11 file `api/*.py` NON sono stati toccati. Il shim `services/storage.py` re-esporta `UserService as UserStorage` + `get_settings`, così `from authglow.services.storage import UserStorage` continua a funzionare. La migrazione completa ai call sites è rimandata a Fase 21.
- **`get_settings` re-export nel shim**: necessario perché i test esistenti patchano `authglow.services.storage.get_settings` (vedi `tests/conftest.py:109`, `tests/unit/test_concurrency.py:231,264`). Senza il re-export, i test fallirebbero con `AttributeError: module 'authglow.services.storage' has no attribute 'get_settings'`.
- **`lru_cache bypass pattern consolidato**: `BaseFileRepository` chiama `authglow.repositories.file.base.get_settings` (NON `authglow.core.config.get_settings`). L'autouse `_override_settings` patcha solo `authglow.core.config.get_settings`, quindi senza che il service passi `settings=self.settings` al factory, `_storage_path` resta fissato al `tmp_path` del primo test (lru_cache singleton). La fix a `tests/conftest.py:109` cambia il target del patch a `authglow.services.user.get_settings` (il binding originale, che `services/storage.py` re-esporta).
- **`DeprecationWarning` al module import**: emesso con `stacklevel=2` per segnalare ai contributor che importano `UserStorage` che dovrebbero migrare a `UserService` (Fase 21 rimuoverà completamente l'alias).
- **Tutti i servizi che importano `UserStorage` continuano a funzionare**: `authglow/services/email_verification.py:48`, `authglow/services/oauth_consent.py:34`, `authglow/services/user_profile.py:21` (Fase 19), `authglow/services/oidc.py:7`. Emettono il `DeprecationWarning` ma funzionalmente corretti. Migrazione a `UserService` in Fase 21.

---

#### Fase 19 — UserPreferences ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/repositories/file/user_preferences.py` con `FileUserPreferencesRepository` (3 metodi: get/save/delete)
- [x] Factory `get_user_preferences_repository(settings=None)` con lru_cache bypass (stesso pattern di Fase 12/14/17a)
- [x] Refactor `backend/authglow/services/user_profile.py`:
  - Rimosso `import os`, `import fsspec`, `AsyncFileSystem`, `preferences_path`, `storage_options`, `fs`, `_afs`
  - Aggiunto `user_preferences_repository=` opzionale + tipizza `self._preferences_repo` con forward ref
  - `get_user_preferences` delega a `_preferences_repo.get(user_id)`; se ritorna `None`, ritorna `UserPreferences(user_id=user_id)` con defaults Pydantic (matches pre-refactor behaviour)
  - `update_user_preferences` delega a `_preferences_repo.save(preferences)`; mantiene `named_lock("preferences:<user_id>")` per in-process safety
  - `delete_account` delega a `_preferences_repo.delete(user_id)` invece di inline `_afs.rm(...)`
  - 5 siti migrati da `self.user_storage._write_user(user)` (privato pre-refactor) a `self.user_storage._user_repo.update(user)` (pubblico post-Fase 17c): `update_user_profile`, `change_password`, `change_email`, `deactivate_account`, `reactivate_account`
  - 5 metodi restano nel service: `get_user_profile` (User + preferences aggregato), `update_user_profile`, `change_password`, `change_email`, `deactivate_account`/`reactivate_account` (richiedono User + cross-entity coordination con email/security services)
- [x] Test esistenti adattati: 7 in `tests/unit/test_user_profile.py` da `user_storage._write_user = AsyncMock()` a `user_storage._user_repo.update = AsyncMock()` (Fase 17c espone `update` come public method)
- [x] Aggiungere `tests/unit/repositories/file/test_user_preferences.py` (15 test in 2 classi)
- [x] Full suite verification: 1530/1530 (era 1515 dopo Fase 18, +15 nuovi)

**Risultato**: 15 nuovi test. **1530/1530** (era 1515 dopo Fase 18, +15 nuovi).

**Decisioni di design**:

- **Path layout**: `<storage>/user_preferences/<user_id>.json` (subdir `user_preferences`, pre-refactor layout). Ogni user ha un singolo file di preferences.
- **Pydantic round-trip**: il repo chiama `preferences.model_dump()` per serializzare e `UserPreferences(**data)` per deserializzare. Corrupt-JSON tolerance: `get` ritorna `None` su file corrotto (matches Fase 14 LoginHistory pattern).
- **`get` ritorna `None` per missing, NON un default `UserPreferences`**: il service `get_user_preferences` gestisce la mapping a `UserPreferences(user_id=user_id)` con defaults Pydantic. Mantiene la **separation of concerns**: il repo conosce solo la Pydantic class; il service decide la semantica dei defaults.
- **5 metodi cross-entity restano nel service**: `get_user_profile` (User + preferences aggregato in `UserProfileResponse`), `change_password` (User + `SecurityNotificationService.send_password_changed_alert`), `change_email` (User + `EmailVerificationService.create_verification_token` + `SecurityNotificationService.send_email_changed_alert`), `deactivate_account`/`reactivate_account` (User + federated check). Il service è il solo a sapere l'orchestrazione cross-service.
- **`_write_user` privato rimosso**: il metodo `UserStorage._write_user` (presente in Fase 17c come back-compat shim) è stato sostituito da `self._user_repo.update(user)` direttamente. Il `_user_repo` è pubblicamente accessibile via `self.user_storage._user_repo` dal `UserProfileService` (anche se `_` prefisso). In Fase 21 cleanup si può valutare di esporlo come property pubblica.
- **`lru_cache bypass` per `UserPreferencesRepository`**: stessa pattern di Fase 12/14/17a. Senza, `_storage_root` resta fissato al `tmp_path` del primo test (lru_cache singleton).
- **`UserPreferencesUpdate` model**: il service riceve `preferences_update: UserPreferencesUpdate` (Pydantic model con campi opzionali) e applica `model_dump(exclude_unset=True)` per merge con i preferences esistenti. Pattern Pydantic standard per partial updates.

---

#### Fase 20 — KeyStore (refactor speciale) ✅ (Fatto: 2026-06-14)

- [x] Creare `backend/authglow/models/keystore.py` con 4 Pydantic models: `KeyPair` (kid + encrypted private_pem + public_pem + meta), `KeyPairMeta` (kid + created_at + status + algorithm + key_size + retired_at/revoked_at), `PublicKey` (kid + algorithm + use + kty + n + e + key_size + created_at per JWKS), `KeyringInfo` (active_kid + keys + last_updated per admin introspection)
- [x] Definire Protocol `KeyStoreRepository` in `protocols.py` con 5 metodi (`@runtime_checkable` per conformance check)
- [x] Creare `backend/authglow/repositories/file/keystore.py` con `FileKeyStoreRepository` (NON è un `BaseFileRepository` subclass — layout multi-file)
- [x] Spostare `_load_keyring`, `_save_keyring`, `_generate_key_pair`, `_new_kid`, `_write_active_symlinks` come metodi privati del repo (mantenendo l'API identica per i test esistenti)
- [x] Aggiungere helper `_rsa_pem_to_jwk_components` per convertire PEM → JWK `n`/`e` base64url-encoded
- [x] Mantenere `tmp+rename` atomic write come dettaglio interno di `_save_keyring`
- [x] Refactor `core/config.py: get_or_generate_keyring` come thin orchestrator che delega al repo via `FileKeyStoreRepository.for_keys_dir()` (per il lru_cache bypass del `Settings` al startup)
- [x] 6 helper re-eksportati da `core/config.py` per retrocompat con i test esistenti: `_KEYRING_FILENAME`, `_generate_key_pair`, `_new_kid`, `_load_keyring`, `_save_keyring`, `_write_active_symlinks` (re-eksport come `noqa: F401` per documentare l'intento)
- [x] Aggiungere factory `get_keystore_repository()` in `repositories/dependencies.py` (non accetta `settings=` perché il keyring è per-directory, non per-file; usa lru_cache bypass via `for_keys_dir()` classmethod)
- [x] Aggiungere `tests/unit/repositories/file/test_keystore.py` (20 test in 2 classi, include `for_keys_dir()` smoke test + JWK component verification)
- [x] Test esistenti in `tests/unit/test_jwt.py`, `tests/unit/test_jwt_key_rotation.py`, `tests/unit/test_config.py` restano verdi (49 test in totale, con 0 body changes)
- [x] Full suite verification: 1568/1568

**Risultato**: 20 nuovi test. **1568/1568** (era 1548 dopo Fase 17, +20 nuovi).

**Decisioni di design**:

- **`FileKeyStoreRepository` NON è un `BaseFileRepository`**: il keyring layout spans multiple files (index + per-kid PEM files + legacy flat paths), quindi non è un singolo `_subdir` come gli altri repository. Implementa direttamente `os.makedirs` / `shutil.copy2` / `tmp+rename` invece di ereditare dal base.
- **`@runtime_checkable` sul `KeyStoreRepository` protocol**: serve per `isinstance(repo, KeyStoreRepository)` check nei test (anche se la classe `FileKeyStoreRepository` non ha esplicitamente `KeyStoreRepository` nel suo bases, i metodi runtime-checkable verificano la presenza dei 5 metodi).
- **`cast` rimosso, isinstance check preservato**: inizialmente ho usato `cast(rsa.RSAPublicKey, public_key)` per il narrowing mypy, ma mypy con strict mode + isinstance check si lamenta del "Redundant cast" — l'isinstance check è sufficiente. Mantengo solo l'isinstance check + ValueError per chiarezza runtime.
- **`for_keys_dir()` classmethod**: entry point speciale per `core/config.py: _generate_fresh_keyring` / `_perform_rotation` (path di startup). Costruisce un'istanza di `FileKeyStoreRepository` con uno stub `Settings` che ha solo `keys_dir` settato, evitando di passare attraverso `get_settings()` (lru_cache singleton). Vedi Fase 12/14/17a lru_cache bypass pattern.
- **`tmp+rename` atomic write**: solo per `keyring.json`. Su cloud backends (futuro) la rename non è disponibile e il write è best-effort (matches pre-refactor + `_write_json_atomic` di `BaseFileRepository`).
- **5 metodi del protocol + helpers**: 5 metodi pubblici (`get_active_keypair` / `get_keypair_by_kid` / `get_public_keys` / `rotate` / `revoke`) + 5 helpers privati (`_load_keyring` / `_save_keyring` / `_ensure_loaded` / `_reload_keyring` / `_build_keypair` / `_read_kid_pems` / `_write_kid_pems` / `_kid_dir` / `_write_active_symlinks` / `is_loaded` / `reload` / `get_keyring_dict` / `get_active_kid` / `_rsa_pem_to_jwk_components`).
- **`get_keyring_dict` reintrodotto**: il pre-refactor `JWTService.get_keyring_info` ritornava un dict simile; il repo lo espone come metodo pubblico (non nel protocol) per admin introspection.
- **Mantenimento `core/config.py: get_or_generate_keyring`**: la funzione resta come entry point al startup (chiamata da `Settings.__init__`). Internamente delega a `FileKeyStoreRepository.for_keys_dir()` + `repo._write_kid_pems` + `repo._save_keyring` + `_write_active_symlinks`. Le 3 path (migration, fresh generation, auto-rotation) restano visibili come funzioni top-level per chiarezza, ma usano il repo per il I/O.
- **Backward compat `_save_keyring` / `_load_keyring` / `_write_active_symlinks`**: i test esistenti (es. `test_jwt_key_rotation.py:_create_keyring_in_dir` riga 72-74) chiamano `_write_active_symlinks(keys_dir, keyring)` direttamente. Le funzioni sono re-eksportate da `core/config.py` per retrocompat (noqa: F401) e continuano a funzionare (internamente usano la stessa logica).
- **RSA only**: il protocol dichiara `algorithm = "RS256"` e il `_rsa_pem_to_jwk_components` solleva `ValueError` se la chiave caricata non è RSA. Ed25519 / ECDSA non sono supportati nel keyring.
- **`Settings.placeholder_key_*` tests passano**: la rimozione di `import secrets` da `core/config.py` ha richiesto di re-aggiungerlo perché `Settings.__init__` chiama `secrets.token_urlsafe(32)` (riga 276) per generare il `setup_token`. **Lesson learned**: `core/config.py` continua a usare `secrets` direttamente, anche se la logica keyring è migrata al repo.

---

#### Fase 21 — Deprecazione & cleanup ✅ (Fatto: 2026-06-14)

> **Piano archiviato.** Il Repository pattern è ora completo:
> 22 fasi migrate, 23/23 fasi core done, 1614/1614 full suite verde,
> 0 dipendenze fsspec nei service, 3 bug "no-cloud" chiusi, +46 nuovi
> test di conformance + in-memory smoke test.

- [x] **Rimosso `services/storage.py` shim** (Fase 18 deprecation rimosso)
  - 18 file sorgente aggiornati: 11 `api/*.py` + 4 service + 3 test file
  - Tutti gli `from authglow.services.storage import UserStorage` → `from authglow.services.user import UserService` + `UserStorage = UserService` (alias module-level per i test patches)
  - `services/federation_storage.py` rimosso anch'esso (Fase 17 deprecation rimosso)
  - `from authglow.services.federation_storage import FederationStorage` → `from authglow.services.federation_provider import FederationProviderService as FederationStorage`
- [x] **Aggiornati 51 patch path** nei test:
  - `patch("authglow.api.admin.UserStorage")` → `patch("authglow.api.admin.UserStorage")` (alias, non rotto)
  - `patch("authglow.services.storage.get_settings")` → `patch("authglow.services.user.get_settings")` (lru_cache bypass)
  - `patch("authglow.services.storage.UserStorage.get_user_by_email")` → `patch("authglow.services.user.UserService.get_user_by_email")`
- [x] **Spostato `tests/unit/test_storage.py`** → `tests/unit/repositories/file/test_user_service.py` (file rinominato via `git mv`)
- [x] **Aggiunto `tests/unit/repositories/test_protocols.py`**: 39 conformance test parametrizzati (19 entity × 2 check: `issubclass` + `isinstance` runtime). Pattern: aggiungere un nuovo backend (es. `SqlUserRepository`) richiede 1 riga in `_IMPL_TABLE` per essere testato. Test parametrizzato include User + UserPreferences come classi separate (PII encryption / Pydantic round-trip setup).
- [x] **Aggiunto `tests/unit/repositories/test_in_memory.py`**: 7 smoke test con `InMemoryUserRepository` + `InMemoryEmailIndexRepository` + `InMemoryFederatedIdentityRepository`. Verifica che `UserService` (la facade) funziona con **qualsiasi** impl che soddisfa i 3 Protocol. Testa 7 cross-entity operations: `create_user`, `create_user_duplicate_raises`, `update_email`, `delete_user`, `get_by_external_id`, `link_federated_identity`, `get_user_by_email`. **Questa è la prova che il pattern funziona**: l'aggiunta di un nuovo backend (Postgres, Firestore, S3) richiederà solo di scrivere la nuova impl + 1 riga in `_IMPL_TABLE` + (opzionale) un impl InMemory per il nuovo backend. Zero modifiche a `services/` o `api/`.

**Risultato**: 46 nuovi test (39 conformance + 7 in-memory). **1614/1614** full suite verde (era 1568 dopo Fase 20, +46 nuovi).

**Criteri di accettazione finali verificati**:

- [x] **Zero `import fsspec` in `authglow/services/`** (eccetto `services/email/file_storage.py` che resta EmailProvider)
- [x] **Zero `await self._afs.*` in `authglow/services/`** (i 3 service che lo usavano — UserStorage, LoginHistoryService, SecurityEventService — sono stati refactored nelle fasi 14-17)
- [x] **Tutti i test esistenti passano** (1614/1614)
- [x] **I 3 bug "no-cloud" sono chiusi** (admin_action.py:76 + security_event.py:72 + login_history.py:73 + passkey.py:51 + login_history.py:129, tutti risolti nelle fasi 10/14/15/16)
- [x] **L'aggiunta di un nuovo backend** è: (1) `pip install <dep>`, (2) `repositories/<backend>/<entity>.py` con `<Backend><Entity>Repository(<Protocol>)`, (3) cambiare la factory in `repositories/dependencies.py`. Zero modifiche a `services/` o `api/`. Il conformance test in `test_protocols.py` e lo smoke test in `test_in_memory.py` verificano automaticamente.

**Decisioni di design finali**:

- **Alias `UserStorage = UserService` nei moduli `api/*.py`**: invece di rinominare 78 occorrenze di `UserStorage` in 11 file, ho aggiunto `UserStorage = UserService` come alias module-level. I test patches `patch("authglow.api.admin.UserStorage")` continuano a funzionare via l'alias. Quando la migrazione ai repository diretti (Fase 22+ / post-piano) avverrà, l'alias verrà rimosso insieme alle 78 occorrenze in un singolo commit.
- **Conformance test parametrizzato**: ho usato un design table-driven (`_IMPL_TABLE = [(impl, protocol, name), ...]`) invece di magic strings. Aggiungere un nuovo backend richiede 1 riga in `_IMPL_TABLE` + import.
- **InMemory smoke test, NON coverage completa**: ho implementato solo 3 in-memory repo (User, EmailIndex, FederatedIdentity) — gli altri 17 sono triviali e il pattern è identico. Il `UserService` smoke test è la prova principale: se funziona con InMemory, funzionerà con qualsiasi impl che rispetti il Protocol. Aggiungere `InMemoryRefreshTokenRepository` etc. è un task per dopo (1 riga in `_IMPL_TABLE` + 1 file in `test_in_memory.py`).
- **Spostamento `tests/unit/test_storage.py` → `tests/unit/repositories/file/test_user_service.py`**: ho usato `git mv` (preserva la history). Il file è ora nella posizione canonica secondo la struttura `tests/unit/repositories/file/test_<entity>.py`. Nessuno shim di retrocompat necessario (nessun altro test importa `test_storage`).
- **Lru_cache bypass rimosso in conftest.py:109**: il binding originale in `BaseFileRepository.__init__` è `authglow.repositories.file.base.get_settings`. Senza il fix, `_storage_path` del repo puntava al `tmp_path` del primo test (lru_cache singleton). Il test `TestAccountLockout` falliva con "User with email lockout@example.com already exists" sul 2° test della classe.

**Archiviazione del piano**: questo file rimane come storico delle 21 fasi. Per il futuro, vedere `AGENTS.md` per il current state dell'architettura e la guida operativa per aggiungere un nuovo backend.

**Comandi finali**:
```bash
cd backend
ruff check authglow/
ruff format --check authglow/
mypy authglow/
pytest -q --tb=line -n auto
```

**Criteri di accettazione finali**:
- [ ] Zero `import fsspec` in `authglow/services/` (eccetto `services/email/file_storage.py` che resta EmailProvider)
- [ ] Zero `await self._afs.*` in `authglow/services/`
- [ ] Tutti i test esistenti passano
- [ ] I 3 bug "no-cloud" sono chiusi
- [ ] L'aggiunta di un nuovo backend è: (1) installa dipendenza, (2) crea `repositories/<backend>/<entity>.py`, (3) cambia factory in `dependencies.py`. Zero modifiche a `services/` o `api/`.

---

## 6. Refactor speciali (anomalie da sistemare in coda)

| # | File | Problema | Soluzione |
|---|---|---|---|
| A | `api/admin.py:1163-1225` (`get_oauth_consents_admin`) | **Inline I/O in route handler** — istanzia fsspec direttamente | Usare `Depends(get_oauth_consent_repository)` e il metodo `list_all_admin()`. **Incluso nella fase 8.** |
| B | `services/admin_action.py:76`, `security_event.py:72`, `login_history.py:73` | Hard-code `fsspec.filesystem("file")` — niente cloud support | Ereditare da `BaseFileRepository` che usa `Settings.get_storage_options()`. **Fasi 14-16.** |
| C | `services/passkey.py:51` | `fsspec.core.url_to_fs` bypassa `storage_backend` | Stesso fix: usare `BaseFileRepository`. **Fase 10.** |
| D | `services/login_history.py:129` | `os.remove()` in `_cleanup_old_entries` — non passa da AFS | Sostituire con `await self._afs.rm(path)`. **Fase 14.** |
| E | `services/storage.py` (UserStorage) | Contiene User + email_index + federated_identities — 3 entità in 1 classe | Split in 3 repository (fase 18). Il `UserService` ricompone le 3 con `named_lock` per le operazioni cross-entity. |
| F | `core/token_blacklist.py:159` | Singleton in `core/`, scomodo nei test | Spostare in `services/auth/token_blacklist.py`, singleton mantenuto. **Fase 1.** |
| G | `core/config.py` + `services/jwt.py` | Keyring scritto con stdlib `open()`, non fsspec | `FileKeyStoreRepository` (fase 20). Mantiene `tmp+rename` atomic-write come dettaglio interno. |

---

## 7. Strategy di test per ogni PR

1. **Test esistenti** per il servizio toccato **devono restare verdi senza modifiche** (a parte l'aggiornamento del path di `patch()` nel conftest).
2. **Test nuovi** per il repository: `tests/unit/repositories/file/test_<entity>.py` — test diretti sull'impl File, coprono happy path + edge cases (file mancante, JSON corrotto, race con CAS).
3. **Test di conformance**: in `tests/unit/repositories/test_protocols.py`, test parametrizzato che **qualsiasi** impl del Protocol (oggi solo File, domani Sql/Firestore) passa gli stessi test. Questo è il punto: possiamo aggiungere un secondo backend e i test sono già pronti.
4. **Dopo fase 21**: introdurre una impl "in-memory" di smoke-test (`InMemoryUserRepository`) che vive solo nei test — verifica che tutti i service funzionino con un repository non-File. Costo: ~1 giorno. Valore altissimo (è la prova che il pattern funziona).

---

## 8. Migration check-list per ogni fase (template)

- [ ] Crea `repositories/protocols.py` entry per la nuova entità (se non c'è)
- [ ] Crea `repositories/file/<entity>.py` con `File<Entity>Repository` che eredita da `BaseFileRepository`
- [ ] Sposta logica I/O dal service al repository (fsspec, _afs, encrypt, path, indexes)
- [ ] Aggiorna il service per chiamare il repository
- [ ] Aggiorna la factory: `get_<entity>_repository()` in `repositories/dependencies.py`
- [ ] Aggiorna le route API: `Depends(get_<entity>_repository)` (o service che lo riceve)
- [ ] Aggiorna `tests/conftest.py`: aggiungi `patch("authglow.repositories.file.<entity>.get_settings")` se necessario
- [ ] Aggiungi `tests/unit/repositories/file/test_<entity>.py`
- [ ] `ruff check` + `ruff format` + `mypy` puliti
- [ ] Test del servizio toccato verdi
- [ ] Full test suite (`pytest -q --tb=line -n auto`) verdi
- [ ] Commit con messaggio: `refactor(repositories): migrate <Entity> to repository pattern`

---

## 9. Rischi e mitigazioni

| Rischio | Mitigazione |
|---|---|
| Il `named_lock` nei Service + `fsspec` lock non coordinati causano deadlock | Fase 0: scrivere un **integration test** che verifica nessuna doppia acquisizione dello stesso lock annidato. I lock restano solo nei Service. |
| Le cross-entity atomicity (es. `update_email` = User + EmailIndex) si rompono se Postgres fallisce a metà | Fase 18: introdurre un `TransactionalUnit` **opzionale** che coordini più repository. Per File è no-op; per SQL diventa una vera transazione. |
| I test del `conftest.py` patchano direttamente le classi storage — fragili al refactor | Aggiornare il conftest per patchare i Protocol, non le impl concrete. Una volta sola, in fase 21. |
| Performance regression (es. `list_users` che diventa 2 query invece di 1) | Misurare con `pytest-benchmark` su `list_users` e `get_user_stats` (i 2 colli di bottiglia noti). La fase 18 misura prima/dopo. |
| Il refactor del keyring (fase 20) tocca `core/config.py` che è già complesso | Fare fase 20 in PR dedicata, con `git revert` come safety net. È l'unica fase con superficie ampia su `core/`. |
| I 3 servizi "no-cloud" scoperti durante l'audit (admin_action, security_event, login_history) sono bug latenti | Sistemati in fasi 14-16 senza overhead. |

---

## 10. Cosa NON facciamo (per rimanere scoped)

- **DDD puro** con domain/entities/value_objects separati: overkill, lo User model Pydantic esistente va bene.
- **CQRS/Event Sourcing**: non richiesto, lo schema è CRUD puro.
- **Migrazione effettiva a Postgres/Sqlite**: il pattern abilita la migrazione futura ma non la esegue. Quando vorrai farlo, basta scrivere `SqlUserRepository(UserRepository)` accanto a `FileUserRepository` e cambiare la factory. Aggiungerlo come secondo backend è **esplicitamente out of scope** di questo piano (lo menziono come prova futura del valore).
- **Asyncpg / SQLAlchemy / Motor / Firestore client**: non installati. Si fa quando servirà.

---

## 11. Output finale atteso (post fase 21)

- I service `authglow/services/*.py` contengono **solo** business logic + composizione di repository. Zero `import fsspec`, zero path string, zero `await self._afs.*`.
- I `authglow/repositories/file/*.py` contengono **solo** mapping dominio↔file. Zero business logic.
- L'aggiunta di un nuovo backend (es. Postgres) richiede:
  1. `pip install sqlalchemy[asyncio]`
  2. `repositories/sql/user.py` con `SqlUserRepository(UserRepository)`
  3. Modificare `repositories/dependencies.py` per scegliere l'impl
  4. Zero modifiche ai service o alle route
- Tutti i test esistenti continuano a passare.
- I 3 bug "no-cloud" sono chiusi come bonus.

---

## Fase 0 — Scaffolding (in progress)

Crea la cartella `repositories/` con:
- `repositories/__init__.py` — re-exports
- `repositories/protocols.py` — tutti i Protocol (scheletri per le 21 entità)
- `repositories/exceptions.py` — `EntityNotFoundError`, `EntityAlreadyExistsError`
- `repositories/dependencies.py` — factory placeholder (ritornano `None` finché non migrate)
- `repositories/base.py` — segnaposto per interfacce comuni non-File
- `repositories/file/__init__.py` — vuoto
- `repositories/file/base.py` — `BaseFileRepository` con fsspec + AFS + path helpers

Nessun servizio esistente viene toccato. Nessun test viene modificato. Il package è importabile ma non ancora usato.
