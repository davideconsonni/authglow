# Repository Pattern

This document describes the repository layer architecture in AuthGlow, how services interact with storage, and guidelines for adding or extending storage backends.

## Architecture Overview

AuthGlow separates business logic from persistence using the **Repository Pattern**:

- **Services depend on Protocols, not concrete implementations.** Every service constructor takes optional repository arguments and falls back to a factory function in `authglow/repositories/dependencies.py`.
- **Cross-entity atomicity lives in services**, not repositories. Multi-entity operations (e.g., `create_user` spanning `User`, `EmailIndex`, and `FederatedIdentity`) acquire `named_lock()` inside the service layer.
- **Backend-agnostic contracts.** All repository interfaces are defined in `authglow/repositories/protocols.py` as runtime-checkable `typing.Protocol` classes.

```
Service Layer (services/<module>.py)
  ├── Depends on Protocol contracts
  ├── Coordinates cross-entity transactions (named_lock)
  └── Injects repos via factory: get_<entity>_repository(settings=self.settings)
        │
        ▼
Repository Factories (repositories/dependencies.py)
  ├── _REGISTRY + register_backend() selector
  └── Dispatches based on Settings.repository_backend (default: "file")
        │
        ▼
Concrete Implementation (repositories/file/<entity>.py)
  ├── Subclasses BaseFileRepository
  ├── Implements <Entity>Repository protocol
  └── Pydantic serialization, PII encryption, atomic writes
```

## Protocol Contracts

All storage operations are governed by 36 Protocol contracts defined in `authglow/repositories/protocols.py`. Each Protocol specifies async methods:

- `get(id: str) -> Optional[Entity]`
- `create(entity: Entity) -> Entity`
- `update(entity: Entity) -> Entity`
- `delete(id: str) -> bool`
- Specialized domain queries (e.g., `get_by_email`, `list_by_client_id`)

Exceptions are defined in `authglow/repositories/exceptions.py`:
- `EntityNotFoundError`
- `EntityAlreadyExistsError`

## Implementation Hierarchy

```
BaseFileRepository (authglow/repositories/file/base.py)
  ├── Shared fsspec + AsyncFileSystem handling
  ├── Atomic file operations (_write_json_atomic, _read_json, _glob, _delete)
  ├── Path resolution helpers (_path, _ensure_parent)
  └── Settings resolution with lru_cache bypass

File<Entity>Repository (BaseFileRepository, <Entity>Repository)
  ├── Pydantic round-trip (model_dump / model_validate)
  ├── Backend-specific concerns (PII encryption, HMAC keys, CAS)
  └── Implements the Protocol contract

FileKeyStoreRepository (authglow/repositories/file/keystore.py)
  ├── Rooted at settings.keys_dir
  ├── Versioned atomic writes for keyring.json (_write_json_versioned)
  └── for_keys_dir() classmethod for startup bootstrap
```

## Adding a New Storage Backend

To introduce a new storage backend (e.g., Postgres, MongoDB):

1. **Install dependencies**: add required drivers to `pyproject.toml`.
2. **Implement repository classes**: create `authglow/repositories/<backend>/<entity>.py` implementing `<Entity>Repository` protocols.
3. **Register the backend**: in `authglow/repositories/dependencies.py`, register the implementation mapping in `_REGISTRY`.
4. **Zero changes** to `services/` or `api/` layers.
5. **Verify with conformance tests**: update `tests/unit/repositories/test_protocols.py` to add the new backend to `_IMPL_TABLE`.

## LRU Cache Bypass Pattern (Critical for Test Isolation)

`BaseFileRepository.__init__` accepts an optional `settings: Optional[Settings] = None` argument.

Because `_override_settings` in `tests/conftest.py` patches `authglow.core.config.get_settings`, file repositories must not rely on the cached singleton. Every factory in `repositories/dependencies.py` accepts `settings` and passes it to the repository constructor. Services pass `self.settings` to factories:

```python
# Service initialization
def __init__(self, repository: Optional[UserRepository] = None, settings: Optional[Settings] = None):
    self.settings = settings or get_settings()
    self._repo = repository or get_user_repository(settings=self.settings)
```

Without this pattern, repositories share storage paths across test fixtures under pytest-xdist (`-n auto`), causing state leakage and false duplicate key errors.

## Testing Strategy

- **Conformance Tests (`tests/unit/repositories/test_protocols.py`)**: Parametrized suite verifying that every implementation satisfies its Protocol contract and handles non-existent entities, duplicate keys, and round-trip serialization.
- **In-Memory Smoke Tests (`tests/unit/repositories/test_in_memory.py`)**: Tests services end-to-end with pure in-memory mock repositories (`InMemoryUserRepository`, etc.) to guarantee zero file-system coupling in business logic.
