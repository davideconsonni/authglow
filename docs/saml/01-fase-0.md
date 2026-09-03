# Fase 0 — Fondazioni SAML (dipendenze, settings, certificati, modelli, repository)

> **Scopo (IT)**: posare le fondamenta senza toccare alcun flusso di
> login esistente: dipendenze XML, settings, gestione certificati
> X.509, modelli Pydantic, repository pattern-conformi, scaffold del
> router. A fine fase nulla è ancora raggiungibile pubblicamente se
> non l'inventario certificati admin.
> **Prerequisito**: nessuno. Questa è la prima fase.

## Handoff contract (EN)

- Read `AGENTS.md` and `docs/saml/00-assessment.md` §3, §6, §7, §10 first.
- Item IDs are stable: `F0-NN`. Tick checkboxes as you close them.
- Do not implement ACS/SSO endpoints (Fase 1/2), do not add login
  buttons, do not touch the OIDC federation flow.

## Checklist

- [ ] F0-01 Dependencies added
- [ ] F0-02 Settings added
- [ ] F0-03 Certificate module + startup wiring
- [ ] F0-04 Admin certificate inventory endpoint
- [ ] F0-05 `SamlIdpConfig` models
- [ ] F0-06 `SamlIdpConfigRepository` protocol + file impl + factory
- [ ] F0-07 Conformance + repository tests
- [ ] F0-08 Router scaffold registered in `main.py`
- [ ] F0-09 ARCHITECTURE.md updated
- [ ] F0-10 Verification run clean

---

## F0-01 — Dependencies

`backend/requirements.in` is pip-compiled into `requirements.txt`
(verify the tooling: repo has both files; regenerate with
`pip-compile` if available, otherwise hand-pin matching the file's
style).

Add:

```
lxml
signxml
```

Notes:
- `signxml` 4.x works with the repo's `cryptography==50.0.0` (verify
  during compile; if signxml pins an older cryptography, resolve the
  conflict in `requirements.in` constraints and record it here).
- No `defusedxml`: the hardened lxml parser (Fase 1, `core/saml_xml.py`)
  is the control. No `xmlsec1`: banned at runtime (DR-02).
- After compile: `pip install -r requirements.txt` and import smoke:
  `python -c "import lxml, signxml; print(signxml.__version__)"`.

## F0-02 — Settings

`backend/authglow/core/config.py` — add to the `Settings` class
(`pydantic_settings`, follow existing field style + docstrings):

| Field | Type | Default | Notes |
|---|---|---|---|
| `saml_enabled` | `bool` | `False` | gates startup cert generation |
| `saml_clock_skew_seconds` | `int` | `90` | `Field(ge=0, le=300)` |
| `saml_request_ttl_seconds` | `int` | `600` | AuthnRequest store TTL (used F1) |
| `saml_idp_assertion_lifetime_seconds` | `int` | `300` | used F2 |
| `saml_org_name` | `str` | `"AuthGlow"` | metadata Organization |
| `saml_org_display_name` | `str` | `"AuthGlow"` | metadata Organization |
| `saml_org_url` | `Optional[str]` | `None` | defaults to `base_url` |
| `saml_technical_contact_name` | `Optional[str]` | `None` | metadata ContactPerson |
| `saml_technical_contact_email` | `Optional[str]` | `None` | metadata ContactPerson |

Every setting is automatically overridable by the existing admin
runtime override service (`services/settings_override.py`) — no extra
work needed; just mention them in its UI allowlist if one exists
(check `api/admin_settings.py` for the allowlist pattern).

## F0-03 — Certificate module

New file `backend/authglow/core/saml_certs.py`.

```python
@dataclass(frozen=True)
class SamlCertificate:
    role: str                 # "sp" | "idp"
    private_key_pem: str      # PEM, never logged, never serialized to responses
    certificate_pem: str      # PEM with trailing newline
    fingerprint_sha256: str   # colon-separated hex
    subject_cn: str
    not_before: datetime
    not_after: datetime

def get_or_generate_saml_certificates(
    settings: "Settings",
) -> Dict[str, SamlCertificate]:
    """Load or create saml_sp_signing / saml_idp_signing key pairs."""
```

Requirements:
- Files in `settings.keys_dir` (same root as `keyring.json`):
  `saml_sp_signing.key`, `saml_sp_signing.crt`,
  `saml_idp_signing.key`, `saml_idp_signing.crt`.
- Generation via `cryptography` (`x509.CertificateBuilder`, self-signed):
  RSA-2048, `SHA256`, CN = hostname of `settings.base_url`
  (`urlparse`), O = `saml_org_name`, serial = `x509.random_serial_number()`,
  validity 3650 days (`not_before = utcnow() - 1 day` for clock skew).
- Key encoding: PKCS8 PEM, no passphrase.
- **lru_cache bypass pattern (CRITICAL)**: no module-level cache of the
  certificates keyed on nothing — accept `settings` explicitly and let
  callers (services created per-request or per-function) pass the
  patched settings. If you add caching, key it on
  `(keys_dir, base_url)`. This mirrors the `FileKeyStoreRepository.for_keys_dir`
  rationale (see AGENTS.md "Lru_cache bypass pattern").
- Thread/async safety: file generation wrapped in `asyncio.to_thread`
  by the caller; module itself is sync. Use a lock file or
  `named_lock("saml_certs")` around check-then-generate to avoid
  concurrent workers racing (existing repo pattern: `core/concurrency.py`).
- Secrets discipline: private key never logged, never included in API
  responses (F0-04 returns public material only). structlog events:
  `saml_cert_generated` (role, fingerprint, not_after — no key material).
- If `saml_enabled` is False: do not generate at startup (lazy generation
  on first use is acceptable and preferred to avoid cert files appearing
  in sandboxes).

Startup wiring in `backend/main.py` lifespan: if `settings.saml_enabled`,
call `await asyncio.to_thread(get_or_generate_saml_certificates, settings)`
after `startup_hydrate()`; wrap in try/except that logs
`saml_cert_init_failed` and **does not** crash the app (feature-degraded
posture, consistent with other optional subsystems).

## F0-04 — Admin certificate inventory endpoint

New `backend/authglow/api/saml.py` (this file is the F1/F2 router home):

```python
router = APIRouter(prefix="/api", tags=["saml"])

@router.get("/admin/saml/certificates")
async def list_saml_certificates(
    admin: User = Depends(get_current_admin_user),  # reuse existing admin dependency
):
```

Response model `SamlCertificateInfo` (Pydantic, in `models/saml.py`):
`role, subject_cn, fingerprint_sha256, not_before, not_after,
public_cert_pem`. Two entries (sp, idp). If `saml_enabled` is False →
404 with detail "SAML disabled" (consistent with feature flags elsewhere).

Register `from authglow.api.saml import router as saml_router` in
`main.py` next to the federation router include (inspect `main.py` for
the exact include block style).

## F0-05 — `SamlIdpConfig` models

New file `backend/authglow/models/saml.py`. Mirror the shape of
`models/federation.py::ExternalIdpConfig` (read it first) for shared
UX fields, then SAML-specific fields.

`SamlIdpConfig(BaseModel)` — persistence model:

| Field | Type | Default | Validation |
|---|---|---|---|
| `id` | `str` | `uuid4()` | — |
| `label` | `str` | required | — |
| `description` | `Optional[str]` | `None` | — |
| `protocol` | `Literal["saml"]` | `"saml"` | discriminator for the merged provider list |
| `idp_entity_id` | `str` | required | non-empty, ≤ 512 |
| `idp_sso_redirect_url` | `Optional[str]` | `None` | https URL when present |
| `idp_sso_post_url` | `Optional[str]` | `None` | https URL; at least one of redirect/post required |
| `idp_slo_url` | `Optional[str]` | `None` | https URL (used F3) |
| `idp_signing_certificates` | `List[str]` | `[]` | PEM (X.509 CERTIFICATE) blocks; non-empty at ACS time (F1 enforces at runtime) |
| `name_id_format` | `str` | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` | closed enum: persistent, emailAddress, unspecified |
| `sign_requests` | `bool` | `True` | DR-06 |
| `require_signed_assertion` | `bool` | `False` | strict opt-in (DR-05) |
| `require_signed_response` | `bool` | `False` | strict opt-in (DR-05) |
| `trust_email` | `bool` | `False` | DR-14 |
| `allow_unsolicited` | `bool` | `False` | DR-14/T-06 |
| `requested_authn_context` | `Optional[SamlAuthnContext]` | `None` | `{comparison: Literal["minimum","exact","maximum","better"], class_refs: List[str]}` |
| `clock_skew_seconds` | `Optional[int]` | `None` | `ge=0, le=300` override |
| `icon_uri`, `logo_uri` | `Optional[str]` | `None` | same http/https + length validators as OIDC (copy the `field_validator`s) |
| `enabled` | `bool` | `True` | — |
| `visible_contexts` | `List[str]` | `["dashboard", "oauth2"]` | same semantics as OIDC |
| `auth_levels` | `Optional[List[str]]` | `None` | as OIDC |
| `claims_mapping` | `Dict[str, str]` | same default as OIDC minus `sub` → use `name_id → external_id` default | see below |
| `rate_limit_per_minute` | `Optional[int]` | `None` | `ge=1, le=1000` |
| `created_at` / `updated_at` | `datetime` | `utcnow()` | from `authglow.core.datetime` |
| `created_by` | `Optional[str]` | `None` | — |

Default `claims_mapping`:
```python
{
    "name_id": "external_id",
    "email": "email",
    "name": "name",
    "given_name": "given_name",
    "family_name": "family_name",
}
```
(SAML attribute names are case-insensitive per interop practice; the
F1 lookup helper must compare case-insensitively — note this in the
model docstring.)

`SamlIdpConfigCreate` / `SamlIdpConfigUpdate` / `SamlIdpConfigResponse`:
mirror the OIDC Create/Update/Response variants exactly (Response
**must not** include certificates in full — expose
`certificate_fingerprints: List[str]` instead; PEM bodies are admin
view-only via a dedicated GET if ever needed).

Validators: URL scheme https-only for IdP URLs (stricter than OIDC's
http/https — SAML IdPs are always TLS in scope), PEM parse check via
`cryptography.x509.load_pem_x509_certificate` (raise `ValueError` on
garbage), enum-checked `name_id_format`.

## F0-06 — Repository protocol + file impl + factory

1. `backend/authglow/repositories/protocols.py` — add
   `SamlIdpConfigRepository(runtime_checkable)` mirroring the existing
   `FederationProviderRepository` protocol method-for-method
   (read it first): `get_by_id`, `list(enabled_only)`, `create`,
   `update`, `delete`. Same docstring discipline.
2. `backend/authglow/repositories/file/saml_idp_config.py` —
   `FileSamlIdpConfigRepository(BaseFileRepository, SamlIdpConfigRepository)`,
   file `saml_idp_configs.json`, following
   `repositories/file/federation.py` as the template (Pydantic
   round-trip via `model_dump`/`model_validate` — never `.dict()`).
3. `backend/authglow/repositories/dependencies.py` —
   `get_saml_idp_config_repository(settings: Settings | None = None)`
   factory (the `settings=` bypass is mandatory — AGENTS.md
   "Lru_cache bypass pattern").
4. `backend/authglow/services/saml_provider.py` — `SamlProviderService`
   CRUD facade mirroring `services/federation_provider.py` exactly
   (same `named_lock(f"saml_provider:{id}")` placement, same docstring
   style, factory fallback when `provider_repository=None`).

## F0-07 — Conformance + repository tests

- `backend/tests/unit/repositories/test_protocols.py`: add the new
  impl to `_IMPL_TABLE` (one line — the parametrized conformance suite
  does the rest).
- `backend/tests/unit/repositories/file/test_saml_idp_config.py`:
  CRUD round-trip, PEM validation rejects garbage, https-only URL
  validator, defaults snapshot (name_id_format, trust_email=False,
  allow_unsolicited=False), update partial-field semantics.
- `backend/tests/unit/test_saml_certs.py`: generate → files exist →
  reload returns same fingerprint; RSA-2048 + 10y validity asserts;
  both roles independent; re-entry does not regenerate (fingerprint
  stable); private key never in the public response model
  (`SamlCertificateInfo` has no key field — assert at model level).

## F0-08 — Router scaffold

- `backend/authglow/api/saml.py` contains only the F0-04 endpoint and
  a module docstring stating the F1/F2 endpoints land there.
- `main.py` include + ensure `/api/admin/saml/...` requires the admin
  dependency (same as other admin routers — inspect `api/admin.py`
  header for the exact dependency name).

## F0-09 — ARCHITECTURE.md

Add a SAML section to the architecture notes: new modules, endpoints
table (F0 subset), decision-record pointer to `docs/saml/00-assessment.md`.
Keep the existing directory maps style.

## F0-10 — Verification commands

From `backend/`:

```bash
ruff check authglow/ && ruff format --check authglow/
mypy authglow/
pytest tests/unit/repositories tests/unit/test_saml_certs.py -q --tb=line
```

Full suite (optional here, mandatory before commit):

```bash
pytest -q --tb=line -n auto   # Bash tool timeout: 300000
```

## Out of scope (do not do in this phase)

- Any ACS/SSO/metadata endpoint, any login button, any frontend change.
- `SamlSpClient` model (Fase 2).
- Claim policy changes (Fase 2).
- Replay/request stores (Fase 1) — do not create them now.
- Certificate rotation endpoints (Fase 3).
