# Fase 2 — AuthGlow come Identity Provider SAML (SSO outbound per SP registrati)

> **Scopo (IT)**: applicazioni esterne (SP) possono registrarsi su
> AuthGlow e usare AuthGlow come Identity Provider SAML: registro SP
> admin, metadata IdP, endpoint `/saml/sso` che autentica l'utente
> (riusando la sessione AuthGlow come per `/oauth2/authorize`) e
> restituisce una Response firmata con Assertion, Attributi dalle
> claim policy esistenti. Nota critica di integrazione: il namespace
> `/saml/*` va sbloccato dal fallback SPA di `main.py`.
> **Prerequisito**: Fase 0 completata (certificato `idp`, settings,
> modelli infra). La Fase 1 è indipendente: si può sviluppare in
> parallelo, ma essa fornisce lo store di replay e gli helper XML che
> qui si riusano — se Fase 1 non è mergiata, replicare quei due
> componenti con la stessa specifica.

## Handoff contract (EN)

- Read `AGENTS.md`, `docs/saml/00-assessment.md` §3, §4, §6, §7, §10.
- Item IDs `F2-NN`. The issuer/audience/recipient triple and the
  signing defaults (DR-06) are non-negotiable.
- The IdP must never accept an ACS URL from the wire (T-17).

## Checklist

- [ ] F2-01 `SamlSpClient` models
- [ ] F2-02 Repository protocol + file impl + factory + conformance
- [ ] F2-03 Claim policy engine: `saml_attribute` target
- [ ] F2-04 IdP metadata endpoint
- [ ] F2-05 AuthnRequest validation
- [ ] F2-06 Response/Assertion building + signing
- [ ] F2-07 SSO endpoints + session flow + SPA fallback patch
- [ ] F2-08 Admin CRUD + claims API + `AdminSamlClientsPage`
- [ ] F2-09 Test matrix complete
- [ ] F2-10 ARCHITECTURE.md updated
- [ ] F2-11 Verification run clean

---

## F2-01 — `SamlSpClient` models

Add to `backend/authglow/models/saml.py`:

`SamlSpClient(BaseModel)`:

| Field | Type | Default | Validation |
|---|---|---|---|
| `id` | `str` | `uuid4()` | — |
| `client_name` | `str` | required | admin-facing label |
| `sp_entity_id` | `str` | required | unique across registry |
| `acs_url` | `str` | required | https, exact-match destination (T-17) |
| `slo_url` | `Optional[str]` | `None` | used in Fase 3 |
| `sp_signing_certificates` | `List[str]` | `[]` | PEM; required when `require_signed_requests` |
| `name_id_format` | `str` | persistent | enum: persistent, emailAddress |
| `sign_response` | `bool` | `True` | DR-06 |
| `sign_assertion` | `bool` | `True` | DR-06 |
| `require_signed_requests` | `bool` | `True` | T-16 |
| `allow_idp_initiated` | `bool` | `False` | unsolicited opt-in |
| `default_relay_state` | `Optional[str]` | `None` | ≤ 80 bytes, only used for IdP-initiated |
| `assertion_lifetime_seconds` | `int` | from settings | `ge=60, le=3600` |
| `authn_context_class_ref` | `Optional[str]` | `None` | fixed class override; otherwise session-derived |
| `enabled` | `bool` | `True` | — |
| `created_at` / `updated_at` / `created_by` | — | — | as F0-05 |

`SamlSpClientCreate` / `Update` / `Response` mirroring F0-05 style
(Response exposes `certificate_fingerprints`, not PEMs).

## F2-02 — Repository

- Protocol `SamlSpClientRepository` in `repositories/protocols.py`
  (same method set as F0-06 + `get_by_entity_id(sp_entity_id)`).
- `repositories/file/saml_sp_client.py` (`saml_sp_clients.json`),
  factory `get_saml_sp_client_repository(settings=)`.
- `_IMPL_TABLE` row + `tests/unit/repositories/file/test_saml_sp_client.py`
  (CRUD, unique entity id enforcement, PEM validation).

## F2-03 — Claim policy: `saml_attribute` target

`backend/authglow/models/claim_policy.py`:

- `ClaimTarget.SAML_ATTRIBUTE = "saml_attribute"` (docstring: values
  emitted in the SAML `AttributeStatement` of SP-client assertions).
- `ClaimRule` gains optional fields: `saml_attribute_name: Optional[str]`,
  `saml_attribute_friendly_name: Optional[str]`,
  `saml_name_format: Optional[Literal["basic", "uri", "unspecified"]]`
  (URIs: `urn:oasis:names:tc:SAML:2.0:attrname-format:{basic|uri|unspecified}`).
- Validator: `saml_attribute_name` **required** when
  `"saml_attribute" in include_in`; forbidden otherwise.
- Evaluation: locate the evaluator used by the existing token claim
  policies (inspect `services/oidc_claims.py` and the claim-policy
  service consumed by `api/claim_policy.py`) and extend it with the
  new target — one engine (DR-12), no parallel implementation.
- API: mirror the OAuth-client claim-policy endpoints under
  `/api/admin/saml-clients/{client_id}/claim-policy`
  (GET/PUT/DELETE) in the F2-08 admin router.
- Existing `SOURCE_OPTIONS` (user_field, rbac_roles, rbac_permissions,
  static, jwt_meta) all valid; `api_key_field` not applicable.

## F2-04 — IdP metadata endpoint

`SamlIdpService.build_idp_metadata() -> bytes` in
`services/saml_idp.py`; served at `GET /saml/metadata`
(public, rate-limited 30/min, `Cache-Control: no-cache, no-store`):

```xml
<EntityDescriptor entityID="{base_url}/saml/metadata">
  <IDPSSODescriptor WantAuthnRequestsSigned="true" protocolSupportEnumeration="…protocol">
    <KeyDescriptor use="signing"> … idp cert … </KeyDescriptor>
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <SingleSignOnService Binding="…HTTP-Redirect" Location="{base_url}/saml/sso"/>
    <SingleSignOnService Binding="…HTTP-POST"     Location="{base_url}/saml/sso"/>
    <Organization>…</Organization>
    <ContactPerson contactType="technical">…</ContactPerson>
  </IDPSSODescriptor>
</EntityDescriptor>
```

(`SingleLogoutService` entries are added in Fase 3.)

## F2-05 — AuthnRequest validation (IdP side)

`SamlIdpService.validate_authn_request(raw: bytes | redirect_params) ->
(SamlSpClient, request_id)`:

1. Both bindings accepted: POST (b64 XML) or Redirect (DEFLATE+b64 +
   optional query signature). Hardened parse via F1-01 helpers; root
   `{samlp}AuthnRequest`, `Version="2.0"`.
2. `assert_unique_ids` (S1); `IssueInstant` within skew (S5).
3. **Issuer** must match a registered, enabled `sp_entity_id` (T-16);
   no dynamic registration.
4. **Destination**, when present, must equal `{base_url}/saml/sso`.
5. **Signature**: if `require_signed_requests` (default true) → a
   valid signature over the AuthnRequest element is mandatory,
   verified with `sp_signing_certificates` only (allowlist sha256 /
   rsa-sha256, same mechanical rules as F1-07 step 6). Redirect-binding
   query signature verified per bindings §3.4.4.1 (F1-04 reverse).
6. **ACS**: the registered `acs_url` is the only destination used;
   `AssertionConsumerServiceURL`/`ProtocolBinding` attributes in the
   request, when present, must be **identical** to the registered
   values, otherwise reject (T-17 — never adopt from the wire).
7. **NameIDPolicy**: if present, its Format must be compatible with
   `sp_client.name_id_format` (persistent requested vs email-configured
   → reject with `InvalidNameIDPolicy`).
8. Request ID replay-checked against the F1-08 store (one-time use).

Error path: respond with a **signed** `{samlp}Response`
(Status `urn:oasis:...:status:Responder`, second-level code as
appropriate: `RequestNotSupported`, `InvalidNameIDPolicy`,
`RequestDenied`) delivered to the registered ACS via POST binding —
never a bare 4xx to the SP's browser when the SP expects a SAML
message. If the failure happens before the SP is identified, a plain
400 is acceptable. Audit `saml_idp_request_rejected`.

## F2-06 — Response/Assertion building + signing

`SamlIdpService.build_response(sp_client, user, session, request_id |
None, relay_state) -> (html_auto_form, saml_response_b64)`:

Structure (saml-core §2.3.3):

- `Response`: `ID`, `IssueInstant`, `Destination=acs_url`,
  `Issuer={base_url}/saml/metadata`, `Status=Success`.
- `Assertion`:
  - `Subject/NameID`: **pairwise persistent** value =
    `HMAC-SHA256(SECRET_KEY, f"saml-pnid|{sp_entity_id}|{user_id}")`
    base64url-truncated to 64 chars — stable per (user, SP), not
    linkable across SPs. When `name_id_format=emailAddress` → user
    email. Format URI set accordingly.
  - `SubjectConfirmation` Bearer + `SubjectConfirmationData`:
    `Recipient=acs_url`, `InResponseTo` (SP-initiated only),
    `NotOnOrAfter=now+assertion_lifetime_seconds`, `Audience` =
    `sp_entity_id` in `AudienceRestriction` inside `Conditions`
    (`NotBefore=now-skew`).
  - `AuthnStatement` `AuthnInstant` (session auth timestamp or now),
    `SessionIndex` = AuthGlow session ID (Fase 3 SLO depends on it),
    `AuthnContext/AuthnContextClassRef` = explicit override or
    session-derived: password-only →
    `urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport`;
    MFA step-up in session → `…:ac:classes:TimeSyncToken`.
  - `AttributeStatement`: evaluate the SP client's claim policy with
    the `saml_attribute` target (F2-03) → `<saml:Attribute
    Name=… NameFormat=… FriendlyName=…>` + `AttributeValue` elements
    (string values; lists → repeated AttributeValue).
- **Signing (DR-06)**: `sign_assertion` → enveloped signature on the
  Assertion; `sign_response` → enveloped signature on the Response
  (sign the Response **after** embedding the signed assertion).
  `signxml` with the idp cert + key, exclusive C14N, RSA-SHA256.
- Delivery: POST binding auto-submit form to `acs_url`, `SAMLResponse`
  + echoed `RelayState`. Inline-HTML CSP handling as in F1-04 note.
- If no user session exists at `/saml/sso` → 302 to the login UI with
  a return URL preserving the full SAML request context (mirror the
  `/oauth2/authorize` session-check mechanism — inspect
  `api/auth.py::authorize` and reuse its return/redirect plumbing).
- IdP-initiated: `GET /saml/sso` with no `SAMLRequest` param → allowed
  only when `allow_idp_initiated`; uses `default_relay_state`;
  `InResponseTo` omitted (profile-conformant unsolicited response).

## F2-07 — SSO endpoints + SPA fallback patch

- `GET/POST /saml/sso` in `api/saml.py` (rate-limited 30/min;
  `Cache-Control: no-cache, no-store`). GET without SAMLRequest →
  IdP-initiated path; POST/GET with SAMLRequest → F2-05 → F2-06.
- **CRITICAL `main.py` patch**: add `"saml"` to the backend-only
  namespaces tuple in `spa_fallback` (~line 269) — otherwise both
  endpoints return the SPA HTML shell. Add a regression test asserting
  `GET /saml/metadata` returns XML, not HTML (via TestClient).

## F2-08 — Admin CRUD + UI

Backend (`api/saml.py`):
- `/api/admin/saml/clients` CRUD (admin dependency; audit
  `saml_sp_client_created|updated|deleted`), toggle, and the
  `/{client_id}/claim-policy` endpoints from F2-03.

Frontend:
- `frontend/src/pages/admin/AdminSamlClientsPage.tsx`: registry table +
  create/edit form (entity id, ACS, SLO, certs paste → fingerprints,
  NameID format, flags, default relay state, lifetime) + "IdP metadata"
  copy/download link + per-client claims editor reusing the
  `TokenClaimsTab` interaction pattern with `saml_attribute` target
  (attribute Name/FriendlyName/NameFormat inputs).
- Route registration in the router config + `Sidebar` entry (follow
  `AdminOAuthClientsPage` wiring); `data-testid` everywhere; vitest
  unit test for the page (mock `useApiQuery`).

## F2-09 — Test matrix

Unit (`backend/tests/unit/`):

| File | Covers |
|---|---|
| `test_saml_idp_metadata.py` | F2-04 structure (entityID, two SSO bindings, WantAuthnRequestsSigned) |
| `test_saml_idp_request_validation.py` | F2-05: each rule (issuer unknown, destination mismatch, unsigned+required, bad ACS adoption attempt T-17, NameIDPolicy mismatch, replay) |
| `test_saml_idp_assertion.py` | F2-06: assertion shape, pairwise NameID stability + non-linkability, conditions window, attribute emission from policy, signing defaults, signature verifies with the idp public cert |
| `test_saml_claim_policy_saml_target.py` | F2-03: validation (name required), evaluation output |

Integration (`backend/tests/integration/`):

| File | Covers |
|---|---|
| `test_saml_idp_sso_flow.py` | full SP-initiated round trip: mock SP (in-repo helper) posts signed AuthnRequest → authenticated session → auto-form Response → assertion validates through an F1-style pipeline (reuse the validators as library code); IdP-initiated opt-in; unsigned-request rejection; error Response delivery to ACS |
| `test_saml_admin_clients.py` | CRUD authz + claims API |
| `test_saml_spa_fallback.py` | `/saml/*` not swallowed by the SPA shell |

Frontend: vitest for `AdminSamlClientsPage` (render, form validation,
claims tab interaction).

Must stay green: `tests/unit/repositories/`,
`tests/unit/test_claim_policy*` (or the claim-policy test files that
exist), `tests/integration/test_saml_sso_flow.py` from Fase 1, OIDC
claim policy tests (the engine extension must not change existing
targets' behavior).

## F2-10 — ARCHITECTURE.md

IdP role section: endpoints, registry, claim policy extension,
SPA-fallback note.

## F2-11 — Verification commands

```bash
# from backend/
ruff check authglow/ && ruff format --check authglow/
mypy authglow/
pytest tests/unit/test_saml_idp_metadata.py tests/unit/test_saml_idp_request_validation.py \
       tests/unit/test_saml_idp_assertion.py tests/unit/test_saml_claim_policy_saml_target.py \
       tests/unit/repositories -q --tb=line
pytest tests/integration/test_saml_idp_sso_flow.py tests/integration/test_saml_admin_clients.py \
       tests/integration/test_saml_spa_fallback.py -q --tb=line
```

Full suite before commit: `pytest -q --tb=line -n auto` (timeout
300000). Frontend: `npm run lint` + `npm test` + `npm run build`.

## Out of scope (do not do in this phase)

- SLO endpoints (`/saml/slo`, `/api/federation/saml/slo/...`) — Fase 3.
- `EncryptedAssertion` / encryption KeyDescriptor — Fase 3.
- SLO fan-out registry — non-goal (DR-11).
- Metadata fetch from URL — Fase 3.
- Consent UI for SAML logins (SP clients are admin-trusted by design;
  if ever needed it is a separate feature).
