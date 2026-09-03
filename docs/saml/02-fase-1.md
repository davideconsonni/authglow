# Fase 1 — AuthGlow come Service Provider SAML (login via IdP esterni)

> **Scopo (IT)**: un admin configura un IdP SAML esterno (incollando il
> suo metadata); l'utente clicca il bottone in login, AuthGlow invia
> l'AuthnRequest firmata, l'IdP risponde, la pipeline ACS valida
> tutto con le contromisure di sicurezza ratificate, e l'utente entra
> con lo stesso comportamento del flusso OIDC esistente (linking,
> JIT, bridge OAuth2). È la fase più corposa del piano.
> **Prerequisito**: Fase 0 completata e verificata.

## Handoff contract (EN)

- Read `AGENTS.md`, `docs/saml/00-assessment.md` §3 (S1–S13), §4, §6, §7, §10 first.
- Item IDs `F1-NN`. The validation pipeline order (F1-07) is
  **normative**: reordering steps weakens security; do not reorder.
- The XSW corpus (F1-13) is written to be failed by wrong code. If a
  vector passes when it should fail, fix the pipeline, never the
  fixture outcome.

## Checklist

- [ ] F1-01 Hardened XML utilities (`core/saml_xml.py`)
- [ ] F1-02 SP metadata generation
- [ ] F1-03 IdP metadata parsing + admin parse endpoint
- [ ] F1-04 AuthnRequest building + both bindings
- [ ] F1-05 `SamlRequestStore`
- [ ] F1-06 Login endpoint
- [ ] F1-07 ACS validation pipeline
- [ ] F1-08 Replay store
- [ ] F1-09 Shared finalize helper + account linking
- [ ] F1-10 ACS endpoint + middleware integration
- [ ] F1-11 Merged provider list + login buttons
- [ ] F1-12 Admin CRUD + admin UI for SAML providers
- [ ] F1-13 Golden fixtures (XSW corpus + valid vectors)
- [ ] F1-14 Test matrix complete
- [ ] F1-15 ARCHITECTURE.md updated
- [ ] F1-16 Verification run clean

---

## F1-01 — Hardened XML utilities

New `backend/authglow/core/saml_xml.py`:

```python
HARDENED_PARSER = lxml.etree.XMLParser(
    resolve_entities=False, no_network=True, load_dtd=False,
    dtd_validation=False, huge_tree=False, remove_pis=True,
)

def parse_saml(data: bytes) -> lxml.etree._Element: ...
def find_ids(root) -> list[str]          # all ID-ish attributes (ID/xml:id) doc-wide
def assert_unique_ids(root) -> None      # S1: NCName regex + doc-wide uniqueness
def element_to_xml_bytes(elem) -> bytes  # canonical-ish serialization for logging (truncate)
def find_child_by_localname(elem, name, ns) -> Optional[...]
```

Rules:
- Exactly one parse entry point for all SAML messages (S11). Nothing
  else in the codebase may call lxml parse directly for SAML.
- Reject: entity references, DOCTYPE, processing instructions with
  inline DTD, documents > `MAX_SAML_XML_BYTES` (256 KB constant).
- `assert_unique_ids` enforces `^[A-Za-z_.][A-Za-z0-9_.\-]*$`
  (T-01/SamQuote) and rejects duplicate IDs (XSW prerequisite).

## F1-02 — SP metadata generation

`SamlSpService.build_sp_metadata(providerless) -> bytes` in
`backend/authglow/services/saml_sp.py`:

```xml
<EntityDescriptor entityID="{SP_ENTITY_ID}" xmlns="urn:oasis:names:tc:SAML:2.0:metadata">
  <SPSSODescriptor AuthnRequestsSigned="true" WantAssertionsSigned="true"
                   protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>{b64 DER}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </KeyDescriptor>
    <!-- NO encryption KeyDescriptor (DR-04) -->
    <NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</NameIDFormat>
    <NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</NameIDFormat>
    <AssertionConsumerService index="0" isDefault="true"
      Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="{base_url}/api/federation/saml/acs/{provider_id}"/>
    <Organization>… from settings …</Organization>
    <ContactPerson contactType="technical">… from settings …</ContactPerson>
  </SPSSODescriptor>
</EntityDescriptor>
```

- `SP_ENTITY_ID = f"{base_url}/saml/sp/metadata"` (DR-09), no
  provider_id inside the entity ID; only the ACS carries provider_id.
- Metadata served per provider_id (ACS location differs). ValidUntil =
  now + 7 days; regenerate on every request (cheap, no caching needed).
- Sign the metadata? Not required by interop profile; skip (note it in
  the docstring).

## F1-03 — IdP metadata parsing + admin endpoint

`SamlSpService.parse_idp_metadata(xml: bytes) -> ParsedIdpMetadata`
(dataclass: `entity_id`, `sso_redirect_url`, `sso_post_url`,
`slo_url`, `signing_certificates: List[str]`, `name_id_formats`).

- Parse with `parse_saml` (F1-01), namespace-aware only; never
  string-search XML.
- Extract from `IDPSSODescriptor`: `SingleSignOnService` locations for
  Redirect and POST bindings (missing both → error), optional
  `SingleLogoutService` (store for F3), all `KeyDescriptor use="signing"`
  certs (dedupe by fingerprint), `NameIDFormat` list.
- Certificates stored as PEM strings; validate parseability.
- Admin endpoint `POST /api/federation/admin/saml/parse-metadata`
  (admin dependency, rate-limited 10/min, body cap 256 KB): returns
  parsed fields for form prefill. **No URL fetch in this phase** (DR-08).

## F1-04 — AuthnRequest + bindings

`SamlSpService.build_authn_request(provider, request_id, acs_url) -> bytes`
— template (see saml-core §3.4.1), attributes: `ID=request_id`,
`Version="2.0"`, `IssueInstant` = `utcnow()` formatted
`YYYY-MM-DDTHH:MM:SSZ`, `Destination` = provider's SSO URL,
`AssertionConsumerServiceURL` = ACS, `ProtocolBinding` = HTTP-POST;
children: `Issuer` = SP entity ID; `NameIDPolicy`
`Format={provider.name_id_format}` `AllowCreate="true"`;
`RequestedAuthnContext` only when configured
(`Comparison="minimum"`, class refs as elements).

Bindings (in `services/saml_sp.py`, one function per binding):

1. **HTTP-Redirect (default for requests)**: raw DEFLATE
   (`zlib.compressobj(wbits=-15)`) → base64 → percent-encode →
   `SAMLRequest=` param; `RelayState=request_id` (≤ 80 bytes, S10);
   when `provider.sign_requests` (default True, DR-06): `SigAlg` fixed
   to `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256`; signature =
   RSA PKCS1v15/SHA-256 (`cryptography`) over the byte string
   `SAMLRequest={urlenc}&RelayState={urlenc}&SigAlg={urlenc}`
   (omit `RelayState` segment if absent — spec §3.4.4.1); `Signature`
   param = base64. Return the full redirect URL.
2. **HTTP-POST**: base64 (no deflate) of the XML → auto-submit HTML
   form (`<input type="hidden" name="SAMLRequest">` + RelayState +
   `document.forms[0].submit()`), `<noscript>` fallback button.
   **CSP check**: inspect `middleware/security_headers.py` — if
   `form-action` is restrictive, either allowlist IdP destinations via
   a per-response CSP header override or keep POST binding secondary;
   Redirect binding is the default and avoids the issue.

## F1-05 — `SamlRequestStore`

`backend/authglow/repositories/file/saml_request_store.py` +
`SamlRequestStore` protocol in `protocols.py` +
factory `get_saml_request_store_repository(settings=)`.

- Backing file `saml_requests.json`; in-memory dict hydrated at
  startup (`startup_hydrate()` called in `main.py` lifespan next to
  `token_blacklist().startup_hydrate()`).
- API: `put(request_id, entry)`, `pop(request_id) -> Optional[entry]`
  (single-use: delete on read), `sweep_expired(now)`.
- Entry: `{"provider_id": str, "redirect_uri": str,
  "oauth2_context": dict | None, "created_at": iso}`.
- Concurrency: `named_lock("saml_requests")` around mutations (repo
  pattern per AGENTS.md).
- TTL from `settings.saml_request_ttl_seconds`; expired entries never
  returned.
- Security rationale (docstring): the browser carries only the opaque
  request id (T-08); the store is server-authoritative; single-use
  pop enforces AuthnRequest anti-replay.

## F1-06 — Login endpoint

`GET /api/federation/saml/login/{provider_id}` in `api/saml.py`
(`@limiter.limit("5/minute")`, `request: Request` first param — same
as `api/federation.py::federation_login`, read it and mirror the
query-param contract: `redirect_uri`, `client_id`,
`oauth_redirect_uri`, `scope`, `app_state`, `code_challenge`,
`code_challenge_method`, `response_type`):

1. Load provider (enabled only) → 404 generic otherwise (T-20).
2. OAuth2 context captured exactly as the OIDC flow does (validate
   `oauth_redirect_uri` against the client's registered redirect URIs
   — mirror the existing check in `federation_login`; do not weaken it).
3. `request_id = str(uuid4())`; store entry via F1-05.
4. Build AuthnRequest, bind via Redirect (or POST if the provider only
   advertises POST); 302 or HTML auto-form response.
5. Audit event `saml_login_initiated` (provider_id, hashed request id).

## F1-07 — ACS validation pipeline (the core)

`SamlSpService.consume_response(provider, saml_response_b64,
relay_state, expected_request: Optional[store_entry]) -> SamlAssertions`
in `services/saml_sp.py`. **Ordered, fail-closed** (each step's failure
→ `SamlValidationError` with a machine reason; HTTP 400 generic):

1. b64 strict decode (reject whitespace/malformed); size cap.
2. `parse_saml` → root must be `{samlp}Response`, `Version="2.0"`.
3. `assert_unique_ids` (S1).
4. `Status/StatusCode` == `urn:oasis:names:tc:SAML:2.0:status:Success`
   (top-level only; authn failures come as `Responder`+sub-status →
   map to generic 401-style error, audit reason).
5. `Destination` attribute, when present, must equal our ACS URL exactly.
6. **Signature verification (S2–S4, T-01, T-10, T-11)**:
   - Collect signatures. Allowed: signature on the Response, and/or on
     a single Assertion. Anything else (signature on a second
     assertion, on SubjectConfirmationData, multiple signatures on one
     element) → reject.
   - Enforce S3 mechanically: single `ds:Reference`, `URI="#<ID>"`,
     target ID == the ID of the element the signature is a direct
     child of, digest ∈ {sha256}, sig method ∈ {rsa-sha256}.
   - Verify with `signxml` (`verify(require_x509=False,
     x509_cert=<pinned provider cert>)`, `expect_references=1`,
     `expect_digest_algorithm`/`expect_signature_algorithm` per
     allowlist) against **only** `provider.idp_signing_certificates`
     (T-11). Try each pinned cert; all must fail before rejecting.
   - If Response signed: the Assertion used MUST be located by
     traversal from the *verified* Response element; reject if the
     document contains any Assertion outside that subtree (S2).
   - If only the Assertion signed: it must be the single direct
     Assertion child of the Response.
   - Honor `require_signed_assertion` / `require_signed_response`
     strict flags (DR-05).
7. **Replay (T-02)**: Response ID and Assertion ID checked against the
   replay store (F1-08) — reject duplicates; record consumed IDs with
   TTL = assertion `NotOnOrAfter` (+ skew) after all checks pass.
8. **Timing (S5, T-04)**: `IssueInstant` ≤ now+skew; Conditions
   `NotBefore` ≤ now+skew and `NotOnOrAfter` > now−skew; missing
   Conditions → reject (spec allows omission, we require it — record
   as deliberate strictness).
9. **Audience (S6, T-05)**: some `AudienceRestriction` contains the
   exact SP entity ID; absent → reject.
10. **SubjectConfirmation (S7/S8, T-06/T-07)**: Method == Bearer;
    `SubjectConfirmationData` required: `InResponseTo` ==
    `expected_request.request_id` (from F1-05 pop) — if absent:
    reject unless `provider.allow_unsolicited` (then the login
    proceeds with the provider default landing); `Recipient` == our
    ACS URL exactly; `NotOnOrAfter` > now−skew.
11. **NameID (S9, T-15)**: non-empty; `Format` in provider-allowed
    set; `transient` → reject with dedicated reason
    `saml_nameid_transient`.
12. **Attributes**: collect `AttributeStatement` attributes
    (namespace-aware; duplicate attribute names with conflicting
    values → reject; case-insensitive lookup per F0-05 note).
13. Return a normalized dict: `name_id`, `name_id_format`,
    `attributes` (lowercased keys), `session_index` (from
    AuthnStatement, if present), `assertion_id`, `in_response_to`.

Audit event per outcome: `saml_response_accepted` /
`saml_response_rejected` (reason, provider_id, subject fingerprint —
mask PII per `audit_email_log_level`).

## F1-08 — Replay store

`backend/authglow/repositories/file/saml_replay.py` (+ protocol +
factory): same shape as F1-05 but keyed by message ID with
`put(id, expires_at)` / `contains(id)`; backing file
`saml_replay.json`; opportunistic sweep on access; `named_lock("saml_replay")`.
Docstring: multi-worker safety is the reason a plain TTLCache is not used.

## F1-09 — Shared finalize helper + linking

- Extract the post-authentication portion of
  `api/federation.py::federation_callback` (lines ~231–324: claim
  mapping, external-id lookup, VAPT-035 auto-link, JIT create, cookie
  issuance / OAuth2 bridge) into
  `backend/authglow/services/federation_finalize.py` as
  `async def finalize_federated_login(user_storage, provider_id,
  external_id, claims, provider_trusts_email: bool, redirect_uri,
  oauth2_context) -> Response`.
- Refactor the OIDC callback to call it — **existing integration tests
  (`tests/integration/test_federation.py`,
  `test_federation_oauth2_callback.py`) must stay green unmodified**;
  if they need changes, stop and re-read the extraction (you probably
  changed behavior).
- SAML calls it with `provider_trusts_email=provider.trust_email`
  (DR-14), `external_id=NameID value` — the FederatedIdentity key
  becomes `saml_provider_id|NameID` via the existing
  `link_federated_identity`.
- Audit: `saml_user_linked`, `saml_user_created`.

## F1-10 — ACS endpoint + middleware integration

`POST /api/federation/saml/acs/{provider_id}` in `api/saml.py`
(`@limiter.limit("30/minute")`, consumes `SAMLResponse` + `RelayState`
form fields):

1. `pop` the request entry by `RelayState` (missing/expired → 400
   generic); unsolicited path only if `provider.allow_unsolicited`.
2. Run the F1-07 pipeline.
3. `finalize_federated_login(...)` → same response contract as the
   OIDC callback (cookies / JSON / OAuth2 bridge redirect).
4. Response headers: `Cache-Control: no-cache, no-store` (S12).

Middleware checks (read each middleware first, then wire):
- `middleware/csrf.py`: verify whether form-POST exemptions exist
  (e.g. for `/oauth2/token`); add the ACS (and F3 SLO) paths to the
  same exemption list — the request's authenticity comes from the
  validated SAML signature, not a browser CSRF token.
- `middleware/request_body_size.py`: confirm the default body cap
  admits ≥ 64 KB form bodies for the ACS path (typical signed
  response ≈ 10–30 KB); bump only if needed, with a test.
- `middleware/security_headers.py`: ACS returns no HTML (JSON/redirect);
  the POST-binding auto-form (F1-04 step 2) is the only inline-HTML
  case — resolve CSP per its note.

## F1-11 — Merged provider list + login buttons

- Extend the public providers listing (`api/federation.py`,
  `list_public_providers`): merge enabled SAML providers, each item
  gains `protocol: "oidc"|"saml"` and `login_path` (server-computed
  full path: `/api/federation/login/{id}` vs
  `/api/federation/saml/login/{id}`); keep response backwards-compatible
  (old fields retained).
- `frontend/src/components/auth/FederationLoginButtons.tsx`: use
  `login_path` from the response instead of building the URL by
  convention; keep the oauth2 context query forwarding (mirror the
  existing param list). No visual changes.

## F1-12 — Admin CRUD + admin UI

Backend:
- `api/saml.py`: `/api/federation/admin/saml-providers` CRUD
  (list/create/update/toggle/delete) mirroring the OIDC admin routes in
  `api/federation.py` (same dependency, same audit events
  `saml_provider_created|updated|deleted`, same toggle semantics).
- Wire `SamlProviderService` (F0-06 item 4).

Frontend (`AdminFederationPage.tsx`):
- Protocol column + tabbed form ("OIDC" | "SAML").
- SAML form: "Paste IdP metadata XML" textarea → Parse button →
  `POST /api/federation/admin/saml/parse-metadata` → prefill fields
  (entity id, SSO URLs, SLO URL, cert fingerprints, NameID formats);
  manual override fields for everything; checkboxes for
  `trust_email`, `allow_unsolicited`, `require_signed_assertion`,
  `require_signed_response`; `requested_authn_context` JSON textarea
  with validation; SP metadata URL displayed with copy button.
- `data-testid` on all new controls (E2E in Fase 3 depends on it).
- Vitest unit test for the new form section (mirror
  `AdminJwkKeysPage.test.tsx` style).

## F1-13 — Golden fixtures

Directory `backend/tests/fixtures/saml/`:

```
valid/response_signed_assertion.xml.b64     # Okta-style: only Assertion signed
valid/response_signed_response.xml.b64      # ADFS-style: only Response signed
valid/response_signed_both.xml.b64
attacks/xsw01_unsigned_assertion_spliced.xml.b64
attacks/xsw02_wrapper_assertion.xml.b64
attacks/xsw03_cloned_signature_new_id.xml.b64
attacks/xsw04_signature_relocated.xml.b64
attacks/xsw05_duplicate_id.xml.b64
attacks/xsw06_comment_in_id.xml.b64         # SamQuote
attacks/xsw07_extra_assertion_outside.xml.b64
attacks/xsw08_sha1_downgrade.xml.b64
meta.json   # {filename: {expected: "accept"|"reject", reason: "..."}}
```

- One-time generation script `backend/scripts/generate_saml_golden_fixtures.py`
  using the **xmlsec1 CLI** (document its local install in the script
  docstring; it is NOT a runtime or CI dependency — fixtures are
  committed). Test IdP cert/key pair committed alongside
  (`fixtures/saml/test_idp.{crt,key}` — dedicated test material;
  add a path-allowlist entry in `.gitguardian.yaml` with a safety
  comment, per AGENTS.md Secret Management).
- Each fixture signed against a fixed SP entity ID, ACS, audience, and
  near-fixed timestamps (validity window must be long enough: use
  2026–2036 dates, and the tests must freeze time — see F1-14).
- `valid/*` must be accepted by the pipeline given the matching
  pinned cert; every `attacks/*` must be rejected with the recorded
  reason.

## F1-14 — Test matrix

Unit (`backend/tests/unit/`):

| File | Covers |
|---|---|
| `test_saml_xml.py` | F1-01: hardened parser rejects entities/doctype/huge; NCName; uniqueness |
| `test_saml_metadata.py` | F1-02/F1-03: SP metadata structure (KeyDescriptor, ACS, no encryption descriptor); IdP parse happy + malformed |
| `test_saml_authn_request.py` | F1-04: XML shape, Redirect signature string per §3.4.4.1 (verify with `cryptography` public key), DEFLATE raw, RelayState ≤ 80 |
| `test_saml_request_store.py` | F1-05: TTL, single-use pop, persistence round-trip, lock |
| `test_saml_replay.py` | F1-08: duplicate rejection, TTL expiry |
| `test_saml_acs_validation.py` | F1-07: every pipeline step individually (status, destination, timing with frozen clock, audience, InResponseTo, Recipient, NameID formats incl. transient reject, EncryptedAssertion → 400) |
| `test_saml_xsw_corpus.py` | F1-13: parametrized over fixtures + `meta.json` expected outcomes; clock frozen via monkeypatched `utcnow` |
| `test_saml_linking.py` | F1-09: trust_email=True links by email; False → 403 message; JIT creates; transient never links |

Integration (`backend/tests/integration/`):

| File | Covers |
|---|---|
| `test_saml_sso_flow.py` | end-to-end with in-repo mock IdP (`tests/helpers/saml_mock_idp.py`, signxml-based, functional only per DR-10): login endpoint → 302 → POST ACS → cookies set; oauth2 bridge variant; unsolicited opt-in variant; disabled provider variant |
| `test_saml_providers_api.py` | admin CRUD + parse-metadata endpoint (authz: non-admin 403) |
| `test_federation_providers_merge.py` | F1-11 merged list contract |

Frontend (`frontend/src/...`): vitest for the SAML admin form section.

Must stay green (regression boundary): all of
`tests/integration/test_federation.py`,
`tests/integration/test_federation_oauth2_callback.py`,
`tests/unit/test_federation_verify_id_token.py`,
`tests/unit/repositories/`, plus any test file you touch for the F1-09
extraction.

## F1-15 — ARCHITECTURE.md

Update the SAML section: SP endpoints, stores, finalize helper, admin
routes, fixtures layout.

## F1-16 — Verification commands

From `backend/`:

```bash
ruff check authglow/ && ruff format --check authglow/
mypy authglow/
pytest tests/unit/test_saml_xml.py tests/unit/test_saml_metadata.py \
       tests/unit/test_saml_authn_request.py tests/unit/test_saml_request_store.py \
       tests/unit/test_saml_replay.py tests/unit/test_saml_acs_validation.py \
       tests/unit/test_saml_xsw_corpus.py tests/unit/test_saml_linking.py \
       tests/unit/repositories -q --tb=line
pytest tests/integration/test_saml_sso_flow.py tests/integration/test_saml_providers_api.py \
       tests/integration/test_federation.py tests/integration/test_federation_oauth2_callback.py \
       -q --tb=line
```

Full suite before commit: `pytest -q --tb=line -n auto` (Bash tool
timeout: 300000). Frontend: `npm test` (SAML form file) + `npm run lint`.

## Out of scope (do not do in this phase)

- Any IdP-role endpoint (`/saml/metadata`, `/saml/sso`) or the
  `SamlSpClient` model — Fase 2.
- SLO of any kind — Fase 3.
- Decryption of `EncryptedAssertion` — Fase 3 (must 400, tested).
- Metadata URL fetch — Fase 3 (parse endpoint accepts XML bodies only).
- Certificate rotation endpoints — Fase 3.
- Changes to OIDC behavior beyond the F1-09 extraction (any green test
  turning red is a stop condition).
