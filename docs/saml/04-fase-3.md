# Fase 3 — SLO, assertion cifrate, hardening, interop, E2E

> **Scopo (IT)**: chiudere il supporto SAML: Single Logout per-SP
> (front-channel, entrambi i ruoli), decifratura delle
> `EncryptedAssertion` (XML-Enc custom su lxml+cryptography), fetch
> dei metadata da URL con guardie SSRF, rotazione certificati con
> finestra di overlap, E2E Playwright e checklist di interoperabilità
> contro IdP/SP reali.
> **Prerequisito**: Fasi 0, 1, 2 completate e verificate.

## Handoff contract (EN)

- Read `AGENTS.md`, `docs/saml/00-assessment.md` §3, §4, §6, §7, §10.
- Item IDs `F3-NN`. SLO is per-SP only (DR-11): if you find yourself
  building a session-participant registry, stop — it is a non-goal.
- Encryption never substitutes signature validation (normative order
  in F3-03).

## Checklist

- [ ] F3-01 SP role: consume LogoutRequest, emit LogoutRequest
- [ ] F3-02 IdP role: `/saml/slo`
- [ ] F3-03 XML-Enc decryption + encryption KeyDescriptor
- [ ] F3-04 Metadata URL fetch with SSRF guard
- [ ] F3-05 Certificate rotation (dual KeyDescriptor overlap)
- [ ] F3-06 E2E Playwright suite
- [ ] F3-07 Interop checklist executed and documented
- [ ] F3-08 Performance offload + benchmark
- [ ] F3-09 Docs (FEATURES.md, user guide, ARCHITECTURE.md)
- [ ] F3-10 Verification run clean

---

## F3-01 — SP role SLO

New `backend/authglow/services/saml_slo.py` + endpoints in `api/saml.py`
(`Cache-Control: no-cache, no-store` everywhere).

**Inbound** — `GET/POST /api/federation/saml/slo/{provider_id}` (the
IdP sends a LogoutRequest; rate-limited 30/min):

1. Parse (Redirect/POST bindings) with F1-01 helpers; root
   `{samlp}LogoutRequest`, `Version="2.0"`.
2. Signature **mandatory**, verified against
   `provider.idp_signing_certificates` (same mechanical rules as
   F1-07 step 6). Issuer == `idp_entity_id`. `IssueInstant` within
   skew; request ID replay-checked (F1-08 store).
3. Identify the local session: `SessionIndex` (== AuthGlow session ID
   per F2-06) or `NameID` == the federated identity's NameID of the
   current session cookie. Destroy the AuthGlow session via the
   session service (inspect `services/session.py`; mirror what
   `/api/auth/logout` does).
4. Respond with a **signed** `LogoutResponse`
   (`InResponseTo` = the LogoutRequest ID, `Status` Success) to
   `idp_slo_url` via Redirect binding (signed query string,
   F1-04-reverse). If `idp_slo_url` is not configured, still destroy
   the session and return 200 with a generic body.

**Outbound** — user-initiated logout for a session established via
SAML provider with `idp_slo_url` configured: build a signed
`LogoutRequest` (`ID`, `IssueInstant`, `Issuer` = SP entity ID,
`NameID`+`Format`, `SessionIndex`, optional `NotOnOrAfter` +
`Reason=urn:oasis:names:tc:SAML:2.0:logout:user`) → Redirect binding
→ 302 to the IdP; then validate the coming `LogoutResponse`
(`InResponseTo` match via the request store, `Status` Success).
Wire this into the logout flow behind a check
"current session was created by provider X" (session metadata — add
`auth_provider`/`session_index` fields to the session record if
absent; inspect `models/session.py`).

## F3-02 — IdP role SLO

`GET/POST /saml/slo` in `api/saml.py`:

1. LogoutRequest from a registered SP: signature verified with
   `sp_signing_certificates`; Issuer registered; `SessionIndex` ==
   AuthGlow session ID → destroy it; unknown/expired session → still
   respond Success (idempotent semantics, profile §4.4.4).
2. Signed `LogoutResponse` to `sp_client.slo_url` via POST or
   Redirect binding with `InResponseTo`.
3. No fan-out: only the requesting SP's session is destroyed (DR-11).

## F3-03 — XML-Enc decryption

- Extend `core/saml_certs.py` with role `sp_encryption`
  (`saml_sp_encryption.key/.crt`) — generated together with the
  others when `saml_enabled`.
- New `backend/authglow/core/saml_xenc.py`:

```python
def decrypt_encrypted_assertion(
    encrypted_assertion_elem, key_pair: SamlCertificate,
) -> lxml.etree._Element:  # the inner <saml:Assertion>
```

Support matrix (xenc):
- `EncryptedKey` EncryptionMethod: `rsa-oaep-mgf1p` (DigestMethod
  sha1 or sha256) **and** `rsa-1_5` (legacy but widespread; implement
  with the standard Bleichenbacher countermeasures — constant-time
  behavior and randomized dummy decryption on failure; note in
  docstring). `rsa-oaep` with MGF1-SHA256 (xenc11) supported as well.
- `EncryptedData`: `aes128-cbc`, `aes256-cbc` (CBC padding per xenc =
  ISO/IEC 10126: strip last byte length — do **not** use PKCS#7).
  `aes128-gcm`/`aes256-gcm` (xenc11) supported.
- Key resolution: inline `EncryptedKey` inside `EncryptedData/KeyInfo`
  or sibling via `RetrievalMethod`; one level of indirection is
  enough for interop.
- Output is *not trusted*: the decrypted Assertion is fed into the
  F1-07 pipeline **from step 6 (signature verification) onward** —
  the IdP is expected to sign the assertion inside the encryption
  envelope. An encrypted-but-unsigned assertion is accepted only if
  the *Response* itself is signed (DR-05 semantics preserved).

Pipeline integration: in `consume_response` (F1-07), before step 6,
replace each `EncryptedAssertion` child with its decrypted Assertion
(max 1, per S2). Metadata: `build_sp_metadata` (F1-02) gains
`<KeyDescriptor use="encryption">` with the encryption cert.

- Golden encrypted fixtures: extend the F1-13 generation script with
  `xmlsec1 --encrypt` cases (OAEP+AES-256-CBC, RSA1_5+AES-128-CBC,
  GCM) → `backend/tests/fixtures/saml/encrypted/*.xml.b64` +
  `meta.json` entries (expected: decrypt-then-validate outcomes,
  including "encrypted but unsigned assertion + unsigned response →
  reject").
- Unit tests `tests/unit/test_saml_xenc.py`: each algorithm combo,
  wrong-key rejection (generic error), tampered ciphertext rejection,
  the normative order above.

## F3-04 — Metadata URL fetch with SSRF guard

New `backend/authglow/core/ssrf.py`:

```python
async def fetch_public_xml(url: str) -> bytes:
    """SSRF-guarded fetch of IdP metadata. Blocks non-global targets."""
```

Controls (minimum bar, all mandatory):
- Scheme https only; hostname resolution via `asyncio.getaddrinfo` →
  every resolved IP must be global unicast (`ipaddress.is_global`) —
  block private, loopback, link-local, CGNAT, multicast, reserved.
- No redirects (`follow_redirects=False`); 10s timeout; 1 MB body cap;
  content-type must start with `application/xml` or `text/xml`.
- Endpoint `POST /api/federation/admin/saml/parse-metadata` extended:
  accepts either `metadata_xml` (Fase 1 behavior) or `metadata_url`
  → fetch → parse (F1-03). Admin-only + rate-limited 10/min.
- **Recommended (do it if the effort is bounded)**: pin the connection
  to the first resolved IP with a custom `httpx.AsyncHTTPTransport`
  (SNI/hostname preserved for TLS validation) to close the
  DNS-rebinding window between check and connect. If skipped, document
  the residual risk in the module docstring and in this file's status
  notes — the decision must be visible.
- Metadata validity: honor `ValidUntil`/`cacheDuration` on subsequent
  re-fetches (admin re-fetch action only; no background refetching).

## F3-05 — Certificate rotation

- `core/saml_certs.py` gains a manifest `saml_cert_manifest.json` in
  `keys_dir`: `{role: {current: {fingerprint, not_after},
  previous: {…} | None}}`.
- `POST /api/admin/saml/certificates/{role}/rotate` (admin, audit
  `saml_cert_rotated`): generate new pair → current becomes previous
  (both key files retained with suffixes) → manifest updated.
- Metadata emission (F1-02 SP / F2-04 IdP): **both** certs as
  KeyDescriptors, current first (overlap window per DR-07).
- IdP-role verification (F2-05) automatically accepts signatures from
  either cert (both are in the trusted set). SP-role verification
  depends on partner-pinned certs — the UI (extend the F0-04
  inventory view with a "Rotate" button + fingerprints/dates display,
  placed in the SAML admin area) must instruct the admin to send the
  new cert to partners and remove the old one after migration via
  `DELETE /api/admin/saml/certificates/{role}/previous`.
- Tests: rotation keeps verification working with old-signed fixtures
  (reuse F1-13 valid vectors signed by the pre-rotation cert), removal
  of previous drops acceptance, manifest persistence.

## F3-06 — E2E Playwright

- `e2e/support/mock_idp_server.py` — minimal FastAPI micro-app
  (uvicorn) serving: `GET /sso` → signed AuthnRequest-consumer that
  always returns an auto-submit POST form with a **freshly signed**
  `SAMLResponse` (signxml + committed test cert from F1-13; functional
  signing is allowed for the mock, DR-10). Launched via
  `playwright.config.ts` extra `webServer` entry (serial, `workers: 1`,
  chromium + mobile projects per repo config).
- Insecure-URL allowance for tests: add setting
  `saml_allow_insecure_idp_urls: bool = False`; the F0-05 https
  validators check it (test env sets it True). Runtime default stays
  https-only; add a unit test proving the default rejects http.
- `e2e/flows/saml-login.spec.ts`:
  1. Admin configures a SAML provider via `AdminFederationPage`
     (paste metadata served by the mock IdP `GET /metadata`).
  2. Logout → login page shows the SAML button (`data-testid` from
     F1-12) → click → mock IdP auto-POST → dashboard visible.
  3. Second login with same NameID → same user (linking stable).
  4. Unsolicited attempt on a provider without opt-in → generic error.
- Mobile project: same happy path on the mobile viewport.

## F3-07 — Interop checklist (execute + document)

Create `docs/saml/interop-checklist.md`; run each row against a real
peer, record evidence (screenshot/log excerpt) and any code fix in a
table. Peers: SimpleSAMLphp (Docker, both roles), Okta developer org
(IdP), Entra ID (IdP), Shibboleth SP if reachable.

| Check | Expected |
|---|---|
| Redirect-binding AuthnRequest accepted | login completes |
| POST-binding AuthnRequest accepted | login completes |
| Signed AuthnRequest verified by IdP | per IdP logs |
| Assertion signed Response-only / Assertion-only / both | all accepted (DR-05) |
| Timestamps with fractional seconds | tolerated |
| zlib-wrapped DEFLATE on inbound Redirect messages | tolerated |
| Multiple signing certs in IdP metadata | all pinned, any verifies |
| RelayState round-trip ≥ 60 bytes | preserved |
| Error Response (wrong audience) delivered as SAML message | conformant Status codes |
| SLO round trip (F3-01/02) | session destroyed both sides |

Known-quirks table (add rows as discovered): SHA256 URI variants,
`xsi:type` on AttributeValue, empty `NameQualifier/SPNameQualifier`,
extra whitespace in base64, IdP-specific RelayState casing.

## F3-08 — Performance

- Wrap CPU-bound SAML operations (DEFLATE, sign, verify, xenc
  decrypt) in `asyncio.to_thread` at the service boundary (repo
  pattern: `core/async_io.py` usage examples).
- `tests/performance/test_saml_pipeline_perf.py`: 100 sequential ACS
  validations of a 25 KB signed response complete under a generous
  budget (e.g. 30 s) — a smoke guard, not a strict SLA.

## F3-09 — Docs

- `docs/FEATURES.md`: SAML section (SP + IdP, endpoints table).
- `docs/SAML.md`: admin user guide — configure Okta/Entra
  step-by-step (paste metadata flow), SP-client registration,
  certificate rotation runbook, troubleshooting table.
- `ARCHITECTURE.md`: final SAML module map + decision-record pointer.

## F3-10 — Verification commands

```bash
# from backend/
ruff check authglow/ && ruff format --check authglow/
mypy authglow/
pytest tests/unit/test_saml_xenc.py tests/unit/test_saml_slo.py \
       tests/unit/test_saml_cert_rotation.py tests/unit/repositories \
       -q --tb=line
pytest tests/integration/test_saml_slo_flow.py tests/integration/test_saml_encrypted.py \
       tests/integration/test_saml_metadata_fetch.py -q --tb=line
pytest tests/performance/test_saml_pipeline_perf.py -q --tb=line
pytest -q --tb=line -n auto          # full suite, Bash timeout 300000

# frontend/
npm run lint && npm test && npm run build
npx playwright test e2e/flows/saml-login.spec.ts
```

## Out of scope (declared non-goals — do not implement)

- Multi-SP SLO fan-out / session-participant registry (DR-11).
- HTTP-Artifact binding, ECP, SOAP back-channel (DR-03).
- SAML 1.x, unsigned-anything modes, SHA-1 acceptance (S3).
- Background automatic metadata refresh (admin-triggered only).
