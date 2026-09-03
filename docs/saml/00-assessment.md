# SAML 2.0 Full Support — Assessment & Handoff Plan (2026-09-03)

> **Scope**: abilitazione completa del supporto SAML 2.0 in AuthGlow, in
> entrambi i ruoli (Service Provider e Identity Provider), con conformità
> agli standard OASIS considerata **non derogabile**.
> **Metodo**: ogni fatto citato è stato verificato direttamente nel
> codice corrente (`backend/authglow/`, `frontend/src/`), non dedotto
> dalla documentazione.
> **Uso**: questi documenti sono pensati per l'handoff a sessioni di
> implementazione separate. Ogni fase è un file autonomo. Prima di
> eseguire una fase, leggere le sezioni 6, 7 e 11 di questo file.
> **Stato**: 0/4 fasi completate. Spunta le checkbox nei file di fase
> man mano che vengono chiuse.

---

## Sintesi esecutiva (Italiano)

AuthGlow è oggi un provider CIAM + OAuth2/OIDC completo. Supporta già
federazione **in ingresso verso IdP OIDC esterni** (Okta, Google, CIE)
e agisce da **Identity Provider OAuth2/OIDC**. Non esiste alcuna
traccia di SAML nel codebase: nessuna dipendenza XML (`lxml`,
`signxml`, `defusedxml` assenti da `backend/requirements.txt`), nessun
modello, nessun endpoint.

Questo piano aggiunge il supporto SAML 2.0 completo in **4 fasi
indipendenti e sequenziali**, ognuna consegnabile in una sessione di
implementazione dedicata:

| Fase | Contenuto | File |
|---|---|---|
| **Fase 0** | Fondazioni: dipendenze, settings, certificati X.509, modelli, repository, conformance | `01-fase-0.md` |
| **Fase 1** | AuthGlow come **SP**: login via IdP SAML esterni (metadata, AuthnRequest, pipeline ACS, linking, UI admin) | `02-fase-1.md` |
| **Fase 2** | AuthGlow come **IdP**: registro SP client, endpoint SSO, costruzione/firma Assertion, claim policy, UI | `03-fase-2.md` |
| **Fase 3** | SLO, XML-Enc (assertion cifrate), hardening SSRF, interop checklist, E2E | `04-fase-3.md` |

Decisioni architetturali chiave (dettaglio completo in §6, **vincolanti**):

- Librerie: **signxml + lxml** (nessun binario xmlsec1 a runtime;
  usato solo una volta, localmente, per generare le golden fixture di test).
- Corpo di messaggi SAML validato con **pipeline fail-closed** con
  contromisure XSW esplicite e corpus di attacchi committato come
  fixture statiche generate con un percorso crittografico indipendente.
- Identità: NameID `persistent` come chiave di linking (transient
  sempre rifiutato); auto-link per email solo con flag admin
  `trust_email` per provider (default false, semantica VAPT-035).
- Certificati X.509 dedicati per ruolo, rotazione solo manuale.
- Un solo SP entity ID per istanza; contesto provider nel relay state
  server-side, non nel RelayState del browser.

Rischi principali: la conformità SAML si dimostra solo contro IdP/SP
reali (checklist interop in Fase 3); le assertion cifrate e il SLO con
fan-out sono esplicitamente scorporati per contenere la Fase 1.

Per iniziare: eseguire `01-fase-0.md`, poi procedere in ordine.

---

## 1. Scope & Goals

1. **SP role (inbound)** — AuthGlow delegates login to external SAML
   2.0 IdPs (Okta, Entra ID, ADFS, SimpleSAMLphp, SPID/CIE-compatible
   IdPs). Parity with the existing OIDC RP flow: same admin UX surface,
   same account linking, same OAuth2 bridge, same login buttons.
2. **IdP role (outbound)** — AuthGlow acts as a SAML 2.0 Identity
   Provider for registered SP clients, issuing signed Responses and
   Assertions, with per-SP attribute policies reusing the existing
   claim policy engine.
3. **Bindings in scope (non-negotiable)**: HTTP-Redirect (requests,
   SLO) and HTTP-POST (requests, responses, SLO). Artifact binding,
   ECP, and SOAP back-channel are out of scope for the whole plan.
4. **SLO in scope (Phase 3)**: per-SP front-channel Single Logout.
   Multi-SP session fan-out is a declared non-goal (DR-11).
5. **XML-Enc in scope (Phase 3 only)**: decryption of
   `<saml:EncryptedAssertion>`. Phase 1 interop posture: SP metadata
   carries NO encryption KeyDescriptor (conformant IdPs send plaintext).

Out of scope for the entire plan (do not implement): Artifact binding,
ECP, SAML 1.x, multi-SP SLO fan-out, metadata URL fetch before the
SSRF guard exists, XML signature algorithms other than RSA-SHA256.

## 2. Current State (verified facts)

| Component | Location | Relevant facts |
|---|---|---|
| OIDC RP federation | `backend/authglow/services/federation.py` | `FederationService` verifies external `id_token` via JWKS (RS256-only allowlist `_ALLOWED_FEDERATION_ALGORITHMS`), maps claims, stateless signed state |
| Federation models | `backend/authglow/models/federation.py:13` | `ExternalIdpConfig` + Create/Update/Response variants; URI scheme validators; `claims_mapping` dict |
| Federation API | `backend/authglow/api/federation.py:76` | `GET /api/federation/login/{provider_id}` (rate-limited 5/min), `federation_callback` at `:157` |
| Callback linking logic | `backend/authglow/api/federation.py:231-324` | lookup by external_id → auto-link only if IdP asserts `email_verified` (**VAPT-035**) → else 403 with "link this provider" message → JIT `create_user` + `link_federated_identity` |
| Signed state | `backend/authglow/services/federation_state.py` | `FederationStateToken` — signed JWT embedding provider_id, redirect_uri, OAuth2 bridge context, expiry |
| Federated identities | `backend/authglow/repositories/file/federated_identity.py` | key `provider_id|external_id` → user_id; lock delegated to `UserStorage` `named_lock` |
| Provider CRUD service | `backend/authglow/services/federation_provider.py` | `named_lock("federation:create")` pattern, repo factory injection with `settings=` bypass |
| IdP role (OAuth2/OIDC) | `backend/authglow/api/auth.py`, `services/jwt.py`, `core/jwt_singleton.py` | `/oauth2/authorize`, token endpoint, userinfo, JWKS; RSA keyring with 90-day auto-rotation (independent from SAML certs) |
| Claim policy engine | `backend/authglow/models/claim_policy.py`, `backend/authglow/api/claim_policy.py` | `ClaimSource`/`ClaimTarget`/`ClaimSourceConfig`; targets `access_token`/`id_token`/`userinfo`; per-client policies |
| Repository pattern | `backend/authglow/repositories/protocols.py`, `dependencies.py`, `file/base.py` | runtime_checkable Protocols; conformance tests in `tests/unit/repositories/test_protocols.py` via `_IMPL_TABLE`; **lru_cache bypass: factories accept `settings=`** |
| Keys | `backend/authglow/core/config.py` (`get_or_generate_keyring`), `repositories/file/keystore.py` | `keys_dir` settings root; versioned keyring JSON |
| SPA fallback | `backend/main.py:266-278` | backend-only namespaces tuple `("api", "well-known", "docs", "redoc", "openapi.json")` — **`/saml/*` would be swallowed by the SPA shell unless added** |
| Middleware | `backend/authglow/middleware/` | security_headers (CSP), request_body_size, csrf, https_enforcement, request_id, proxy_headers |
| Frontend admin | `frontend/src/pages/admin/AdminFederationPage.tsx` | provider CRUD UI (`/api/federation/admin/providers`), form with Issuer/ClientID fields |
| Frontend login | `frontend/src/components/auth/FederationLoginButtons.tsx` | fetches `/api/federation/providers?context=...`, builds login URL from provider id |
| Dependencies | `backend/requirements.in` → `requirements.txt` (pip-compile, 324 lines) | `pyjwt[crypto]`, `cryptography==50.0.0`, `httpx==0.28.1`. **No XML stack.** |
| Testing | `backend/tests/{unit,integration,performance}`, `frontend` vitest + Playwright | `pytest -q --tb=line -n auto`; serial E2E, chromium+mobile projects; `.gitguardian.yaml` path-allowlist exists for test fixtures |

## 3. Standards Baseline (non-negotiable)

Every implementing agent MUST satisfy these normative references. Where
a rule here conflicts with convenience or library defaults, **the rule
wins**. Deviations require an explicit decision from the user.

| Standard | Used for |
|---|---|
| OASIS saml-core-2.0-os | Assertion/protocol schema, Bearer SubjectConfirmation, Conditions, Status codes |
| OASIS saml-bindings-2.0-os | HTTP-Redirect (§3.4: DEFLATE, base64, SigAlg/Signature query params, signature input string), HTTP-POST (§3.5), RelayState handling |
| OASIS saml-profiles-2.0-os | Web Browser SSO Profile (§4.1), Single Logout Profile (§4.4) |
| OASIS saml-metadata-2.0-os | EntityDescriptor/SPSSODescriptor/IDPSSODescriptor, KeyDescriptor, ACS index/isDefault, Organization, ContactPerson, ValidUntil |
| SAML V2.0 Metadata Interop Profile | Minimal metadata elements set for interop |
| XML Signature (XMLDSig) + Exclusive C14N | Enveloped signatures; `http://www.w3.org/2001/04/xmldsig-more#rsa-sha256` only |
| XSD dateTime | UTC `Z`-suffixed instant formatting (`YYYY-MM-DDTHH:MM:SSZ`), fractional seconds tolerated on input |

**MUST-level protocol rules** (enforced by tests, see §4):

- S1. Every message element ID must match `NCName` syntax
  `^[A-Za-z_.][A-Za-z0-9_.\-]*$` (kills SamQuote/comment-injection).
- S2. Exactly one `<saml:Assertion>` child per Response; more than one
  Assertion element anywhere in the document → reject.
- S3. Signature: single `<ds:Reference>` with `URI="#<ID>"` pointing at
  the element the signature is a direct child of; digest method
  `sha256`; signature method `rsa-sha256`. SHA-1 anywhere → reject.
- S4. Signature verification happens **before** any payload data is
  read (other than locating the signature itself).
- S5. All timing checks use a single clock-skew budget (default 90s,
  provider override capped at 300s): IssueInstant, NotBefore,
  NotOnOrAfter, SubjectConfirmationData@NotOnOrAfter.
- S6. `AudienceRestriction` containing the exact SP entity ID is
  **mandatory**; absent → reject.
- S7. `InResponseTo` must equal a known, un-expired, un-consumed
  AuthnRequest ID (server-side store). Absent `InResponseTo` is only
  accepted when the provider opts in to unsolicited responses
  (`allow_unsolicited`, default **false**).
- S8. `SubjectConfirmationData@Recipient` must equal our ACS URL exactly.
- S9. NameID value must be non-empty; `Format` must be in the provider's
  allowed set; `transient` is **never** usable as a linking key.
- S10. `RelayState`, when we issue it, is ≤ 80 bytes (interop profile).
- S11. XML parsing is always: `resolve_entities=False`,
  `no_network=True`, `load_dtd=False`, `dtd_validation=False`,
  `huge_tree=False` (lxml `XMLParser`); plus body size caps.
- S12. All SAML endpoints set `Cache-Control: no-cache, no-store`.
- S13. Errors are generic and audit-logged with reason; responses to
  the browser never leak internal detail (enumeration discipline).

## 4. Threat Model & Required Controls

| ID | Threat / vector | Control | Phase | Test |
|---|---|---|---|---|
| T-01 | XML Signature Wrapping (all 8 classic variants: unsigned assertion spliced into signed response, cloned/relocated signatures, wrapper assertions, duplicated IDs) | S1–S4 rules; corpus of static golden attack fixtures with expected reject outcomes | F1 | `test_saml_xsw_corpus.py` |
| T-02 | Assertion replay | Response ID + Assertion ID single-use replay store (file-based, multi-worker), TTL = NotOnOrAfter + skew | F1 | `test_saml_replay.py` |
| T-03 | XXE / billion laughs / entity expansion | S11 hardened parser + request size cap (existing `request_body_size` middleware covers form bodies) | F1 | `test_saml_parser_hardening.py` |
| T-04 | Clock skew abuse (long-lived assertions accepted, future-issued accepted) | S5 two-sided window; skew cap 300s | F1 | `test_saml_timing_validation.py` |
| T-05 | Audience confusion (assertion minted for another SP replayed) | S6 exact audience match | F1 | `test_saml_acs_validation.py` |
| T-06 | InResponseTo bypass (unsolicited injection) | S7 request store + `allow_unsolicited` default false | F1 | `test_saml_acs_validation.py` |
| T-07 | Recipient/ACS confusion (assertion posted to our ACS although addressed elsewhere) | S8 exact Recipient match | F1 | `test_saml_acs_validation.py` |
| T-08 | RelayState tampering / open redirect | RelayState is only an opaque 36-char request ID; all flow context lives server-side in `SamlRequestStore`; redirect_uri validated against allowlist as in OIDC flow | F1 | `test_saml_request_store.py` |
| T-09 | SigAlg confusion / algorithm downgrade on Redirect binding | SigAlg param fixed to rsa-sha256; other values rejected before signature check; signature over exact canonical query string per bindings §3.4.4.1 | F1 | `test_saml_bindings.py` |
| T-10 | SHA-1 / weak algorithm acceptance | S3: digest+signature algorithm allowlist | F1/F2 | corpus + unit tests |
| T-11 | Certificate substitution (attacker re-signs with own cert) | Only certificates pinned in provider config (`idp_signing_certificates`) are trust anchors; no metadata fetch trust at runtime | F1 | `test_saml_signatures.py` |
| T-12 | SSRF via admin-entered metadata URL | F1: paste/upload only, no fetch. F3: fetch with resolver check + private-range blocklist + no redirects + size/time caps | F1/F3 | `test_saml_metadata_fetch_guard.py` |
| T-13 | Email-based account takeover via federation (VAPT-035 class) | Auto-link only with per-provider `trust_email` flag (default false); audit event on every link | F1 | `test_saml_linking.py` |
| T-14 | EncryptedAssertion downgrade confusion | P1: explicit 400 error, no silent parse attempts; no encryption KeyDescriptor advertised | F1 | `test_saml_acs_validation.py` |
| T-15 | Transient NameID account forking | S9: transient rejected with actionable error | F1 | `test_saml_acs_validation.py` |
| T-16 | Unsigned AuthnRequest spoofing (IdP role) | `require_signed_requests` default true; Issuer must be a registered SP | F2 | `test_saml_idp_sso.py` |
| T-17 | ACS confusion on IdP role (Response delivered to attacker URL) | ACS URL exact-match against registered `acs_url` only; `AssertionConsumerServiceURL` in request ignored unless identical | F2 | `test_saml_idp_sso.py` |
| T-18 | Metadata fetch poisoning (interop) | ValidUntil/cacheDuration honored on fetched metadata (F3) | F3 | interop checklist |
| T-19 | Key compromise | Dedicated per-role certs, manual rotation with dual-KeyDescriptor overlap window | F0/F3 | `test_saml_certificates.py` |
| T-20 | Enumeration via login endpoints | Same anti-enumeration posture as OIDC federation endpoints; generic errors | F1 | integration tests |

## 5. Target Architecture

### 5.1 Module map (new files only; nothing existing is deleted)

```
backend/authglow/
  core/
    saml_certs.py              # F0: X.509 generation/loading per role
    saml_xml.py                # F1: hardened parser + XML utils (ID scan, serialization)
    saml_xenc.py               # F3: XML-Enc decryption (AES-CBC/GCM + RSA-OAEP/RSA1_5)
    ssrf.py                    # F3: SSRF-guarded public XML fetch
  models/
    saml.py                    # F0: SamlIdpConfig (+Create/Update/Response)
                               # F2: SamlSpClient (+Create/Update/Response)
  repositories/
    protocols.py               # + SamlIdpConfigRepository (F0), SamlSpClientRepository (F2)
    dependencies.py            # + factories (settings= bypass pattern)
    file/
      saml_idp_config.py       # F0: file impl (saml_idp_configs.json)
      saml_sp_client.py        # F2: file impl (saml_sp_clients.json)
      saml_request_store.py    # F1: ephemeral AuthnRequest store (saml_requests.json)
      saml_replay.py           # F1: assertion/response ID replay cache (saml_replay.json)
  services/
    saml_sp.py                 # F1: SamlSpService (metadata, AuthnRequest, ACS pipeline)
    saml_provider.py           # F0: SamlProviderService CRUD facade (mirror of federation_provider)
    saml_idp.py                # F2: SamlIdpService (SSO endpoint logic, assertion build/sign)
    saml_slo.py                # F3: SLO message build/validate for both roles
    federation_finalize.py     # F1: extracted shared post-auth helper (used by OIDC + SAML callbacks)
  api/
    saml.py                    # F1: SP endpoints; F2: IdP endpoints; F3: SLO endpoints
```

### 5.2 Endpoints

| Endpoint | Role | Phase | Notes |
|---|---|---|---|
| `GET /api/federation/saml/{provider_id}/metadata` | SP | F1 | SP metadata XML (public, rate-limited 30/min) |
| `GET /api/federation/saml/login/{provider_id}` | SP | F1 | 302 to IdP (Redirect binding) or auto-submit form (POST binding); rate-limited 5/min like OIDC |
| `POST /api/federation/saml/acs/{provider_id}` | SP | F1 | ACS: form `SAMLResponse` + `RelayState`; mirrors `federation_callback` output behavior |
| `GET/POST /api/federation/saml/slo/{provider_id}` | SP | F3 | consume LogoutRequest, send LogoutRequest to IdP |
| `GET /saml/metadata` | IdP | F2 | IdP metadata XML (public) |
| `GET/POST /saml/sso` | IdP | F2 | consume AuthnRequest (SP-initiated) or unsolicited (opt-in) |
| `GET/POST /saml/slo` | IdP | F3 | consume LogoutRequest from SPs |
| `POST /api/federation/admin/saml/parse-metadata` | admin | F1 | paste XML → parsed fields (no fetch) |
| `/api/federation/admin/saml-providers` CRUD | admin | F1 | mirror of OIDC provider admin CRUD |
| `/api/admin/saml/clients` CRUD | admin | F2 | SP client registry (IdP role) |
| `GET /api/admin/saml/certificates` | admin | F0 | cert inventory (subject, fingerprint, validity) |
| `GET /api/federation/providers` (existing) | public | F1 | extended to merge OIDC + SAML providers with `protocol` and `login_path` |

**Critical integration detail**: `backend/main.py` SPA fallback
(`spa_fallback`, line ~269) 404s only known backend namespaces. Fase 2
must add `"saml"` to that tuple, otherwise `GET /saml/metadata` and
`GET /saml/sso` return the SPA HTML shell.

### 5.3 Cryptographic model

- **Certificates**: `saml_sp_signing` and `saml_idp_signing` key pairs,
  self-signed X.509, RSA-2048, SHA-256, validity 3650 days, CN =
  hostname of `base_url`. Generated at startup (only when
  `saml_enabled`) following the `get_or_generate_keyring` pattern into
  `keys_dir`. No auto-rotation (DR-07). Rotation (F3): new cert
  appended to metadata KeyDescriptors alongside the old one; both
  accepted during overlap; old removed only after partner migration.
- **Signatures (POST binding)**: enveloped XML-DSig via `signxml`,
  exclusive C14N, RSA-SHA256.
- **Signatures (Redirect binding)**: raw RSA PKCS1v15/SHA-256 over the
  §3.4.4.1 canonical query string, computed with `cryptography`
  directly (not signxml — that signature is not XML-DSig).
- **Encryption (F3)**: separate `saml_sp_encryption` key pair;
  xenc RSA-OAEP-MGF1P / AES-128|256-CBC decryption implemented on
  lxml+cryptography; never treated as a substitute for signature
  validation.

### 5.4 State model (SP role)

`RelayState` issued by AuthGlow is the AuthnRequest ID (a 36-char
UUID). All flow context (provider_id, redirect_uri, OAuth2 bridge
context) lives server-side in `SamlRequestStore`:

- File-backed (fsspec) repository `saml_request_store.py`, mirroring
  the `token_blacklist` startup_hydrate pattern, protected by
  `named_lock("saml_requests")`.
- Entry: `{request_id → {provider_id, redirect_uri, oauth2_context,
  created_at}}`, TTL 600s, single-use (deleted on ACS consumption —
  this also enforces AuthnRequest anti-replay).
- Because the context never round-trips through the browser, no
  signed state token is required for the SAML SP flow; the browser
  cannot tamper with a value it never carries.

### 5.5 Frontend model

- `AdminFederationPage.tsx` gains a protocol concept: OIDC form as
  today; SAML form with paste-metadata parser, manual fields, cert
  display, SP metadata URL copy/download.
- `FederationLoginButtons.tsx` consumes the merged provider list
  (`protocol`, `login_path`) — server decides the login URL; the
  component no longer builds paths by convention.
- Fase 2 adds `AdminSamlClientsPage.tsx` (SP registry + claims tab,
  reusing the `TokenClaimsTab` interaction pattern).

## 6. Decision Record (binding)

These decisions were ratified on 2026-09-03 and are **not to be
re-litigated during implementation**. If a phase discovers a conflict,
stop and ask the user.

| ID | Decision | Rationale |
|---|---|---|
| DR-01 | Both roles (SP + IdP), phased: SP first | Reuses existing federation infrastructure; highest value first |
| DR-02 | Libraries: `signxml` + `lxml`, no xmlsec1 binary at runtime | Native on Windows dev + Linux; every security behavior is in-repo testable code |
| DR-03 | Web Browser SSO (Redirect+POST) + per-SP SLO; no Artifact/ECP | Covers the real-world 95%; keeps scope honest |
| DR-04 | XML-Enc deferred to Fase 3; Phase 1 SP metadata advertises no encryption KeyDescriptor | Standards-correct way to say "cannot decrypt"; Phase 1 stays lean |
| DR-05 | Inbound: at least one valid signature (Assertion OR Response); strict "both signed" per-provider opt-in flags | Okta signs only the Assertion by default, ADFS often only the Response; requiring both breaks interop |
| DR-06 | Outbound: sign everything by default (AuthnRequest signed; IdP signs Response AND Assertion) | Many IdPs require signed requests; several SPs expect signed Responses |
| DR-07 | Dedicated X.509 certs per role, self-signed, 10y validity, manual rotation only | Partner metadata is copied manually; short-lived certs would silently break integrations |
| DR-08 | IdP metadata import: paste/upload in Fase 1; URL fetch with SSRF guard in Fase 3 | No new SSRF surface before hardening |
| DR-09 | Instance-wide entity IDs: SP `https://{base_url}/saml/sp/metadata`, IdP `https://{base_url}/saml/metadata`; provider context server-side | Recreating a provider must not invalidate partner configs (GitLab-style single SP) |
| DR-10 | Golden test fixtures generated once with xmlsec1 CLI (independent crypto path), committed as static files with expected outcomes; functional tests use an in-repo mock IdP on signxml; live interop checklist in Fase 3 | Avoids testing the library against itself for adversarial vectors |
| DR-11 | SLO per-SP, front-channel only; multi-SP fan-out is a non-goal | 80% of the value, 20% of the complexity; revisit later |
| DR-12 | Outbound attributes: extend the existing claim policy engine with a `saml_attribute` target | One auditable engine, consistent admin UX |
| DR-13 | Docs: Italian executive summary + English technical body | Reading comfort + model-handoff precision |
| DR-14 | NameID `persistent` default, `transient` never a linking key; auto-link only via per-provider `trust_email` (default false) | Account stability + VAPT-035 semantics |
| DR-15 | Handoff format: `docs/saml/` with one autonomous file per phase | Each implementing session loads 1 phase file + this assessment |

## 7. Ratified Technical Defaults

| Setting | Default | Cap / notes |
|---|---|---|
| `saml_enabled` | `False` | gates cert generation at startup |
| `saml_clock_skew_seconds` | `90` | provider override allowed, max 300 |
| `saml_request_ttl_seconds` | `600` | AuthnRequest store TTL |
| `saml_allow_insecure_idp_urls` | `False` | http IdP URLs for tests only (F3-06) |
| `saml_idp_assertion_lifetime_seconds` | `300` | Fase 2, NotOnOrAfter on SubjectConfirmationData |
| `saml_org_name` / `saml_org_display_name` / `saml_org_url` | — | metadata Organization |
| `saml_technical_contact_name` / `saml_technical_contact_email` | — | metadata ContactPerson |
| Replay store TTL | `NotOnOrAfter + skew` | file-based, multi-worker |
| `allow_unsolicited` (per provider / SP client) | `false` | IdP-initiated SSO explicit opt-in |
| `trust_email` (per provider) | `false` | auto-link gate |
| `require_signed_requests` (IdP role, per SP client) | `true` | T-16 |
| `sign_response` / `sign_assertion` (IdP role, per SP client) | `true` / `true` | DR-06 |
| AuthnContext Comparison | `minimum` | RequestedAuthnContext optional per provider |

## 8. Phase Plan & Dependency Graph

```
F0 (foundations) ──► F1 (SP inbound) ──► F2 (IdP outbound) ──► F3 (SLO, XML-Enc, hardening, interop, E2E)
        │                                        ▲
        └────────────────────────────────────────┘   (F2 reuses F0 cert + model infra)
```

| Phase | Deliverable | Primary risk | Est. sessions |
|---|---|---|---|
| 0 | Deps, settings, certs, models, repos + conformance, router scaffold | low | 1 |
| 1 | Working login via external SAML IdPs, admin UI, security corpus | interop quirks | 3–5 |
| 2 | Working SSO for registered SPs, claim policy extension, registry UI | CSP/SPA-fallback integration | 2–4 |
| 3 | SLO, decryption, SSRF-guarded fetch, interop checklist, E2E | real-IdP interop cycles | 2–3 |

## 9. Glossary (minimum viable)

- **ACS** Assertion Consumer Service — SP endpoint receiving `<samlp:Response>`.
- **AuthnRequest** — SP → IdP authentication request (`<samlp:AuthnRequest>`).
- **Bearer SubjectConfirmation** — proof that the assertion was issued
  for exactly this request/recipient within a time window.
- **Conditions** — `NotBefore`/`NotOnOrAfter`/`AudienceRestriction` validity envelope.
- **Entity ID** — globally unique URI identifying an SP or IdP.
- **KeyDescriptor** — metadata element advertising a signing/encryption cert.
- **NameID** — subject identifier; format (`persistent`, `emailAddress`,
  `transient`, …) determines linking semantics.
- **RelayState** — opaque request-scoped value echoed by the peer; here:
  the AuthnRequest ID only.
- **XSW** XML Signature Wrapping — family of attacks that relocate or
  duplicate signed elements to smuggle unsigned content.
- **xenc** — XML Encryption namespace; `<EncryptedAssertion>` wrapper
  with `EncryptedKey` + `EncryptedData`.

## 10. Handoff Protocol for Implementing Agents

1. Read `AGENTS.md` (repo conventions are binding: ruff, mypy, structlog,
   UTC via `authglow.core.datetime`, repository pattern, lru_cache
   bypass via `settings=`, test-saving rules).
2. Read this file at least §3, §4, §6, §7 (standards, threats, decision
   record, defaults).
3. Open only the phase file you are implementing; phases are
   self-contained and ordered.
4. Respect the **"Out of scope"** section at the bottom of every phase
   file: if you find yourself implementing something listed there, stop.
5. Run the verification commands listed in the phase file; all must
   pass; existing tests listed as "must stay green" define the
   regression boundary.
6. When a phase completes, tick its checkboxes in the phase file and
   update the "Stato" line at the top of this file.
