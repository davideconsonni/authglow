# Piano Compliance OAuth2 / OIDC — verso conformità ottima

Stato: bozza operativa con handoff completo. Lavorazione in sessioni separate, una fase alla volta.
Legenda checkbox: `- [ ]` = da fare, `- [x]` = completato (con commit/test di riferimento).
Ogni punto ha un codice univoco **`OA-xxx`** — citarlo sempre in commit, test, xfail e handoff
(es. `OA-101`). Il numero di fase (`1.1`) resta solo come indicazione di posizione, non come chiave.

> Come usare questo file in una nuova sessione: prendi UN solo item, leggi la sua
> sezione "Contesto" + "Istruzioni", implementa, esegui i test indicati in
> "Acceptance", poi marca `- [x]` e aggiungi una riga nel Registro completamenti citando il codice.

Baseline: assessment 2026-09-10 (authorize POST, token endpoint, discovery, userinfo, logout, DCR, device flow, DPoP opt-in, revocation/introspection).

Obiettivo: nessun client conforme rotto + nessuna deviazione silenziosa + ogni hardening documentato in discovery/docs + suite di conformità verde.

---

## Assessment di partenza (2026-09-10) — leggere prima di implementare

Questa sezione è il "perché" di ogni item del piano. Se in una nuova sessione non si capisce
un item, si torna qui al punto A corrispondente.

### Metodo e perimetro

Analisi statica read-only su: `api/auth.py` (`POST /api/oauth2/authorize`, `POST /oauth2/token`,
`POST /api/auth/refresh`), `api/oidc.py` (discovery, JWKS, userinfo, logout, DCR),
`api/oauth2_advanced.py` (revoke/introspect), `api/device_auth.py`, `services/oauth2.py`,
`services/oauth_client.py`, `services/jwt.py`, `models/oauth_client.py`, `models/oidc.py`.
Non sono stati eseguiti flow runtime né suite di conformance esterne (previste in Fase 4).

### Giudizio di sintesi

Maturità **medio-alta, orientata a Security BCP / FAPI 2.0**. Le scelte "dure" sono sopra la
media (PKCE-S256 obbligatorio, implicit/hybrid rifiutati, redirect exact-match + https-only,
client-auth multipla + DPoP opt-in, rotation refresh con reuse detection, binding `aud`/`azp`,
`iss` RFC 9207). I problemi non sono vulnerabilità banali, ma **deviazioni dallo standard e
special-case first-party** che rompono client conformi e creano due classi di token/sessione
con garanzie diverse.

### Punti forti (non toccare senza regression test)

- PKCE solo `S256`, `plain` rifiutato, `code_verifier` sempre richiesto (oltre la spec, in linea BCP).
- Grant `implicit` rifiutato ovunque (modelli + discovery + DCR + migration script esistente).
- `redirect_uri` con exact-match contro `client.redirect_uris` (`oauth_client.py verify_redirect_uri`)
  + https-only con eccezione solo loopback (`_validate_redirect_uri` in `oidc.py`).
- Client auth al token endpoint su tre canali: Basic, POST, `client_assertion` JWT (HS256/RS256).
- Refresh opachi con rotazione + reuse detection, lifetime da policy (`refresh_token_expire_days`).
- Token `aud`-bound (`aud=client_id`, `azp=client_id`) per i flow federati; `INTERNAL_AUDIENCE`
  per i flow interni — disegno giusto, enforcement futuro (vedi OA-504).
- `iss` RFC 9207 in ogni authorization response (successo + errore) — anti mix-up.
- Revocation/introspection con client-auth obbligatoria e risposte non-oracle (`active:false`
  senza dire il perché) + audience binding.
- Rate limiting su tutti gli endpoint protocollo; audit strutturato con PII masking.

### Matrice compliance (stato alla baseline)

| Area                                   | Giudizio                        | Dettaglio                                                                                                                                               |
|----------------------------------------|---------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------------|
| RFC 6749 Authorization Code            | Buona, con deviazioni           | `code` single-use + CAS, `redirect_uri` exact-match, grant allowlist, errori via redirect 302. Ma: `state` obbligatorio, authorize reale è POST non GET |
| RFC 6749 Client Credentials / Refresh  | Buona                           | Auth multipla, scope narrowing su refresh. Ma cookie-flow con regole diverse                                                                            |
| RFC 6749 Password grant                | Rifiutato (voluto)              | `unsupported_grant_type`, corretto                                                                                                                      |
| RFC 7636 PKCE                          | Ottima                          | Solo S256. Dettaglio: verifier errato → 401 invece di 400                                                                                               |
| RFC 6750 Bearer                        | Buona                           | `Bearer`/`DPoP`, `WWW-Authenticate` presente                                                                                                            |
| RFC 7009 Revocation                    | Buona da confermare             | Ramo refresh ok; ramo access da verificare (lettura troncata)                                                                                           |
| RFC 7662 Introspection                 | Buona                           | Non-oracle, audience binding; estende con `email`/`username` (PII, accettabile)                                                                         |
| RFC 8628 Device                        | Parziale                        | Polling/`slow_down`/ownership ok. **Non-conforme**: riusa param `code` invece di `device_code`                                                          |
| OIDC Discovery                         | Buona, 1 pubblicità ingannevole | Response/grant/challenge corretti; ma `fragment` pubblicizzato mai emesso                                                                               |
| OIDC ID Token                          | Buona                           | Claims, `nonce`, `at_hash` ok; `c_hash` mai passato (codice morto)                                                                                      |
| OIDC UserInfo                          | Buona                           | Richiede `aud` + `openid`, DPoP se `cnf`; rigetta token legacy senza `aud`                                                                              |
| OIDC Logout                            | Parziale                        | Allowlist redirect + `id_token_hint` obbligatorio (bene), ma **non revoca nulla**                                                                       |
| RFC 7591 DCR                           | Buona con 1 buco                | Redirect/auth-method/grant hardening ok; `software_statement` non verificato                                                                            |
| RFC 7523 JWT client auth               | Presente                        | Annunciato e verificato                                                                                                                                 |
| RFC 9449 DPoP                          | Presente opt-in                 | `dpop_bound`, `cnf/jkt`, `token_type: DPoP`; non di default                                                                                             |
| RFC 9207 `iss`                         | Presente                        | Su success + error redirect                                                                                                                             |
| PAR / JAR / mTLS / Resource Indicators | Assenti                         | Lecito per OP base; non pubblicizzarli finché assenti                                                                                                   |

### Comportamenti strani rilevati (con spiegazione)

- **A1. Doppio binario first-party.** `FIRST_PARTY_BROWSER_CLIENT_ID="password_grant"`, fallback
  `_first_party_oauth_client`, cookie httpOnly settati dentro `/oauth2/token`, e per il client
  first-party la risposta è `{"ok": True}` invece di `Token`. Perché è un problema: ogni fix futura
  va fatta due volte, i token hanno due forme di `aud`, i client generici si rompono. → OA-301 (+OA-103).
- **A2. `state` obbligatorio.** `_validate_state` (min 16 char, regex stretta) con 400 JSON diretto.
  La RFC lo vuole RECOMMENDED/opzionale; qui un client conforme senza `state` fallisce, e il charset
  stretto blocca state legittimi. Era una hardening VAPT-044 consapevole ma breaking. → OA-201.
- **A3. Device grant con nome param sbagliato.** `device_code = code` nel ramo device: la spec vuole
  `device_code=`, quindi librerie standard falliscono. → OA-101.
- **A4. Cookie-flow separato.** `/api/auth/refresh` usa `client_id` hardcodato + niente DPoP check,
  contro il ramo refresh standard che li ha: stessa operazione, due policy → bypass via browser per
  client DPoP-bound. → OA-103.
- **A5. Downgrade silenzioso degli scope.** Al token endpoint gli scope non granted vengono filtrati
  in silenzio invece di `invalid_scope`; in authorize danno 400. Il client crede di avere più diritti. → OA-203.
- **A6. Logout non revoca.** GET fa audit+cookie+iframe, POST solo audit; nessun `jti` in blacklist,
  nessuna revoca refresh family. Il bearer resta spendibile dopo il "logout". → OA-102.
- **A7. Front-channel fan-out + `sid` fresh.** Iframe a TUTTI i client con logout URI (non solo sessione)
  e `sid=secrets.token_hex(16)` nuovo per ogni ID token: sessioni non correlabili, leak a terzi. → OA-204.
- **A8. Discovery/implementazione disallineate.** `fragment` annunciato mai emesso; `authorization_endpoint`
  annunciata come GET mentre il flusso passa per POST+SPA. Un RP diretto fallisce. → OA-202.
- **A9. `software_statement` finto-validato.** `jwt.decode(..., verify_signature=False)`: qualsiasi JWT
  ben formato passa come trust anchor DCR. → OA-205.
- **A10. Dettagli errore non conformi.** Verifier errato → 401 (atteso 400 `invalid_grant`); mismatch
  client → 400 generico (atteso 401 in alcuni casi); gate `offline_access` senza spiegazione;
  `c_hash` implementato ma mai passato. → OA-302, OA-303, OA-304.
- **A11. Audit incompleto.** `client_auth_method` loggato solo per `client_credentials`: in incident
  response manca il "come si è autenticato il client" per gli altri grant. → OA-305.

Mappa rapida finding→item: A1→OA-301/OA-103 · A2→OA-201 · A3→OA-101 · A4→OA-103 · A5→OA-203 ·
A6→OA-102/OA-104 · A7→OA-204 · A8→OA-202 · A9→OA-205 · A10→OA-302/OA-303/OA-304 · A11→OA-305.

---

Glossario rapido: AS = Authorization Server (AuthGlow); RP = Relying Party / client;
`aud` = audience del token; `azp` = authorized party; DPoP = proof-of-possession (RFC 9449).

---

## Fase 0 — Harness di conformità (prerequisito di tutte le altre)

Contesto generale: oggi i test OAuth2/OIDC sono sparsi (`tests/unit/test_*.py`,
`tests/integration/test_oidc_api.py`, `test_dcr_jwt_auth_method.py`, …) e non esiste
una matrice unica che dica "questo RFC/claim è coperto o è un gap noto". Senza
harness, ogni fix delle Fasi 1–3 rischia regressioni silenziose e la Fase 4

(conformance esterna) non ha un gate interno.

- [x] **[OA-001]** 0.1 Matrice di conformità come test.
  Contesto: creare `backend/tests/conformance/test_oauth2_oidc_matrix.py` che importa
  le costanti di questo piano e per ogni item ha un test dedicato — anche `pytest.mark.xfail`
  all'inizio per i gap aperti. Deve coprire almeno: PKCE S256 obbligatorio, implicit/hybrid
  rifiutati, `redirect_uri` exact-match, grant allowlist, `device_code` param, logout-revoca,
  `state` policy, scope espliciti, `sid` stabile, risposta Token standard, codici errore.
  Istruzioni: un file, un test per claim, nomi `test_<rfc>_<claim>`; usare le fixture di OA-002.
  Acceptance: `pytest backend/tests/conformance -q` eseguibile, con xfail motivati che citano
  l'item del piano (es. `xfail("OA-101 device_code param")`).

- [x] **[OA-002]** 0.2 Fixture client standard.
  Contesto: oggi i test costruiscono client ad-hoc; servono 5 fixture riusabili con valori
  fissi e documentati: (a) public PKCE (`token_endpoint_auth_method=none`, `require_pkce=True`),
  (b) confidential Basic (`client_secret_basic`), (c) `private_key_jwt` con JWK di test,
  (d) `dpop_bound=True`, (e) device client con grant device_code. Metterle in
  `backend/tests/conformance/conftest.py` (o estendere `backend/tests/conftest.py`).
  Istruzioni: riusare `_generate_rsa_keys()` esistente per le chiavi; mai secret reali
  (vedi AGENTS.md "Secret Management"); i secret di test via `secrets.token_urlsafe`.
  Acceptance: ogni fixture crea client via API/storage e lo pulisce; i test 0.1 le usano tutte.

- [x] **[OA-003]** 0.3 Done fase: `pytest tests/conformance -q` verde-a-parte-xfail + lista xfail == gap aperti delle Fasi 1–3.

---

## Fase 1 — Correzioni P0: wire-format e sessione (breaking, fare per prime)

Perché prima: cambiano il formato sul filo o la semantica di logout; più si aspetta,
più client si assuefanno al comportamento non-standard.

- [x] **[OA-101]** 1.1 Device grant: accettare `device_code=`.
  Contesto: RFC 8628 §3.4 richiede al token endpoint `grant_type=urn:ietf:params:oauth:grant-type:device_code`
  con parametro `device_code`. AuthGlow riusa invece il parametro `code`
  (`backend/authglow/api/auth.py`, ramo `grant_type == "urn:ietf:params:oauth:grant-type:device_code"`,
  riga ~1829-1831: `device_code = code`). Qualsiasi libreria OAuth2 standard fallisce.
  Comportamento atteso: accettare `device_code=` come canonico; tenere `code=` come alias
  deprecato per UNA release con audit warning (`device_code_alias_used`), poi rimuovere.
  Istruzioni: aggiungere `device_code: Annotated[Optional[str], Form()] = None` alla firma di
  `token_endpoint`; nel ramo device risolvere `resolved = device_code or code`; se usato `code`,
  loggare warning di deprecazione; aggiornare `DeviceCodeFlow` frontend e docs con esempi curl standard.
  Acceptance: test con `device_code=` va a buon fine; test con `code=` passa con warning; test senza
  nessuno dei due → `invalid_request`.
  Rischi: breaking per chi usava `code=` — mitigato dall'alias.

- [x] **[OA-102]** 1.2 Logout che revoca davvero.
  Contesto: oggi `GET /oauth2/logout` (`backend/authglow/api/oidc.py` ~L404) fa audit +
  clear-cookie + iframe frontchannel, e `POST /oauth2/logout` (~L582) fa solo audit.
  Nessuno dei due inserisce il `jti` access in blacklist né revoca la refresh family:
  dopo il "logout" il bearer resta spendibile fino a scadenza. RP-Initiated Logout si aspetta
  terminazione della sessione AS.
  Comportamento atteso: entrambe le varianti, quando ricevono un token/sessione valido,
  (a) mettono il `jti` access in blacklist (`services/auth/token_blacklist.py`),
  (b) revocano i refresh token della sessione/utente (`RefreshTokenService.revoke_user_tokens`
  o per-family se disponibile), (c) poi clear-cookie + audit esistenti.
  Istruzioni: riusare `token_blacklist()` già usato in `decode_token`/`introspect`; attenzione a non
  revocare token di altri client (binding per `sub`+`aud`); il caso "nessun token valido" resta
  idempotente 200/`{"message": "Logged out..."}`.
  Acceptance: login → logout → stesso access a `userinfo` dà 401; introspect dà `active:false`;
  refresh dopo logout dà `invalid_grant`.
  Rischi: double-logout deve restare idempotente; non rompere il fan-out frontchannel (vedi OA-204).

- [x] **[OA-103]** 1.3 Cookie-flow `/api/auth/refresh` allineato al branch refresh standard.
  Contesto: `POST /api/auth/refresh` (`backend/authglow/api/auth.py` ~L2085) legge il cookie
  refresh e ruota con `client_id=settings.oauth2_client_id` hardcodato, senza client-auth né
  enforcement DPoP esplicito come nel ramo `grant_type=refresh_token` del token endpoint
  (che invece chiama `_authenticate_client_at_token_endpoint` + `_require_dpop_proof_if_bound`).
  Due policy diverse per la stessa operazione = bypass per client DPoP-bound via browser.
  Comportamento atteso: UNA delle due — (A, consigliata) il cookie-flow applica le stesse regole
  (binding client dal cookie/cliente first-party + DPoP proof se il client è `dpop_bound` + stesso
  audit), oppure (B) è marcato first-party-only e rifiuta con 403 cookie emessi per altri client.
  Istruzioni: estrarre helper comune `rotate_refresh_for_client(...)` usato da entrambi i percorsi;
  non duplicare la logica di rotation.
  Acceptance: cookie di altro client → 403/401 (non ruotato); client `dpop_bound` senza proof → 401;
  audit `ACCESS_TOKEN_REFRESHED` equivalente nei due percorsi.

- [x] **[OA-104]** 1.4 Revoca access-token: verificare + testare il ramo JWT.
  Contesto: `/oauth2/revoke` (`backend/authglow/api/oauth2_advanced.py` ~L67) — il ramo refresh è
  verificato (revoca + audit), il ramo access-token era troncato in lettura durante l'assessment:
  va confermato che inserisca il `jti` in blacklist (coerente con il check in
  `JWTService.decode_token` e in `introspect_token`). Se manca, è un buco logout/revoca.
  Comportamento atteso: revoke di un access valido → `userinfo` 401 + `introspect` `active:false`
  (RFC 7009: risposta sempre 200 `{}` anche per token già invalidi — non-oracle).
  Istruzioni: leggere per intero `revoke_token` oltre L120; aggiungere test di regressione.
  Acceptance: i tre assert sopra in un unico test.

- [x] **[OA-105]** 1.5 Done fase: 1.1–1.4 verdi + CHANGELOG/docs aggiornati per i breaking (device param, logout-revoca, cookie-flow).

---

## Fase 2 — P1: deviazioni dichiarate vs rimosse

Principio: o si rimuove la deviazione, o la si dichiara in discovery/docs con test che la fissa.
Niente deviazioni silenziose.

- [x] **[OA-201]** 2.1 Policy `state` unificata.
  Contesto: RFC 6749 rende `state` RECOMMENDED ma opzionale; AuthGlow lo rende obbligatorio
  (`_validate_state`, `_MIN_STATE_LEN=16`, regex charset in `backend/authglow/api/auth.py` ~L198-221,
  enforcement ~L701) con 400 JSON diretto. Client conformi senza state si rompono; inoltre gli errori
  post-validazione dovrebbero viaggiare via redirect 302 (come già fa `_oauth_error_redirect`),
  non come 400 JSON. Il charset stretto blocca anche state legittimi con altri caratteri URL-safe.
  Comportamento atteso (consigliato): `state` opzionale; se assente/debole → errore via redirect
  `error=invalid_request` (mai echo di state tainted); documentare la raccomandazione
  `secrets.token_urlsafe(32)` per i client.
  Istruzioni: toccare `authorize_post` + `_validate_state` + `_oauth_error_redirect`; aggiornare
  `OAuthAuthorizePage.tsx` (non deve pretendere state) e docs.
  Acceptance: flow senza state si completa; state tainted non viene echoato nel redirect; state valido
  viene echoato intatto.
  Rischi: abbassa una hardening VAPT-044 — compensato dal redirect-error (niente oracle) + docs.

- [x] **[OA-202]** 2.2 Discovery veritiera.
  Contesto: `openid_configuration` (`backend/authglow/api/oidc.py` ~L114-157) pubblicizza
  `response_modes_supported=["query","fragment"]` ma `fragment` non è mai emesso (solo `query`
  via `_build_oauth_redirect`); `form_post` è già stato rimosso correttamente (commento A8).
  Inoltre `authorization_endpoint` è annunciata come `GET /oauth2/authorize` mentre il flusso reale
  passa per `POST /api/oauth2/authorize` + SPA (`OAuthAuthorizePage.tsx`) — un RP diretto si perde.
  Comportamento atteso: `response_modes_supported=["query"]` finché `fragment` non esiste davvero;
  e O chiarire in docs che l'endpoint è front-channel via frontend, O aggiungere un `GET` conforme.
  Istruzioni: una riga in `oidc.py` + snapshot test discovery + paragrafo docs "come chiamare authorize".
  Acceptance: snapshot test discovery fallisce se qualcuno ri-aggiunge `fragment` senza implementarlo.

- [x] **[OA-203]** 2.3 Scope espliciti al token endpoint.
  Contesto: nel ramo `authorization_code` (`backend/authglow/api/auth.py` ~L1321) gli scope vengono
  filtrati in silenzio (`[s for s in processed if s in user.scopes or s in oidc_standard_scopes]`),
  mentre in authorize uno scope invalido dà 400. Il client crede di avere più di quanto ha.
  Comportamento atteso: scope non granted → `invalid_scope` esplicito (RFC 6749 §5.2), mai downgrade silenzioso.
  Istruzioni: sostituire il filtro con un check che solleva `OAuth2Error(INVALID_SCOPE)`; verificare che
  `offline_access` resti nel set OIDC standard per il gate refresh (vedi OA-304).
  Acceptance: token con scope non granted → `invalid_scope`, non token ridotto.

- [x] **[OA-204]** 2.4 `sid` di sessione + frontchannel mirato.
  Contesto: `create_id_token` (`backend/authglow/services/jwt.py` ~L551) genera
  `sid=secrets.token_hex(16)` fresh per OGNI id token — due ID token della stessa sessione non sono
  correlabili, rompendo front/back-channel logout. E `logout_get` (`api/oidc.py` ~L499) fa fan-out
  degli iframe a TUTTI i client con `frontchannel_logout_uri`, non solo a quelli della sessione
  (rumore + leak di `sid` a terzi).
  Comportamento atteso: `sid` stabile per sessione (derivato dalla sessione/refresh family, non fresh);
  logout notifica solo i client con sessione attiva per quel `sid`.
  Istruzioni: richiede una nozione di "sessione" (refresh family o session service) da propagare fino a
  `create_id_token`; se troppo invasivo, alternativa minima: documentare il limite + notificare solo i
  client coinvolti se l'informazione è disponibile, altrimenti tenere fan-out ma con `sid` pairwise.
  Acceptance: due login → `sid` distinti e stabili per sessione; logout notifica solo i client della sessione.
  Rischi: tocca il cuore sessione/token — fare DOPO la 1.2.

- [x] **[OA-205]** 2.5 `software_statement` DCR.
  Contesto: `register_oauth_client` (`backend/authglow/api/oidc.py` ~L723) valida lo statement solo come
  "è un JWT ben formato" (`jwt.decode(..., verify_signature=False)`). Qualsiasi JWT autofirmato passa
  come trust anchor DCR.
  Comportamento atteso: verificare la firma contro JWKS/configured trust anchor, OPPURE rimuovere il campo
  finché la verifica non esiste (meglio niente campo che finta validazione).
  Acceptance: statement con firma non trusted → 400; statement assente → registrazione ok.

- [x] **[OA-206]** 2.6 Done fase: zero deviazioni silenziose; ogni hardening residuo è in discovery/docs con test.

---

## Fase 3 — P2: uniformità first-party e dettagli protocollo

Tema: oggi esiste un "doppio binario" first-party (`oauth2_client_id` + `password_grant`,
`_first_party_oauth_client`, `aud=authglow-internal` vs `aud=client_id`) con rami speciali nel
token endpoint. Va ricondotto a UN solo code-path con il first-party come client normale + cookie
come convenienza same-origin.

- [x] **[OA-301]** 3.1 Risposta token first-party standard.
  Contesto: per `resolved_client_id == settings.oauth2_client_id` + first-party redirect, il token
  endpoint restituisce `{"ok": True}` + cookie (`backend/authglow/api/auth.py` ~L1560-1574) invece di
  un oggetto `Token` (`access_token/refresh_token/id_token/expires_in`). Client generici si rompono;
  il frontend deve parsare due formati.
  Comportamento atteso: sempre `Token` standard + cookie same-origin come extra (non come sostituto).
  Istruzioni: restituire `access_token_response` (già con `refresh_token`/`id_token`) e settare i cookie
  sulla stessa risposta; aggiornare `OAuthAuthorizePage.tsx` + playground.
  Acceptance: il first-party riceve `access_token`/`refresh_token`/`id_token` parsabili + cookie settati.

- [x] **[OA-302]** 3.2 Codici errore conformi.
  Contesto: `code_verifier` errato → 401 (`api/auth.py` ~L1288, atteso `400 invalid_grant`);
  `client_id` mismatch con l'authorization code → 400 generico (~L1215, in alcuni casi atteso
  `401 invalid_client`). Dettagli, ma le suite di conformità li controllano.
  Comportamento atteso: envelope `{"error": ...}` RFC 6749 §5.2 con status corretti.
  Acceptance: test per ogni caso con `error` + status esatti.

- [x] **[OA-303]** 3.3 `c_hash` morto o vivo.
  Contesto: `create_id_token` supporta `c_hash` (`services/jwt.py` ~L565) ma il call-site
  authorization_code (`api/auth.py` ~L1520) passa solo `access_token=` (per `at_hash`), mai
  `authorization_code=`. Parametro morto che suggerisce una garanzia (binding code→ID token) non data.
  Comportamento atteso: O passare il code e testare `c_hash` verificabile, O rimuovere il parametro.
  Acceptance: test che verifica `c_hash` (se tenuto) o assenza del parametro (se rimosso).

- [ ] **[OA-304]** 3.4 Gate `offline_access` documentato.
  Contesto: refresh emesso solo con scope `offline_access` (OIDC Core §11) — corretto, ma chi si aspetta
  refresh dal grant `refresh_token` senza aver chiesto `offline_access` non riceve refresh senza spiegazione
  (rami `authorization_code` ~L1347, device ~L1943).
  Comportamento atteso: docs + messaggio chiaro (es. in `Token` docs e nel playground: "refresh solo con
  offline_access"); valutare warning audit quando il grant lo permetterebbe ma lo scope manca.
  Acceptance: test senza `offline_access` → solo access, e docs che lo dicono.

- [ ] **[OA-305]** 3.5 `client_auth_method` in audit su tutti i grant.
  Contesto: solo `client_credentials` logga il metodo (`basic/post/assertion`) in
  `ClientCredentialsMetadata`; gli altri grant no — in incident response non si sa come si è autenticato il client.
  Istruzioni: estendere il pattern `cc_auth_method` agli altri rami del token endpoint.
  Acceptance: ogni `ACCESS_TOKEN_ISSUED` contiene `client_auth_method`.

- [ ] **[OA-306]** 3.6 Done fase: un solo code-path per grant, first-party = client normale + cookie.

---

## Fase 4 — OIDC conformance suite (test-only, poi fix)

- [ ] **[OA-401]** 4.1 Eseguire un profilo OIDC Basic (RP/OP) o tool esterno di conformance contro env di test.
  Contesto: la Fase 0 dà il gate interno, ma solo una suite esterna certifica. Allegare il report
  (pass/fail per profilo) in `docs/plans/active/` accanto a questo file.
  Acceptance: report allegato + ogni MUST fallito mappato a un item (esistente o nuovo) di questo piano.

- [ ] **[OA-402]** 4.2 MUST rimasti: `nonce` (obbligatorio con `openid`+code? oggi copiato se presente ma non imposto),
  `auth_time`/`max_age`/`prompt=none` (già implementati in `authorize_post` ~L732-850 → servono test di
  regressione dedicati, inclusi `login_required`/`consent_required` via redirect).
  Acceptance: un test per MUST, nessuno `xfail` a fine fase (o waiver scritto qui).

- [ ] **[OA-403]** 4.3 Snapshot: discovery + JWKS (rotazione kid, `304`/ETag, revoked esclusi — `api/oidc.py` ~L160-243)
  + userinfo (`aud` richiesto, `openid` richiesto, DPoP con `cnf` — `api/oidc.py` ~L277-380).
  Acceptance: snapshot test che falliscono su qualsiasi cambio non intenzionale del documento.

- [ ] **[OA-404]** 4.4 Done fase: zero MUST falliti (o waiver scritti e firmati in questo file).

---

## Fase 5 — FAPI 2.0 / Security BCP hardening (opt-in → default dove possibile)

Contesto: oggi AuthGlow è "BCP-oriented" (PKCE-only, no implicit, client JWT auth, DPoP opt-in,
`iss` mix-up mitigation) ma mancano i pezzi FAPI che danno il salto a "ottima": PAR, JAR,
sender-constraining di default. Sono feature nuove, non fix — farle DOPO che le Fasi 1–3 hanno
stabilizzato il wire-format.

- [ ] **[OA-501]** 5.1 PAR (RFC 9126): `POST /oauth2/par` che emette `request_uri` + il token endpoint / authorize
  lo richiede per i client FAPI; discovery con `pushed_authorization_request_endpoint`.
  Handoff: definire TTL `request_uri` (consigliato 60–90s), single-use, binding client; riusare il
  repository pattern (`repositories/file/` + `protocols.py` + conformance test come per gli altri repo).
- [ ] **[OA-502]** 5.2 JAR (`request=` object) e/o registrazione `request_uri`; `response_mode=form_post` solo se
  implementato davvero (oggi rimosso correttamente — non ri-pubblicizzarlo senza implementazione).
- [ ] **[OA-503]** 5.3 mTLS (`tls_client_auth`) o DPoP obbligatorio per client ad alto rischio; valutare
  `dpop_bound=True` di default per nuovi client confidenziali (con migration per gli esistenti).
- [ ] **[OA-504]** 5.4 Sender-constrained refresh rotation + enforcement `aud` su ogni resource server interno
  (oggi `INTERNAL_AUDIENCE="authglow-internal"` esiste in `services/jwt.py` ~L74 ma l'enforcement
  è futuro).
- [ ] **[OA-505]** 5.5 Done fase: profilo FAPI deciso e documentato (tabella default vs opt-in) in `SECURITY.md`/docs.

---

## Fase 6 — Docs, audit e chiusura

- [ ] **[OA-601]** 6.1 `ARCHITECTURE.md` + `docs/` per ogni endpoint toccato: parametri canonici, errori `error=`,
  esempi curl con client standard (non solo first-party). Chi tocca un endpoint aggiorna la sua doc
  nello stesso commit (regola AGENTS.md).
- [ ] **[OA-602]** 6.2 Playground/frontend allineati: `DeviceCodeFlow` usa `device_code`, `state` non richiesto,
  risposta Token standard parsata (niente più `{"ok": True}`), `PkceFlow`/`AuthorizationCodeFlow`
  invariati se già S256.
- [ ] **[OA-603]** 6.3 Test: dopo ogni item, solo i file dell'area toccata; full backend
  (`pytest -q --tb=line -n auto`, timeout 300000) solo a fine fase. Separare failure pre-esistenti
  (noti: event loop 3.13, CSP, `setup_page` import) dalle regressioni — **chiedere prima di fixare
  le pre-esistenti** (regola AGENTS.md).
- [ ] **[OA-604]** 6.4 Dichiarazione finale: tabella RFC×stato firmata qui sotto (tutte `[x]` = done).

### Dichiarazione finale di compliance (compilare a fine Fase 6)

| Codice | RFC / Profilo | Stato | Evidenza (test/report) |
|---|---|---|---|
| OA-701 | RFC 6749 code / client_credentials / refresh | - [ ] | |
| OA-702 | RFC 7636 PKCE S256-only | - [ ] | |
| OA-703 | RFC 6750 Bearer | - [ ] | |
| OA-704 | RFC 7009 revocation | - [ ] | |
| OA-705 | RFC 7662 introspection | - [ ] | |
| OA-706 | RFC 8628 device | - [ ] | |
| OA-707 | OIDC Discovery / UserInfo / Logout / DCR | - [ ] | |
| OA-708 | RFC 7523 JWT client auth | - [ ] | |
| OA-709 | RFC 9449 DPoP | - [ ] | |
| OA-710 | RFC 9207 iss + BCP mix-up | - [ ] | |
| OA-711 | PAR / FAPI 2.0 (profilo deciso) | - [ ] | |

---

## Registro completamenti

| Data | Codice | Fase/Item | Commit | Note |
|------|--------|-----------|--------|------|
| 2026-09-11 | OA-002 | Fase 0 / 0.2 Fixture client standard | n/a (non committato) | `backend/tests/conformance/conftest.py` con 5 fixture (public PKCE, confidential Basic, private_key_jwt, dpop_bound, device); smoke 5/5 verde serial + `-n auto`, ruff pulito. |
| 2026-09-11 | OA-001 | Fase 0 / 0.1 Matrice di conformità | n/a (non committato) | `backend/tests/conformance/test_oauth2_oidc_matrix.py`: 15 test (6 verdi + 9 xfail strict OA-101/102/201/202/203/204/205/301/302), verde-a-parte-xfail serial + `-n auto`, ruff pulito. |
| 2026-09-11 | OA-101 | Fase 1 / 1.1 Device device_code | n/a (non committato) | `api/auth.py`: form field canonico `device_code=` + alias `code=` deprecato (precedenza canonico, warning `device_code_alias_used`); doc aggiornata; matrice 9 verdi + 8 xfail, regressione device/grant/offline verde, ruff pulito. |
| 2026-09-11 | OA-102 | Fase 1 / 1.2 Logout revoca | n/a (non committato) | `api/oidc.py`: helper `_revoke_session_tokens` (blacklist jti + `revoke_user_tokens` scoped aud/first-party) nei 3 rami logout; doc aggiornata; matrice 10 verdi + 7 xfail, regressione revoke/oidc/logout/discovery verde, ruff pulito. |
| 2026-09-12 | OA-104 | Fase 1 / 1.4 Revoca access-token | n/a (non committato) | Ramo JWT già conforme (blacklist jti + audience binding + 200 non-oracle): nuovo `TestRFC7009Revocation::test_rfc7009_revoke_access_token` verde (revoke → userinfo 401 + introspect inactive + unknown → 200 `{}`); harness esteso con `oauth2_advanced.router`. |
| 2026-09-12 | OA-003 | Fase 0 / 0.3 Done fase | n/a (non committato) | Matrice 14 verdi + 9 xfail strict (201/202/203/204/205/301/302/303/305) serial + `-n auto`, ruff pulito; nuovi pin verdi OA-103a/b (cookie first-party-only), OA-104 (revoca), OA-304 (gate offline_access); OA-103/OA-304 restano aperti solo per lavoro docs/strutturale (OA-103 chiuso il 2026-09-12, vedi riga sotto). |
| 2026-09-12 | OA-103 | Fase 1 / 1.3 Cookie-flow allineato | n/a (non committato) | `api/auth.py`: owner risolto dal RT (`_resolve_cookie_refresh_owner`) + gate grant/DPoP + first-party-only esplicito + audit condiviso (`_audit_refresh_rotation`, con family); `expected_htu` parametrizzato; minting invariato (OA-301/504). Test `TestOAuth2CookieFlow` 5/5 (no-proof → 400 `missing_dpop_proof`, deviazione concordata dai 401 dell'acceptance); fix pin OA-003 vacui (header Cookie espliciti); docs aggiornate; area 98 verdi + mypy/ruff puliti. |
| 2026-09-12 | OA-105 | Fase 1 / 1.5 Done fase | n/a (non committato) | Full suite `2802 passed, 9 xfailed, 0 failed` (`-n auto`); docs breaking complete (`refresh-token-rotation.md` per OA-103, resto già coperto in OA-101/102); niente CHANGELOG nel repo → il Registro funge da changelog; frontend invariato (`DeviceCodeFlow` già canonico). Fase 1 chiusa. |
| 2026-09-12 | OA-201 | Fase 2 / 2.1 Policy state | n/a (non committato) | `api/auth.py`: S2 — assente completa senza echo, debole → 302 `invalid_request` senza echo; choke point `valid_state` su tutti gli echo/storage + hardening in `_oauth_error_redirect`; helper/charset invariati. Matrice 21 verdi + 8 xfail (xfail OA-201 rimosso, 3 nuovi test); `test_state_param.py` riscritto, `test_vapt044.py` verde; sistemati 3 test che passavano vacuamente sul vecchio gate (csrf, hint); restano solo 2 expired pre-esistenti (provati via stash); docs `authorization-code-pkce.md`; mypy/ruff puliti. |
| 2026-09-12 | OA-202 | Fase 2 / 2.2 Discovery veritiera | b7d16b6 | `api/oidc.py` + `models/oidc.py` → `response_modes_supported=["query"]`; xfail OA-202 rimosso (TestOIDC verde); nuovo guard `test_fragment_not_advertised` in `test_discovery.py`; docs `authorization-code-pkce.md` (come chiamare authorize + response mode); `authorization_endpoint` invariato (front-channel via SPA, docs-only come da grill G1). Test area 14 passed + regressione oidc 5 passed, ruff/mypy puliti. |
| 2026-09-12 | OA-203 | Fase 2 / 2.3 Scope espliciti | 34a0514 | `api/auth.py` ramo authorization_code: filtro silenzioso → `400 invalid_scope` con nomi scope eccedenti (RFC 6749 §5.2); set OIDC invariato (gate `offline_access`/OA-304 intatto); xfail rimosso (matrice 23 passed); zero fallout (auth/token/federation/MFA 194 passed); docs `authorization-code-pkce.md`; ruff/mypy puliti. |
| 2026-09-12 | OA-204 | Fase 2 / 2.4 sid + frontchannel mirato | ba7d319 | `services/jwt.py`: nuovo `session_sid()` = `HMAC(secret, user\|client\|auth_time)`[:32hex], usato da `create_id_token` (unico mint); `api/oidc.py`: `_logout_session_targets()` — iframe solo a hint-client (sid vero) + holder RT attivi (sid pairwise), target prima della revoca, fallback hint-only; Opzione B scartata (euristica auth_time, limiti in docs). Matrice 26 passed + area jwt/oidc/logout 66 passed; harness `matrix_app` esteso (rebind OAuth2Service/UserService per GET-logout); docs `oidc-logout.md`; ruff/mypy puliti. |
| 2026-09-12 | OA-205 | Fase 2 / 2.5 software_statement DCR | e3dcf2f | `api/oidc.py` P.3: finta verifica (`verify_signature=False`) → rifiuto esplicito `400 unapproved_software_statement` (RFC 7591 §3.2.2, nessun anchor da operare — verifica vera rimandata); assente → `201` invariato; campo tenuto in schema (niente drop silenzioso). xfail rimosso; gate + area DCR 22 passed; docs `features.md`; ruff/mypy puliti. |
| 2026-09-12 | OA-206 | Fase 2 / 2.6 Done fase | 9547fb7 | Docs gate `offline_access` in `authorization-code-pkce.md` (warning audit resta OA-304); matrice 27 passed + 4 xfail tutti Fase 3 (zero gap Fase 2); full suite `2813 passed, 4 xfailed, 0 failed` (`-n auto`, 25.6s); 1 regressione Fase 2 trovata/fixata (`test_offline_access_gate.py`: mock user senza `scopes` → `scopes=["read"]`); zero pre-esistenti manifestati. Fase 2 chiusa. |
| 2026-09-12 | OA-301 | Fase 3 / 3.1 Token first-party standard | 4471ad2 | `api/auth.py`: cancellato ramo `{"ok": True}` (cookie già su risposta a L1484) → sempre `Token` + cookie; `OAuthCallbackPage.tsx`: parsing Token-unico + nonce se richiesto; gate rafforzato (access/refresh/id_token + 2 cookie); cookie-flow `/api/auth/refresh` invariato. Matrice 28 passed + area 73 passed; tsc/eslint + unit frontend verdi; E2E login-dashboard 4 passed con backend su 8001 (il fallimento iniziale era backend spento, non regressione). |
| 2026-09-12 | OA-302 | Fase 3 / 3.2 Codici errore conformi | e63bba8 | `api/auth.py`: verifier errato `401`→`400 invalid_grant` (RFC 6749 §5.2); mismatch pinnato come corretto (`issued to another client` → `invalid_grant`/400, contro-correzione al piano); gate esteso a 2 casi; L1267 invariato (residuo annotato). Matrice + area PKCE/auth 37 passed; docs errori; ruff/mypy puliti. |
| 2026-09-12 | OA-303 | Fase 3 / 3.3 c_hash legato al code | OA-303 (questo commit) | `api/auth.py`: `authorization_code=code` al mint (plaintext mai persistito, solo hash); xfail rimosso (matrice 30 passed + 1 xfail OA-305); area jwt/id_token 64 passed; docs hashes; ruff/mypy puliti. |
