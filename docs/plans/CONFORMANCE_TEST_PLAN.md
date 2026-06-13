# AuthGlow — OIDC / OAuth 2.0 Conformance Test Plan

> Piano di test sistematico per validare la conformance di AuthGlow con OAuth 2.0 e OpenID Connect Core 1.0.
> Complementare a [`docs/CONFORMANCE_REMEDIATION_PLAN.md`](CONFORMANCE_REMEDIATION_PLAN.md): per ogni Workstream lì definito, qui ci sono i test case.
>
> **Obiettivo finale**: passare l'OpenID Foundation Conformance Profile (o, dove non applicabile, certificare i singoli profili).
> **Strategia**: usare la suite open-source [`oidctest`](https://github.com/openid-certification/oidctest) e [`python-openidconnect`](https://github.com/jpadilla/pyopenid) come riferimento, replicandone i test case.
> **Esecuzione**: una sessione per Workstream. Le checkbox si spuntano singolarmente dopo aver visto passare il test.

---

## Indice dei Test Suite

| ID | Suite | Lavoro coperto | File pytest |
|---|---|---|---|
| TS-01 | Discovery & JWKS | Workstream E, R | `tests/conformance/test_discovery.py` |
| TS-02 | JWT & ID Token Claims | Workstream A, F, M | `tests/conformance/test_id_token.py` |
| TS-03 | Authorization Code + PKCE | Workstream A, B, C, G, H, Q | `tests/conformance/test_authcode_pkce.py` |
| TS-04 | Implicit Grant Removal | Workstream E | `tests/conformance/test_implicit_removal.py` |
| TS-05 | Client Credentials | Workstream A | `tests/conformance/test_client_credentials.py` |
| TS-06 | Refresh Token Rotation | (già implementato) | `tests/conformance/test_refresh_rotation.py` |
| TS-07 | Token Revocation (RFC 7009) | (già implementato) | `tests/conformance/test_revocation.py` |
| TS-08 | Token Introspection (RFC 7662) | Workstream A | `tests/conformance/test_introspection.py` |
| TS-09 | Dynamic Client Registration (RFC 7591) | Workstream P | `tests/conformance/test_dcr.py` |
| TS-10 | DCR Management (RFC 7592) | Workstream K | `tests/conformance/test_dcr_management.py` |
| TS-11 | UserInfo Endpoint | Workstream A, N | `tests/conformance/test_userinfo.py` |
| TS-12 | RP-Initiated Logout | Workstream D | `tests/conformance/test_rp_logout.py` |
| TS-13 | Back/Front-Channel Logout | Workstream L | `tests/conformance/test_backchannel_logout.py` |
| TS-14 | CSRF Protection | Workstream C | `tests/conformance/test_csrf.py` |
| TS-15 | Token Blacklist Persistence | Workstream J | `tests/conformance/test_blacklist_persistence.py` |
| TS-16 | Device Authorization (RFC 8628) | Workstream S | `tests/conformance/test_device_flow.py` |
| TS-17 | `prompt` Parameter | Workstream G | `tests/conformance/test_prompt.py` |
| TS-18 | `max_age` Parameter | Workstream H | `tests/conformance/test_max_age.py` |
| TS-19 | `id_token_hint` | Workstream I | `tests/conformance/test_id_token_hint.py` |
| TS-20 | `at_hash` / `c_hash` | Workstream M | `tests/conformance/test_at_hash.py` |
| TS-21 | Rate Limiting | Workstream O | `tests/conformance/test_rate_limit.py` |
| TS-22 | State Parameter | Workstream Q | `tests/conformance/test_state.py` |
| TS-23 | FAPI / OAuth 2.1 | Workstream T | `tests/conformance/test_fapi.py` |
| TS-24 | `jwks_uri` Status | Workstream R | `tests/conformance/test_jwks_status.py` |

---

## Convenzioni

- Ogni test case ha un ID `TC-XX.YY` (TS-XX, test YY) per tracking in issue tracker.
- Test cases che richiedono tooling esterno (oidctest, jq, openssl) marcati con **[EXT]**.
- Test cases che richiedono browser automation (Playwright) marcati con **[E2E]**.
- Test cases che richiedono multiple instance dell'AS marcati con **[MULTI-INSTANCE]**.

### Helper di test condivisi

Da implementare in `tests/conformance/conftest.py`:

```python
@pytest.fixture
def oidc_discovery(base_url):
    """Cache the discovery document."""
    return httpx.get(f"{base_url}/.well-known/openid-configuration").json()

@pytest.fixture
def jwks(base_url):
    """Fetch and parse the JWKS."""
    return jwt.PyJWKClient(f"{base_url}/.well-known/jwks.json")

@pytest.fixture
def registered_client(base_url, admin_token):
    """Create a fresh OAuth2 client for the test session."""
    response = httpx.post(
        f"{base_url}/api/oauth-clients",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "client_name": "Conformance Test Client",
            "redirect_uris": ["https://test.example.com/callback"],
            "allowed_scopes": ["openid", "profile", "email", "offline_access"],
            "grant_types": ["authorization_code", "refresh_token"],
            "is_confidential": True,
            "require_pkce": True,
        },
    )
    return response.json()  # includes plaintext client_secret

@pytest.fixture
def public_client(base_url, admin_token):
    """Create a public client (no secret) for PKCE testing."""
    response = httpx.post(
        f"{base_url}/api/oauth-clients",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={
            "client_name": "Public Test Client",
            "redirect_uris": ["https://public.example.com/callback"],
            "allowed_scopes": ["openid", "profile", "email"],
            "grant_types": ["authorization_code"],
            "is_confidential": False,
            "require_pkce": True,
        },
    )
    return response.json()

@pytest.fixture
def test_user(base_url):
    """Create a fresh user with known password."""
    email = f"test-{uuid4()}@example.com"
    httpx.post(f"{base_url}/api/users", json={
        "email": email,
        "password": "Test1234!Strong",
        "first_name": "Test",
        "last_name": "User",
    })
    return {"email": email, "password": "Test1234!Strong"}

def pkce_pair():
    """Generate a PKCE verifier/challenge pair."""
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge

def authorize_url(client_id, redirect_uri, scope, state, code_challenge=None, **extra):
    """Build an authorization URL."""
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    params.update(extra)
    return params
```

---

## TS-01: Discovery & JWKS

**File**: `tests/conformance/test_discovery.py`

### TC-01.01 — Discovery Required Fields [EXT]
- [ ] `issuer` è HTTPS in produzione, HTTP in dev
- [ ] `authorization_endpoint` presente e raggiungibile
- [ ] `token_endpoint` presente
- [ ] `userinfo_endpoint` presente
- [ ] `jwks_uri` presente e raggiungibile
- [ ] `scopes_supported` contiene `openid`
- [ ] `response_types_supported` contiene `code`
- [ ] `subject_types_supported` contiene `public`
- [ ] `id_token_signing_alg_values_supported` contiene almeno `RS256`
- [ ] `claims_supported` contiene `sub`, `iss`, `aud`, `exp`, `iat`

### TC-01.02 — Discovery MUST NOT Include Implicit [Workstream E]
- [ ] `grant_types_supported` **non** contiene `implicit`
- [ ] `response_types_supported` **non** contiene `token`, `id_token`, `code token`, `code id_token`, `token id_token`, `code token id_token`
- [ ] `response_types_supported` contiene solo `code`

### TC-01.03 — Discovery PKCE Methods
- [ ] `code_challenge_methods_supported` contiene solo `S256`
- [ ] `code_challenge_methods_supported` **non** contiene `plain`

### TC-01.04 — Discovery Optional Endpoints
- [ ] `revocation_endpoint` presente
- [ ] `introspection_endpoint` presente
- [ ] `end_session_endpoint` presente
- [ ] (Workstream S) `device_authorization_endpoint` presente

### TC-01.05 — Discovery Claims
- [ ] (Workstream F) `claims_supported` contiene `acr`, `amr`
- [ ] `claims_supported` contiene tutti gli OIDC standard claims (profile, email, phone, address)

### TC-01.06 — JWKS Structure [EXT]
- [ ] `keys` è un array non vuoto
- [ ] Ogni key ha `kty`, `use`, `alg`, `kid`, `n`, `e` (per RSA)
- [ ] `kty` = `RSA` per tutte le chiavi correnti
- [ ] `use` = `sig` per tutte
- [ ] `alg` corrisponde a `settings.jwt_algorithm`

### TC-01.07 — JWKS Excludes Revoked Keys
- [ ] Dopo `revoke_key(kid)`, il JWKS **non** contiene quel kid
- [ ] Solo chiavi con status `active` o `verifying` sono esposte

### TC-01.08 — JWKS Multiple Active Keys
- [ ] Dopo `rotate_keys()`, il JWKS contiene sia vecchia (verifying) che nuova (active) chiave
- [ ] Entrambe hanno kid distinti

### TC-01.09 — Discovery Caching
- [ ] Headers `Cache-Control` o simili sono sensati
- [ ] (Opzionale) La risposta è stabile tra chiamate successive

### TC-01.10 — Discovery HTTPS in Production
- [ ] Se `app_env=production`, `issuer` è HTTPS
- [ ] Tutti gli endpoint URL sono HTTPS

---

## TS-02: JWT & ID Token Claims

**File**: `tests/conformance/test_id_token.py`

### TC-02.01 — ID Token Required Claims [Workstream A]
- [ ] `iss` presente e uguale a `discovery.issuer`
- [ ] `sub` presente e non-null
- [ ] `aud` presente e uguale al `client_id` del client che ha fatto la richiesta
- [ ] `exp` presente e nel futuro
- [ ] `iat` presente e nel passato

### TC-02.02 — ID Token `azp` Claim [Workstream A]
- [ ] Se `aud` è singolo e uguale al client_id, `azp` può essere assente o uguale a `aud`
- [ ] Se l'ID token ha multiple audiences, `azp` è obbligatorio e = client_id emittente
- [ ] (Implementazione attuale) `azp` aggiunto per ogni ID token come `aud`

### TC-02.03 — ID Token `aud` Validation [Workstream A — P0 CRITICO]
- [ ] ID token emesso per client A → `decode_id_token(expected_aud="B")` ritorna `None`
- [ ] ID token emesso per client A → `decode_id_token(expected_aud="A")` ritorna payload
- [ ] Cross-client token confusion attack: impossibile
- [ ] Test con [EXT]: usare [`oidctest`](https://github.com/openid-certification/oidctest) per validare

### TC-02.04 — ID Token `amr` Claim [Workstream F]
- [ ] Login solo password → `amr = ["pwd"]`
- [ ] Login password + TOTP → `amr = ["pwd", "totp"]`
- [ ] Login con passkey → `amr = ["webauthn"]`
- [ ] Login con backup code → `amr = ["pwd", "backup_code"]`
- [ ] `amr` assente se claim non richiesto (opzionale, non MUST)

### TC-02.05 — ID Token `acr` Claim [Workstream F]
- [ ] Login solo password → `acr = "1"`
- [ ] Login password + TOTP → `acr = "2"`
- [ ] Login con passkey → `acr = "3"`
- [ ] `acr` rispetta la gerarchia (più alto = più forte)

### TC-02.06 — ID Token `auth_time` Claim
- [ ] `auth_time` presente nell'ID token
- [ ] `auth_time` riflette la sessione corrente, non un login precedente
- [ ] (Workstream H) `auth_time` usato per `max_age` validation

### TC-02.07 — ID Token `nonce` Claim
- [ ] Se il client ha passato `nonce` in auth request, l'ID token include quel `nonce` intatto
- [ ] Se `nonce` assente in auth request, l'ID token non include `nonce`
- [ ] Validazione RP: il `nonce` ritornato = `nonce` mandato

### TC-02.08 — ID Token `at_hash` Claim [Workstream M]
- [ ] Se `response_type=code id_token`, l'ID token include `at_hash`
- [ ] `at_hash` = `base64url(SHA-256(access_token)[:16])` senza padding
- [ ] Se `response_type=id_token` (no code), `at_hash` assente (non richiesto)
- [ ] RP può validare `at_hash` ricalcolando

### TC-02.09 — ID Token Signature Validation [EXT]
- [ ] L'ID token è firmato con la chiave active del JWKS
- [ ] Algoritmo = `RS256` (o altro in `id_token_signing_alg_values_supported`)
- [ ] Header `kid` matcha una chiave nel JWKS
- [ ] Token scaduto (`exp` < now) → rifiutato
- [ ] Token con `alg=none` → rifiutato
- [ ] Token con algoritmo non supportato (es. `HS256`) → rifiutato

### TC-02.10 — ID Token Tampering [EXT]
- [ ] Modifica del `sub` → verifica firma fallisce
- [ ] Modifica dell'`aud` → verifica firma fallisce
- [ ] Modifica dell'`exp` → verifica firma fallisce
- [ ] (Workstream A) Anche se la firma è valida, `aud` mismatch con client corrente → rifiutato

### TC-02.11 — Access Token Validation
- [ ] `iss` presente e uguale a `discovery.issuer`
- [ ] `sub` presente
- [ ] `exp` presente e futuro
- [ ] `iat` presente
- [ ] `jti` presente (per revocation)
- [ ] `token_type` = `"access"`
- [ ] (Workstream A) Se emesso per un client, `aud` = client_id

### TC-02.12 — Refresh Token Validation
- [ ] `token_type` = `"refresh"`
- [ ] `jti` presente
- [ ] `scopes` presenti e uguali a quelli autorizzati

### TC-02.13 — Token Blacklist Check
- [ ] Dopo `revoke_token(jti)`, il token non è più decodificabile
- [ ] (Workstream J) La revoca è persistente e visibile cross-instance

---

## TS-03: Authorization Code + PKCE

**File**: `tests/conformance/test_authcode_pkce.py`

### TC-03.01 — Happy Path: Auth Code + PKCE [EXT]
- [ ] Client costruisce authorization URL con `code_challenge` + `code_challenge_method=S256`
- [ ] User completa login + consent
- [ ] Authorization server redirige a `redirect_uri?code=...&state=...`
- [ ] Client scambia code con `code_verifier` al token endpoint
- [ ] Risposta 200 con `access_token`, `id_token`, `refresh_token`, `expires_in`
- [ ] `id_token` decodificabile e valido

### TC-03.02 — PKCE Required for Public Client [Workstream B]
- [ ] Public client senza `code_challenge` → errore (no auth code emesso)
- [ ] Error message chiaro

### TC-03.03 — PKCE Required by Default (All Clients) [Workstream B]
- [ ] Confidential client con `require_pkce=True` senza `code_challenge` → errore
- [ ] Confidential client con `require_pkce=False` senza `code_challenge` → OK (legacy)

### TC-03.04 — PKCE Validation: Wrong Verifier
- [ ] `code_verifier` non corrisponde al `code_challenge` salvato → 400
- [ ] Error: `invalid_grant` o simile

### TC-03.05 — PKCE Validation: Missing Verifier
- [ ] Auth code con `code_challenge` salvato, client omette `code_verifier` → 400

### TC-03.06 — PKCE: Only S256 Accepted [EXT]
- [ ] `code_challenge_method=plain` → rifiutato esplicitamente
- [ ] `code_challenge_method=S256` → accettato
- [ ] `code_challenge_method` omesso ma `code_challenge` presente → assunto S256 o errore (definire)

### TC-03.07 — Authorization Code Reuse Prevention
- [ ] Dopo aver scambiato il code, riutilizzarlo → errore
- [ ] (Sicurezza) La revoca non è solo lato client ma enforced server-side

### TC-03.08 — Authorization Code Expiration
- [ ] Dopo `oauth2_authorization_code_expire_minutes`, il code è invalido

### TC-03.09 — Redirect URI Mismatch [EXT]
- [ ] `redirect_uri` in token request diverso da quello in auth request → errore
- [ ] Strict equality (no prefix/suffix match)

### TC-03.10 — Redirect URI Validation
- [ ] Redirect URI non registrato per il client → 400
- [ ] (Workstream P) Redirect URI `http://` non loopback → 400

### TC-03.11 — State Parameter [Workstream Q]
- [ ] State presente in auth request → ritornato intatto in redirect
- [ ] State assente in auth request → nessun state in redirect
- [ ] State presente ma client non lo usa (non c'è confronto server-side, è responsabilità del client)
- [ ] Warning loggato se state assente in auth request

### TC-03.12 — Scope Validation
- [ ] Scope non consentito per il client → 400 (o filtrato se `oauth2_reject_unknown_scopes=False`)
- [ ] OIDC standard scopes (`openid`, `profile`, `email`, `phone`, `address`) sempre permessi

### TC-03.13 — Client Authentication on Token Endpoint
- [ ] Confidential client senza autenticazione → 401
- [ ] Public client senza secret → OK
- [ ] `client_secret_basic` (HTTP Basic) → OK
- [ ] `client_secret_post` (form param) → OK
- [ ] Client secret errato → 401

### TC-03.14 — `client_id` Mismatch
- [ ] `client_id` nel token request diverso da quello nell'auth code → errore

### TC-03.15 — Consent Required
- [ ] Primo login con scope nuovi → consent screen mostrata
- [ ] Login successivo con stessi scope → no consent
- [ ] Login con scope aggiuntivi → consent screen ri-mostrata
- [ ] `require_consent=False` sul client → no consent mai

### TC-03.16 — MFA Interrupts Auth Code Flow [Workstream C]
- [ ] User con MFA abilitato, device non trusted → risposta `mfa_required` invece di redirect
- [ ] POST `/oauth2/mfa-verify` con code corretto → auth code emesso
- [ ] Session MFA scaduta → errore

### TC-03.17 — CSRF Protection [Workstream C]
- [ ] POST `/oauth2/authorize` con cookie di sessione valido ma senza CSRF token → 403
- [ ] POST con CSRF token valido → 200
- [ ] CSRF token scaduto → 403

---

## TS-04: Implicit Grant Removal [Workstream E]

**File**: `tests/conformance/test_implicit_removal.py`

### TC-04.01 — Discovery Compliance
- [ ] `grant_types_supported` non contiene `implicit`
- [ ] `response_types_supported` non contiene `token`, `id_token`, ecc.

### TC-04.02 — Endpoint Rejects Implicit
- [ ] Auth request con `response_type=token` → errore `unsupported_response_type`
- [ ] Auth request con `response_type=id_token` → errore
- [ ] Auth request con `response_type=code token` → errore

### TC-04.03 — Migration Audit
- [ ] Client esistenti con `grant_types` contententi `implicit` → migration script rimuove
- [ ] Audit log dell'operazione

---

## TS-05: Client Credentials

**File**: `tests/conformance/test_client_credentials.py`

### TC-05.01 — Happy Path
- [ ] POST `/oauth2/token` con `grant_type=client_credentials`, Basic auth, scope → 200
- [ ] Response: `access_token`, `token_type=Bearer`, `expires_in`, `scope`
- [ ] NO `refresh_token` (RFC 6749 §4.4.3)

### TC-05.02 — Client Authentication Required
- [ ] Senza credenziali → 401
- [ ] Credenziali errate → 401
- [ ] `WWW-Authenticate: Basic realm="OAuth2"` header presente

### TC-05.03 — Scope Validation
- [ ] Scope non consentito → 400 `invalid_scope`

### TC-05.04 — No User-Bound Claims
- [ ] L'access token non è legato a un `sub` utente
- [ ] `sub` = `client_id` o assente (RFC 6749 non lo richiede)
- [ ] UserInfo endpoint rifiuta questo token (no user corrispondente)

### TC-05.05 — (Workstream A) Audience Validation
- [ ] Access token client_credentials ha `aud` = client_id
- [ ] Decode con `expected_aud` mismatch → rifiutato

---

## TS-06: Refresh Token Rotation

**File**: `tests/conformance/test_refresh_rotation.py`

### TC-06.01 — Happy Path Rotation
- [ ] POST `/oauth2/token` con `grant_type=refresh_token` → 200
- [ ] Response include NUOVO `refresh_token` (diverso da quello usato)
- [ ] Vecchio refresh token ora ha `used=True`

### TC-06.02 — Reuse Detection [EXT]
- [ ] Refresh riusato dopo rotation → family intera revocata
- [ ] Tutti i discendenti del refresh token ora revoked
- [ ] User deve re-autenticarsi

### TC-06.03 — Client ID Binding
- [ ] Refresh con `client_id` diverso da quello originale → errore
- [ ] Refresh con `client_id` omesso → errore

### TC-06.04 — Expiration
- [ ] Dopo `refresh_token_expire_days`, il refresh è invalido

### TC-06.05 — Revocation
- [ ] Dopo `revoke_token`, il refresh non è più usabile
- [ ] (Multi-instance) Revoca visibile cross-instance [MULTI-INSTANCE]

### TC-06.06 — Scope Preservation
- [ ] Nuovo access token ha gli stessi scope del refresh (o subset se richiesto)

### TC-06.07 — Revoke All User Tokens
- [ ] `POST /api/tokens/refresh/revoke-all` → tutti i refresh dell'utente revocati

### TC-06.08 — Cookie-Based Refresh
- [ ] `POST /api/auth/refresh` con cookie httpOnly → nuovo access + refresh
- [ ] Cookie viene ruotato

---

## TS-07: Token Revocation (RFC 7009)

**File**: `tests/conformance/test_revocation.py`

### TC-07.01 — Happy Path Refresh Token
- [ ] `POST /oauth2/revoke` con refresh_token valido + client auth → 200
- [ ] Dopo revoca, il refresh non è più usabile

### TC-07.02 — Happy Path Access Token
- [ ] `POST /oauth2/revoke` con access_token valido + client auth → 200
- [ ] Dopo revoca, l'access token non è più decodificabile (blacklist)

### TC-07.03 — `token_type_hint` [EXT]
- [ ] `token_type_hint=refresh_token` → tenta refresh prima
- [ ] `token_type_hint=access_token` → tenta access prima
- [ ] `token_type_hint` omesso → tenta refresh poi access (RFC raccomanda refresh prima)

### TC-07.04 — Invalid Token Returns 200
- [ ] Token inesistente → 200 con body vuoto (no information leak)
- [ ] Client non autenticato → 200 con body vuoto
- [ ] Client autenticato con token di un altro client → 200 con body vuoto

### TC-07.05 — Client Authentication Required
- [ ] Senza client auth → 200 (no info leak) MA non revoca
- [ ] Con client auth errata → 200, non revoca
- [ ] Con client auth corretta → revoca effective

### TC-07.06 — (Workstream J) Cross-Instance Revocation [MULTI-INSTANCE]
- [ ] Revoca su instance A → token invalido su instance B

---

## TS-08: Token Introspection (RFC 7662)

**File**: `tests/conformance/test_introspection.py`

### TC-08.01 — Active Token Response
- [ ] `POST /oauth2/introspect` con access_token valido + client auth → 200
- [ ] Response: `active: true`, `scope`, `client_id`, `token_type`, `exp`, `iat`, `sub`
- [ ] Se user-bound: `email`, `username`

### TC-08.02 — Inactive Token Response
- [ ] Token scaduto → `active: false`
- [ ] Token revocato → `active: false`
- [ ] Token inesistente → `active: false`
- [ ] Token di altro client → `active: false` (o errore)

### TC-08.03 — Refresh Token Introspection
- [ ] Refresh valido → `active: true`, `token_type: "refresh_token"`
- [ ] Refresh revocato → `active: false`

### TC-08.04 — Client Authentication Required
- [ ] Senza client auth → 401
- [ ] Client errato → 401
- [ ] `WWW-Authenticate` header presente

### TC-08.05 — `token_type_hint`
- [ ] Hint corretto → introspection più veloce
- [ ] Hint errato → fallback a tentativo altro tipo
- [ ] Hint omesso → tenta entrambi

### TC-08.06 — (Workstream A) Audience Match
- [ ] Resource server con `client_id=A` introspecta token emesso per `client_id=B` → può vedere i metadata ma `aud` non corrisponde
- [ ] Comportamento: l'AS ritorna metadata, il RS decide se accettare

---

## TS-09: Dynamic Client Registration (RFC 7591)

**File**: `tests/conformance/test_dcr.py`

### TC-09.01 — Happy Path [EXT]
- [ ] `POST /oauth2/register` con redirect_uris validi → 201
- [ ] Response: `client_id`, `client_secret`, `redirect_uris`, `client_id_issued_at`, `client_secret_expires_at: 0`
- [ ] `client_secret` ritornato SOLO in questa response

### TC-09.02 — Required Fields
- [ ] Senza `redirect_uris` → 400
- [ ] Con `redirect_uris` vuoto → 400

### TC-09.03 — Redirect URI HTTPS Required
- [ ] `redirect_uris=["http://evil.com/callback"]` → 400
- [ ] `redirect_uris=["https://good.com/callback"]` → OK
- [ ] `redirect_uris=["http://localhost:3000/callback"]` → OK (RFC 8252)
- [ ] `redirect_uris=["http://127.0.0.1:3000/callback"]` → OK
- [ ] `redirect_uris=["https://localhost/callback"]` → OK

### TC-09.04 — `client_secret` Strength
- [ ] `client_secret` è almeno 32 caratteri random
- [ ] Salvato hashed (bcrypt), non in chiaro

### TC-09.05 — `grant_types` Validation [Workstream P]
- [ ] `grant_types=["authorization_code", "refresh_token"]` → OK
- [ ] `grant_types=["implicit"]` → rifiutato (rimosso)
- [ ] `grant_types=["client_credentials"]` → OK
- [ ] `grant_types=["unknown"]` → 400

### TC-09.06 — `token_endpoint_auth_method` [Workstream P]
- [ ] `client_secret_basic` → client confidential
- [ ] `client_secret_post` → client confidential
- [ ] `none` → client pubblico (PKCE required)
- [ ] `none` con `require_pkce=False` → rifiutato

### TC-09.07 — Scope Validation
- [ ] `scope` opzionale, default = read
- [ ] Scope multipli space-separated → OK

### TC-09.08 — Rate Limiting
- [ ] 11 registrazioni consecutive in 1h → 429 sulla 11ª

### TC-09.09 — Audit Log
- [ ] Ogni registrazione loggata con client_id, client_name, grant_types

### TC-09.10 — `software_statement` Validation [Workstream P]
- [ ] `software_statement` non-JWT → 400
- [ ] `software_statement` JWT con signature invalida → 400

---

## TS-10: DCR Management (RFC 7592) [Workstream K]

**File**: `tests/conformance/test_dcr_management.py`

### TC-10.01 — GET Client Config [EXT]
- [ ] `GET /oauth2/register/{client_id}` con client auth (Basic) → 200
- [ ] Response: client config SENZA `client_secret`
- [ ] Senza client auth → 401
- [ ] Client inesistente → 404

### TC-10.02 — PUT Update Client
- [ ] `PUT /oauth2/register/{client_id}` con nuovo `client_name` → 200
- [ ] Modifica persistent
- [ ] Modifica di `redirect_uris` valida (HTTPS) → OK
- [ ] Modifica di `redirect_uris` invalida (HTTP non-loopback) → 400
- [ ] Update di `client_secret` NON permesso via PUT (usare rotate endpoint)

### TC-10.03 — DELETE Client
- [ ] `DELETE /oauth2/register/{client_id}` con client auth → 204
- [ ] Dopo delete, il client non esiste più
- [ ] Token emessi prima del delete → ancora validi fino a scadenza
- [ ] Nuove auth request per quel client → falliscono

### TC-10.04 — Authentication Method
- [ ] Client authentication richiesta per ogni operazione
- [ ] HTTP Basic con client_id/secret funziona
- [ ] Client secret errato → 401

### TC-10.05 — Rate Limiting
- [ ] Update/delete hanno rate limit (es. 30/hour, 20/hour)

---

## TS-11: UserInfo Endpoint

**File**: `tests/conformance/test_userinfo.py`

### TC-11.01 — Happy Path
- [ ] `GET /oauth2/userinfo` con Bearer access_token (scope `openid`) → 200
- [ ] Response include `sub`

### TC-11.02 — Scope-Based Claims [EXT]
- [ ] Scope `openid` → solo `sub`
- [ ] Scope `profile` → aggiunge `name`, `given_name`, `family_name`, `preferred_username`, `picture`, `locale`, `zoneinfo`, `updated_at`
- [ ] Scope `email` → aggiunge `email`, `email_verified`
- [ ] Scope `phone` → aggiunge `phone_number`, `phone_number_verified`
- [ ] Scope `address` → aggiunge `address`
- [ ] Combinazioni multiple → tutti i claim corretti

### TC-11.03 — OpenID Scope Required
- [ ] Access token senza `openid` scope → 403 `insufficient_scope`

### TC-11.04 — Bearer Token Validation
- [ ] Senza token → 401 con `WWW-Authenticate: Bearer`
- [ ] Token invalido → 401
- [ ] Token scaduto → 401

### TC-11.05 — POST Support
- [ ] UserInfo supporta anche `POST` (RFC 7628)

### TC-11.06 — `address` Claim [Workstream N]
- [ ] User con address popolato + scope address → claim ritornato
- [ ] User senza address + scope address → claim assente
- [ ] Formato address conforme a OIDC (oggetto JSON)

### TC-11.07 — Custom Claims [Workstream N]
- [ ] `permissions` claim rimosso OPPURE dichiarato in `claims_supported`
- [ ] `roles` claim rimosso OPPURE dichiarato in `claims_supported`

### TC-11.08 — (Workstream A) Audience Mismatch
- [ ] UserInfo accessibile solo se l'audience del token = il client corrente
- [ ] (O implementazione alternativa) audience = l'AS stesso, il client è identificato diversamente

---

## TS-12: RP-Initiated Logout

**File**: `tests/conformance/test_rp_logout.py`

### TC-12.01 — Happy Path GET
- [ ] `GET /oauth2/logout?id_token_hint=...` → 303 redirect
- [ ] Se `post_logout_redirect_uri` valido → redirect a quella URL
- [ ] `state` ritornato nel redirect

### TC-12.02 — Happy Path POST
- [ ] `POST /oauth2/logout` con Bearer token → 200
- [ ] Audit log dell'evento

### TC-12.03 — `id_token_hint` Validation
- [ ] Senza `id_token_hint` (in dev) → errore o accettato con warning
- [ ] `id_token_hint` invalido → 400 o procedi senza subject
- [ ] `id_token_hint` valido → subject estratto per audit

### TC-12.04 — `post_logout_redirect_uri` Validation [Workstream D — P0]
- [ ] Production + URI non registrato → 400
- [ ] Production + URI registrato → 303
- [ ] Dev mode + URI qualsiasi → 303 con warning loggato
- [ ] Strict equality, no pattern matching

### TC-12.05 — `state` Parameter
- [ ] `state` passato → ritornato nel redirect
- [ ] `state` assente → nessun state nel redirect

### TC-12.06 — Logout Effective
- [ ] (Workstream L) Logout reale invalida cookie di sessione + refresh tokens
- [ ] Audit log di tutti i logout

### TC-12.07 — `allowed_post_logout_redirect_uris`
- [ ] Client ha lista separata di URI permessi per logout
- [ ] Verifica strict equality

---

## TS-13: Back-Channel & Front-Channel Logout [Workstream L]

**File**: `tests/conformance/test_backchannel_logout.py` e `test_frontchannel_logout.py`

### TC-13.01 — `sid` Claim
- [ ] ID token include `sid` (session ID)
- [ ] `sid` è univoco per sessione

### TC-13.02 — Back-Channel Logout Trigger
- [ ] Quando l'utente fa logout, AS invia POST a `backchannel_logout_uri` di tutti i client con sessione attiva
- [ ] Il body include un logout_token firmato

### TC-13.03 — Logout Token Claims
- [ ] `iss` = issuer
- [ ] `aud` = client_id del client ricevente
- [ ] `iat`, `exp`, `jti` presenti
- [ ] `sub` (opzionale)
- [ ] `sid` (opzionale)
- [ ] `events: {"http://schemas.openid.net/event/backchannel-logout": {}}`

### TC-13.04 — Logout Token Signature
- [ ] Verificabile con il JWKS
- [ ] Algoritmo RS256

### TC-13.05 — Front-Channel Logout
- [ ] RP-Initiated Logout include `<iframe>` per ogni client con `frontchannel_logout_uri`
- [ ] L'iframe src contiene `iss`, `sid`

### TC-13.06 — `backchannel_logout_session_required`
- [ ] Se true, il logout_token include `sid`
- [ ] Se false, può essere omesso

### TC-13.07 — Discovery Metadata
- [ ] `backchannel_logout_supported: true`
- [ ] `frontchannel_logout_supported: true`
- [ ] `backchannel_logout_session_supported: true` (se supportato)

---

## TS-14: CSRF Protection [Workstream C]

**File**: `tests/conformance/test_csrf.py`

### TC-14.01 — CSRF Token Required with Session
- [ ] POST `/oauth2/authorize` con cookie di sessione valido ma senza CSRF token → 403
- [ ] POST con CSRF token valido → 200
- [ ] POST con CSRF token scaduto (> 1h) → 403

### TC-14.02 — CSRF Token Rotation
- [ ] CSRF token monouso (dopo uso, vecchio token non più valido)
- [ ] CSRF token associato alla sessione

### TC-14.03 — CSRF Token Generation
- [ ] GET `/oauth2/authorize` (page render) → CSRF token in form + cookie
- [ ] Doppia submit cookie pattern: cookie + form field devono matchare

### TC-14.04 — No CSRF Without Session
- [ ] POST senza cookie di sessione (solo email+password) → CSRF opzionale o non richiesto
- [ ] Tuttavia, state parameter sempre raccomandato

### TC-14.05 — Audit Log
- [ ] Ogni mismatch CSRF loggato con severity high
- [ ] Rate limit su IP dopo N mismatch (defense-in-depth)

---

## TS-15: Token Blacklist Persistence [Workstream J]

**File**: `tests/conformance/test_blacklist_persistence.py`

### TC-15.01 — Persistent Storage
- [ ] Revoca di un `jti` persiste nello storage backend
- [ ] Sopravvive a restart del processo

### TC-15.02 — Cross-Instance [MULTI-INSTANCE]
- [ ] Revoca su instance A → token rifiutato su instance B (con storage condiviso)
- [ ] Revoca su instance A → token accettato su instance B (con storage non condiviso) → FAIL chiaro

### TC-15.03 — TTL Cleanup
- [ ] Entry con `exp < now` rimosse automaticamente
- [ ] Cleanup non rimuove entry ancora attive

### TC-15.04 — Backend Selection
- [ ] `blacklist_backend=memory` → in-process (default per dev)
- [ ] `blacklist_backend=storage` → persistente (default per prod)
- [ ] Failover graceful se backend non disponibile

### TC-15.05 — Performance
- [ ] Lookup < 5ms anche con 100k entry
- [ ] (Con cache in-memory) Hot path ancora più veloce

---

## TS-16: Device Authorization (RFC 8628) [Workstream S]

**File**: `tests/conformance/test_device_flow.py`

### TC-16.01 — Device Code Request [EXT]
- [ ] `POST /oauth2/device` con client_id → 200
- [ ] Response: `device_code`, `user_code`, `verification_uri`, `verification_uri_complete`, `expires_in`, `interval`

### TC-16.02 — User Code Format
- [ ] `user_code` è human-friendly (es. `WDJB-MJHT`)
- [ ] `user_code` non contiene caratteri ambigui (0/O, 1/l/I)

### TC-16.03 — Polling: Authorization Pending
- [ ] `POST /oauth2/device/token` con `device_code` e `grant_type=urn:ietf:params:oauth:grant-type:device_code`
- [ ] User non ha ancora approvato → 400 `authorization_pending`

### TC-16.04 — Polling: Slow Down
- [ ] Client polling troppo veloce → 400 `slow_down`
- [ ] Client aumenta `interval` di 5s

### TC-16.05 — Polling: Access Denied
- [ ] User nega l'accesso → 400 `access_denied`

### TC-16.06 — Polling: Token Issued
- [ ] User approva → polling ritorna access token
- [ ] Response: `access_token`, `token_type`, `expires_in`, `refresh_token` (se `offline_access`)

### TC-16.07 — Device Code Expiration
- [ ] Dopo `expires_in` secondi, il device code è invalido
- [ ] User code rimane valido per UI

### TC-16.08 — Discovery Update
- [ ] `device_authorization_endpoint` presente
- [ ] `grant_types_supported` include `urn:ietf:params:oauth:grant-type:device_code`

### TC-16.09 — User Approval UI
- [ ] UI per inserire user code e approvare/negare
- [ ] Mostra client_name, scope richiesti
- [ ] Logout invalida la sessione del user (anche se device code ancora pending)

---

## TS-17: `prompt` Parameter [Workstream G]

**File**: `tests/conformance/test_prompt.py`

### TC-17.01 — `prompt=none` + Not Authenticated [EXT]
- [ ] Auth request con `prompt=none` + utente non autenticato → redirect con `error=login_required`
- [ ] `state` ritornato intatto
- [ ] NO HTML form mostrato (no UI)

### TC-17.02 — `prompt=none` + Authenticated
- [ ] Auth request con `prompt=none` + utente autenticato → redirect con `code`
- [ ] No re-prompting per password
- [ ] Se consent mancante → `error=consent_required`
- [ ] Se `select_account` sarebbe appropriato → `error=account_selection_required`

### TC-17.03 — `prompt=login`
- [ ] Auth request con `prompt=login` + utente autenticato → forza re-login
- [ ] Sessione precedente invalidata
- [ ] Auth code emesso solo dopo re-login

### TC-17.04 — `prompt=consent`
- [ ] Auth request con `prompt=consent` + consenso già dato → mostra comunque consent screen
- [ ] User può revocare consensi precedenti

### TC-17.05 — `prompt=select_account` [E2E]
- [ ] Auth request con `prompt=select_account` → mostra account selector
- [ ] (Con 1 solo account) → salta selezione

### TC-17.06 — `prompt=none` + max_age Exceeded [Workstream H]
- [ ] Se `max_age` superato, `prompt=none` → `error=login_required`

### TC-17.07 — Multiple Prompt Values
- [ ] `prompt=login consent` → entrambi enforced
- [ ] `prompt=none login` → contraddizione, errore OIDC `invalid_request`

### TC-17.08 — No `prompt` (Default)
- [ ] Comportamento attuale preservato (UI di login)

---

## TS-18: `max_age` Parameter [Workstream H]

**File**: `tests/conformance/test_max_age.py`

### TC-18.01 — `max_age=0`
- [ ] Sempre forza re-login
- [ ] Anche se sessione valida 1 secondo fa

### TC-18.02 — `max_age=3600` + Fresh Auth
- [ ] Auth time = now → no re-login
- [ ] Auth code emesso normalmente

### TC-18.03 — `max_age=3600` + Stale Auth
- [ ] Auth time = 2h fa → forza re-login
- [ ] Trattato come `prompt=login`

### TC-18.04 — `max_age` + `prompt=none`
- [ ] Se max_age exceeded, `prompt=none` → `error=login_required` (no UI)

### TC-18.05 — `auth_time` Accuracy
- [ ] `auth_time` claim riflette auth time reale della sessione, non `user.last_login`
- [ ] Verificabile estraendo il claim e confrontando con un'altra fonte

---

## TS-19: `id_token_hint` [Workstream I]

**File**: `tests/conformance/test_id_token_hint.py`

### TC-19.01 — Pre-filled Login
- [ ] Auth request con `id_token_hint` valido → login page pre-populated con email/user
- [ ] User deve solo inserire password (non email)

### TC-19.02 — Invalid id_token_hint
- [ ] Token invalido/scaduto → ignorato (non errore)
- [ ] Login normale senza pre-fill

### TC-19.03 — `id_token_hint` + `prompt=none`
- [ ] Combinazione: l'AS può identificare l'utente anche senza UI
- [ ] Se utente autenticato e `sub` in id_token_hint = utente corrente → ok
- [ ] Se mismatch → errore o re-login

---

## TS-20: `at_hash` / `c_hash` [Workstream M]

**File**: `tests/conformance/test_at_hash.py`

### TC-20.01 — `at_hash` Computation
- [ ] ID token con access token → `at_hash` = `base64url(SHA-256(access_token)[:16])`
- [ ] No padding in base64url
- [ ] Validabile dal client

### TC-20.02 — `at_hash` When `response_type=code id_token`
- [ ] `at_hash` presente

### TC-20.03 — `at_hash` When `response_type=id_token` (no code)
- [ ] `at_hash` assente (non richiesto, sarebbe ridondante)

### TC-20.04 — `c_hash` (Hybrid Flow)
- [ ] Se supportato `response_type=code id_token`, `c_hash` presente
- [ ] Computation: `base64url(SHA-256(code)[:16])`
- [ ] (NOTA: il flow `code id_token` non è attualmente supportato da AuthGlow)

---

## TS-21: Rate Limiting [Workstream O]

**File**: `tests/conformance/test_rate_limit.py`

### TC-21.01 — `/api/token`
- [ ] 6 chiamate in 1 minuto → 429 sulla 6ª

### TC-21.02 — `/oauth2/authorize`
- [ ] 11 chiamate in 1 minuto → 429 sull'11ª

### TC-21.03 — `/oauth2/mfa-verify`
- [ ] 4 chiamate in 1 minuto → 429 sulla 4ª

### TC-21.04 — `/oauth2/revoke`
- [ ] 21 chiamate in 1 minuto → 429 sulla 21ª

### TC-21.05 — `/oauth2/introspect`
- [ ] 61 chiamate in 1 minuto → 429 sulla 61ª

### TC-21.06 — `/.well-known/openid-configuration`
- [ ] 61 chiamate in 1 minuto → 429 sulla 61ª

### TC-21.07 — `/.well-known/jwks.json`
- [ ] 61 chiamate in 1 minuto → 429 sulla 61ª

### TC-21.08 — `/oauth2/userinfo`
- [ ] 121 chiamate in 1 minuto → 429 sulla 121ª

### TC-21.09 — `/oauth2/logout`
- [ ] 31 chiamate in 1 minuto → 429 sulla 31ª

### TC-21.10 — Rate Limit Headers
- [ ] Response include `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`
- [ ] Response 429 include `Retry-After`

---

## TS-22: State Parameter [Workstream Q]

**File**: `tests/conformance/test_state.py`

### TC-22.01 — State Echo
- [ ] State in auth request → state nel redirect intatto
- [ ] State URL-encoded correttamente

### TC-22.02 — State Missing Warning
- [ ] Auth request senza state → warning loggato
- [ ] Nessun errore (state è raccomandato, non required)

### TC-22.03 — State Length Validation
- [ ] State molto lungo (> 1KB) → 400 o troncato
- [ ] State vuoto `state=` → trattato come assente

---

## TS-23: FAPI / OAuth 2.1 Alignment [Workstream T]

**File**: `tests/conformance/test_fapi.py`

### TC-23.01 — No Implicit Grant [EXT]
- [ ] FAPI richiede solo authorization_code + PKCE
- [ ] AuthGlow supporta solo questo dopo i fix

### TC-23.02 — No Resource Owner Password [EXT]
- [ ] FAPI vieta il password grant per client di terze parti
- [ ] AuthGlow ha `/api/token` ma documentato come first-party only

### TC-23.03 — PKCE Required [EXT]
- [ ] FAPI richiede PKCE per tutti i client
- [ ] AuthGlow: `require_pkce=True` di default dopo Workstream B

### TC-23.04 — Sender-Constrained Tokens (DPoP)
- [ ] (Opzionale) AuthGlow supporta DPoP-bound access tokens
- [ ] RFC 9449 conformance test

### TC-23.05 — PAR (Pushed Authorization Requests)
- [ ] (Opzionale) Supporto RFC 9126 per pushed authorization requests

### TC-23.06 — JARM (JWT-secured Authorization Response Mode)
- [ ] (Opzionale) Authorization response firmato come JWT

---

## TS-24: JWKS Status Disclosure [Workstream R]

**File**: `tests/conformance/test_jwks_status.py`

### TC-24.01 — Status Endpoint
- [ ] `GET /oauth2/jwks/status` → 200 con keyring completo
- [ ] Ogni kid ha `status`, `created_at`, `algorithm`, `key_size`
- [ ] Eventuali `retired_at`, `revoked_at` per chiavi non attive

### TC-24.02 — Rate Limiting
- [ ] Endpoint ha rate limit

### TC-24.03 — Admin Auth (Opzionale)
- [ ] Se richiesto, solo admin può accedere
- [ ] Senza auth, 401 o 200 con info limitate (definire policy)

---

## Test di Conformance Globale (OpenID Foundation)

### TC-EXT-01 — OpenID Foundation Conformance Profile [EXT]
- [ ] Eseguire la suite [OpenID Foundation](https://www.certification.openid.net/) per il profilo "Basic OP"
- [ ] Risultato: PASS su tutti i test
- [ ] Report salvato in `docs/conformance_reports/`

### TC-EXT-02 — FAPI Conformance (Se implementato)
- [ ] Eseguire suite FAPI-Read-Write se AuthGlow vuole certificazione FAPI
- [ ] Tutti i test passano

### TC-EXT-03 — OAuth 2.0 Security BCP [EXT]
- [ ] Verificare compliance con le raccomandazioni del draft OAuth Security BCP
- [ ] Checklist completata in `docs/SECURITY_BCP_CHECKLIST.md`

### TC-EXT-04 — RFC 8414 (OAuth Authorization Server Metadata)
- [ ] Verificare che il discovery sia anche un valido AS metadata (RFC 8414)
- [ ] Campi: `issuer`, `authorization_endpoint`, `token_endpoint`, ecc.

### TC-EXT-05 — E2E con Real RPs [E2E]
- [ ] Test con Auth0 SPA SDK
- [ ] Test con NextAuth
- [ ] Test con Keycloak come RP (consume AuthGlow come OP)
- [ ] Test con oidc-client-js
- [ ] Tutti i flow funzionano

---

## Comandi di Esecuzione

```bash
# Tutti i test di conformance
pytest -q tests/conformance/ -n auto --tb=short

# Singolo workstream
pytest -q tests/conformance/test_discovery.py
pytest -q tests/conformance/test_id_token.py
pytest -q tests/conformance/test_authcode_pkce.py

# Test con output verbose per debugging
pytest tests/conformance/test_id_token.py -v -s

# Test specifico
pytest tests/conformance/test_id_token.py::TestIDTokenAudience::test_cross_client_confusion -v

# Test E2E (richiede Playwright)
pytest tests/conformance/test_prompt.py -v --headed
```

## CI Integration

Aggiungere a `.github/workflows/conformance.yml`:

```yaml
name: OIDC Conformance Tests
on: [push, pull_request]
jobs:
  conformance:
    runs-on: ubuntu-latest
    services:
      authglow:
        # ... build & start AuthGlow
    steps:
      - uses: actions/checkout@v3
      - name: Install dependencies
        run: pip install -r backend/requirements.txt -r backend/requirements-test.txt
      - name: Run conformance tests
        run: pytest -q backend/tests/conformance/ -n auto --tb=line
      - name: Upload results
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: conformance-results
          path: backend/test-results/
```

## Metriche di Successo

| Metrica | Target |
|---|---|
| Test pass rate | 100% |
| Code coverage su `services/{jwt,oidc,oauth2}.py` | > 90% |
| Test E2E con RP reali | ≥ 4 RPs testati |
| OpenID Foundation Conformance | PASS tutti i moduli applicabili |
| RFC compliance | Vedi tabella in `CONFORMANCE_REMEDIATION_PLAN.md` §6 → tutte a 🟢 |

## Note Finali

- Ogni test case in questo file è una checkbox che va spuntata **solo dopo aver visto passare quel test specifico**.
- Per test [EXT], salvare l'output in `docs/conformance_reports/{test_id}.log`.
- Per test [E2E], salvare screenshot in `docs/conformance_screenshots/`.
- L'ordine consigliato di esecuzione: TS-01 → TS-02 → TS-03 → TS-04 → TS-05 → TS-06 → TS-07 → TS-08 → TS-09 → TS-10 → TS-11 → TS-12 → TS-13 → TS-14 → TS-15 → TS-16 → TS-17 → TS-18 → TS-19 → TS-20 → TS-21 → TS-22 → TS-23 → TS-24 → TC-EXT-*.
