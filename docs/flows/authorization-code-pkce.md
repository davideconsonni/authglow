# Authorization Code + PKCE Flow

Autenticazione autorizzazione con redirect del browser. È il flusso
principale per app web e mobile e l'unico che produce un ID token
(quando è richiesto lo scope `openid`).

---

## Standard

- **Authorization Code Grant** — RFC 6749 §4.1
- **PKCE (Proof Key for Code Exchange)** — RFC 7636
- **OAuth 2.0 Security BCP** — RFC 9700
- OpenID Connect Core (per lo scope `openid`) — OIDC Core 1.0

---

## Come lo supportiamo

Due passaggi principali: l'**authorization request** (browser → AuthGlow)
e l'**token request** (client → server, backchannel).

### 1. Authorization Request

```
POST /api/oauth2/authorize                (form URL-encoded)
```

Parametri (form):

| Parametro              | Obbligatorio | Note |
|------------------------|--------------|------|
| `client_id`            | SÌ | Deve esistere e essere attivo. |
| `redirect_uri`         | SÌ | Match **esatto** contro `redirect_uris` registrati. |
| `scope`                | sì (default `read`) | Validato contro gli scope del client. |
| `state`                | **SÌ** | Opaque nonce ≥ 32 caratteri (RFC 6819 §4.4.1.8) — custom, vedi sotto. |
| `code_challenge`       | SÌ | PKCE obbligatorio. |
| `code_challenge_method`| `S256` | Solo `S256`, `plain` rifiutato. |
| `response_type`        | `code` | Implicit rifiutato. |
| `nonce`                | no | Echo nell'ID token. |
| `prompt`               | no | `none`, `login`, `consent`, `select_account`. |
| `max_age`              | no | Forza re-auth se `auth_time` più vecchia. |
| `id_token_hint`        | no | Pre-identifica l'utente. |
| `claims`               | no | OIDC Core §5.5 — filtra claim dell'ID token (JSON). |
| `acr_values`          | no | Valore richiesto per l'ID token. |

L'endpoint:

1. Verifica client, PKCE, redirect_uri, stato (VAPT-044).
2. È autenticato l'utente? Cookie-first, poi `email`+`password`.
3. Risponde MFA se richiesta, poi una pagina single-page (login → MFA → consent).
4. Emette un **authorization code** (gettono monouso, breve vita) e redirige:

```
HTTP 302  Location: {redirect_uri}?code={code}&state={state}
```

Se `prompt=none` e non autenticato → `302 ?error=login_required`.

### 2. Token request (backchannel)

```
POST /oauth2/token   (form URL-encoded)   grant_type=authorization_code
```

- `code`, `redirect_uri`, `code_verifier` sono obbligatori.
- Client auth obbligatorio per client **confidential** (Basic o `client_assertion`);
  i client **pubblici** si autenticano solo con il `client_id` (PKCE funge da auth).
- PKCE `S256`: `SHA256(code_verifier)` MUST match `code_challenge` salvato.
- Il codice viene **marcato usato** (CAS-protetto) → non riutilizzabile.
- Emette: **access token** (JWT), **refresh token** (con rotazione), e
  **ID token** quando `openid` è tra gli scope.

```
{
  "access_token":  "…",
  "token_type":    "Bearer",        // "DPoP" se client legato a DPoP
  "expires_in":    3600,
  "refresh_token": "…",
  "scope":         "openid profile",
  "id_token":      "…"
}
```

---

## Conformità

| Aspetto | Stato |
|--------|-------|
| PKCE | **Più severo dello standard**. OBBLIGATORIO per tutti i client (non solo public), solo `S256`. RFC 7636 + Security BCP richiedono PKCE per i client **pubblici**; qui è richiesto **anche per i confidential**. |
| Redirect URI | Esatto match, registro dinamico. |
| State | **Custom, più severo**: campo **obbligatorio** e validato come nonce opaco (VAPT-044). Lo standard lo considera raccomandato, non obbligatorio. |
| Flusso consent | **Custom UX**: login, MFA e consent nella **stessa pagina** `/oauth2/authorize` (no redirect tra fasi). |
| Memoria consenso | Consent "remember" → `consent/check` auto-crea il code senza ripassare dalla pagina. |
| `response_type` | Solo `code`. **Implicit flow rifiutato** (a livello di modello client). |
| ACR | Value `0/1/2/3` (password, MFA, passkey) esposti nell'ID token. |

---

## Endpoint coinvolti

| Method | Path | Ruolo |
|--------|------|-------|
| POST | `/api/oauth2/authorize` | Authorization request + login + MFA + consent |
| POST | `/oauth2/token` | Scambia code+verifier per token |
| GET | `/api/oauth2/authorize-info` | Info pubbliche client per la pagina |
| GET | `/api/oauth2/consent/check` | Check consentimento memorizzato |
| POST | `/oauth2/consent` | Decisione di consenso |
| GET | `/oauth2/userinfo` | Claim utente (se richiesti) |

---

> **Custom vs standard**: nel rispetto dello standard, il flusso aggiunge
> (1) PKCE obbligatoria ovunque, (2) `state` obbligatorio e validato, (3)
> UI single-page, (4) refresh-token rotation, (5) rifiuto esplicito di
> `implicit` e `password`. Tutto il resto segue RFC 6749 / RFC 7636.