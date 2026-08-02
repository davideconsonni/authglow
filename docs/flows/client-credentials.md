# Client Credentials Flow

Autenticazione **machine-to-machine**: il client si autentica come tale,
senza utente finale.

---

## Standard

- **Client Credentials Grant** — RFC 6749 §4.4

---

## Come lo supportiamo

```
POST /oauth2/token   (form URL-encoded)   grant_type=client_credentials
```

Parametri:

| Parametro       | Obbligatorio | Note |
|-----------------|--------------|------|
| `grant_type`    | SÌ | `client_credentials` |
| `client_id`     | SÌ | Form oppure HTTP Basic. |
| `client_secret` | SÌ | Form oppure HTTP Basic. |
| `scope`         | no | Validato contro `allowed_scopes` del client. |
| `client_assertion` / `client_assertion_type` | no | JWT-Bearer auth (RFC 7523), alternativa forte al secret (T.2). |

Client authentication:

1. `client_secret_basic` (HTTP Basic) o `client_secret_post` (form).
2. Oppure **JWT-Bearer** `client_assertion` (HS256/RS256) — FAPI-aligned.

Lo scope è sempre validato: gli scope sconosciuti vengono filtrati o
rifiutati (vedi `oauth2_reject_unknown_scopes`).

Risposta:

```
{
  "access_token": "…",
  "token_type":   "Bearer",        // "DPoP" se client legato a DPoP
  "expires_in":   3600,
  "scope":        "api"
}
```

Il subject del token è il `client_id` (nessun utente). Se il client è
`dpop_bound`, la risposta richiede un DPoP proof e il token esce con `cnf`.

---

## Conformità

| Aspetto | Stato |
|--------|-------|
| Standard | RFC 6749 §4.4 **conforme**. |
| Scope | **Strettamente validato** — gli scope non in `allowed_scopes` sono filtrati o rifiutati (nessuno scope custom emesso). |
| Client che NON consentono `client_credentials` | Rifiutati via `grant_types`. |
| Machine credential | Client `access_token_lifetime` applicato per-client. |
| ROPC | Mai consentito qui. |

---

## Endpoint

| Method | Path | Ruolo |
|--------|------|-------|
| POST | `/oauth2/token` | Scambia le credenziali del client per un access token |

---

> **Custom vs standard**: conforme a RFC 6749 §4.4. Le uniche differenze
> sono la validazione stretta degli scope e il supporto alternativo di
> `client_assertion` (RFC 7523) come metodo di autenticazione — entrambe
> aggiunte, mai un override.