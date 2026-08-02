# First-Party Browser Login (`/api/token`)

Login utente con email+password **riservato al frontend AuthGlow** stesso.
**NON è un grant OAuth2 standard** — non va usato da client di terze parti.

---

## Standard

Nessuno. Questo è un flusso **custom** proprietario che NON implementa un
grant definito da RFC 6749. È il "login classico" first-party.

---

## Come lo supportiamo

```
POST /api/token   (form URL-encoded)
```

Parametri: `username` (email), `password`, `grant_type=password` (accettato
solo qui dal frontend, non sul `/oauth2/token`).

1. Verifica le credenziali (bcrypt + re-hash trasparente se il costo cambia).
2. Ottiene l'utente; attiva account lockout su tentativi falliti.
3. Emette **access token** JWT e **refresh token** (con rotazione).
4. Imposta **cookie di sessione httpOnly** (`auth_cookie_access_name`,
   `auth_cookie_refresh_name`) sulla risposta.

Il browser non deve toccare i token in JS: la sessione viaggia nei cookie.

---

## Conformità

È **esplicitamente non-standard**. Si differenzia dal `/oauth2/token` per:

| Aspetto | `/oauth2/token` | `/api/token` |
|---------|-----------------|--------------|
| Grant | `authorization_code`, `client_credentials`, `refresh_token`, `device_code` | password (custom, non-OAuth) |
| Client auth | Richiesto | Nessuno (first-party) |
| Session | access token in body | access + refresh token in **cookie httpOnly** |
| Uso | Client di terze parti | Solo il frontend AuthGlow |

**Per questo endpoint:**
- `grant_type=password` NON è OAuth2 ROPC nel senso RFC 6749 §4.3: è
  un login proprietario del frontend.
- Risulta "unsupported" sul token endpoint standard (`/oauth2/token`).
- Da usare **solo** dalla prima parte; non esporlo a terzi.

---

## Endpoint

| Method | Path | Ruolo |
|--------|------|-------|
| POST | `/api/token` | Login email+password → set cookie session |

---

> **Custom vs standard**: interamente custom. Serve al frontend, non è un
> grant OAuth2. I client di terze parti devono usare `authorization_code`
> + PKCE (vedi `authorization-code-pkce.md`).