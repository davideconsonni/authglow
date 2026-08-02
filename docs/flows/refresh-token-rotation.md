# Refresh Token Flow — Rotation & Reuse Detection

Prolunga la sessione senza ri-autenticare l'utente. AuthGlow applica
**rotazione ad ogni utilizzo** e **rilevamento del riuso**.

---

## Standard

- **Refreshing an Access Token** — RFC 6749 §6
- **OAuth 2.0 Security BCP** — RFC 9700 (raccomanda rotazione + revoca family)

---

## Come lo supportiamo

```
POST /oauth2/token   (form URL-encoded)   grant_type=refresh_token
```

Parametri:

| Parametro      | Obbligatorio | Note |
|----------------|--------------|------|
| `grant_type`   | SÌ | `refresh_token` |
| `refresh_token`| SÌ | Form oppure cookie `auth_cookie_refresh_name`. |
| `client_id`    | SÌ | |

Il servizio `RefreshTokenService.validate_and_rotate`:

1. Recupera il refresh token (lookup l'hash, mai il plaintext persistito).
2. Verifica: non revocato, `client_id` match, non scaduto.
3. Se `rt.used` è già `True` → **riuso rilevato**: revoca l'intera
   famiglia (tutti i token collegati via `parent_token_id`) e rifiuta.
4. Altrimenti segna `used=True`, crea un **nuovo refresh token** figlio
   (`parent_token_id` = id del precedente) e rimuove il vecchio dall'index
   attivo.
5. Emette un nuovo **access token** JWT (nuovo `jti`) e lo sostituisce.

Il tutto è protetto da un `named_lock` sulla chiave e da retry
optimistic-concurrency (CAS) per evitare race su rotazioni concorrenti.

Risposta:

```
{
  "access_token":  "…",
  "token_type":    "Bearer",
  "expires_in":    3600,
  "refresh_token": "<NUOVO>",
  "scope":         "openid profile"
}
```

---

## Conformità

| Aspetto | Stato |
|--------|-------|
| RFC 6749 §6 | **Conforme** (include rotation, che è raccomandata non richiesta). |
| Rotazione automatica | Sempre attiva. Ogni refresh emette un nuovo refresh token e invalida il precedente. |
| Riuso rilevato | **Custom, più severo dello standard**: se un refresh token già usato viene ripresentato, l'intera famiglia viene revocata (RFC 9700 BCP lo consiglia). |
| Cookie fallback | Il refresh token può arrivare via cookie httpOnly (per il frontend first-party). |
| Replay | Nuovo `jti` ad ogni refresh; riuso del vecchio token → famiglia revocata. |
| Gestione di sessione | `GET /api/tokens/refresh/list`, revoca singola o revoca-all "log out from all devices". |

---

## Endpoint

| Method | Path | Ruolo |
|--------|------|-------|
| POST | `/oauth2/token` | Rinnova access + refresh (rotazione) |
| GET | `/api/tokens/refresh/list` | Lista refresh token attivi dell'utente |
| POST | `/api/tokens/refresh/revoke-all` | Revoca tutti i refresh token dell'utente |
| DELETE | `/api/tokens/refresh/{token_id}` | Revoca un singolo refresh token |
| POST | `/oauth2/revoke` | Revoca (RFC 7009) — fallisce la rotazione |

---

> **Custom vs standard**: il flusso segue RFC 6749 §6 e RFC 9700, ma
> promuove a obbligatoria la rotazione e applica la **revoca dell'intera
> famiglia** al riuso — più severo del default. Inoltre il client può
> rinnovare passando il refresh token in un cookie httpOnly **custom**.