# OIDC RP-Initiated Logout

Permette a una Relying Party di stendere il logout dell'utente tramite
AuthGlow, e di farlo propagare verso più applicazioni collegate.

---

## Standard

- **OpenID Connect RP-Initiated Logout 1.0**
- **OpenID Connect Front-Channel Logout 1.0** (per i client che lo usano)

---

## Come lo supportiamo

```
GET /oauth2/logout? + id_token_hint=… + post_logout_redirect_uri=… + state=…
```

O anche `POST /oauth2/logout` (con Bearer auth, per audit).

Logica:

1. Se è presente `post_logout_redirect_uri`, **`id_token_hint` è
   obbligatorio** — serve a identificare il client (custom: lo standard lo
   raccomanda, qui è richiesto).
2. Valida `id_token_hint` (firma + `aud`).
3. Verifica che `post_logout_redirect_uri` sia nella lista
   `allowed_post_logout_redirect_uris` del client. Altrimenti 400.
4. Redirige a `post_logout_redirect_uri` con lo `state` riportato.
5. **Front-Channel Logout**: se alcuni client hanno `frontchannel_logout_uri`,
   la risposta è una pagina HTML con un `<iframe>` per ciascuno
   (`?iss=…&sid=…`), poi re-direzione dopo ~2s.

AuthGlow è **stateless**: non tiene una sessione lato server. L'utente o il
client eliminano i propri token; il server revoca il refresh token e
blacklista il `jti` dell'access token. L'evento viene audit-logged.

---

## Conformità

| Aspetto | Stato |
|--------|-------|
| RP-Initiated Logout 1.0 | **Conforme**. |
| `post_logout_redirect_uri` | Strict match contro `allowed_post_logout_redirect_uris`. |
| `id_token_hint` + redirect | **Custom, più severo**: obbligatorio quando si chiede un redirect. |
| Front-Channel Logout | Supportato (iframe `iss` + `sid`). |
| Back-Channel Logout | `backchannel_logout_uri` supportato sul client ma **non** eseguito (stateless). |
| `state` | Ri-appenduto nella redirect URL. |

---

## Endpoint

| Method | Path | Ruolo |
|--------|------|-------|
| GET | `/oauth2/logout` | RP-Initiated Logout (query params) |
| POST | `/oauth2/logout` | Idem, con Bearer auth |

---

> **Custom vs standard**: unica differenza — `id_token_hint` è obbligatorio
> quando si richiede un redirect (lo standard lo raccomanda). Il back-channel
> logout non è eseguito: il client è stateless e la revoca avviene
> client-side.