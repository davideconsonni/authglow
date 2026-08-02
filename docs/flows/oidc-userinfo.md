# OIDC UserInfo Endpoint

Ritorna le claim dell'utente autenticato. Usato dalle Relying Party che
hanno ottenuto un access token con `scope` includente claim profiling.

---

## Standard

- **UserInfo Endpoint** — OpenID Connect Core §5.1 (5.3, 5.4)

---

## Come lo supportiamo

```
GET /oauth2/userinfo   (Authorization: Bearer <access_token>)
```

1. Verifica l'**access token** (firma + `jti` blacklist). Può anche
   verificare `ath` se il token è DPoP-bound (RFC 9449).
2. Valida gli **scope** concessi: le claim emesse dipendono dallo scope
   (`openid`, `profile`, `email`, `phone`, `address`).
3. Applica l'eventuale **`claims` request parameter** (OIDC Core §5.5):
   se il client ha mandato un `claims` al momento dell'autorizzazione,
   filtra la risposta alle sole claim richieste.

Risposta (claim esempio, dipendono dallo scope):

```json
{
  "sub":            "user-id",
  "email":          "user@example.com",
  "email_verified": true,
  "name":           "Mario Rossi",
  "preferred_username": "mariorossi"
}
```

---

## Conformità

| Aspetto | Stato |
|--------|-------|
| OIDC Core §5.1 | **Conforme**. |
| Scope-based emission | Claim limitate agli scope concessi. |
| `claims` request (…5.5) | Supportato (filtra sia UserInfo che ID token). |
| Provider | Supporta il `sub`, `azp` (authorized party). |
| DPoP | Se token DPoP-bound, richiede una proof con `ath` fresh. |

---

## Endpoint

| Method | Path | Ruolo |
|--------|------|-------|
| GET | `/oauth2/userinfo` | Ritorna claim utente in base a scope + claims param |

---

> **Custom vs standard**: conforme a OIDC Core §5.1/§5.5. L'unica estensione
> è l'integrazione del `claims` request parameter per filtrare la risposta.