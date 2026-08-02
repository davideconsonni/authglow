# Token Revocation & Introspection

Due endpoint utili ai client e ai resource server per gestire il ciclo di
vita dei token: **revocarli** (RFC 7009) e **interrogarli** (RFC 7662).

---

## Standard

- **Token Revocation Endpoint** — RFC 7009
- **Token Introspection Endpoint** — RFC 7662
- Access token revocation — RFC 7009 + JWT jti blacklist

---

## Revocation — RFC 7009

```
POST /oauth2/revoke   (form)   token, token_type_hint, client_id, client_secret
```

Richiede **client authentication** (HTTP Basic o form):

- **refresh_token** → revoca il refresh token nel repository.
- **access_token** → decodifica il JWT e aggiunge il suo `jti` alla
  **blacklist** (persistita su disco, per-instanza condivisa).

RFC 7009 impone di rispondere **sempre 200** (anche se il token non esiste
o le credenziali sono errate) per non far leakare informazioni. AuthGlow
rispetta questa regola — i client auth reject rispondono comunque `200
{ }`.

## Introspection: RFC 7662

```
POST /oauth2/introspect   (form)   token, token_type_hint, client_id, client_secret
```

Richiede **client authentication**. Restituisce:

```
{
  "active":     true,
  "scope":      "openid profile",
  "client_id":  "…",
  "token_type": "access_token",
  "exp":        1690000000,
  "iat":        1689996400,
  "sub":        "user-id"
}
```

Per gli **access token** (JWT) applica anche:
- **Audience binding**: se il `aud` del token NON è il client che introspect,
  ritorna `active=false` (RFC 7662 §2.2 — non fugare il motivo).
- **Blacklist check**: un `jti` revocato → `active=false`.

---

## Conformità

| Aspetto | Revocation | Introspection |
|--------|-----------|---------------|
| RFC | 7009 **conforme** | 7662 **conforme** |
| Client auth | Sì (Basic o form) | Sì (Basic o form) |
| Sempre 200 | Sì (anche per errore credenziali) | — |
| Audience binding | — | custom: `active:false` se `aud` mismatch |
| Access token | jti blacklist persistita | jti blacklist rispettata |

---

## Endpoint

| Method | Path | Standard |
|--------|------|----------|
| POST | `/oauth2/revoke` | RFC 7009 |
| POST | `/oauth2/introspect` | RFC 7662 |

---

> **Custom vs standard**: entrambi conformi. Unica estensione: il binding
> dell'audience in introspection (solo il client target può ottenere
> informazioni attive sul token) — comportamento più restrittivo e sicuro
> di quanto richiesto.