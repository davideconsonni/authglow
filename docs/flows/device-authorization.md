# Device Authorization Grant

Per dispositivi senza browser o senza input ricco (TV, CLI, IoT,
smart display). L'utente completa l'approvazione su un altro dispositivo.

---

## Standard

- **Device Authorization Grant** — RFC 8628

---

## Come lo supportiamo

### 1. Device → server (init)

```
POST /oauth2/device/authorize   (form)   client_id + scope
```

Risposta (RFC 8628 §3.2):

```
{
  "device_code":               "…",
  "user_code":                 "ABCD-1234",
  "verification_uri":          "https://…/oauth2/device/verify",
  "verification_uri_complete": "https://…/oauth2/device/verify?user_code=ABCD-1234",
  "expires_in":                1800,
  "interval":                   5
}
```

### 2. Utente → approva (su un altro dispositivo)

L'utente visita la verification_uri oppure usa il `user_code`. Gli endpoint
di verifica/approvazione di AuthGlow **richiedono una sessione utente
autenticata** (cookie/first-party):

| Method | Path | Ruolo |
|--------|------|-------|
| POST | `/api/oauth2/device/verify` | Guarda il `user_code`, ritorna client+scopes |
| POST | `/api/oauth2/device/approve` | Approva il dispositivo (`user_code`) |
| POST | `/api/oauth2/device/deny` | Rifiuta |
| GET | `/api/oauth2/device/authorizations` | Lista i propri device auths |
| POST | `…/{user_code}/revoke` | Revoca la propria device authorization |

### 3. Device → server (polling)

```
POST /oauth2/token   grant_type=urn:ietf:params:oauth:grant-type:device_code
     device_code=…
```

Risposte temporanee (RFC 8628 §3.5):

| Errore | Significato |
|--------|-------------|
| `authorization_pending` | Utente non ha ancora risposto → ri-poll senza error |
| `slow_down` | Polling troppo rapido — aumenta l'intervallo |
| `access_denied` | Utente ha rifiutato |
| `expired_token` | `device_code` scaduto |

Quando l'utente ha approvato: emette access token (e refresh token).

---

## Conformità

| Aspetto | Stato |
|--------|-------|
| Endpoint device auth | RFC 8628 §3.1 **conforme**. |
| `user_code` | Formato 8-char human-friendly. |
| Polling | Intervallo minimo enforced server-side (`interval` + `slow_down`). |
| Approvazione | **Custom**: richiede sessione utente autenticata sugli endpoint `/api/oauth2/device/*` (sono endpoint first-party API di AuthGlow, non parte di RFC 8628). |
| `verification_uri_complete` | Emesso (ottimizzazione UX). |
| Scopes | Default `read`; validati se il client li ha concessi. |

---

## Endpoint

| Method | Path | Standard | Ruolo |
|--------|------|----------|-------|
| POST | `/oauth2/device/authorize` | RFC 8628 §3.1 | Init del flusso |
| POST | `/oauth2/token` | RFC 8628 §3.4 | Polling → token |
| POST | `/api/oauth2/device/verify` | custom | Lookup user_code (auth utente) |
| POST | `/api/oauth2/device/approve` | custom | Approva |
| POST | `/api/oauth2/device/deny` | custom | Rifiuta |
| GET | `/api/oauth2/device/authorizations` | custom | Lista miei auths |
| POST | `/api/oauth2/device/authorizations/{user_code}/revoke` | custom | Revoca |

---

> **Custom vs standard**: il device-init e il polling seguono RFC 8628.
> Le API di verifica/approvazione (`/api/oauth2/device/*`) sono un'estensione
> first-party custom che richiede una sessione utente autenticata — non fa
> parte dello standard, serve al frontend per l'approvazione da una
> sessione autenticata sul dispositivo secondario.