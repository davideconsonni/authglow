# DPoP — Sender-Constrained Tokens (RFC 9449)

Legatura dimostrabile del possesso (proof-of-possession): l'access token è
vincolato alla chiave pubblica del client, rendendo l'uso del token
necessario per chi possiede la chiave.

---

## Standard

- **Demonstrating Proof of Possession (DPoP)** — RFC 9449
- **Proof-of-Possession Key Semantics** — RFC 7800 (`cnf` claim)
- FAPI 2.0 §5.2.2

---

## Come lo supportiamo

DPoP è **opt-in per-client** tramite il flag `dpop_bound` (default `False`).
Quando è attivo:

1. Il client presenta un **DPoP proof JWT** nell'header `DPoP:` su ogni
   richiesta al token endpoint e a UserInfo.
2. L'access token è emesso con `cnf={"jkt":"<thumbprint>"}` e
   `token_type=DPoP` (invece di `Bearer`).
3. UserInfo richiede una proof con `ath` legata al token.

### DPoP proof JWT

Claim richiesti dal proof:

| Claim | Semantica |
|-------|-----------|
| `htm` | HTTP method (`POST`, `GET`…) |
| `htu` | URL del token endpoint (target) |
| `iat` | Short-lived: max **120s** |
| `jti` | Monouso, replay-protected via cache server-side |
| `jwk` | Nell'header del proof — chiave pubblica del client |

Algoritmo: **solo `ES256`** (per rispondere a FAPI 2.0).

---

## Conformità

| Aspetto | Stato |
|--------|-------|
| RFC 9449 | **Conforme** (ES256). |
| `cnf` + `jkt` (RFC 7800) | Emesso sugli access token bound. |
| `token_type` | `DPoP` invece di `Bearer`. |
| Opt-in | **Custom**: non obbligatorio — attivato per-client (`dpop_bound`), non di default. |
| Finestra `iat` | Max 120s, replay cache. |

---

## Endpoint

| Method | Path | Standard | Note |
|--------|------|----------|------|
| POST | `/oauth2/token` | RFC 9449 | Richiede DPoP proof per i client bound |
| GET | `/oauth2/userinfo` | RFC 9449 | Richiede proof con `ath` fresh |

---

> **Custom vs standard**: pienamente conforme a RFC 9449, ma **opt-in** per
> client (non obbligatorio di default) — il che lo distingue dal deployment
> obbligatorio di FAPI 2.0. Il token esce sempre `cnf` + `token_type=DPoP`.