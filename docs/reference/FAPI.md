# FAPI Profile — Decided Defaults vs Opt-ins (OA-505)

> **AuthGlow is NOT FAPI 2.0 certified.** It is Security-BCP-oriented with
> FAPI opt-ins per client. This page records the decided profile: what is
> default, what is opt-in, what is out of scope, and why. Every row cites
> the plan item (`docs/plans/archive/oauth2-oidc-compliance-plan.md`) and
> the evidence (test or code) behind it.

## Decided profile (default vs opt-in)

| Mechanism | Status | Evidence |
|---|---|---|
| PKCE S256 required | **Default ON** (`enforce_pkce=True`); `plain` rejected | `test_oauth2_oidc_matrix.py`, OA-001 baseline |
| Implicit / hybrid grants | **Rejected everywhere** | models + DCR + migration, OA-001 baseline |
| `redirect_uri` exact-match, https-only (loopback excepted) | **Default ON** | `oauth_client.py verify_redirect_uri`, OA-001 baseline |
| Client auth (Basic / POST / `client_assertion` HS256+RS256) | **Supported**, method per client | `client_jwt_auth.py`, OA-001 baseline |
| Refresh rotation + reuse detection | **Default ON** | `RefreshTokenService.validate_and_rotate` |
| `iss` (RFC 9207) on every authorization response | **Default ON** | `test_rfc9207_iss.py` |
| PAR (RFC 9126) | **Opt-in** per client (`require_par`, default off) | `test_par.py`, OA-501 |
| JAR `request=` objects at authorize | **Not supported** — rejected `invalid_request`, use PAR | `TestOA502JarNotSupported`, OA-502 |
| Pre-registered `request_uri` | **Not supported** (PAR `request_uri` only) | OA-502 |
| `response_mode` | **`query` only**; `form_post` rejected | OA-502 |
| DPoP sender-constrained tokens (RFC 9449, ES256) | **Opt-in** per client (`dpop_bound`, default off; DCR + admin UI) | `test_dpop.py`, `test_token_endpoint_dpop.py`, OA-503 |
| `tls_client_auth` / mTLS | **Absent (waived)** — needs proxy TLS termination + cert forwarding first | OA-503 waiver |
| `aud` presence on user-resolving endpoints | **Default ON** (any value; legacy no-`aud` rejected) | `TestOA504AudPresence`, OA-504 |
| Per-value `aud` routing (which aud where) | **Deferred** — needs traffic mapping | OA-504 waiver → OA-505 follow-up |
| `dpop_bound=True` default for new confidential clients | **Deferred** — playground/snippets send no proofs; integrators need notice | OA-503 waiver → OA-505 follow-up |
| JARM | **Non-goal** — FAPI 2.0 superseded it; only `code` is ever emitted | OA-502 |

## Derogations (written, not silent)

1. **DPoP/PAR default off** (OA-503, OA-501): turning either on by default
   today would break the playground, the code snippets, and new integrators
   without notice. High-risk clients SHOULD opt in (see `docs/flows/dpop.md`).
2. **mTLS waived** (OA-503): the app runs behind a reverse proxy with no
   client-cert forwarding (`middleware/proxy_headers.py`,
   `https_enforcement.py`). Revisit only with a dedicated TLS-infra project.
3. **`aud` value not routed** (OA-504): presence is enforced; per-endpoint
   allowlists need the federated-vs-internal traffic map (see Follow-ups).
4. **`nonce` optional in the code flow** (OA-402): echoed when present, never
   required.

## Follow-ups (post-Fase 5 candidates)

- Traffic map federated-vs-internal + per-value `aud` routing (from OA-504).
- `dpop_bound=True` default for new confidential clients, with migration +
  notice (from OA-503) — requires playground DPoP support first.
- PAR-required clients as the FAPI track (`require_par` default for new
  confidential clients) — same precondition as above.

## Non-goals

- FAPI 2.0 certification, JARM, `form_post`, pre-registered JAR `request_uri`,
  `tls_client_auth` without the TLS-infra project.
