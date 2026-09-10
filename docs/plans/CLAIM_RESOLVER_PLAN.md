# Claim Resolver Pluggable — Piano di implementazione

> Workflow: plan-grill-implement. Grilling completato (5Q: strict-422, degrado, ctx, no-timeout-centrale, slow-warning).
> Stato workflow: `[x] Step 1 Plan` → `[x] Step 2 Grill` → `[x] Step 3 Implement` → `[x] Step 4 Test` → `[x] Step 5 Mark Done`

## - [x] 1. Contesto (current vs desired)

**Current:** `ClaimSource` enum chiuso a 6 sorgenti; `_resolve_source` staticmethod sync con if-chain; aggiungere una sorgente esterna (CRM, feature flags) richiedeva enum + resolver + validatori.
**Desired:** `ClaimSource.CUSTOM` + registro runtime `register_claim_resolver(name, async_fn)`; resolver async `(rule, ClaimResolveContext)`; degrado a issue-time; 422 strict a save-time; osservabilità slow/failed su `authglow.audit`.

## - [x] 2. File modificati

| File | Azione |
|------|--------|
| `backend/authglow/models/claim_policy.py` | `CUSTOM="custom"`, `custom_resolver`/`custom_config`, validatori coerenza |
| `backend/authglow/services/claim_policy.py` | `ClaimResolveContext` frozen, `ClaimResolver`, `_RESOLVERS`, `register_claim_resolver`, `_resolve_source` async, check save-time, `claim_resolver_{missing,failed,slow}` |
| `backend/tests/unit/test_claim_resolvers.py` | 12 test (nuovo) |
| `ARCHITECTURE.md` | Riga Quick Reference resolver |

## - [x] 3. Test

`test_claim_resolvers` (12) + `test_claim_policy` + repo file claim/api-key-claim + `test_rbac_jwt_injection` → **98 passed**. `ruff check`/`format`/`mypy` puliti.

## - [x] 4. Rischi

`_resolve_source` sync→async: unico chiamante interno, nessun uso esterno. Resolver lenti: solo warning (no enforcement). Restart senza plugin: skip+warn.

## - [x] 5. Stima / consuntivo

4 file, complessità media. Diff solo hunk propri (verificato via `git diff`).
Uso: `register_claim_resolver("crm_tier", fn)` + rule `{source: custom, custom_resolver: crm_tier}`.

---
*Completato con approvazione utente. Non committato (nessuna richiesta di commit).*
