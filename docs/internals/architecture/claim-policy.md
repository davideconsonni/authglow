# Claim Policy System (OIDC §5.1.2)

This document describes the declarative claim policy system in AuthGlow, governing how custom claims are attached to OAuth2/OIDC tokens and UserInfo responses.

## Overview

The Claim Policy system allows administrators to configure declarative rules per OAuth 2.0 client that control:
- Which claims (RBAC roles, RBAC permissions, user attributes, or static values) are embedded in issued tokens.
- Which token targets receive each claim (`ACCESS_TOKEN`, `ID_TOKEN`, or `USERINFO`).
- Which OAuth scopes are required to release each claim.

## Architecture

- **Data Models (`authglow/models/claim_policy.py`)**: Defines `ClaimRule`, `ClientClaimPolicy`, built-in templates (`BUILTIN_TEMPLATES`), and the `OIDC_STANDARD_CLAIMS` allowlist.
- **Repository (`authglow/repositories/file/claim_policy.py`)**: Stores policies per client at `<storage_path>/client_claim_policies/<client_id>.json`.
- **Service (`authglow/services/claim_policy.py`)**: `ClaimPolicyService.build_claims(user, client_id, scopes, target) -> dict`. Reads RBAC roles/permissions, evaluates configured client rules, filters by destination target and authorized scopes, and returns claims to merge into the token payload.
- **Custom Resolvers**: Supports dynamic resolvers via `register_claim_resolver("<name>", async_fn)` for claims requiring external lookups or runtime computation.
- **JWT Plumbing (`authglow/services/jwt.py`)**: `create_access_token` and `create_id_token` accept `extra_claims: Optional[Dict[str, Any]]`. The JWT service filters reserved claims (`iss`, `sub`, `aud`, `exp`, `iat`, `jti`, `azp`, `cnf`, `token_type`) to protect cryptographic integrity.

## Default Behavior

When no custom policy is configured for a client, or for first-party flows (password login, API-key exchange, token refresh, passkey, federation, MFA):
- Emits namespaced RBAC roles and permissions claims into the access token.
- Uses `settings.claim_namespace` as the base URI (default: `https://authglow.example.com/claims`).

## OIDC §5.1.2 Namespacing Rule

In compliance with OpenID Connect Core 1.0 §5.1.2:
- Any custom claim name not in the `OIDC_STANDARD_CLAIMS` allowlist **MUST be a valid URI**.
- Plain names (such as `roles`, `plan`, `org_id`) are rejected at the model validation level (`_validate_claim_name`) to prevent collisions with future protocol specifications.
- Example valid claim: `https://authglow.example.com/claims/roles`.
