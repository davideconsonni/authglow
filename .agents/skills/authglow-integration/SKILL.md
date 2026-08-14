---
name: authglow-integration
description: Integrate an application with the AuthGlow OAuth2/OIDC Authorization Server, or audit an existing integration. Detects the host framework, selects the correct flow, uses mature protocol libraries, implements the smallest safe change, and gates completion on security and compliance checks.
compatibility: Requires repository access, the current AuthGlow issuer or source checkout, and the host project's normal package manager and test tooling.
---

# AuthGlow Integration

Use this skill when a developer asks to integrate AuthGlow, add AuthGlow login, protect an application with AuthGlow tokens, migrate from another identity provider, or audit an existing AuthGlow integration.

The skill is version-aware. AuthGlow follows trunk-based development, so do not assume a historical API contract. Discover the current contract from the active AuthGlow checkout and/or the configured issuer before writing code.

## Non-negotiable rules

- Use standard OAuth2/OIDC endpoints discovered from the issuer metadata.
- Use Authorization Code + PKCE for browser, SPA, desktop, and mobile public clients.
- Use Authorization Code with confidential client authentication for server-side web applications.
- Use Client Credentials only for machine-to-machine access without a user.
- Never use `/api/token` for integration; it is not a registered endpoint. The AuthGlow dashboard itself uses Authorization Code + PKCE.
- Never use Resource Owner Password Credentials or collect AuthGlow passwords in the client application.
- Never store access tokens, refresh tokens, client secrets, or ID tokens in `localStorage`.
- Generate `state`, `nonce`, and PKCE `code_verifier` with a platform CSPRNG.
- Validate callback origin/path, `state`, authorization errors, and the authorization code before exchange.
- Validate ID token signature, `iss`, `aud`, `exp`, `iat`, and `nonce` when OIDC is used.
- Validate access tokens with the issuer JWKS and enforce audience and scopes at the resource server.
- Register exact redirect URIs. Never use wildcards or prefix matching.
- Do not implement OAuth2, JWT, JWK, or PKCE cryptography from scratch when a maintained library exists.
- Do not weaken AuthGlow server policy to make an integration pass.
- Do not claim compliance until the final checklist has evidence for every applicable control.

## Modes

Infer the mode from the request, then confirm it briefly if ambiguous:

- `integrate`: implement a new AuthGlow integration.
- `audit`: inspect an existing integration and report/fix deviations.
- `migrate`: replace another identity provider while preserving application sessions.
- `troubleshoot`: diagnose a concrete OAuth2/OIDC failure without redesigning unrelated code.

## Required workflow

### Phase 0: Preserve the worktree

1. Read the host repository instructions and package manifests.
2. Run the host project's status command and do not revert unrelated changes.
3. Identify the active AuthGlow version by checking, in order:
   - configured `AUTHGLOW_ISSUER` or equivalent environment variable;
   - issuer discovery metadata;
   - the AuthGlow checkout's current branch/commit and public configuration;
   - only then, the bundled reference material in this skill.
4. Record the discovered issuer, protocol capabilities, and host framework in the final report.

### Phase 1: Discover the protocol contract

Fetch or inspect `${issuer}/.well-known/openid-configuration`.

Required values:

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `jwks_uri`
- `userinfo_endpoint` when profile claims are needed
- `end_session_endpoint` when logout is needed
- `revocation_endpoint` when token revocation is needed
- `grant_types_supported`
- `response_types_supported`
- `code_challenge_methods_supported`
- `token_endpoint_auth_methods_supported`

Stop and ask for operator action when discovery is unavailable, the issuer is inconsistent, or the required capability is not advertised. Do not guess endpoint URLs if discovery is available.

### Phase 2: Classify the application

Choose exactly one primary client shape:

| Application | Client type | Flow | Token handling |
| --- | --- | --- | --- |
| Browser SPA | Public | Authorization Code + PKCE | Prefer backend-for-frontend or memory; never localStorage |
| Server-rendered web app | Confidential | Authorization Code | Server session; tokens stay server-side |
| Native/mobile app | Public | Authorization Code + PKCE | System browser and platform secure storage |
| CLI/device | Public | Device Authorization Grant when appropriate | OS credential store |
| Service-to-service | Confidential | Client Credentials | Secret or private key stays server-side |
| API/resource server | Resource server | No login flow | Validate JWT via JWKS, issuer, audience, scopes |

If the application has both a UI and an API, model them separately. Do not use one client ID and one token policy for unrelated trust boundaries.

### Phase 3: Plan the smallest integration

Before editing, list:

- environment variables and secret locations;
- client registration fields;
- login, callback, logout, and protected-route files;
- session boundary;
- token validation boundary;
- tests to add or update;
- security controls that must be demonstrated.

Prefer the host framework's mature OIDC library. The integration should wrap that library rather than duplicate its protocol implementation.

### Phase 4: Implement

Implement in this order:

1. Configuration and issuer discovery.
2. Client registration instructions or configuration.
3. Login initiation with fresh `state`, `nonce`, and PKCE where applicable.
4. Callback validation before token exchange.
5. Token exchange with the correct client authentication method.
6. Application session creation.
7. UserInfo or local claims mapping only after token validation.
8. Protected route/API middleware.
9. Refresh and revocation behavior.
10. OIDC RP-initiated logout.

Never expose a client secret to browser, mobile bundle, source map, or public environment variables.

### Phase 5: Security and compliance gate

Run the checks in `checklists/security-compliance.md`. A failed high-severity control blocks completion. If a control is not applicable, record why and what evidence supports that decision.

### Phase 6: Validate

Run the host project's targeted tests, lint, typecheck, and build. Add an integration test for the complete login/callback/token/session path. If a real AuthGlow issuer is available, run a smoke test against it; otherwise report that live validation remains pending.

### Phase 7: Final report

Use `checklists/final-report.md` as the output format. Include:

- detected architecture and selected flow;
- AuthGlow version/issuer source;
- files changed;
- environment variables;
- tests and commands run;
- compliance evidence;
- residual risks and manual operator steps.

## Framework guidance

Read the matching reference before implementing:

- SPA/browser: `references/spa.md`
- server-side web: `references/server-side.md`
- machine-to-machine: `references/machine-to-machine.md`
- resource server: `references/resource-server.md`
- protocol rules: `references/protocol-contract.md`
- security gate: `checklists/security-compliance.md`

If no framework reference exists, use the protocol contract and the host framework's official OIDC documentation. Do not invent an AuthGlow-specific abstraction just because the framework is unfamiliar.

## Stop conditions

Stop and ask the user when:

- the intended client type is ambiguous;
- the redirect URI or deployment origin is unknown;
- the application expects passwords to be handled directly;
- a client secret would need to be shipped to a public client;
- discovery and the local AuthGlow source disagree;
- the requested behavior requires disabling PKCE, issuer/audience validation, TLS, or consent;
- the host project has no safe secret storage strategy.
