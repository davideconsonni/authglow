# OAuth2 / OIDC compliance checklist (server side)

AuthGlow is an Authorization Server and Resource Server. Verify the change
against the specs below. When the spec is unclear on a point, **fetch the
relevant RFC/OIDC section** instead of guessing; cite the section in the finding.

## Standards to apply

| Area | Standard |
| --- | --- |
| OAuth 2.0 core | RFC 6749 |
| Bearer tokens | RFC 6750 |
| Token revocation | RFC 7009 |
| Token introspection | RFC 7662 |
| PKCE | RFC 7636 |
| Dynamic client registration | RFC 7591 / RFC 7592 |
| JWT access tokens / JWT profile | RFC 9068 |
| DPoP | RFC 9449 |
| mTLS / certificate-bound tokens | RFC 8705 |
| OIDC Core | OpenID Connect Core 1.0 |
| OIDC Discovery | OpenID Connect Discovery 1.0 |
| OIDC RP-initiated logout | OpenID Connect RP-Initiated Logout 1.0 |
| JWT | RFC 7519; JWS RFC 7515; JWK RFC 7517 |
| Device flow | RFC 8628 |

## Controls to verify

**Authorization endpoint**

- [ ] `response_type`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`
      validated; unknown/duplicate params rejected.
- [ ] `redirect_uri` matched **exactly** against registered URIs (no wildcards,
      no prefix matching); mismatch never redirects back with a code.
- [ ] `state` required and echoed unchanged; errors returned per RFC 6749 §4.1.2.1
      (never as a token response).
- [ ] PKCE `code_challenge` (S256) required for public clients; plain rejected if
      policy is S256-only.
- [ ] Consent recorded and scope echoed within what was requested/granted.

**Token endpoint**

- [ ] Client authentication methods enforced per registered client
      (`client_secret_basic`, `client_secret_post`, `client_secret_jwt`,
      `private_key_jwt`, or `none` for public clients with PKCE).
- [ ] Authorization codes single-use, short-lived, bound to client + redirect_uri
      + PKCE verifier; reuse invalidates the code.
- [ ] Refresh-token rotation on every use; reuse of a rotated token invalidates
      the token family and is treated as a security event (audit + revoke).
- [ ] `grant_type` restricted to supported grants; unsupported grants rejected
      with `unsupported_grant_type`.
- [ ] Errors use the correct `error` codes and `400` / `401` semantics
      (RFC 6749 §5.2); no token leakage in error bodies or logs.

**Tokens and validation**

- [ ] JWT signatures validated against the current JWKS; `kid` honored; rotation
      handled without downtime.
- [ ] `iss`, `aud`, `exp`, `iat`, `nbf` validated; clock skew bounded.
- [ ] Access-token scopes and audience enforced at the resource server.
- [ ] DPoP proofs (when used) validated: `htm`/`htu`, `jti` replay, key binding,
      nonce handling; `token_type` is `DPoP`.
- [ ] Tokens are not written to logs, URLs, or error responses.

**Revocation, introspection, lifecycle**

- [ ] `revocation_endpoint` (RFC 7009) revokes both access and refresh tokens and
      returns `200` for unknown tokens.
- [ ] `introspection_endpoint` (RFC 7662) requires client authentication and
      returns `active: false` for invalid tokens.
- [ ] RP-initiated logout validates `post_logout_redirect_uri` against
      registered values.

**Discovery and keys**

- [ ] `/.well-known/openid-configuration` and `/.well-known/jwks.json` reflect the
      change (new grant, endpoint, or key).
- [ ] Advertised capabilities match actual behavior.

**AuthGlow-specific invariants (from the integration contract)**

- [ ] External clients never use `/api/token`; token calls go to the discovered
      `token_endpoint`.
- [ ] No Resource Owner Password Credentials flow; passwords are never collected
      by integratees.
- [ ] Authorization responses use `query` mode only; PKCE is S256-only.

## Evidence

- [ ] Protocol/conformance tests cover the changed behavior (positive and failure
      cases).
- [ ] Audit events emitted for the protocol step (see `AGENTS.md` audit logging).
