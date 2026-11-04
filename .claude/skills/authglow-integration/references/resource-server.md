# Resource Server Integration

An API that accepts AuthGlow access tokens is a resource server. It does not need to run a login flow.

## Validation requirements

Validate the JWT signature against the discovered `jwks_uri` and enforce:

- `iss` equals the configured issuer;
- `aud` equals the API's registered audience;
- `exp` has not passed;
- token type is an access token where the library exposes it;
- required scopes are present;
- user/account is still allowed by application policy.

Cache JWKS with a bounded lifetime and support key rotation by refreshing on an unknown `kid` or cache expiry. Never accept a token only because it decodes successfully.
