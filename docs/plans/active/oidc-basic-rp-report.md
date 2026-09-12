# OA-401 OIDC Basic RP report

Self-made Basic profile probe (not an OpenID Foundation certification run): a generic third-party RP speaking only the public protocol surface. Backend demo mode, credentials read at runtime from `/api/meta`. Base: `http://127.0.0.1:8001`.

35/35 checks passed

| Check | Result | Evidence | MUST/Item |
|---|---|---|---|
| demo meta exposes credentials | PASS | GET /api/meta | env |
| discovery has issuer | PASS | http://localhost:8001 | OIDC Discovery §3 |
| discovery has authorization_endpoint | PASS | http://localhost:8001/oauth2/authorize | OIDC Discovery §3 |
| discovery has token_endpoint | PASS | http://localhost:8001/oauth2/token | OIDC Discovery §3 |
| discovery has userinfo_endpoint | PASS | http://localhost:8001/oauth2/userinfo | OIDC Discovery §3 |
| discovery has jwks_uri | PASS | http://localhost:8001/.well-known/jwks.json | OIDC Discovery §3 |
| discovery has registration_endpoint | PASS | http://localhost:8001/oauth2/register | OIDC Discovery §3 |
| discovery has revocation_endpoint | PASS | http://localhost:8001/oauth2/revoke | OIDC Discovery §3 |
| discovery has introspection_endpoint | PASS | http://localhost:8001/oauth2/introspect | OIDC Discovery §3 |
| discovery has end_session_endpoint | PASS | http://localhost:8001/oauth2/logout | OIDC Discovery §3 |
| discovery response_types code-only | PASS | ['code'] | OA-202/A8 |
| discovery response_modes query-only | PASS | ['query'] | OA-202 |
| discovery PKCE S256-only | PASS | ['S256'] | RFC 7636 |
| discovery no implicit grant | PASS | ['authorization_code', 'refresh_token', 'client_credentials', 'urn:ietf:params:oauth:grant-type:device_code'] | BCP |
| jwks non-empty RSA sig keys | PASS | 1 keys | OIDC Discovery §3 |
| DCR registers (201) | PASS | 201 | RFC 7591 §3 |
| DCR returns client credentials | PASS | client_id present | RFC 7591 §3 |
| authorize yields code | PASS | code present | RFC 6749 §4.1.2 |
| authorize echoes state intact | PASS | state ok | RFC 6749 §4.1.2 |
| authorize response carries iss | PASS | http://localhost:8001 | RFC 9207 §2 |
| token exchange yields access/refresh/id_token | PASS | token_type=Bearer | RFC 6749 §4.1.4 |
| id_token signature + iss/aud/exp | PASS | ok | OIDC Core §3.1.3 |
| id_token nonce echoed | PASS | nonce ok | OIDC Core §3.1.3.6 |
| id_token at_hash binds access token | PASS | asQCya_EuMVHrg3wztUI3Q | OIDC Core §3.1.3.6 |
| id_token c_hash binds code | PASS | xDqcY18VK3eqarCFFCYx6w | OA-303 |
| id_token sid present | PASS | 4b9a03e92a2e1b374c31c9c1934f65b7 | OA-204 |
| userinfo 200 + sub match | PASS | 200 | OIDC Core §5.3 |
| refresh rotates to new tokens | PASS | rotated | RFC 6749 §6 / OA-105 |
| introspect active token | PASS | True | RFC 7662 |
| revoke returns 200 | PASS | 200 | RFC 7009 |
| introspect revoked token inactive | PASS | False | RFC 7662 / OA-104 |
| logout → userinfo 401 | PASS | 200/401 | OA-102 |
| wrong verifier → 400 invalid_grant | PASS | 400 {"error":"invalid_grant","error_description":"Invalid code_verifier"} | OA-302 |
| evil redirect_uri rejected | PASS | 400 | RFC 6749 §3.1.2 |
| implicit response_type refused via redirect | PASS | 302 | BCP / OA-201 |

No failures — nothing to map to new plan items.
