# Machine-to-Machine Integration

Use Client Credentials only when there is no end user and no user consent transaction.

## Requirements

- Keep client secret or private key in a server-side secret manager.
- Request only the scopes required by the service.
- Authenticate at the token endpoint using the registered method.
- Cache access tokens until shortly before expiry.
- Never issue or store refresh tokens for a service that can obtain a new client-credentials token.
- Send the access token only to the intended resource server.

If the service needs to act on behalf of a user, do not use Client Credentials; use Authorization Code and preserve the user subject.
