# Security Policy

## Reporting a Vulnerability

AuthGlow takes security seriously. If you discover a security vulnerability, please report it privately rather than opening a public issue.

**Email:** `security@authglow.dev`  
**PGP:** [Download public key](https://authglow.dev/.well-known/security.txt)

Please include the following in your report:

- A clear description of the vulnerability
- Steps to reproduce (proof-of-concept code or screenshots)
- Affected component(s): backend, frontend, or specific flow (OAuth2, OIDC, MFA, Passkey, Federation)
- The version or commit hash you tested against
- Any potential impact assessment

## Response Timeline

| Step | Timeframe |
|---|---|
| Acknowledgment of receipt | Within 48 hours |
| Initial triage and assessment | Within 5 business days |
| Status update | Every 5 business days until resolved |
| Fix released | Coordinated with reporter |

## Disclosure Policy

AuthGlow follows a coordinated disclosure process:

1. Reporter submits vulnerability privately
2. AuthGlow validates, develops, and releases a fix
3. After the fix is released, both parties coordinate on a public disclosure timeline

By default, we target **90 days** from receipt to public disclosure. This may be extended by mutual agreement if the fix requires significant coordination.

## Scope

The following components are in scope:

- **Backend** — All API endpoints (`backend/authglow/api/`), authentication flows, JWT handling, session management, encryption/decryption
- **Frontend** — OAuth2 consent screen, MFA verification, passkey authentication, federation login flow (`frontend/src/components/auth/`, `frontend/src/pages/`)
- **OAuth2 / OIDC** — Authorization code flow, client credentials flow, token endpoint, token refresh, revocation, introspection, consent persistence
- **Federation** — Zitadel and generic OIDC federation, state token handling, consent bridging
- **MFA / Passkeys** — TOTP enrollment and verification, backup code generation, WebAuthn authentication
- **RBAC** — Role-based access control, permission enforcement
- **Admin API** — All endpoints under `/api/admin/`

### Out of Scope

- Denial of Service (DoS) attacks without a novel vector
- Social engineering or phishing attacks
- Physical attacks against infrastructure
- Vulnerabilities in third-party dependencies already publicly known (report those to the dependency maintainer)
- Issues that require unrestricted physical access to the user's device

## Safe Harbor

AuthGlow supports security research conducted in good faith. We consider vulnerability research done in accordance with this policy to be:

- Authorized under applicable anti-hacking laws
- Exempt from DMCA restrictions on circumventing technical controls, provided the circumvention is limited to what is necessary to identify the vulnerability

We will not pursue legal action against researchers who:

- Act in good faith to follow this policy
- Avoid harming users, degrading services, or destroying data
- Provide us reasonable time to fix the issue before public disclosure

## Preferred Languages

We accept reports in **English** and **Italian**.

## Acknowledgments

We maintain a [hall of fame](#) for researchers who report valid vulnerabilities. Thank you for helping keep AuthGlow and its users safe.
