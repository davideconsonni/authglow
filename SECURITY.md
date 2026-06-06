# Security Policy

## Reporting a Vulnerability

AuthGlow takes security seriously. If you discover a security vulnerability, please open a GitHub issue with the details below.

Please include the following in your report:

- A clear description of the vulnerability
- Steps to reproduce (proof-of-concept code or screenshots)
- Affected component(s): backend, frontend, or specific flow (OAuth2, OIDC, MFA, Passkey, Federation)
- The version or commit hash you tested against
- Any potential impact assessment

## Scope

The following components are in scope:

- **Backend** — All API endpoints (`backend/authglow/api/`), authentication flows, JWT handling, session management, encryption/decryption
- **Frontend** — OAuth2 consent screen, MFA verification, passkey authentication, federation login flow (`frontend/src/components/auth/`, `frontend/src/pages/`)
- **OAuth2 / OIDC** — Authorization code flow, client credentials flow, token endpoint, token refresh, revocation, introspection, consent persistence
- **Federation** — OIDC federation providers, state token handling, consent bridging
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
