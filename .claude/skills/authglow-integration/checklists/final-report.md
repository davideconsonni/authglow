# AuthGlow Integration Report

## Summary

- Mode:
- Application type:
- Selected flow:
- AuthGlow issuer:
- AuthGlow version/commit source:
- Result: PASS / PASS WITH WARNINGS / BLOCKED

## Contract

- Discovery URL:
- Authorization endpoint:
- Token endpoint:
- JWKS URI:
- UserInfo endpoint:
- Logout endpoint:
- Client authentication method:

## Changes

- Files changed:
- Environment variables:
- Secrets/configuration actions required from operator:

## Verification

- Tests:
- Lint/typecheck:
- Build:
- Live smoke test:
- Security checklist: `checklists/security-compliance.md`

## Residual risks

-

## Operator handoff

- Register or verify the exact redirect URI.
- Configure the issuer and client ID.
- Store confidential credentials in the deployment secret manager.
- Run the documented smoke test in the target environment.
