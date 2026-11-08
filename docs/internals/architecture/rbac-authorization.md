# RBAC-Driven Authorization

This document describes the Role-Based Access Control (RBAC) architecture, administrative permission gating, and anti-lockout mechanisms in AuthGlow.

## Overview

Admin authority in AuthGlow is **role-based, not scope-based**. Holding the OAuth `admin` scope does NOT grant administrative authority.

The system role **"Authglow Administrator"** (`models/rbac.py:ADMIN_ROLE_NAME`) is seeded at startup via `RBACService.initialize_defaults` during application lifespan. The first user created through `POST /api/setup/create-admin` is automatically assigned this role. In demo mode, the seeded demo administrator receives it idempotently on boot.

## Permission Vocabulary

Permissions follow a clean, section-based vocabulary mapped to administrative functions:

| Permission | Admin Section | Description |
|---|---|---|
| `users.manage` | Users | CRUD, MFA, passwords, suspend/activate, bulk actions, invites |
| `sessions.manage` | Sessions | Active sessions, Consents, Device Authorizations, Password Resets |
| `clients.manage` | Clients | OAuth Clients, Claim Policies, Playground, Federation, Webhooks |
| `keys.manage` | Keys | API Keys administration, JWK rotation/revocation |
| `system.manage` | System | System settings, Dynamic rate limit configuration |
| `roles.manage` | Roles | RBAC role, permission, and assignment management |
| `admin.read` | Global Read | View-only access across all administrative pages (auditors/support) |
| `roles.read` | Roles Read | Legacy read-only endpoint for role queries |

## Enforcement Rules

- **Mutations**: Write operations require the specific area's `.manage` permission (`require_permission` exact match).
- **Reads**: Read operations accept either the area's `.manage` permission OR `admin.read` (`any(area.manage, admin.read)`).
- **No Bypasses**: `PermissionChecker` verifies explicit permission assignments. The "Authglow Administrator" role holds the entire permission set — it passes authorization *by holding all permissions, never by bypassing checks*.

## Security Guards and Anti-Lockout

- **Role Check vs Permission Guard**: Legacy `require_administrator` is retained only where a complete user gate is appropriate. New endpoints use `require_permission` dependencies.
- **Reserved Scopes**: The OAuth `admin` scope is rejected at token issuance and ingestion (see `core.scopes.RESERVED_SCOPE_TOKENS`).
- **API Key Authorization**: An API key is never an admin on its own. The BOPLA guard in `services/api_key.py` evaluates permissions based on the key owner's identity. Creating keys with `keys.manage` or higher privileges requires `users.manage`.
- **Anti-Lockout Protection**: `DELETE /api/rbac/user-roles/{user}/{role}` returns `409 Conflict` when attempting to remove the Administrator role from the current caller or from the last remaining administrator in the system.
- **Upgrade Path**: `initialize_defaults` automatically backfills newly introduced default permissions into an existing Administrator role during startup, preventing lockouts across version upgrades.

## Persistence

RBAC data is persisted in the repository layer under:
- Roles: `<storage>/rbac/roles/`
- Permissions: `<storage>/rbac/permissions/`
- User Role Assignments: `<storage>/rbac/user_roles/`
