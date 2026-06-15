"""Authentication-domain services.

The ``auth`` subpackage groups services that manage session-level
state (token revocation, future SSO bridges, etc.). They were
previously scattered under ``authglow.core`` and ``authglow.services``;
the repository-pattern refactor (Fase 1 of
``docs/REFACTOR_REPOSITORY_PLAN.md``) consolidates them here so that
``authglow.core`` remains for pure primitives (config, crypto, locks).
"""
