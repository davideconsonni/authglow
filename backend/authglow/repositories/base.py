"""Placeholder for cross-cutting repository abstractions.

This module will host Protocol / ABC classes that span multiple
storage backends but do not belong to a single entity — for example,
a future ``TransactionalUnit`` that coordinates multi-entity writes
(SQL transaction abstraction). The migration roadmap is in
``docs/REFACTOR_REPOSITORY_PLAN.md``; the first concrete need is
expected in phase 18 (User + EmailIndex + FederatedIdentity atomic
updates).
"""
