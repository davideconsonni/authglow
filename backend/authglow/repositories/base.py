"""Placeholder for cross-cutting repository abstractions.

This module will host Protocol / ABC classes that span multiple
storage backends but do not belong to a single entity — for example,
a future ``TransactionalUnit`` that coordinates multi-entity writes
(SQL transaction abstraction). Cross-entity atomicity is currently
handled by the ``UserService`` facade with ``named_lock``.
"""
