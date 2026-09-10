"""Postgres repository backend (placeholder).

Not registered in ``authglow.repositories.dependencies._REGISTRY`` yet:
any ``Settings(repository_backend="postgres")`` intentionally fails fast
with ``ValueError`` until the first concrete
``Postgres<Entity>Repository`` lands here and calls
``register_backend("postgres", {...})``.

Add a new backend in 3 steps (zero changes to services/API):

1. ``repositories/postgres/<entity>.py`` with
   ``Postgres<Entity>Repository(<Protocol>)``.
2. ``register_backend("postgres", {"<entity>": lambda s: ...})``.
3. One line in ``tests/unit/repositories/test_protocols.py::_IMPL_TABLE``.
"""
