"""Performance micro-benchmarks for AuthGlow hot-path components.

Unlike ``tests/unit/`` (which is fast, deterministic, runs on every commit)
and ``tests/integration/`` (which exercises cross-module flows), this suite:

* contains tests that take seconds to run (bcrypt is ~100-300ms per op by design);
* is excluded from the default ``pytest`` run (use ``pytest -m performance``);
* is not a substitute for proper load testing under ``tests/load/`` — it only
  validates single-operation overhead and concurrency safety of the new
  ``asyncio.to_thread`` bcrypt path.

The Tier 1.1 of ``docs/plans/PERFORMANCE_OPTIMIZATION_PLAN.md`` introduced
``hash_password_async`` / ``verify_password_async``; this file is the
regression test that proves the async path is correct AND does not
block the event loop.

When to run:

    # Run only the performance suite
    cd backend && pytest -m performance

    # Skip performance tests in a normal run
    cd backend && pytest -m 'not performance'
"""
