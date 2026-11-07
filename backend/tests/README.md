# Backend tests — patterns and pitfalls

Commands and suite-scoping rules live in the root `AGENTS.md`. This file
records the patterns that repeatedly cost debug cycles in tests touching
threads, timing, and direct handler invocation — copy them instead of
re-deriving them.

## Running

- One file: `pytest tests/unit/test_x.py -q --tb=line`
- Only the affected subset: `python scripts/affected_tests.py --run`
  (inspects the working tree; `--base origin/main` is for committed diffs).
- Performance micro-benchmarks: `pytest -m performance`
  (see `tests/performance/README.md`).
- Windows: never pipe pytest into `Select-String`/`tail` — subprocess
  buffering produces false tool timeouts. Run directly, or background the
  shell and read the output file when it finishes.

## Direct handler tests

- Use the `http_request` fixture (`tests/conftest.py`). FastAPI validates
  the `request` parameter type at call time: a `MagicMock` raises
  `parameter 'request' must be an instance of starlette.requests.Request`
  before the handler body ever runs.
- Dependencies are plain arguments: pass mocked storage/audit (`MagicMock`
  with `AsyncMock` methods) straight to the handler coroutine — no app
  stack needed. See `tests/unit/test_vapt050.py`.
- Settings gates: `conftest.py` patches `get_settings` in the *service*
  module namespaces only. API modules keep their own import binding, so
  patch the module attribute explicitly:
  `monkeypatch.setattr(api_module, "settings", SimpleNamespace(...))`.

## Concurrency and timing tests

- Assert **structure, not wall time**:
  - Thread identity: the `cpu_pool_probe` fixture returns the name of the
    thread a `core.executors.run_cpu_bound` job ran on.
  - Tick counters: run a ticker coroutine (`asyncio.sleep(0.005)`) while a
    **known-duration** job executes; assert a floor on ticks with ≥3×
    margin, never an exact count.
  - Pool separation: occupy a 1-worker default executor via
    `asyncio.to_thread(time.sleep, …)`, then assert a CPU-pool dispatch
    completes immediately — this fails loudly if the pools are shared.
- bcrypt runs at `bcrypt_rounds=4` in tests (~1-2 ms): real hashes are too
  fast to detect loop blocking. Inject a `time.sleep` job when the point
  of the test is latency.
- Loop-independent primitives must be exercised across two consecutive
  `asyncio.run()` calls — that is where loop-bound objects break
  (`test_concurrency.py`, `test_executors.py`).
- API gotchas learned the hard way: `loop.set_default_executor(None)`
  raises (it needs an executor instance); `ThreadPoolExecutor.max_workers`
  is private (`_max_workers`); `asyncio.to_thread` uses the *running
  loop's* default executor.

Reference examples: `tests/unit/test_executors.py`,
`tests/unit/test_concurrency.py`, `tests/unit/test_vapt050.py`.
