# Load tests (PERF-011)

Real load baseline for the hot paths called out in the perf plan:
**concurrent logins** (bcrypt verify + code issuance) and **concurrent
refresh-token rotation** (JWT signing + record writes). These are *not*
pytest tests — they need a running instance — and unlike the micro-
benchmarks in `tests/performance/`, they measure end-to-end throughput
and latency percentiles under concurrency.

| File | Role |
|---|---|
| `run_baseline.py` | Driver: boots a disposable uvicorn on file storage, seeds admin + N users through the public APIs, runs locust headless, writes CSVs + `summary.md` |
| `locustfile.py` | Scenario: `LoginUser` (full authorize→token ceremony) + `RefreshUser` (rotation chain per session), weights 1:3 |
| `authflow.py` | Plain-`requests` implementation of the browser flow, shared by driver and scenario |
| `requirements-load.txt` | Locust pin, installed in the backend venv, kept out of the app lockfile |

## Local baseline (one command)

From `backend/`, with the venv Python and locust installed:

```bash
.venv/Scripts/python -m pip install -r tests/load/requirements-load.txt   # once
.venv/Scripts/python tests/load/run_baseline.py --users 30 --duration 60s
```

Results go to `tests/load/results/<UTC-timestamp>/` (gitignored):
`baseline_statistics.csv`, `baseline_percentiles.csv`, `baseline_failures.csv`,
`manifest.json` (seeded credentials), `summary.md` (the numbers to cite).

Useful flags: `--spawn-rate`, `--seed-users` (pool size, default = 2× users:
every virtual user gets its own account and respawned ones still have spare
emails to land on),
`--bcrypt-rounds` (e.g. `4` to measure the crypto-free envelope),
`--port`, `--workers` (PERF-004 experiments), `--base-url` / `--skip-seed`
(see below).

## Against a staging instance

```bash
.venv/Scripts/python tests/load/run_baseline.py \
    --base-url https://staging-authglow... --users 50 --duration 120s
```

The driver still seeds (admin via `--setup-token`... see caveat below) and
then points locust at the target. Notes:

- Seeding uses `SETUP_TOKEN` bootstrapped by the instance; a fresh staging
  box prints it once in its startup logs. On an already-initialized
  staging instance, seed once manually (or reuse a `manifest.json` with
  `--skip-seed --out-dir <run>`).
- The rate limiter will cap a remote run unless it is disabled from the
  admin UI (rate limits → kill switch) — same switch the local driver
  pre-seeds on disk. Locust hitting one URL from one IP otherwise trips
  the 30-60/minute decorator limits in seconds.
- Percentiles over WAN include network time; use the local mode for
  before/after comparisons of a fix, staging only for capacity checks.

## Reading `summary.md`

- `login authorize` — the bcrypt-bound step (password verify); its p50
  roughly *is* `bcrypt_rounds` cost + storage reads.
- `login token exchange` — JWT issuance + refresh-token persistence.
- `LOGIN end-to-end` — synthetic aggregate of the full ceremony (not a
  server span; sum of client-observed steps).
- `refresh rotation` — the steady-state hot path: validate + revoke old
  + create new + sign JWT. Its max req/s is the practical RPS ceiling of
  the storage layer.
- `# Fails` should be 0. Nonzero means the scenario outran the server's
  own sanity (timeouts, 429/5xx) — read `baseline_failures.csv`.

## What this pins down (for the perf plan)

Baseline "before" numbers belong in
`docs/project/plans/active/perf-fix-plan.md` under PERF-011 (run against
the released version being compared, note the machine: single dev laptop,
one uvicorn worker, file storage, bcrypt 12). Items to re-measure after
each merge: PERF-001 (CAS locks), PERF-002 (index cache), PERF-003 (CPU
pool), PERF-004 (`--workers 4` becomes meaningful).
