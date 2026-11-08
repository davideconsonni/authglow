"""One-shot load-baseline driver for AuthGlow (PERF-011).

Brings up a disposable local instance on file storage, seeds it through
the public APIs, runs a headless locust scenario (concurrent logins +
refresh rotations), and writes CSVs plus a human-readable ``summary.md``
under ``tests/load/results/<timestamp>/``.

Usage (from ``backend/``, venv Python with ``requirements-load.txt``)::

    python tests/load/run_baseline.py --users 30 --duration 60s

Point it at a staging instance instead (no server lifecycle, still seeds)::

    python tests/load/run_baseline.py --base-url https://staging... --setup-token ...

The numbers land where the perf plan (PERF-011) can cite them; rerun the
same command after each fix to get the matching "after" figure.
"""

import argparse
import csv
import json
import os
import platform
import secrets
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import authflow
import requests

HERE = Path(__file__).resolve().parent
BACKEND_DIR = HERE.parent.parent  # backend/
ADMIN_EMAIL = "load-admin@example.com"
USER_EMAIL_DOMAIN = "loadtest.example.com"
RATE_LIMIT_CONFIG = {"enabled": False, "overrides": {}, "updated_at": None}


def log(message: str) -> None:
    print(f"[baseline] {message}", flush=True)


def strong_password() -> str:
    """Policy-safe password: fixed classes + random body."""
    return "Lx9!" + secrets.token_urlsafe(16)


def wait_for_health(base: str, timeout_s: float = 90.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = requests.get(f"{base}/health", timeout=5)
            if resp.status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(0.5)
    raise RuntimeError(f"server at {base} never became healthy")


def disable_rate_limits(storage_path: Path) -> None:
    """Pre-seed the persisted rate-limit config in its disabled state.

    The file backend applies this document at startup (bind_app), so the
    whole run executes without slowapi capping the load (single source IP
    would hit 30-60/minute limits within seconds otherwise).
    """
    cfg_dir = storage_path / "rate_limit_config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    doc = dict(RATE_LIMIT_CONFIG)
    doc["updated_at"] = datetime.now(timezone.utc).isoformat()
    (cfg_dir / "config.json").write_text(json.dumps(doc), encoding="utf-8")


def start_server(
    port: int,
    data_dir: Path,
    workers: int,
    bcrypt_rounds: Optional[int],
) -> subprocess.Popen:
    """Spawn uvicorn on a disposable file-storage instance; return the proc."""
    keys_dir = data_dir / "keys"
    storage_path = data_dir / "storage"
    keys_dir.mkdir(parents=True, exist_ok=True)
    storage_path.mkdir(parents=True, exist_ok=True)
    disable_rate_limits(storage_path)

    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "APP_ENV": "development",
        # Force off: a leaked DEMO_MODE=true (e.g. from backend/.env, which
        # pydantic-settings still reads for unset keys) seeds a demo admin
        # that silently breaks the create-admin bootstrap below.
        "DEMO_MODE": "false",
        "SECRET_KEY": secrets.token_urlsafe(48),
        "KEYS_DIR": str(keys_dir),
        "STORAGE_PATH": str(storage_path),
        "SETUP_TOKEN": SETUP_TOKEN,
        "OAUTH2_CLIENT_ID": "loadtest-dashboard",
        "OAUTH2_CLIENT_SECRET": secrets.token_urlsafe(32),
        # Pinned explicitly so a stray BCRYPT_ROUNDS in backend/.env cannot
        # skew the baseline: the whole point is comparable before/after runs.
        "BCRYPT_ROUNDS": str(bcrypt_rounds or 12),
    }

    cmd = [
        sys.executable,
        "-m",
        "uvicorn",
        "main:app",
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--workers",
        str(workers),
        "--no-access-log",
    ]
    if workers > 1:
        log("note: uvicorn --workers on Windows spawns processes that inherit "
            "this environment; supported, but timings then include spawn noise")
    server_log = open(data_dir / "server.log", "wb")
    proc = subprocess.Popen(
        cmd,
        cwd=str(BACKEND_DIR),
        env=env,
        stdout=server_log,
        stderr=subprocess.STDOUT,
    )
    return proc


def seed(
    base: str,
    client_id: str,
    redirect_uri: str,
    num_users: int,
    admin_password: str,
    setup_token: str,
    admin_email: str,
) -> List[Dict[str, str]]:
    """Create bootstrap admin + load users through the public APIs.

    If the admin already exists (re-run against a persistent instance),
    creation is skipped and the stored credentials are used to log in.
    """
    log("creating bootstrap admin via /api/setup/create-admin")
    try:
        authflow.create_admin(base, setup_token, admin_email, admin_password)
    except authflow.FlowError as exc:
        if exc.status_code in (400, 404):
            log(f"admin already present ({exc.status_code}); logging in instead")
        else:
            raise

    admin_session = requests.Session()
    log("logging in the admin (authorize + PKCE + code exchange)")
    tokens = authflow.login(
        admin_session,
        base,
        client_id=client_id,
        redirect_uri=redirect_uri,
        email=admin_email,
        password=admin_password,
    )

    creds: List[Dict[str, str]] = []
    log(f"seeding {num_users} users via /api/admin/users/create (bcrypt each)...")
    batch: List[Any] = []
    for i in range(num_users):
        password = strong_password()
        batch.append((f"loaduser{i}@{USER_EMAIL_DOMAIN}", password))
        creds.append({"email": batch[-1][0], "password": password})
        if len(batch) == 25:
            authflow.create_users(base, tokens["access_token"], batch)
            log(f"  ... {len(creds)}/{num_users}")
            batch = []
    if batch:
        authflow.create_users(base, tokens["access_token"], batch)
    return creds


def run_locust(
    manifest_path: Path,
    base: str,
    users: int,
    spawn_rate: float,
    duration: str,
    csv_prefix: Path,
) -> int:
    """Run headless locust against the seeded instance; returns exit code."""
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "LOADTEST_MANIFEST": str(manifest_path),
        "LOADTEST_API_BASE": base,
    }
    cmd = [
        sys.executable,
        "-m",
        "locust",
        "-f",
        str(HERE / "locustfile.py"),
        "--headless",
        "-u",
        str(users),
        "-r",
        str(spawn_rate),
        "-t",
        duration,
        "--host",
        base,
        "--csv",
        str(csv_prefix),
    ]
    log(f"running locust: -u {users} -r {spawn_rate} -t {duration}")
    proc = subprocess.Popen(cmd, cwd=str(HERE), env=env)
    return proc.wait()


def summarize(out_dir: Path, csv_prefix: Path, meta: Dict[str, Any]) -> None:
    """Build summary.md from the locust CSV, print it.

    locust 2.47 writes one ``_stats.csv`` carrying both the aggregate
    columns and the approximate percentiles (``50%``..``100%``) per
    request name — no separate percentiles file.
    """
    stats_path = Path(f"{csv_prefix}_stats.csv")
    if not stats_path.exists():  # older locust naming
        stats_path = Path(f"{csv_prefix}_statistics.csv")

    rows: List[Dict[str, str]] = []
    if stats_path.exists():
        with stats_path.open(encoding="utf-8", newline="") as fh:
            rows = [r for r in csv.DictReader(fh) if (r.get("Name") or "").strip()]

    def _fmt_ms(value: str) -> str:
        try:
            return f"{float(value):.0f}"
        except (TypeError, ValueError):
            return "-"

    def _fmt_rate(value: str) -> str:
        try:
            return f"{float(value):.2f}"
        except (TypeError, ValueError):
            return "-"

    lines: List[str] = []
    lines.append(f"# Load baseline — {meta['timestamp']}")
    lines.append("")
    lines.append(f"- AuthGlow commit: `{meta['commit']}`")
    lines.append(f"- Scenario: login ceremony + refresh rotation, ratio "
                 f"LoginUser:RefreshUser = 1:3 (locust weights)")
    lines.append(f"- Load: {meta['users']} users, spawn {meta['spawn_rate']}/s, "
                 f"{meta['duration']}; seeded users: {meta['seed_users']}")
    lines.append(f"- Server: uvicorn workers={meta['workers']}, bcrypt_rounds="
                 f"{meta['bcrypt_rounds']}, rate limiter disabled "
                 f"(pre-seeded config), file storage")
    lines.append(f"- Machine: {meta['platform']} / {meta['cpu']} logical cores / "
                 f"Python {meta['python']}")
    lines.append(f"- Target: {meta['base']}")
    lines.append("")
    header = ("| Request | # req | fails | p50 (ms) | p95 (ms) | p99 (ms) "
              "| avg (ms) | max (ms) | req/s |")
    lines.append(header)
    lines.append("|---|---|---|---|---|---|---|---|---|")
    for row in rows:
        name = row.get("Name", "?")
        lines.append(
            "| {name} | {n} | {f} | {p50} | {p95} | {p99} | {avg} | {mx} | {rps} |".format(
                name=(f"{row.get('Type', '').strip()} {name}").strip(),
                n=row.get("Request Count", "-"),
                f=row.get("Failure Count", "-"),
                p50=_fmt_ms(row.get("50%")),
                p95=_fmt_ms(row.get("95%")),
                p99=_fmt_ms(row.get("99%")),
                avg=_fmt_ms(row.get("Average Response Time")),
                mx=_fmt_ms(row.get("Max Response Time")),
                rps=_fmt_rate(row.get("Requests/s")),
            )
        )
    lines.append("")
    lines.append("Raw CSVs next to this file: `_stats`, `_stats_history`, "
                 "`_failures`, `_exceptions`.")

    summary = "\n".join(lines) + "\n"
    (out_dir / "summary.md").write_text(summary, encoding="utf-8")
    print("\n" + summary)
    log(f"summary written to {out_dir / 'summary.md'}")


def git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=str(BACKEND_DIR.parent),
            capture_output=True,
            text=True,
            timeout=10,
        )
        return out.stdout.strip() or "?"
    except Exception:
        return "?"


SETUP_TOKEN = "loadtest-setup-token-do-not-reuse"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--users", type=int, default=30, help="locust virtual users")
    parser.add_argument("--spawn-rate", type=float, default=5.0)
    parser.add_argument("--duration", default="60s", help="locust -t value (e.g. 60s)")
    parser.add_argument("--seed-users", type=int, default=0,
                        help="pool size (0 = 2x --users, see respawn note)")
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--bcrypt-rounds", type=int, default=None,
                        help="override BCRYPT_ROUNDS for this run")
    parser.add_argument("--base-url", default=None,
                        help="run against a running instance (no server lifecycle)")
    parser.add_argument("--setup-token", default=None,
                        help="SETUP_TOKEN of a running instance (default: the "
                             "disposable token the driver boots local servers with)")
    parser.add_argument("--admin-email", default=ADMIN_EMAIL)
    parser.add_argument("--admin-password", default=None,
                        help="admin credential (default: random, used to create "
                             "the bootstrap admin on a fresh instance)")
    parser.add_argument("--client-id", default=None,
                        help="OAuth client for the flow (default: the local "
                             "server's OAUTH2_CLIENT_ID, 'loadtest-dashboard')")
    parser.add_argument("--redirect-uri", default="http://localhost:5173/auth/callback")
    parser.add_argument("--skip-seed", action="store_true",
                        help="reuse the manifest already present in --out-dir")
    parser.add_argument("--out-dir", default=None, help="results directory")
    args = parser.parse_args()

    # Default pool is 2x virtual users: locust respawns a killed user with
    # a fresh counter slot, and the spare half of the pool keeps those
    # wraps off live accounts (a shared email re-trips theft detection).
    seed_users = args.seed_users or args.users * 2
    base = args.base_url or f"http://127.0.0.1:{args.port}"
    setup_token = args.setup_token or SETUP_TOKEN
    client_id = args.client_id or ("loadtest-dashboard" if not args.base_url
                                   else sys.exit("--client-id is required with --base-url"))
    redirect_uri = args.redirect_uri

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = Path(args.out_dir) if args.out_dir else HERE / "results" / timestamp
    out_dir.mkdir(parents=True, exist_ok=True)
    data_dir = Path(tempfile_mkdtemp(prefix=f"authglow-load-{timestamp}-"))

    log(f"results -> {out_dir}")
    log(f"instance data -> {data_dir} (disposable)")

    server_proc: Optional[subprocess.Popen] = None
    exit_code = 0
    try:
        if not args.base_url:
            server_proc = start_server(args.port, data_dir, args.workers,
                                       args.bcrypt_rounds)
            log(f"uvicorn pid {server_proc.pid}; waiting for /health ...")
            wait_for_health(base)

        manifest_path = out_dir / "manifest.json"
        if args.skip_seed and manifest_path.exists():
            creds = json.loads(manifest_path.read_text(encoding="utf-8"))["users"]
            log(f"reusing manifest ({len(creds)} users)")
        else:
            admin_password = args.admin_password or strong_password()
            creds = seed(base, client_id, redirect_uri, seed_users,
                         admin_password, setup_token, args.admin_email)

        manifest = {
            "api_base": base,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": authflow.DEFAULT_SCOPE,
            "admin": {"email": args.admin_email},
            "users": creds,
        }
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

        rc = run_locust(manifest_path, base, args.users, args.spawn_rate,
                        args.duration, out_dir / "baseline")
        summarize(
            out_dir,
            out_dir / "baseline",
            {
                "timestamp": timestamp,
                "commit": git_commit(),
                "users": args.users,
                "spawn_rate": args.spawn_rate,
                "duration": args.duration,
                "seed_users": len(creds),
                "workers": args.workers,
                "bcrypt_rounds": args.bcrypt_rounds or 12,
                "platform": platform.platform(),
                "cpu": os.cpu_count(),
                "python": platform.python_version(),
                "base": base,
            },
        )
        exit_code = rc if rc != 0 else 0
        if rc != 0:
            log(f"locust exited with code {rc}")
    finally:
        if server_proc is not None:
            log("stopping server")
            server_proc.terminate()
            try:
                server_proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                server_proc.kill()
    return exit_code


def tempfile_mkdtemp(prefix: str) -> str:
    """Named temp dir we can print and reuse (kept on disk for postmortems)."""
    import tempfile

    return tempfile.mkdtemp(prefix=prefix)


if __name__ == "__main__":
    sys.exit(main())
