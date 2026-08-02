"""Migration: enforce PKCE on all existing OAuth2 clients.

Context (OAuth 2.0 Security BCP conformance, workstream B):
    OAuth 2.0 Security BCP requires PKCE for every client. This one-shot
    script sets ``require_pkce=True`` on every existing client that still
    has it set to ``False``. After the migration, the global
    ``Settings.enforce_pkce`` gate (default True) ensures every new
    authorisation request carries a ``code_challenge``.

Usage:
    # Dry-run (default — safe, no writes):
    python -m scripts.migrate_enforce_pkce

    # Apply changes:
    python -m scripts.migrate_enforce_pkce --apply
"""

import argparse
import asyncio
import sys
from typing import List

from authglow.core.config import get_settings
from authglow.services.audit import AuditService
from authglow.services.oauth_client import OAuth2ClientStorage

PAGE_SIZE = 100


async def _migrate(apply: bool) -> int:
    settings = get_settings()
    storage = OAuth2ClientStorage(settings=settings)
    audit = AuditService(settings=settings)

    modified = 0
    scanned = 0
    affected_ids: List[str] = []
    errors: List[str] = []

    offset = 0
    while True:
        page = await storage.list_clients(limit=PAGE_SIZE, offset=offset)
        if not page:
            break
        scanned += len(page)

        for client in page:
            if client.require_pkce:
                continue

            affected_ids.append(client.client_id)
            client.require_pkce = True

            if not apply:
                continue

            try:
                await storage.update_client(client)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{client.client_id}: {exc!r}")
                continue

            try:
                await audit.log_event(
                    event_type="oauth_client_pkce_enforced",
                    user_id=None,
                    metadata={
                        "client_id": client.client_id,
                        "client_name": client.client_name,
                        "previous_require_pkce": False,
                        "new_require_pkce": True,
                        "migration": "enforce_pkce_v1",
                    },
                    severity="medium",
                )
            except Exception:
                pass

            modified += 1

        if len(page) < PAGE_SIZE:
            break
        offset += PAGE_SIZE

    _print_summary(scanned, modified, affected_ids, errors, apply)
    return 1 if errors else 0


def _print_summary(
    scanned: int,
    modified: int,
    affected_ids: List[str],
    errors: List[str],
    apply: bool,
) -> None:
    mode = "APPLY" if apply else "DRY-RUN"
    print(f"[{mode}] Scanned {scanned} client(s).")
    if apply:
        print(f"[{mode}] Modified {modified} client(s).")
    else:
        print(f"[{mode}] Would modify {len(affected_ids)} client(s).")
    if affected_ids:
        print(f"[{mode}] Affected client_ids:")
        for cid in affected_ids:
            print(f"  - {cid}")
    if errors:
        print(f"[{mode}] Errors ({len(errors)}):")
        for err in errors:
            print(f"  ! {err}")


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Set require_pkce=True on every OAuth2 client that still has it disabled.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Persist the changes. Without this flag the script runs in dry-run mode.",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    return asyncio.run(_migrate(apply=args.apply))


if __name__ == "__main__":
    raise SystemExit(main())
