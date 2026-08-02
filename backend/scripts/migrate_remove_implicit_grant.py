"""Migration: remove the 'implicit' grant_type from existing OAuth2 clients.

Context (OAuth 2.0 Security BCP conformance, workstream E):
    The implicit grant is deprecated by the OAuth 2.0 Security BCP and
    was never implemented by AuthGlow. The discovery endpoint and the
    DCR endpoint now refuse it, but legacy clients persisted on disk
    may still list ``"implicit"`` in their ``grant_types`` list. This
    one-shot migration rewrites them in place.

Usage:
    # Dry-run (default — safe, no writes):
    python -m scripts.migrate_remove_implicit_grant

    # Apply changes:
    python -m scripts.migrate_remove_implicit_grant --apply

    # Override the data directory if needed:
    python -m scripts.migrate_remove_implicit_grant --apply --data-dir /var/lib/authglow
"""

import argparse
import asyncio
import sys
from typing import List

from authglow.core.config import get_settings
from authglow.services.audit import AuditService
from authglow.services.oauth_client import OAuth2ClientStorage

PAGE_SIZE = 100


def _diff_grant_types(before: List[str]) -> List[str]:
    """Return the new grant_types list with ``implicit`` removed.

    Preserves order of the remaining entries. Returns a value equal to
    ``before`` (same list object) when nothing changes — callers can
    rely on object identity to skip writes.
    """
    if "implicit" not in before:
        return before
    return [g for g in before if g != "implicit"]


async def _migrate(apply: bool) -> int:
    """Iterate every client and strip ``implicit`` from grant_types.

    Returns the number of clients actually modified.
    """
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
            new_grant_types = _diff_grant_types(client.grant_types)
            if new_grant_types is client.grant_types:
                continue

            before = list(client.grant_types)
            client.grant_types = new_grant_types
            affected_ids.append(client.client_id)

            if not apply:
                continue

            try:
                await storage.update_client(client)
            except Exception as exc:  # noqa: BLE001
                errors.append(f"{client.client_id}: {exc!r}")
                continue

            try:
                await audit.log_event(
                    event_type="oauth_client_implicit_grant_removed",
                    user_id=None,
                    metadata={
                        "client_id": client.client_id,
                        "client_name": client.client_name,
                        "before": before,
                        "after": list(new_grant_types),
                        "migration": "remove_implicit_grant_v1",
                    },
                    severity="medium",
                )
            except Exception:
                # Audit logging must never block the migration.
                pass

            modified += 1

        if len(page) < PAGE_SIZE:
            break
        offset += PAGE_SIZE

    return _MigrationResult(
        scanned=scanned,
        modified=modified,
        affected_ids=affected_ids,
        errors=errors,
        apply=apply,
    )


class _MigrationResult:
    """Small value object so the summary printer stays tidy."""

    def __init__(
        self,
        scanned: int,
        modified: int,
        affected_ids: List[str],
        errors: List[str],
        apply: bool,
    ) -> None:
        self.scanned = scanned
        self.modified = modified
        self.affected_ids = affected_ids
        self.errors = errors
        self.apply = apply


def _print_summary(result: _MigrationResult) -> None:
    mode = "APPLY" if result.apply else "DRY-RUN"
    print(f"[{mode}] Scanned {result.scanned} client(s).")
    if result.apply:
        print(f"[{mode}] Modified {result.modified} client(s).")
    else:
        print(f"[{mode}] Would modify {len(result.affected_ids)} client(s).")
    if result.affected_ids:
        print(f"[{mode}] Affected client_ids:")
        for cid in result.affected_ids:
            print(f"  - {cid}")
    if result.errors:
        print(f"[{mode}] Errors ({len(result.errors)}):")
        for err in result.errors:
            print(f"  ! {err}")


def _parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Remove the 'implicit' grant_type from every OAuth2 client.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Persist the changes. Without this flag the script runs in dry-run mode.",
    )
    return parser.parse_args(argv)


def main(argv: List[str] | None = None) -> int:
    args = _parse_args(argv if argv is not None else sys.argv[1:])
    result = asyncio.run(_migrate(apply=args.apply))
    _print_summary(result)
    return 1 if result.errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
