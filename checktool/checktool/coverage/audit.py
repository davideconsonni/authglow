"""Frontend -> backend coverage audit.

The SPA drives every real operation through an existing backend endpoint
(verified against the router table). A few capabilities, however, are
implemented *client-side only* and therefore cannot be reproduced by a
headless, backend-only checktool. This module records them so they are
surfaced — with a proposed backend shape — instead of silently passing.

Source: audit of ``frontend/src`` (pages, ``lib/api.ts``, hooks, playground).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Gap:
    capability: str
    where: str
    why: str
    proposal: str


GAPS: List[Gap] = [
    Gap(
        capability="Token / claims preview (OAuth Playground)",
        where="frontend/src/components/playground/flows/TokenPreviewFlow.tsx",
        why=(
            "Assembles the claim payload in the browser; RBAC roles/permissions are "
            "hardcoded mocks (['admin','developer'] / ['users.read','users.write',...]) "
            "and user_field/api_key_field/jwt_meta render as literal placeholders. "
            "The backend has no 'render claims for this subject+scope' endpoint."
        ),
        proposal=(
            "Add a read-only endpoint, e.g. POST /api/admin/oauth-clients/{client_id}/"
            "preview-claims (and the api-keys equivalent) that runs ClaimPolicyService."
            "build_claims for a given user/scope and returns the rendered claims — no "
            "token issued."
        ),
    ),
    Gap(
        capability="Claim-rule preview values in admin claim tabs",
        where="frontend/src/components/admin/TokenClaimsTab.tsx, ApiKeyClaimsTab.tsx",
        why=(
            "mockValue() produces sample claim values entirely client-side; only policy "
            "persistence hits the backend."
        ),
        proposal=(
            "Reuse the same preview endpoint above so the samples come from the real "
            "resolve pipeline."
        ),
    ),
    Gap(
        capability="'This device' session detection",
        where="frontend/src/pages/SessionsPage.tsx",
        why=(
            "Picks the session with the max last_active in the browser. "
            "GET /api/tokens/refresh/list returns no 'current' flag, so the guess can be wrong."
        ),
        proposal=(
            "Add an is_current boolean to each session in GET /api/tokens/refresh/list "
            "(or a dedicated GET /api/tokens/refresh/current), derived from the caller's "
            "refresh token."
        ),
    ),
    Gap(
        capability="User data export download",
        where="frontend/src/pages/admin/AdminUsersPage.tsx",
        why=(
            "GET /api/admin/users/{id}/export exists and returns JSON; only the browser "
            "file download (Blob/URL.createObjectURL) is client-side."
        ),
        proposal="Informational: the backend capability exists; no endpoint needed.",
    ),
    Gap(
        capability="Presentational / local-state behaviour (out of scope)",
        where=(
            "oauthClientSnippets.ts, ClientSnippetsList.tsx, AdminOAuthClientsPage.tsx "
            "(templates), ConsentScreen.tsx (preview), lib/clientBranding.ts, "
            "lib/rateLimit.ts, lib/loginStorage.ts, hooks/useTheme.ts, zod validations"
        ),
        why=(
            "Pure rendering, client-side validation, CSS/theme resolution or local "
            "storage. No backend authority is implied."
        ),
        proposal="No backend change; excluded from the checktool by design.",
    ),
]


def build_markdown() -> str:
    lines: List[str] = []
    lines.append("## Frontend -> backend coverage gaps")
    lines.append("")
    lines.append(
        "Every operation the SPA performs is backed by a real endpoint; the items "
        "below are capabilities that exist **only client-side** and therefore cannot "
        "be exercised by this backend-only tool."
    )
    lines.append("")
    for gap in GAPS:
        lines.append(f"### {gap.capability}")
        lines.append("")
        lines.append(f"- Where: `{gap.where}`")
        lines.append(f"- Why client-side: {gap.why}")
        lines.append(f"- Proposed backend shape: {gap.proposal}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def print_report(ui) -> None:
    from rich.markdown import Markdown

    ui.console.print()
    ui.console.print(Markdown(build_markdown()))
