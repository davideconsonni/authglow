"""Reusable safeword challenge store for destructive admin actions.

Several admin actions can permanently break live systems if invoked
by accident (rotate a secret, revoke an API key, rotate the JWT
signing key). To make accidental invocation hard, the admin UI
requires the operator to type a server-issued **safeword** before
the destructive call is accepted.

This module centralises the in-memory challenge store and the two
helpers (``issue_challenge`` and ``consume_challenge``) that the
admin endpoints use to gate their destructive operations.

Wire shape
----------

Each admin endpoint that wants safeword protection exposes two
routes:

  1. ``POST <path>/challenge`` — admin clicks the action, the
     frontend calls this to obtain a single-use challenge:

         response = { challenge_id, word, expires_at }

  2. ``POST <path>`` — the destructive call itself; the body is

         { challenge_id, word }

     and the server runs ``consume_challenge`` before doing the
     destructive work.

The store is process-local (in-memory + thread lock). That is
acceptable for single-process deployments; in a horizontally
scaled setup the same flow should ride a shared store (Redis).
The function signatures here are deliberately small so swapping
the storage layer does not require touching call sites.
"""

from __future__ import annotations

import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from threading import Lock
from typing import Dict

from fastapi import HTTPException, status

from authglow.core.datetime import utcnow
from authglow.core.safeword import generate_safeword


CHALLENGE_TTL_SECONDS: int = 60
MAX_CHALLENGES_PER_TARGET: int = 5


class SafewordPurpose(str, Enum):
    """Tag that scopes a challenge to a specific destructive action.

    A challenge minted for one purpose cannot be redeemed against
    another: typing the safeword from a "rotate-secret" prompt into
    a "delete-key" prompt fails with 400, even if the typed word
    would otherwise match.
    """

    OAUTH_CLIENT_SECRET = "oauth_client_secret"
    OAUTH_CLIENT_JWT_KEY = "oauth_client_jwt_key"
    API_KEY_DELETE = "api_key_delete"
    API_KEY_ROTATE = "api_key_rotate"
    JWK_ROTATE = "jwk_rotate"


@dataclass
class _ChallengeEntry:
    word: str
    target_id: str
    purpose: SafewordPurpose
    expires_at: datetime
    used: bool = False


_challenges: Dict[str, _ChallengeEntry] = {}
_challenges_lock = Lock()


def _purge_expired_challenges() -> None:
    now = utcnow()
    expired = [cid for cid, entry in _challenges.items() if entry.expires_at <= now]
    for cid in expired:
        _challenges.pop(cid, None)


def _active_challenge_count(target_id: str) -> int:
    return sum(
        1 for entry in _challenges.values() if entry.target_id == target_id
    )


def _find_id_for_entry(entry: _ChallengeEntry) -> str:
    for cid, e in _challenges.items():
        if e is entry:
            return cid
    raise RuntimeError("challenge entry not found in store")


def issue_challenge(target_id: str, purpose: SafewordPurpose) -> dict:
    """Mint a new safeword challenge for ``target_id``.

    Returns a dict with ``challenge_id``, ``word`` and
    ``expires_at`` ready to be returned to the admin UI. Raises
    HTTP 429 if the target already has the maximum allowed
    pending challenges.
    """
    with _challenges_lock:
        _purge_expired_challenges()

        if _active_challenge_count(target_id) >= MAX_CHALLENGES_PER_TARGET:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    "Too many pending challenges. Complete or wait "
                    "for an existing one to expire."
                ),
            )

        challenge_id = secrets.token_urlsafe(16)
        entry = _ChallengeEntry(
            word=generate_safeword(),
            target_id=target_id,
            purpose=purpose,
            expires_at=utcnow() + timedelta(seconds=CHALLENGE_TTL_SECONDS),
        )
        _challenges[challenge_id] = entry
        return {
            "challenge_id": challenge_id,
            "word": entry.word,
            "expires_at": entry.expires_at,
            "entry": entry,
        }


def consume_challenge(
    challenge_id: str,
    target_id: str,
    word: str,
    purpose: SafewordPurpose,
) -> None:
    """Verify and atomically consume a challenge.

    Raises HTTP 400 on any of: unknown id, already-used, wrong
    purpose, wrong target, expired, or word mismatch. On any
    failure the entry is either deleted (expired) or marked as
    ``used`` (mismatch) so a brute-force attempt cannot retry
    against the same id.

    Use :func:`lookup_entry` to retrieve the freshly-issued
    challenge entry from the result of :func:`issue_challenge`.
    """
    with _challenges_lock:
        entry = _challenges.get(challenge_id)
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired challenge. Please generate a new safeword.",
            )
        if entry.used:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This challenge has already been used.",
            )
        if entry.purpose != purpose:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This challenge is not valid for this action.",
            )
        if entry.target_id != target_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="This challenge is not valid for this target.",
            )
        if utcnow() > entry.expires_at:
            _challenges.pop(challenge_id, None)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Challenge expired. Please generate a new safeword.",
            )
        if not hmac.compare_digest(
            word.strip().lower(), entry.word.strip().lower()
        ):
            entry.used = True
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Safeword does not match. Please generate a new one.",
            )
        _challenges.pop(challenge_id, None)


def lookup_entry(entry: _ChallengeEntry) -> str:
    """Return the dict key under which ``entry`` is stored.

    Thin indirection so route handlers do not have to scan the
    store to find the just-inserted entry.
    """
    return _find_id_for_entry(entry)
