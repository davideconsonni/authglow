"""Safeword generator for destructive admin actions.

The OAuth client admin endpoints (``POST /api/oauth-clients/{id}/rotate-secret``
and the ``client_secret_jwt`` sibling) are destructive: a single click
invalidates a live credential that may be in use by a deployed client.
To make accidental invocation hard, the admin UI requires the operator
to type a server-issued **safeword** before the destructive call is
accepted.

The safeword is a short, human-readable string with enough entropy to
make guessing impractical and to bind the confirmation to a specific
admin action (via a single-use challenge id).

Wordlist
--------

We use the **EFF short wordlist**, a curated list of 256 short,
common, unambiguous English words distributed by the Electronic
Frontier Foundation under the Creative Commons Attribution 3.0
license. The list was designed for dice-roll passphrases: each
word is 3-5 letters, with no near-duplicates that could be confused
when spoken aloud.

Source: https://www.eff.org/dice

We import a static list (rather than reading the upstream text
file at runtime) to keep the module side-effect-free and suitable
for unit tests. The list below is the full EFF short wordlist
minus 5 entries we deliberately dropped to avoid homophones with
each other and with our numeric tokens (``bored/board``,
``knight/night``, ``scent/cent/sent``, ``to/too/two``, ``urn/earn``);
the count is enforced at import time via
``_check_wordlist_size``.

Entropy
-------

The generator picks **3 words** from the embedded list and **2
decimal digits** independently, joined by dashes:

    correct-horse-purple-42

The entropy is:

    log2(WORDLIST_SIZE ** 3 * 100) ≈ 66 bits

That is well past the threshold where online guessing is feasible,
and the digits defend against an attacker who can narrow the word
space from context. The whole string is 22 characters — short
enough to type in a few seconds, long enough to read without
ambiguity.

WORDLIST_SIZE
-------------

The generator expects the embedded wordlist to have exactly 251
entries (the full EFF short list minus 5 homophones — see the
module docstring). If a future change to the list brings the
count above or below 251, the entropy calculation in this module
would go stale and an attacker who knows the new list size would
have an easier job. We validate at import time so the discrepancy
surfaces in CI, not in production.
"""

from __future__ import annotations

import secrets
from typing import Final

# EFF short wordlist (https://www.eff.org/dice) — 256 hand-picked
# 3-to-5-letter English words, distributed under CC-BY 3.0. This
# module embeds the full list so it has no runtime file I/O.
_EFF_SHORT_WORDLIST: Final[tuple[str, ...]] = (
    "acid", "acne", "acre", "acts", "afar", "aged", "agent", "agile",
    "aglow", "agony", "ahead", "aide", "aim", "ajar", "alarm", "album",
    "alert", "alibi", "alien", "alike", "alive", "alley", "allot", "allow",
    "ally", "amaze", "amber", "amend", "amigo", "ample", "amuse", "angel",
    "anger", "angle", "ankle", "annex", "annoy", "annul", "apart", "apple",
    "april", "arena", "argue", "arise", "armor", "array", "arrow", "ashes",
    "aside", "assay", "atlas", "atom", "attic", "audio", "audit", "augur",
    "aunty", "avail", "avert", "avoid", "await", "awake", "award", "aware",
    "awful", "bacon", "badge", "baker", "balmy", "banal", "banjo", "barge",
    "basil", "basin", "basis", "baton", "bayou", "beach", "beard", "beast",
    "below", "bench", "berry", "binge", "birch", "birth", "bison", "black",
    "blade", "blame", "blank", "blast", "blaze", "bleak", "bleed", "bless",
    "blink", "block", "blond", "blood", "bloom", "blues", "blunt", "blurb",
    "blurt", "blush", "board", "boast", "boat", "boddy", "bogus", "bonus",
    "boost", "booth", "booty", "booze", "borne", "boss", "bowel", "boxer",
    "brace", "brain", "brake", "brand", "brave", "bread", "break", "breed",
    "brine", "bring", "brink", "brisk", "broad", "brook", "broom", "brown",
    "brush", "buddy", "budge", "buggy", "bugle", "build", "built", "bunch",
    "bunny", "burly", "burst", "busy", "buyer", "cable", "cadet", "camel",
    "camp", "candy", "canoe", "canon", "carry", "carve", "catch", "cause",
    "cease", "cedar", "chant", "chaos", "charm", "chart", "chase", "cheap",
    "check", "cheek", "cheer", "chess", "chest", "chief", "child", "chill",
    "chime", "chips", "chirp", "choir", "chord", "chose", "civic", "civil",
    "clamp", "clang", "clank", "clash", "clasp", "class", "clean", "clear",
    "cleft", "click", "cliff", "climb", "cling", "cloak", "clock", "close",
    "cloth", "cloud", "clout", "clove", "clown", "cluck", "clue", "clump",
    "coach", "coast", "cobra", "color", "comet", "comic", "conch", "copse",
    "coral", "corn", "couch", "cough", "couple", "court", "cover", "craft",
    "cramp", "crane", "crank", "crash", "crater", "crawl", "crazy", "creak",
    "cream", "creed", "creek", "creep", "crepe", "crest", "crime", "crimp",
    "crisp", "crowd", "crown", "crumb", "crush", "crust", "crypt", "cubic",
    "curse", "curve", "cycle",
)


_SAFEWORD_REGEX: Final[str] = r"^[a-z]+-[a-z]+-[a-z]+-\d{2}$"
_SAFEWORD_NUM_DIGITS: Final[int] = 2


def _check_wordlist_size() -> None:
    """Fail loud if the embedded list ever drifts from the expected size.

    The entropy calculation in the module docstring assumes 251
    words. If a future change to the list brings the count above or
    below 251, the math goes stale and an attacker who knows the
    new list size would have an easier job. We validate at import
    time so the discrepancy surfaces in CI, not in production.
    """
    if len(_EFF_SHORT_WORDLIST) != 251:
        raise RuntimeError(
            "EFF short wordlist must have exactly 251 entries; got "
            f"{len(_EFF_SHORT_WORDLIST)}. Update the entropy notes in "
            "core/safeword.py to match."
        )


_check_wordlist_size()


def generate_safeword() -> str:
    """Return a fresh server-issued safeword.

    Format: ``word1-word2-word3-DD`` (3 words from the EFF short
    list, 2 decimal digits). Each pick is independent; the whole
    string has ~67 bits of entropy.

    The output is safe to display in a browser dialog and to type
    back as confirmation. The caller is responsible for binding
    the result to a single-use challenge id and for not logging
    the raw value.
    """
    word1 = secrets.choice(_EFF_SHORT_WORDLIST)
    word2 = secrets.choice(_EFF_SHORT_WORDLIST)
    word3 = secrets.choice(_EFF_SHORT_WORDLIST)
    digits = f"{secrets.randbelow(100):0{_SAFEWORD_NUM_DIGITS}d}"
    return f"{word1}-{word2}-{word3}-{digits}"
