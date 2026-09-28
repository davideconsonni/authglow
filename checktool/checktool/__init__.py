"""AuthGlow console checktool.

A black-box, end-to-end verifier that acts like a real user against a
running AuthGlow instance (local by default, remote via ``--base-url``).

It speaks only the public HTTP surface (``httpx``) — no AuthGlow imports —
so it catches wire-format and integration deviations the in-repo pytest
suite cannot see by construction.

Checks are grouped into independent, self-consistent groups (each group
sets up its own fixtures and cleans them up). Run interactively
(``python -m checktool``) or non-interactively
(``python -m checktool --all`` / ``--groups auth,rbac``).
"""

__version__ = "0.1.0"
