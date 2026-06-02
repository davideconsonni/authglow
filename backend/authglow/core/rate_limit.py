"""Central rate limiter instance for AuthGlow.

All API modules must import this singleton to ensure there is a single
Limiter connected to app.state.limiter in main.py.
"""

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
