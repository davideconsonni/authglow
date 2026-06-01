"""Shared TTL caches for read-heavy hot paths.

Bounded LRU+TTL caches protect memory and guarantee eventual-consistency
without stale data.  Suited for serverless: warm instances reuse cached
entries while short TTLs prevent serving outdated data across cold starts.

.. important::
   ``refresh_token_cache`` stores only ``token -> token_id``, **not** the
   full ``RefreshToken`` object.  The token file is always re-read so
   revocation by another instance is never masked by a stale cache entry.
   The cache merely skips the prefix-index lookup on hot tokens, saving
   one storage I/O call per request.

   ``user_cache`` stores full ``User`` objects because user-profile
   staleness does not gate authorisation decisions.
"""

from cachetools import TTLCache

refresh_token_cache = TTLCache(maxsize=5000, ttl=60)

user_cache = TTLCache(maxsize=2000, ttl=300)
