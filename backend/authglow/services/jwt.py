"""Service layer for JWT issuance and validation.

Wraps the :class:`KeyStoreRepository` (which owns the
keyring on the fsspec layer) and provides the high-level
``create_token`` / ``decode_token`` API used by the
FastAPI route handlers. The service keeps an in-memory
cache of the active keypair + the verifying-window public
keys so the hot path (``decode_token``) is purely CPU
work — no I/O per request.

The keyring is owned by :class:`KeyStoreRepository` (the
fsspec-backed implementation is
:class:`FileKeyStoreRepository`). The service holds an
in-memory snapshot of the keyring loaded at construction
time; ``rotate_keys`` / ``revoke_key`` re-read the
repository after the write so the in-memory cache stays
in sync. The service never touches ``os.path`` /
``open()`` directly — all filesystem access goes through
the repository's fsspec layer.

Async-first: ``JWTService.__init__`` is async because the
keyring is loaded through the repository's fsspec layer
via ``asyncio.to_thread``. Callers that need the service
``await`` its constructor (or use a FastAPI dependency
that does so).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, cast
from uuid import uuid4

import jwt

from authglow.core.config import get_settings
from authglow.core.crypto import decrypt_private_key
from authglow.models.oidc import SCOPE_TO_CLAIMS, IDTokenClaims
from authglow.models.token import Token, TokenData
from authglow.services.auth.token_blacklist import token_blacklist


def _extract_extra_claims(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Pull every claim that is not reserved / typed into a free-form dict.

    Used by :meth:`JWTService.decode_token` to populate
    :attr:`TokenData.extra_claims`. The returned dict holds
    exactly the namespaced custom claims the claim policy
    emitted (RBAC roles, permissions, tenant id, etc.) so
    the consumer can iterate over them without the JWT layer
    modelling each one.
    """
    excluded = _RESERVED_CLAIMS | {
        "scope",
        "email",
        "token_version",  # internal sentinel
    }
    return {k: v for k, v in payload.items() if k not in excluded}

# VAPT-046: audience identifier for tokens issued on the
# internal first-party flows (password login, API-key
# exchange, refresh-token rotation, passkey login). The OAuth2
# ``authorization_code`` flow uses ``aud=<client_id>`` (set by
# the route handler) so the resource server can enforce
# audience binding per OIDC Core §3.1.3.7. The internal flows
# do not have a per-client audience — they are issued for
# AuthGlow's own use — so we tag them with a fixed identifier
# that any future resource server can opt to reject (``aud !=
# <expected_audience>``) to keep internal traffic separate
# from federated OAuth2 traffic.
INTERNAL_AUDIENCE = "authglow-internal"

# Claims the JWT service bakes in itself. The ``extra_claims``
# parameter cannot override them — the claim policy can only
# add new claims. The set is duplicated from
# ``services.claim_policy.RESERVED_CLAIMS`` so the contract
# is enforced even if the claim policy service is bypassed
# (e.g. in tests).
_RESERVED_CLAIMS: frozenset[str] = frozenset(
    {
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "azp",
        "cnf",
        "scope",
        "token_type",
    }
)


def _keyring_fingerprint(data: Dict[str, Any]) -> tuple:
    """Build a stable fingerprint of a keyring dict.

    Used by the JWT singleton TTL probe to compare the in-memory
    snapshot against a fresh on-disk read. The tuple captures the
    versioned CAS counter (bumped by every ``_save_keyring`` write,
    so it alone detects any rotation/revocation performed by
    another replica), the active kid, and the per-kid status map as
    a fallback for legacy keyrings written before versioning.
    """
    keys = tuple(
        sorted((kid, str(meta.get("status", ""))) for kid, meta in data.get("keys", {}).items())
    )
    return (data.get("_version", 0), data.get("active_kid", ""), keys)


class JWTService:
    """Service for creating and validating JWT tokens using RS256.

    Supports JWK key rotation: the active key is used for signing,
    while all active + verifying keys are used for verification.

    The keyring is owned by :class:`KeyStoreRepository` (the
    fsspec-backed implementation is
    :class:`FileKeyStoreRepository`). The service holds an
    in-memory snapshot of the keyring loaded at construction
    time; ``rotate_keys`` / ``revoke_key`` re-read the
    repository after the write so the in-memory cache stays
    in sync.
    """

    def __init__(self) -> None:
        # Sync attribute init only — the actual keyring
        # load happens in ``__ainit__``. The split lets
        # ``isinstance`` checks / DI wiring that don't
        # actually need the keyring snapshot work
        # synchronously; production code goes through
        # ``await JWTService.new()`` or the
        # ``get_jwt_service`` FastAPI dependency.
        self.settings = get_settings()
        self._repository = self._build_repository()
        self._keyring: Dict[str, Any] = {}
        self._active_kid: Optional[str] = None
        self._private_key: Optional[bytes] = None
        self._public_keys: Dict[str, bytes] = {}

    @classmethod
    async def new(cls) -> "JWTService":
        """Async constructor — preferred entry point.

        Use this everywhere in production code:
        ``svc = await JWTService.new()``.
        """
        svc = cls()
        await svc._load_keyring_snapshot()
        return svc

    def _build_repository(self):
        """Build the keyring repository honouring
        ``Settings.storage_backend`` (the same factory every
        other entity uses)."""
        from authglow.repositories.dependencies import get_keystore_repository

        return get_keystore_repository(settings=self.settings)

    async def _load_keyring_snapshot(self) -> None:
        """Read the keyring + per-kid PEMs into memory.

        All I/O goes through the repository (fsspec layer
        selected by ``Settings.storage_backend``). The
        snapshot is rebuilt by :meth:`_reload_keyring` after
        any mutation.
        """
        self._repository._keyring = None
        self._repository._active_kid = None
        data = await self._repository._load_keyring()
        if data is None:
            raise RuntimeError(
                f"Keyring not found at {self._repository._keyring_path()}. "
                "Did ``get_or_generate_keyring`` run at startup?"
            )
        self._keyring = data
        self._active_kid = data["active_kid"]
        self._private_key = await self._load_private_key(self._active_kid)
        self._public_keys = await self._load_public_keys()

    async def _load_private_key(self, kid: str) -> bytes:
        """Load and decrypt the private key for a given kid.

        Reads via the repository (fsspec layer) — no
        ``os.path`` / ``open()`` direct access.
        """
        priv_path = self._repository._kid_priv_path(kid)
        if not await self._repository._exists(priv_path):
            raise RuntimeError(f"Private key missing for kid={kid}: {priv_path}")
        raw = await self._repository._afs.read_bytes(priv_path)
        return decrypt_private_key(raw, secret_key=self.settings.secret_key)

    async def _load_public_keys(self) -> Dict[str, bytes]:
        """Load all public keys for verification (active + verifying, not revoked)."""
        public_keys: Dict[str, bytes] = {}
        for kid, meta in self._keyring["keys"].items():
            status = meta.get("status", "")
            if status in ("active", "verifying"):
                pub_path = self._repository._kid_pub_path(kid)
                if await self._repository._exists(pub_path):
                    public_keys[kid] = await self._repository._afs.read_bytes(pub_path)
        return public_keys

    async def _reload_keyring(self) -> None:
        """Reload keyring from the repository (used after rotation/revocation)."""
        await self._load_keyring_snapshot()

    async def keyring_changed_on_disk(self) -> bool:
        """Return ``True`` if the on-disk keyring differs from the snapshot.

        Used by the JWT singleton TTL probe to detect rotations or
        revocations performed by *another* replica. The check is
        cheap: one small JSON read (``keyring.json``) through the
        repository's fresh-read path — no per-kid PEM reads and no
        private-key decryption. The in-memory snapshot is left
        untouched; callers rebuild via ``JWTService.new()`` when
        this returns ``True``.
        """
        fresh = await self._repository.read_keyring_fresh()
        if fresh is None or self._keyring is None:
            return False
        return _keyring_fingerprint(fresh) != _keyring_fingerprint(self._keyring)

    def _encode_token(self, payload: dict) -> str:
        """Encode a token payload using the active private key, including kid in header."""
        if self._private_key is None or self._active_kid is None:
            raise RuntimeError("JWTService not initialised: call ``await JWTService.new()`` first")
        return jwt.encode(
            payload,
            self._private_key,
            algorithm=self.settings.jwt_algorithm,
            headers={"kid": self._active_kid},
        )

    def _decode_token(
        self,
        token: str,
        audience: Optional[str] = None,
    ) -> Optional[dict[str, Any]]:
        """Decode a token using the appropriate public key.

        Strategy:
        1. Extract ``kid`` from the unverified JWT header.
        2. If the kid is known and not revoked, verify with that key.
        3. If the kid is missing or unknown, try all non-revoked keys.
        4. A revoked kid always fails.

        All tokens must have a valid issuer matching the configured issuer
        and the required claims ``exp``, ``iat``, ``sub``.

        Args:
            token: The encoded JWT.
            audience: When provided, PyJWT enforces ``aud == audience`` and
                the ``aud`` claim is added to the required claims list.
                When ``None`` the ``aud`` claim is not validated,
                preserving back-compat with legacy cookie/MFA tokens
                that may not carry an audience.
        """
        try:
            unverified_header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            return None

        kid = unverified_header.get("kid")
        decode_algorithms: List[str] = [self.settings.jwt_algorithm]
        decode_issuer: str = self.settings.issuer
        required_claims: List[str] = ["exp", "iat", "sub"]
        if audience is not None:
            required_claims.append("aud")
        decode_options = cast(
            "jwt.types.Options",
            {
                "require": required_claims,
                "verify_aud": audience is not None,
            },
        )
        decode_kwargs: Dict[str, Any] = {
            "algorithms": decode_algorithms,
            "issuer": decode_issuer,
            "options": decode_options,
        }
        if audience is not None:
            decode_kwargs["audience"] = audience

        # Check if kid is revoked
        if kid and kid in self._keyring["keys"]:
            if self._keyring["keys"][kid].get("status") == "revoked":
                return None

        # If kid is known and we have its public key, verify with it
        if kid and kid in self._public_keys:
            try:
                result: dict[str, Any] = jwt.decode(
                    token,
                    self._public_keys[kid],
                    **decode_kwargs,
                )
                return result
            except jwt.PyJWTError:
                return None

        # Fallback: try all non-revoked keys (back-compat for no-kid tokens)
        for verify_kid, pub_key in self._public_keys.items():
            if verify_kid in self._keyring["keys"]:
                if self._keyring["keys"][verify_kid].get("status") == "revoked":
                    continue
            try:
                decoded: dict[str, Any] = jwt.decode(
                    token,
                    pub_key,
                    **decode_kwargs,
                )
                return decoded
            except jwt.PyJWTError:
                continue

        return None

    # --- Token Creation ---

    def create_access_token(
        self,
        user_id: str,
        email: str,
        scopes: List[str],
        expires_delta: Optional[timedelta] = None,
        audience: Optional[str] = None,
        azp: Optional[str] = None,
        cnf: Optional[Dict[str, Any]] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create an access token with a unique jti for revocation support.

        Args:
            audience: When the token is issued on behalf of an OAuth2
                client, pass the client_id. The ``aud`` claim is then
                bound to that client, enabling OIDC Core §3.1.3.7
                audience validation on the resource server. When
                ``None`` (cookie-first / password grant flows) the
                INTERNAL_AUDIENCE is set so a future resource server
                can opt to reject internal traffic.
            azp: Authorized party (OIDC Core §2). When ``audience`` is
                set, ``azp`` defaults to the same value if not
                explicitly provided. Following the AuthGlow
                convention, ``azp`` is always set whenever the token
                is aud-bound.
            cnf: T.3 / RFC 9449 / RFC 7800 — confirmation claim binding
                the token to a specific key (e.g. ``{"jkt": "<thumbprint>"}``
                for DPoP-bound tokens). The resource server enforces
                the binding. ``None`` for legacy bearer tokens.
            extra_claims: Per-client claim policy output (see
                :class:`ClaimPolicyService.build_claims`). The dict
                is merged into the payload last; reserved claims
                (``iss``, ``sub``, ``aud``, ``exp``, ``iat``,
                ``jti``, ``azp``, ``cnf``, ``token_type``) are
                silently filtered to keep the JWT service the
                single source of truth for the cryptographic
                anchors. ``None`` for callers that have not yet
                been migrated to the claim-policy flow.
        """
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(
                minutes=self.settings.access_token_expire_minutes
            )

        token_data: dict[str, Any] = {
            "iss": self.settings.issuer,
            "jti": str(uuid4()),
            "sub": user_id,
            "email": email,
            # RFC 9068 §2.2: the ``scope`` claim is a single
            # space-delimited string.
            "scope": " ".join(scopes),
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "token_type": "access",
        }
        if audience is not None:
            token_data["aud"] = audience
            token_data["azp"] = azp if azp is not None else audience
        if cnf is not None:
            token_data["cnf"] = cnf
        if extra_claims:
            for claim_name, value in extra_claims.items():
                if claim_name in _RESERVED_CLAIMS:
                    continue
                if value is None:
                    continue
                token_data[claim_name] = value
        return self._encode_token(token_data)

    def create_refresh_token(
        self,
        user_id: str,
        email: str,
        scopes: List[str],
    ) -> str:
        """Create a refresh token with jti for individual revocation."""
        expire = datetime.now(timezone.utc) + timedelta(
            days=self.settings.refresh_token_expire_days
        )
        token_data: dict[str, Any] = {
            "iss": self.settings.issuer,
            "jti": str(uuid4()),
            "sub": user_id,
            "email": email,
            # RFC 9068 §2.2: space-delimited ``scope`` string here too.
            "scope": " ".join(scopes),
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "token_type": "refresh",
        }
        return self._encode_token(token_data)

    def create_mfa_session_token(self, user_id: str, email: str) -> str:
        """Create a temporary session token for MFA verification with jti for revocation."""
        expire = datetime.now(timezone.utc) + timedelta(minutes=5)
        token_data: dict[str, Any] = {
            "iss": self.settings.issuer,
            "jti": str(uuid4()),
            "sub": user_id,
            "email": email,
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "token_type": "mfa_session",
        }
        return self._encode_token(token_data)

    def decode_token(
        self,
        token: str,
        expected_aud: Optional[str] = None,
    ) -> Optional[TokenData]:
        """Decode and validate a JWT token.

        Returns None if the token is invalid, expired, or revoked (blacklisted).

        Args:
            token: The encoded JWT.
            expected_aud: When provided, the token's ``aud`` claim
                must equal this value (OIDC Core §3.1.3.7). When
                ``None`` the ``aud`` claim is not enforced,
                preserving back-compat with cookie/MFA tokens.
        """
        payload = self._decode_token(token, audience=expected_aud)
        if not payload:
            return None

        sub = payload.get("sub")
        email = payload.get("email")
        exp_val = payload.get("exp")
        iat_val = payload.get("iat")
        jti = payload.get("jti")

        if not isinstance(sub, str):
            return None
        if not isinstance(email, str):
            return None
        if not isinstance(exp_val, (int, float)):
            return None
        if not isinstance(iat_val, (int, float)):
            return None

        token_data = TokenData(
            sub=sub,
            email=email,
            # RFC 9068 §2.2: ``scope`` arrives as a space-delimited
            # string; TokenData keeps the parsed list internally.
            scopes=(
                payload["scope"].split()
                if isinstance(payload.get("scope"), str)
                else []
            ),
            exp=datetime.fromtimestamp(exp_val, tz=timezone.utc),
            iat=datetime.fromtimestamp(iat_val, tz=timezone.utc),
            token_type=str(payload.get("token_type", "access")),
            jti=jti if isinstance(jti, str) else None,
            aud=payload.get("aud") if isinstance(payload.get("aud"), str) else None,
            # VAPT-046: expose ``azp`` so resource servers can
            # check the "authorized party" claim alongside ``aud``.
            azp=payload.get("azp") if isinstance(payload.get("azp"), str) else None,
            cnf=payload.get("cnf") if isinstance(payload.get("cnf"), dict) else None,
            # Per-client claim policy output: any payload key
            # that is not a reserved / typed claim ends up here
            # as a free-form dict so the consumer (resource
            # server, UI) can iterate over the namespaced custom
            # claims without the JWT layer having to model each
            # one.
            extra_claims=_extract_extra_claims(payload),
        )

        if token_data.exp < datetime.now(timezone.utc):
            return None

        if token_data.jti and token_blacklist().is_revoked(token_data.jti):
            return None

        return token_data

    def create_id_token(
        self,
        user_id: str,
        client_id: str,
        scopes: List[str],
        user_claims: Dict[str, Any],
        nonce: Optional[str] = None,
        auth_time: Optional[datetime] = None,
        expires_delta: Optional[timedelta] = None,
        acr: Optional[str] = None,
        amr: Optional[List[str]] = None,
        access_token: Optional[str] = None,
        authorization_code: Optional[str] = None,
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create an OpenID Connect ID Token (OIDC Core §2).

        If *access_token* is provided, the ``at_hash`` claim is
        computed (OIDC Core §3.1.3.6). If *authorization_code* is
        provided, the ``c_hash`` claim is computed similarly.

        The hash algorithm is left-half SHA-256, base64url-encoded
        with no padding.

        ``extra_claims`` is the per-client claim policy output
        (see :class:`ClaimPolicyService.build_claims`). Merged
        last so it can add namespaced custom claims (e.g.
        ``https://authglow.example.com/claims/tenant_id``) to
        the ID token. Reserved claims are filtered — the ID
        token's ``iss`` / ``sub`` / ``aud`` / ``azp`` are owned
        by the JWT service.
        """
        iat = datetime.now(timezone.utc)
        if expires_delta:
            expire = iat + expires_delta
        else:
            expire = iat + timedelta(minutes=10)

        id_token_data: dict[str, Any] = {
            "iss": self.settings.issuer,
            "sub": user_id,
            "aud": client_id,
            "azp": client_id,
            "exp": int(expire.timestamp()),
            "iat": int(iat.timestamp()),
            "sid": secrets.token_hex(16),
            "token_version": "3.0-fix-timestamp",
        }
        if nonce:
            id_token_data["nonce"] = nonce
        if auth_time:
            id_token_data["auth_time"] = int(auth_time.replace(tzinfo=timezone.utc).timestamp())
        if acr:
            id_token_data["acr"] = acr
        if amr:
            id_token_data["amr"] = amr
        if access_token:
            digest = hashlib.sha256(access_token.encode()).digest()
            id_token_data["at_hash"] = base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()
        if authorization_code:
            digest = hashlib.sha256(authorization_code.encode()).digest()
            id_token_data["c_hash"] = base64.urlsafe_b64encode(digest[:16]).rstrip(b"=").decode()

        for scope in scopes:
            if scope in SCOPE_TO_CLAIMS:
                for claim in SCOPE_TO_CLAIMS[scope]:
                    if claim in user_claims and user_claims[claim] is not None:
                        id_token_data[claim] = user_claims[claim]

        if extra_claims:
            for claim_name, value in extra_claims.items():
                if claim_name in _RESERVED_CLAIMS:
                    continue
                if value is None:
                    continue
                id_token_data[claim_name] = value

        return self._encode_token(id_token_data)

    def decode_id_token(
        self,
        token: str,
        expected_aud: str,
    ) -> Optional[IDTokenClaims]:
        """Decode and validate an ID token.

        Args:
            token: The encoded ID token (JWT).
            expected_aud: The client_id the token must be issued for.
                The token's ``aud`` claim must equal this value (OIDC
                Core §3.1.3.7). This is a required argument: the
                caller must always know which client it is speaking
                on behalf of.

        Returns None on signature failure, expiration, missing
        ``aud``, audience mismatch, or any other validation error.
        """
        payload = self._decode_token(token, audience=expected_aud)
        if not payload:
            return None
        claims = IDTokenClaims(**payload)
        if datetime.fromtimestamp(claims.exp, tz=timezone.utc) < datetime.now(timezone.utc):
            return None
        return claims

    def create_token_response(
        self,
        user_id: str,
        email: str,
        scopes: List[str],
        include_refresh: bool = True,
        audience: Optional[str] = None,
        azp: Optional[str] = None,
        cnf: Optional[Dict[str, Any]] = None,
        token_type: str = "Bearer",
        extra_claims: Optional[Dict[str, Any]] = None,
    ) -> Token:
        """Create a complete token response (OAuth2 §4.1.4 / §5.1).

        ``audience``/``azp`` are forwarded to the access token so
        the response is aud-bound when the caller knows the
        client_id. ``cnf`` is forwarded to bind the token to a
        specific key (T.3 DPoP). ``token_type`` is ``"Bearer"`` by
        default and ``"DPoP"`` for DPoP-bound responses.

        ``extra_claims`` is the per-client claim policy output
        (see :class:`ClaimPolicyService.build_claims`); the
        access token is the target — the ID token receives the
        same dict (minus reserved claims) via
        :meth:`create_id_token` if the caller also passes one.
        """
        access_token = self.create_access_token(
            user_id,
            email,
            scopes,
            audience=audience,
            azp=azp,
            cnf=cnf,
            extra_claims=extra_claims,
        )
        token_response = Token(
            access_token=access_token,
            token_type=token_type,
            expires_in=self.settings.access_token_expire_minutes * 60,
            scope=" ".join(scopes),
        )
        if include_refresh:
            refresh_token = self.create_refresh_token(user_id, email, scopes)
            token_response.refresh_token = refresh_token
        return token_response

    # --- Key Rotation & Management ---

    async def rotate_keys(self) -> Dict[str, str]:
        """Rotate the active signing key.

        Generates a new RSA key pair, marks the old active key as
        'verifying', and makes the new key the active signer. The
        write is routed through the repository's CAS-protected path
        so concurrent rotators on other instances get
        ``ConcurrentWriteError`` and the call can be retried.

        Returns:
            Dict with ``old_kid`` and ``new_kid``.
        """
        old_kid = self._active_kid
        new_keypair = await self._repository.rotate(secret_key=self.settings.secret_key)
        await self._load_keyring_snapshot()
        from authglow.core.jwt_singleton import reset_jwt_singleton

        await reset_jwt_singleton()
        return {"old_kid": old_kid, "new_kid": new_keypair.kid}

    async def revoke_key(self, kid: str) -> bool:
        """Revoke a key so tokens signed with it are rejected.

        The active key cannot be revoked.

        Returns:
            True if the key was revoked, False if the kid is
            unknown or is the active key.
        """
        if kid == self._active_kid:
            return False
        if kid not in self._keyring["keys"]:
            return False
        await self._repository.revoke(kid)
        await self._load_keyring_snapshot()
        from authglow.core.jwt_singleton import reset_jwt_singleton

        await reset_jwt_singleton()
        return True

    def get_keyring_info(self) -> Dict[str, Any]:
        """Return keyring metadata for inspection.

        Returns:
            Dict with ``active_kid`` and a ``keys`` dict keyed by
            kid with status, created_at, algorithm, and key_size.
        """
        return {
            "active_kid": self._active_kid,
            "keys": dict(self._keyring["keys"]),
        }
