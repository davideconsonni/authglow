"""Business logic for Pushed Authorization Requests (RFC 9126, OA-501)."""

from datetime import timedelta
from typing import Optional

import structlog

from authglow.core.concurrency import named_lock
from authglow.core.config import Settings, get_settings
from authglow.core.datetime import utcnow
from authglow.models.par import PushedAuthorizationRequest
from authglow.repositories.protocols import PushedAuthorizationRequestRepository

logger = structlog.get_logger("authglow.audit")


class PushedAuthorizationService:
    """Create and single-use-consume PAR requests."""

    def __init__(
        self,
        repository: Optional[PushedAuthorizationRequestRepository] = None,
        *,
        settings: Optional[Settings] = None,
    ) -> None:
        """Initialize with an optional repository (lru_cache bypass in tests)."""
        self.settings: Settings = settings or get_settings()
        self._repository: PushedAuthorizationRequestRepository = (
            repository if repository is not None else self._default_repository()
        )
        self._lock = named_lock()

    def _default_repository(self) -> PushedAuthorizationRequestRepository:
        from authglow.repositories.dependencies import get_pushed_authorization_request_repository

        return get_pushed_authorization_request_repository(settings=self.settings)

    async def create_request(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        response_type: str = "code",
        state: Optional[str] = None,
        code_challenge: Optional[str] = None,
        code_challenge_method: Optional[str] = None,
        nonce: Optional[str] = None,
        prompt: Optional[str] = None,
        max_age: Optional[int] = None,
        claims: Optional[str] = None,
    ) -> PushedAuthorizationRequest:
        """Store a pushed request; returns it (with ``request_uri``)."""
        request = PushedAuthorizationRequest(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=scope,
            response_type=response_type,
            state=state,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
            prompt=prompt,
            max_age=max_age,
            claims=claims,
            expires_at=utcnow() + timedelta(seconds=self.settings.par_request_uri_ttl_seconds),
        )
        await self._repository.create(request)
        logger.info(
            "par_request_created",
            client_id=client_id,
            request_id=request.request_id[:8] + "...",
        )
        return request

    async def consume_request(
        self, client_id: str, request_uri: str
    ) -> Optional[PushedAuthorizationRequest]:
        """Resolve + single-use-consume a ``request_uri`` for a client.

        Returns ``None`` when the URN is malformed, unknown, expired,
        already used, or bound to a different client.
        """
        request_id = PushedAuthorizationRequest.request_id_from_uri(request_uri)
        if request_id is None:
            return None
        async with self._lock(f"par:{request_id}"):
            par = await self._repository.get_by_request_id(request_id)
            if par is None:
                return None
            if par.client_id != client_id:
                return None
            if not await self._repository.mark_used(request_id):
                return None
            par.used = True
            return par
