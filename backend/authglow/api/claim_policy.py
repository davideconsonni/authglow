"""Admin API endpoints for the per-OAuth2-client claim policy system.

The four endpoints (read, write, delete, list-templates) let
the admin UI manage the namespaced custom claims emitted in
access tokens / ID tokens / UserInfo responses, per the OIDC
Core §5.1.2 namespacing rule.

The endpoints are mounted under ``/api/admin/oauth-clients``
prefix so the resource hierarchy is clear (the policy belongs
to a specific client) and the existing OAuth client admin
UI can deep-link into the policy tab.
"""

from typing import List, Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field

from authglow.api.auth import get_current_user
from authglow.core.config import get_settings
from authglow.core.rate_limit import limiter
from authglow.models.claim_policy import (
    ClaimRule,
    ClaimSource,
    ClaimSourceConfig,
    ClaimTarget,
    ClientClaimPolicy,
    render_template_claim_name,
)
from authglow.models.user import User
from authglow.services.api_key import APIKeyService
from authglow.services.audit import AuditService
from authglow.services.claim_policy import ClaimPolicyService
from authglow.services.oauth_client import OAuth2ClientStorage

router = APIRouter()


# ---------------------------------------------------------------------------
# Dependency factories
# ---------------------------------------------------------------------------


def get_claim_policy_service() -> ClaimPolicyService:
    """FastAPI factory for the claim policy service."""
    return ClaimPolicyService()


def get_client_storage() -> OAuth2ClientStorage:
    """FastAPI factory for the OAuth2 client storage (used to
    validate that the ``client_id`` in the URL exists)."""
    return OAuth2ClientStorage()


def get_api_key_service() -> APIKeyService:
    """FastAPI factory for the API key service (used to validate
    that the ``key_id`` in the URL exists and to look up the
    key on subsequent reads)."""
    return APIKeyService()


def get_audit_service() -> AuditService:
    """FastAPI factory for the audit service."""
    return AuditService()


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Gate the endpoints on the ``admin`` scope."""
    if "admin" not in current_user.scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required"
        )
    return current_user


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class ClaimRulePayload(BaseModel):
    """API-side payload for a single :class:`ClaimRule`.

    Pydantic's ``model_validate`` against :class:`ClaimRule`
    applies the claim-name URI enforcement and the
    source-config / source coherence check at the API
    boundary, so the admin UI gets a clear 422 on bad input
    rather than a silent skip downstream.
    """

    model_config = ConfigDict(extra="forbid")

    claim_name: str
    source: ClaimSource
    source_config: ClaimSourceConfig = Field(default_factory=ClaimSourceConfig)
    include_in: List[ClaimTarget] = Field(default_factory=list)
    required_scope: Optional[str] = None
    description: Optional[str] = Field(None, max_length=500)


class ClaimPolicyResponse(BaseModel):
    """Response payload returned to the admin UI.

    Always includes the resolved rules + the (server-side)
    default rules so the UI can show "current vs default" and
    surface the diff. ``is_custom`` is ``True`` when the
    response reflects a saved policy file, ``False`` when
    the client falls back to the default rule set.
    """

    model_config = ConfigDict(extra="forbid")

    client_id: str
    is_custom: bool
    rules: List[ClaimRulePayload]
    default_rules: List[ClaimRulePayload]
    updated_at: Optional[str] = None


class ClaimPolicyUpdateRequest(BaseModel):
    """PUT body — replaces the saved policy atomically.

    Empty ``rules`` is the explicit "delete the saved policy,
    revert to default" signal (matches :meth:`ClaimPolicyService.save_policy`).
    """

    model_config = ConfigDict(extra="forbid")

    rules: List[ClaimRulePayload] = Field(default_factory=list)


class ClaimTemplateResponse(BaseModel):
    """API-side payload for a :class:`ClaimTemplate`."""

    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    description: str
    claim_name: str
    source: ClaimSource
    include_in: List[ClaimTarget]
    required_scope: Optional[str] = None
    source_config: ClaimSourceConfig = Field(default_factory=ClaimSourceConfig)


def _to_response_payload(policy: ClientClaimPolicy) -> ClaimPolicyResponse:
    return ClaimPolicyResponse(
        client_id=policy.client_id,
        is_custom=True,
        rules=[
            ClaimRulePayload(
                claim_name=r.claim_name,
                source=r.source,
                source_config=r.source_config,
                include_in=r.include_in,
                required_scope=r.required_scope,
                description=r.description,
            )
            for r in policy.rules
        ],
        default_rules=[],
        updated_at=policy.updated_at.isoformat() if policy.updated_at else None,
    )


def _to_default_payload(client_id: str) -> ClaimPolicyResponse:
    """Return a "no saved policy" response.

    The default first-party RBAC rules are returned in
    ``default_rules`` (read-only informational) — they are
    always emitted at issue time by the JWT service regardless
    of whether the admin saves a custom policy (the API key
    policy is MERGED on top of them). The ``rules`` field
    stays empty so the admin UI's "Current Rules" editable
    section shows the empty state and does not confuse the
    admin with system-emitted rules as if they were their
    own saved rules.
    """
    from authglow.core.config import get_settings

    ns = get_settings().claim_namespace.rstrip("/")
    default = [
        ClaimRule(
            claim_name=f"{ns}/roles",
            source=ClaimSource.RBAC_ROLES,
            include_in=[ClaimTarget.ACCESS_TOKEN],
        ),
        ClaimRule(
            claim_name=f"{ns}/permissions",
            source=ClaimSource.RBAC_PERMISSIONS,
            include_in=[ClaimTarget.ACCESS_TOKEN],
        ),
    ]
    return ClaimPolicyResponse(
        client_id=client_id,
        is_custom=False,
        rules=[],  # no user-saved custom rules
        default_rules=[
            ClaimRulePayload(
                claim_name=r.claim_name,
                source=r.source,
                source_config=r.source_config,
                include_in=r.include_in,
                required_scope=r.required_scope,
                description=r.description,
            )
            for r in default
        ],
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/api/admin/oauth-clients/{client_id}/claim-policy",
    response_model=ClaimPolicyResponse,
)
@limiter.limit("60/minute")
async def get_claim_policy(
    request: Request,
    client_id: str,
    _: User = Depends(require_admin),
    policy_service: ClaimPolicyService = Depends(get_claim_policy_service),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
):
    """Return the saved claim policy for *client_id*, or the
    default rule set if no policy is configured.

    The response is a 200 either way — the admin UI uses the
    ``is_custom`` flag to decide whether to show "Edit" or
    "Create from default".
    """
    client = await storage.get_client(client_id)
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth2 client {client_id!r} not found",
        )
    saved = await policy_service.get_policy(client_id)
    if saved is None:
        return _to_default_payload(client_id)
    return _to_response_payload(saved)


@router.put(
    "/api/admin/oauth-clients/{client_id}/claim-policy",
    response_model=ClaimPolicyResponse,
)
@limiter.limit("20/minute")
async def put_claim_policy(
    request: Request,
    client_id: str,
    payload: ClaimPolicyUpdateRequest = Body(...),
    current_user: User = Depends(require_admin),
    policy_service: ClaimPolicyService = Depends(get_claim_policy_service),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Replace the saved policy for *client_id*. Empty
    ``rules`` deletes the saved policy (revert to default).
    """
    client = await storage.get_client(client_id)
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth2 client {client_id!r} not found",
        )
    # Re-validate every rule through the Pydantic model so
    # the claim-name URI check, the source-config coherence
    # check, and the no-duplicate-claim-names check all run
    # server-side (the API contract is the same as the
    # model — defense in depth). The duplicate check fires
    # at the ``ClientClaimPolicy`` construction (inside
    # ``save_policy``), so we catch any Pydantic ValidationError
    # and re-raise as 422.
    validated_rules: List[ClaimRule] = []
    for raw in payload.rules:
        try:
            validated_rules.append(
                ClaimRule(
                    claim_name=raw.claim_name,
                    source=raw.source,
                    source_config=raw.source_config,
                    include_in=raw.include_in,
                    required_scope=raw.required_scope,
                    description=raw.description,
                )
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
    try:
        saved = await policy_service.save_policy(client_id, validated_rules)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    await audit_service.log_event(
        event_type="claim_policy_updated",
        user_id=current_user.id,
        email=current_user.email,
        ip_address=request.client.host if request.client else None,
        metadata={
            "client_id": client_id,
            "rule_count": len(validated_rules),
        },
    )
    if validated_rules:
        return _to_response_payload(saved)
    # Caller asked for "no policy" — return the default view
    # so the UI knows it's the implicit state.
    return _to_default_payload(client_id)


@router.delete(
    "/api/admin/oauth-clients/{client_id}/claim-policy",
    status_code=status.HTTP_204_NO_CONTENT,
)
@limiter.limit("20/minute")
async def delete_claim_policy(
    request: Request,
    client_id: str,
    current_user: User = Depends(require_admin),
    policy_service: ClaimPolicyService = Depends(get_claim_policy_service),
    storage: OAuth2ClientStorage = Depends(get_client_storage),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Remove the saved policy for *client_id* (revert to the
    default first-party rule set)."""
    client = await storage.get_client(client_id)
    if client is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"OAuth2 client {client_id!r} not found",
        )
    deleted = await policy_service.delete_policy(client_id)
    if not deleted:
        # No saved policy — idempotent success
        return None
    await audit_service.log_event(
        event_type="claim_policy_deleted",
        user_id=current_user.id,
        email=current_user.email,
        ip_address=request.client.host if request.client else None,
        metadata={"client_id": client_id},
    )
    return None


@router.get("/api/admin/claim-templates", response_model=List[ClaimTemplateResponse])
@limiter.limit("60/minute")
async def list_claim_templates(
    request: Request,
    _: User = Depends(require_admin),
    policy_service: ClaimPolicyService = Depends(get_claim_policy_service),
):
    """List the built-in claim rule templates. The admin UI
    shows these as one-click cards the admin can apply to a
    client policy.

    The ``claim_name`` field is the *resolved* (namespaced)
    form, expanded server-side against ``settings.claim_namespace``
    so the admin UI's inline OIDC validator accepts the value
    out of the box. The relative form is only meaningful inside
    :meth:`ClaimPolicyService.apply_template` (server-side
    rule construction).
    """
    namespace = get_settings().claim_namespace
    out: List[ClaimTemplateResponse] = []
    for t in policy_service.list_templates():
        out.append(
            ClaimTemplateResponse(
                id=t.id,
                label=t.label,
                description=t.description,
                claim_name=render_template_claim_name(t.claim_name, namespace),
                source=t.source,
                include_in=t.include_in,
                required_scope=t.required_scope,
                source_config=t.source_config,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Per-API-key claim policy endpoints
#
# API key counterpart of the per-OAuth-client endpoints above.
# The endpoints are mounted under ``/api/admin/api-keys`` so
# the resource hierarchy is clear and the existing API key
# admin UI can deep-link into the policy tab. Empty
# ``rules`` list on PUT deletes the saved policy (revert to
# the default first-party rules). Saved policies are
# MERGED with the default first-party rule set at issue time
# (different from OAuth client policies, which REPLACE the
# default) — see :class:`ClaimPolicyService` for the rationale.
# ---------------------------------------------------------------------------


def _to_response_payload_api_key(policy) -> ClaimPolicyResponse:
    from authglow.models.api_key_claim_policy import APIKeyClaimPolicy

    assert isinstance(policy, APIKeyClaimPolicy)
    return ClaimPolicyResponse(
        client_id=policy.api_key_id,
        is_custom=True,
        rules=[
            ClaimRulePayload(
                claim_name=r.claim_name,
                source=r.source,
                source_config=r.source_config,
                include_in=r.include_in,
                required_scope=r.required_scope,
                description=r.description,
            )
            for r in policy.rules
        ],
        default_rules=[],
        updated_at=policy.updated_at.isoformat() if policy.updated_at else None,
    )


@router.get(
    "/api/admin/api-keys/{key_id}/claim-policy",
    response_model=ClaimPolicyResponse,
)
@limiter.limit("60/minute")
async def get_api_key_claim_policy(
    request: Request,
    key_id: str,
    _: User = Depends(require_admin),
    policy_service: ClaimPolicyService = Depends(get_claim_policy_service),
    api_key_service: APIKeyService = Depends(get_api_key_service),
):
    """Return the saved claim policy for *key_id*, or the
    default rule set if no policy is configured.

    The response is a 200 either way — the admin UI uses the
    ``is_custom`` flag to decide whether to show "Edit" or
    "Create from default".
    """
    key = await api_key_service.get_key(key_id)
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key {key_id!r} not found",
        )
    saved = await policy_service.get_api_key_policy(key_id)
    if saved is None:
        return _to_default_payload(key_id)
    return _to_response_payload_api_key(saved)


@router.put(
    "/api/admin/api-keys/{key_id}/claim-policy",
    response_model=ClaimPolicyResponse,
)
@limiter.limit("20/minute")
async def put_api_key_claim_policy(
    request: Request,
    key_id: str,
    body: ClaimPolicyUpdateRequest,
    current_user: User = Depends(require_admin),
    policy_service: ClaimPolicyService = Depends(get_claim_policy_service),
    api_key_service: APIKeyService = Depends(get_api_key_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Replace the saved policy for *key_id*. Empty
    ``rules`` deletes the saved policy (revert to the default
    first-party rule set alone, since the API key merge
    semantic is "saved rules + default rules")."""
    key = await api_key_service.get_key(key_id)
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key {key_id!r} not found",
        )
    validated_rules: List[ClaimRule] = []
    for raw in body.rules:
        try:
            validated_rules.append(
                ClaimRule(
                    claim_name=raw.claim_name,
                    source=raw.source,
                    source_config=raw.source_config,
                    include_in=raw.include_in,
                    required_scope=raw.required_scope,
                    description=raw.description,
                )
            )
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
    try:
        saved = await policy_service.save_api_key_policy(key_id, validated_rules)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    await audit_service.log_event(
        event_type="api_key_claim_policy_updated",
        user_id=current_user.id,
        email=current_user.email,
        ip_address=request.client.host if request.client else None,
        metadata={
            "key_id": key_id,
            "rule_count": len(validated_rules),
        },
    )
    if validated_rules:
        return _to_response_payload_api_key(saved)
    return _to_default_payload(key_id)


@router.delete(
    "/api/admin/api-keys/{key_id}/claim-policy",
    status_code=status.HTTP_204_NO_CONTENT,
)
@limiter.limit("20/minute")
async def delete_api_key_claim_policy(
    request: Request,
    key_id: str,
    current_user: User = Depends(require_admin),
    policy_service: ClaimPolicyService = Depends(get_claim_policy_service),
    api_key_service: APIKeyService = Depends(get_api_key_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Remove the saved policy for *key_id* (revert to the
    default first-party rule set)."""
    key = await api_key_service.get_key(key_id)
    if key is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key {key_id!r} not found",
        )
    deleted = await policy_service.delete_api_key_policy(key_id)
    if not deleted:
        return None
    await audit_service.log_event(
        event_type="api_key_claim_policy_deleted",
        user_id=current_user.id,
        email=current_user.email,
        ip_address=request.client.host if request.client else None,
        metadata={"key_id": key_id},
    )
    return None
