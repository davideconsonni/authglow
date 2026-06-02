"""API Key management endpoints."""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from authglow.api.auth import get_api_key_service, get_audit_service, get_current_user
from authglow.core.rate_limit import limiter
from authglow.models.api_key import (
    APIKeyCreate,
    APIKeyResponse,
    APIKeyUpdate,
    APIKeyWithSecret,
)
from authglow.models.user import User
from authglow.services.api_key import APIKeyService
from authglow.services.audit import AuditService
from authglow.services.storage import UserStorage

router = APIRouter()


@router.post("/api/keys", response_model=APIKeyWithSecret, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")  # Limit API key creation
async def create_api_key(
    request: Request,
    key_data: APIKeyCreate,
    current_user: User = Depends(get_current_user),
    api_key_service: APIKeyService = Depends(get_api_key_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Create a new API key for the current user.

    The API key secret will only be shown once, so save it securely!
    """
    # Create the key
    api_key, plaintext_key = await api_key_service.create_key(
        user_id=current_user.id, key_data=key_data, created_by=current_user.id
    )

    # Log the creation
    await audit_service.log_event(
        event_type="api_key_created",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "key_id": api_key.key_id,
            "key_name": api_key.name,
            "scopes": api_key.scopes,
        },
        ip_address=request.client.host if request.client else None,
    )

    # Return response with plaintext key
    return APIKeyWithSecret(**api_key.model_dump(), api_key=plaintext_key)


@router.get("/api/keys", response_model=List[APIKeyResponse])
async def list_my_api_keys(
    current_user: User = Depends(get_current_user),
    api_key_service: APIKeyService = Depends(get_api_key_service),
):
    """List all API keys for the current user."""
    keys = await api_key_service.get_user_keys(current_user.id)
    return [APIKeyResponse(**key.model_dump()) for key in keys]


@router.get("/api/keys/{key_id}", response_model=APIKeyResponse)
async def get_api_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    api_key_service: APIKeyService = Depends(get_api_key_service),
):
    """Get details of a specific API key."""
    api_key = await api_key_service.get_key(key_id)

    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    # Check ownership
    if api_key.user_id != current_user.id and "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Not authorized to view this key")

    # Enrich with user email
    user_storage = UserStorage()
    key_data = api_key.model_dump()
    user = await user_storage.get_user(api_key.user_id)
    key_data["user_email"] = user.email if user else None

    return APIKeyResponse(**key_data)


@router.patch("/api/keys/{key_id}", response_model=APIKeyResponse)
@limiter.limit("30/hour")
async def update_api_key(
    request: Request,
    key_id: str,
    update_data: APIKeyUpdate,
    current_user: User = Depends(get_current_user),
    api_key_service: APIKeyService = Depends(get_api_key_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Update an API key."""
    api_key = await api_key_service.get_key(key_id)

    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    # Check ownership
    if api_key.user_id != current_user.id and "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Not authorized to update this key")

    # Update
    updates = update_data.model_dump(exclude_none=True)
    updated_key = await api_key_service.update_key(key_id, updates)
    if not updated_key:
        raise HTTPException(status_code=404, detail="API key not found after update")

    # Log the update
    await audit_service.log_event(
        event_type="api_key_updated",
        user_id=current_user.id,
        email=current_user.email,
        metadata={
            "key_id": key_id,
            "key_name": api_key.name,
            "updates": list(updates.keys()),
        },
        ip_address=request.client.host if request.client else None,
    )

    return APIKeyResponse(**updated_key.model_dump())


@router.post("/api/keys/{key_id}/revoke", response_model=dict)
@limiter.limit("20/hour")
async def revoke_api_key(
    request: Request,
    key_id: str,
    current_user: User = Depends(get_current_user),
    api_key_service: APIKeyService = Depends(get_api_key_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Revoke an API key (makes it inactive but keeps it in the system)."""
    api_key = await api_key_service.get_key(key_id)

    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    # Check ownership
    if api_key.user_id != current_user.id and "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Not authorized to revoke this key")

    # Revoke
    success = await api_key_service.revoke_key(key_id, current_user.id)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to revoke key")

    # Log the revocation
    await audit_service.log_event(
        event_type="api_key_revoked",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"key_id": key_id, "key_name": api_key.name},
        severity="warning",
        ip_address=request.client.host if request.client else None,
    )

    return {"message": "API key revoked successfully"}


@router.delete("/api/keys/{key_id}")
@limiter.limit("20/hour")
async def delete_api_key(
    request: Request,
    key_id: str,
    current_user: User = Depends(get_current_user),
    api_key_service: APIKeyService = Depends(get_api_key_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Permanently delete an API key."""
    api_key = await api_key_service.get_key(key_id)

    if not api_key:
        raise HTTPException(status_code=404, detail="API key not found")

    # Check ownership
    if api_key.user_id != current_user.id and "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Not authorized to delete this key")

    # Delete
    success = await api_key_service.delete_key(key_id)

    if not success:
        raise HTTPException(status_code=500, detail="Failed to delete key")

    # Log the deletion
    await audit_service.log_event(
        event_type="api_key_deleted",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"key_id": key_id, "key_name": api_key.name},
        severity="warning",
        ip_address=request.client.host if request.client else None,
    )

    return {"message": "API key deleted successfully"}


# Admin endpoints


@router.get("/api/admin/keys", response_model=List[APIKeyResponse])
async def list_all_api_keys(
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    active_only: bool = Query(False),
    current_user: User = Depends(get_current_user),
    api_key_service: APIKeyService = Depends(get_api_key_service),
):
    """List all API keys (admin only)."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Admin access required")

    keys = await api_key_service.list_all_keys(limit=limit, offset=offset, active_only=active_only)

    # Enrich with user email
    user_storage = UserStorage()
    responses = []
    for key in keys:
        key_data = key.model_dump()
        user = await user_storage.get_user(key.user_id)
        key_data["user_email"] = user.email if user else None
        responses.append(APIKeyResponse(**key_data))

    return responses


@router.get("/api/admin/users/{user_id}/keys", response_model=List[APIKeyResponse])
async def list_user_api_keys(
    user_id: str,
    current_user: User = Depends(get_current_user),
    api_key_service: APIKeyService = Depends(get_api_key_service),
):
    """List all API keys for a specific user (admin only)."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Admin access required")

    keys = await api_key_service.get_user_keys(user_id)
    return [APIKeyResponse(**key.model_dump()) for key in keys]


@router.post("/api/admin/keys/cleanup")
async def cleanup_expired_keys(
    current_user: User = Depends(get_current_user),
    api_key_service: APIKeyService = Depends(get_api_key_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Delete all expired and inactive API keys (admin only)."""
    if "admin" not in current_user.scopes:
        raise HTTPException(status_code=403, detail="Admin access required")

    deleted_count = await api_key_service.cleanup_expired_keys()

    # Log cleanup
    await audit_service.log_event(
        event_type="api_keys_cleanup",
        user_id=current_user.id,
        email=current_user.email,
        metadata={"deleted_count": deleted_count},
    )

    return {"message": f"Cleaned up {deleted_count} expired API keys"}
