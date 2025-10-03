"""RBAC management API endpoints."""

from typing import List
from fastapi import APIRouter, HTTPException, Depends, status
from datetime import datetime

from authglow.models.rbac import (
    PermissionCreate,
    PermissionResponse,
    RoleCreate,
    RoleUpdate,
    RoleResponse,
    RoleWithPermissions,
    AssignRoleRequest,
    UserRoleResponse,
    UserPermissions
)
from authglow.services.rbac import RBACService
from authglow.services.user_storage import UserStorage
from authglow.core.permissions import require_permission, require_admin, get_current_user

router = APIRouter(prefix="/api/rbac", tags=["RBAC"])


# Permission Endpoints

@router.post("/permissions", response_model=PermissionResponse, status_code=status.HTTP_201_CREATED)
async def create_permission(
    permission: PermissionCreate,
    _: str = Depends(require_admin())
):
    """Create a new permission (admin only)."""
    rbac_service = RBACService()

    # Check if permission name already exists
    existing = await rbac_service.get_permission_by_name(permission.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Permission '{permission.name}' already exists"
        )

    from authglow.models.rbac import Permission
    perm = Permission(**permission.model_dump())
    created = await rbac_service.create_permission(perm)

    return PermissionResponse(**created.model_dump())


@router.get("/permissions", response_model=List[PermissionResponse])
async def list_permissions(
    _: str = Depends(require_permission("roles.read"))
):
    """List all permissions."""
    rbac_service = RBACService()
    permissions = await rbac_service.list_permissions()

    return [PermissionResponse(**p.model_dump()) for p in permissions]


@router.get("/permissions/{permission_id}", response_model=PermissionResponse)
async def get_permission(
    permission_id: str,
    _: str = Depends(require_permission("roles.read"))
):
    """Get permission by ID."""
    rbac_service = RBACService()
    permission = await rbac_service.get_permission(permission_id)

    if not permission:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )

    return PermissionResponse(**permission.model_dump())


@router.delete("/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_permission(
    permission_id: str,
    _: str = Depends(require_admin())
):
    """Delete a permission (admin only)."""
    rbac_service = RBACService()
    success = await rbac_service.delete_permission(permission_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Permission not found"
        )


# Role Endpoints

@router.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    role: RoleCreate,
    _: str = Depends(require_permission("roles.write"))
):
    """Create a new role."""
    rbac_service = RBACService()

    # Check if role name already exists
    existing = await rbac_service.get_role_by_name(role.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Role '{role.name}' already exists"
        )

    # Validate that all permissions exist
    for perm_name in role.permissions:
        perm = await rbac_service.get_permission_by_name(perm_name)
        if not perm:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Permission '{perm_name}' does not exist"
            )

    from authglow.models.rbac import Role
    role_obj = Role(**role.model_dump())
    created = await rbac_service.create_role(role_obj)

    return RoleResponse(**created.model_dump())


@router.get("/roles", response_model=List[RoleResponse])
async def list_roles(
    _: str = Depends(require_permission("roles.read"))
):
    """List all roles."""
    rbac_service = RBACService()
    roles = await rbac_service.list_roles()

    return [RoleResponse(**r.model_dump()) for r in roles]


@router.get("/roles/{role_id}", response_model=RoleWithPermissions)
async def get_role(
    role_id: str,
    _: str = Depends(require_permission("roles.read"))
):
    """Get role by ID with full permission details."""
    rbac_service = RBACService()
    role = await rbac_service.get_role(role_id)

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Get full permission details
    permission_details = []
    for perm_name in role.permissions:
        perm = await rbac_service.get_permission_by_name(perm_name)
        if perm:
            permission_details.append(PermissionResponse(**perm.model_dump()))

    role_dict = role.model_dump()
    role_dict['permission_details'] = [p.model_dump() for p in permission_details]

    return RoleWithPermissions(**role_dict)


@router.patch("/roles/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: str,
    role_update: RoleUpdate,
    _: str = Depends(require_permission("roles.write"))
):
    """Update a role."""
    rbac_service = RBACService()
    role = await rbac_service.get_role(role_id)

    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    if role.is_system:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify system roles"
        )

    # Update fields
    update_data = role_update.model_dump(exclude_unset=True)

    if "name" in update_data:
        # Check if new name conflicts
        existing = await rbac_service.get_role_by_name(update_data["name"])
        if existing and existing.role_id != role_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Role '{update_data['name']}' already exists"
            )

    if "permissions" in update_data:
        # Validate all permissions exist
        for perm_name in update_data["permissions"]:
            perm = await rbac_service.get_permission_by_name(perm_name)
            if not perm:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Permission '{perm_name}' does not exist"
                )

    for field, value in update_data.items():
        setattr(role, field, value)

    updated = await rbac_service.update_role(role)

    return RoleResponse(**updated.model_dump())


@router.delete("/roles/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: str,
    _: str = Depends(require_permission("roles.write"))
):
    """Delete a role (cannot delete system roles)."""
    rbac_service = RBACService()
    success = await rbac_service.delete_role(role_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found or is a system role"
        )


# User-Role Assignment Endpoints

@router.post("/user-roles", response_model=UserRoleResponse, status_code=status.HTTP_201_CREATED)
async def assign_role_to_user(
    assignment: AssignRoleRequest,
    current_user_id: str = Depends(require_permission("roles.write"))
):
    """Assign a role to a user."""
    rbac_service = RBACService()
    user_storage = UserStorage()

    # Validate user exists
    user = await user_storage.get_user(assignment.user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Validate role exists
    role = await rbac_service.get_role(assignment.role_id)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found"
        )

    # Check if user already has this role
    user_roles = await rbac_service.get_user_roles(assignment.user_id)
    if any(ur.role_id == assignment.role_id for ur in user_roles):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already has this role"
        )

    from authglow.models.rbac import UserRole
    user_role = UserRole(
        user_id=assignment.user_id,
        role_id=assignment.role_id,
        assigned_by=current_user_id,
        expires_at=assignment.expires_at
    )

    created = await rbac_service.assign_role_to_user(user_role)

    return UserRoleResponse(
        assignment_id=created.assignment_id,
        user_id=created.user_id,
        user_email=user.email,
        role_id=created.role_id,
        role_name=role.name,
        assigned_by=created.assigned_by,
        assigned_at=created.assigned_at,
        expires_at=created.expires_at
    )


@router.delete("/user-roles/{user_id}/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_role_from_user(
    user_id: str,
    role_id: str,
    _: str = Depends(require_permission("roles.write"))
):
    """Remove a role from a user."""
    rbac_service = RBACService()
    success = await rbac_service.remove_role_from_user(user_id, role_id)

    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role assignment not found"
        )


@router.get("/user-roles/{user_id}", response_model=List[UserRoleResponse])
async def get_user_roles(
    user_id: str,
    current_user_id: str = Depends(get_current_user)
):
    """Get all roles assigned to a user (users can view their own roles)."""
    # Users can view their own roles, or need permission to view others
    if user_id != current_user_id:
        rbac_service = RBACService()
        has_permission = await rbac_service.user_has_permission(current_user_id, "roles.read")
        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )

    rbac_service = RBACService()
    user_storage = UserStorage()

    user = await user_storage.get_user(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    user_roles = await rbac_service.get_user_roles(user_id)

    responses = []
    for ur in user_roles:
        role = await rbac_service.get_role(ur.role_id)
        responses.append(UserRoleResponse(
            assignment_id=ur.assignment_id,
            user_id=ur.user_id,
            user_email=user.email,
            role_id=ur.role_id,
            role_name=role.name if role else None,
            assigned_by=ur.assigned_by,
            assigned_at=ur.assigned_at,
            expires_at=ur.expires_at
        ))

    return responses


@router.get("/users/{user_id}/permissions", response_model=UserPermissions)
async def get_user_permissions(
    user_id: str,
    current_user_id: str = Depends(get_current_user)
):
    """Get all permissions for a user (users can view their own permissions)."""
    # Users can view their own permissions, or need permission to view others
    if user_id != current_user_id:
        rbac_service = RBACService()
        has_permission = await rbac_service.user_has_permission(current_user_id, "roles.read")
        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )

    rbac_service = RBACService()
    user_storage = UserStorage()

    user = await user_storage.get_user(user_id)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Get roles
    user_roles = await rbac_service.get_user_roles(user_id)
    role_names = []
    for ur in user_roles:
        role = await rbac_service.get_role(ur.role_id)
        if role:
            role_names.append(role.name)

    # Get permissions
    permissions = await rbac_service.get_user_permissions(user_id)

    # Check if admin
    is_admin = await rbac_service.user_has_role(user_id, "admin")

    return UserPermissions(
        user_id=user_id,
        user_email=user.email,
        roles=role_names,
        permissions=list(permissions),
        is_admin=is_admin
    )
