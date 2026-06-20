"""Permission checking decorators and utilities."""

from typing import List, Optional, Union

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from authglow.core.config import get_settings
from authglow.core.jwt_singleton import get_jwt_service
from authglow.services.rbac import RBACService

security = HTTPBearer(auto_error=False)


def _extract_token(request: Request, credentials: Optional[HTTPAuthorizationCredentials]) -> str:
    """Extract token from Authorization header or access_token cookie."""
    if isinstance(credentials, HTTPAuthorizationCredentials):
        return credentials.credentials
    settings = get_settings()
    cookie_token = request.cookies.get(settings.auth_cookie_access_name)
    if cookie_token:
        return cookie_token
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated",
    )


class PermissionChecker:
    """Dependency for checking user permissions."""

    def __init__(
        self,
        required_permissions: Optional[List[str]] = None,
        required_roles: Optional[List[str]] = None,
        require_all_permissions: bool = False,
        require_all_roles: bool = False,
    ):
        """Initialize permission checker.

        Args:
            required_permissions: List of permission names required
            required_roles: List of role names required
            require_all_permissions: If True, user must have ALL permissions. If False, ANY permission is enough.
            require_all_roles: If True, user must have ALL roles. If False, ANY role is enough.
        """
        self.required_permissions = required_permissions or []
        self.required_roles = required_roles or []
        self.require_all_permissions = require_all_permissions
        self.require_all_roles = require_all_roles

    async def __call__(
        self,
        request: Request,
        credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    ) -> str:
        """Check if user has required permissions/roles.

        Returns:
            user_id if authorized

        Raises:
            HTTPException: If unauthorized or insufficient permissions
        """
        token = _extract_token(request, credentials)

        # Decode token to get user_id
        token_data = (await get_jwt_service()).decode_token(token)
        if not token_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token",
            )

        user_id = token_data.sub
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing user ID",
            )

        # Check if admin scope (admins bypass permission checks)
        scopes = token_data.scopes or []
        if "admin" in scopes:
            return user_id

        rbac_service = RBACService()

        # Check required permissions
        if self.required_permissions:
            user_permissions = await rbac_service.get_user_permissions(user_id)

            if self.require_all_permissions:
                # User must have ALL required permissions
                missing = [p for p in self.required_permissions if p not in user_permissions]
                if missing:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Missing required permissions: {', '.join(missing)}",
                    )
            else:
                # User must have AT LEAST ONE required permission
                if not any(p in user_permissions for p in self.required_permissions):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Missing any of required permissions: {', '.join(self.required_permissions)}",
                    )

        # Check required roles
        if self.required_roles:
            if self.require_all_roles:
                # User must have ALL required roles
                for role_name in self.required_roles:
                    has_role = await rbac_service.user_has_role(user_id, role_name)
                    if not has_role:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail=f"Missing required role: {role_name}",
                        )
            else:
                # User must have AT LEAST ONE required role
                has_any = False
                for role_name in self.required_roles:
                    if await rbac_service.user_has_role(user_id, role_name):
                        has_any = True
                        break

                if not has_any:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Missing any of required roles: {', '.join(self.required_roles)}",
                    )

        return user_id


def require_permission(permission: Union[str, List[str]], require_all: bool = False):
    """Decorator to require specific permission(s).

    Args:
        permission: Permission name or list of permission names
        require_all: If True and multiple permissions, require all. Otherwise require any.

    Usage:
        @require_permission("users.read")
        @require_permission(["users.read", "users.write"], require_all=True)
    """
    permissions = [permission] if isinstance(permission, str) else permission
    return Depends(
        PermissionChecker(required_permissions=permissions, require_all_permissions=require_all)
    )


def require_role(role: Union[str, List[str]], require_all: bool = False):
    """Decorator to require specific role(s).

    Args:
        role: Role name or list of role names
        require_all: If True and multiple roles, require all. Otherwise require any.

    Usage:
        @require_role("admin")
        @require_role(["admin", "developer"], require_all=False)
    """
    roles = [role] if isinstance(role, str) else role
    return Depends(PermissionChecker(required_roles=roles, require_all_roles=require_all))


def require_admin():
    """Decorator to require admin role."""
    return require_role("admin")


# Convenience dependency for getting current user from token
async def get_current_user(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
) -> str:
    """Get current user ID from token.

    Returns:
        user_id

    Raises:
        HTTPException: If unauthorized
    """
    token = _extract_token(request, credentials)
    token_data = (await get_jwt_service()).decode_token(token)

    if not token_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired token"
        )

    user_id = token_data.sub
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing user ID",
        )

    return user_id
