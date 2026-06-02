"""OpenID Connect service."""

from typing import Any, Dict, List, Optional

from authglow.models.oidc import SCOPE_TO_CLAIMS, UserInfoResponse
from authglow.models.user import User
from authglow.services.storage import UserStorage


class OIDCService:
    """Service for OpenID Connect operations."""

    def __init__(self):
        """Initialize OIDC service."""
        self.user_storage = UserStorage()

    async def get_user_info(self, user_id: str, scopes: List[str]) -> Optional[UserInfoResponse]:
        """Get user info based on requested scopes.

        Args:
            user_id: User identifier
            scopes: List of requested scopes (openid, profile, email, phone, address)

        Returns:
            UserInfoResponse with claims based on scopes
        """
        # Get user from storage
        user = await self.user_storage.get_user(user_id)
        if not user:
            return None

        # Build user info response based on scopes
        user_info_data: dict[str, Any] = {
            "sub": user_id  # Required claim
        }

        # Add claims based on requested scopes
        if "profile" in scopes:
            # Profile scope claims - use getattr for optional fields
            first_name = getattr(user, "first_name", None)
            last_name = getattr(user, "last_name", None)

            if first_name or last_name:
                name_parts = []
                if first_name:
                    name_parts.append(first_name)
                    user_info_data["given_name"] = first_name
                if last_name:
                    name_parts.append(last_name)
                    user_info_data["family_name"] = last_name
                if name_parts:
                    user_info_data["name"] = " ".join(name_parts)

            if user.email:
                user_info_data["preferred_username"] = user.email

            # Optional profile fields - handle gracefully
            avatar_url = getattr(user, "avatar_url", None)
            if avatar_url:
                user_info_data["picture"] = avatar_url

            timezone = getattr(user, "timezone", None)
            if timezone:
                user_info_data["zoneinfo"] = timezone

            language = getattr(user, "language", None)
            if language:
                user_info_data["locale"] = language

            updated_at = getattr(user, "updated_at", None)
            if updated_at:
                user_info_data["updated_at"] = int(updated_at.timestamp())

        if "email" in scopes:
            # Email scope claims
            if user.email:
                user_info_data["email"] = user.email
                user_info_data["email_verified"] = getattr(user, "email_verified", False)

        if "phone" in scopes:
            # Phone scope claims
            phone = getattr(user, "phone", None)
            if phone:
                user_info_data["phone_number"] = phone
                user_info_data["phone_number_verified"] = (
                    False  # TODO: implement phone verification
                )

        if "address" in scopes:
            # Address scope claims (not implemented in User model yet)
            # user_info_data["address"] = {...}
            pass

        # --- Add permissions claim if requested ---
        if "permissions" in scopes:
            user_info_data["permissions"] = user.scopes

        return UserInfoResponse(**user_info_data)

    def build_user_claims(self, user: User, scopes: List[str]) -> Dict[str, Any]:
        """Build user claims dict for ID token based on scopes.

        Args:
            user: User object
            scopes: List of requested scopes

        Returns:
            Dictionary of user claims
        """
        claims = {}

        # Profile scope
        if "profile" in scopes:
            # Use getattr with defaults to handle missing attributes gracefully
            first_name = getattr(user, "first_name", None)
            last_name = getattr(user, "last_name", None)

            if first_name:
                claims["given_name"] = first_name
            if last_name:
                claims["family_name"] = last_name
            if first_name or last_name:
                name_parts = []
                if first_name:
                    name_parts.append(first_name)
                if last_name:
                    name_parts.append(last_name)
                claims["name"] = " ".join(name_parts)

            if user.email:
                claims["preferred_username"] = user.email

            # Optional profile fields - handle gracefully if missing
            avatar_url = getattr(user, "avatar_url", None)
            if avatar_url:
                claims["picture"] = avatar_url

            timezone = getattr(user, "timezone", None)
            if timezone:
                claims["zoneinfo"] = timezone

            language = getattr(user, "language", None)
            if language:
                claims["locale"] = language

            updated_at = getattr(user, "updated_at", None)
            if updated_at:
                claims["updated_at"] = int(updated_at.timestamp())

        # Email scope
        if "email" in scopes:
            claims["email"] = user.email
            claims["email_verified"] = getattr(user, "email_verified", False)

        # Phone scope
        if "phone" in scopes:
            phone = getattr(user, "phone", None)
            if phone:
                claims["phone_number"] = phone
                claims["phone_number_verified"] = False

        # Address scope
        if "address" in scopes:
            # Not implemented yet
            pass

        # --- Add permissions claim if requested ---
        if "permissions" in scopes:
            claims["permissions"] = user.scopes

        return claims

    def filter_claims_by_scopes(self, claims: Dict[str, Any], scopes: List[str]) -> Dict[str, Any]:
        """Filter claims based on requested scopes.

        Args:
            claims: All available claims
            scopes: Requested scopes

        Returns:
            Filtered claims dict
        """
        filtered = {}

        for scope in scopes:
            if scope in SCOPE_TO_CLAIMS:
                for claim in SCOPE_TO_CLAIMS[scope]:
                    if claim in claims:
                        filtered[claim] = claims[claim]

        return filtered
