"""OpenID Connect service."""

from typing import Optional, List, Dict, Any
from authglow.models.oidc import UserInfoResponse, SCOPE_TO_CLAIMS
from authglow.models.user import User
from authglow.services.storage import UserStorage


class OIDCService:
    """Service for OpenID Connect operations."""

    def __init__(self):
        """Initialize OIDC service."""
        self.user_storage = UserStorage()

    async def get_user_info(
        self,
        user_id: str,
        scopes: List[str]
    ) -> Optional[UserInfoResponse]:
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
        user_info_data = {
            "sub": user_id  # Required claim
        }

        # Add claims based on requested scopes
        if "profile" in scopes:
            # Profile scope claims
            if user.first_name or user.last_name:
                name_parts = []
                if user.first_name:
                    name_parts.append(user.first_name)
                    user_info_data["given_name"] = user.first_name
                if user.last_name:
                    name_parts.append(user.last_name)
                    user_info_data["family_name"] = user.last_name
                if name_parts:
                    user_info_data["name"] = " ".join(name_parts)

            if user.email:
                user_info_data["preferred_username"] = user.email

            if user.avatar_url:
                user_info_data["picture"] = user.avatar_url

            if user.timezone:
                user_info_data["zoneinfo"] = user.timezone

            if user.language:
                user_info_data["locale"] = user.language

            if user.updated_at:
                user_info_data["updated_at"] = int(user.updated_at.timestamp())

        if "email" in scopes:
            # Email scope claims
            if user.email:
                user_info_data["email"] = user.email
                user_info_data["email_verified"] = user.email_verified

        if "phone" in scopes:
            # Phone scope claims
            if user.phone:
                user_info_data["phone_number"] = user.phone
                user_info_data["phone_number_verified"] = False  # TODO: implement phone verification

        if "address" in scopes:
            # Address scope claims (not implemented in User model yet)
            # user_info_data["address"] = {...}
            pass

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
            if user.first_name:
                claims["given_name"] = user.first_name
            if user.last_name:
                claims["family_name"] = user.last_name
            if user.first_name or user.last_name:
                name_parts = []
                if user.first_name:
                    name_parts.append(user.first_name)
                if user.last_name:
                    name_parts.append(user.last_name)
                claims["name"] = " ".join(name_parts)
            if user.email:
                claims["preferred_username"] = user.email
            if user.avatar_url:
                claims["picture"] = user.avatar_url
            if user.timezone:
                claims["zoneinfo"] = user.timezone
            if user.language:
                claims["locale"] = user.language
            if user.updated_at:
                claims["updated_at"] = int(user.updated_at.timestamp())

        # Email scope
        if "email" in scopes:
            claims["email"] = user.email
            claims["email_verified"] = user.email_verified

        # Phone scope
        if "phone" in scopes:
            if user.phone:
                claims["phone_number"] = user.phone
                claims["phone_number_verified"] = False

        # Address scope
        if "address" in scopes:
            # Not implemented yet
            pass

        return claims

    def filter_claims_by_scopes(
        self,
        claims: Dict[str, Any],
        scopes: List[str]
    ) -> Dict[str, Any]:
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
