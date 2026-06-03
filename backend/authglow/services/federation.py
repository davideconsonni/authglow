"""OIDC Relying Party service for federated authentication with external IdPs."""

import secrets
from typing import Any, Dict, Optional, Tuple
from urllib.parse import urlencode

import httpx

from authglow.models.federation import ExternalIdpConfig
from authglow.services.federation_storage import FederationStorage


class OidcDiscoveryData:
    """Parsed OIDC discovery metadata from .well-known/openid-configuration."""

    def __init__(self, data: Dict[str, Any]):
        self.issuer: str = data.get("issuer", "")
        self.authorization_endpoint: str = data.get("authorization_endpoint", "")
        self.token_endpoint: str = data.get("token_endpoint", "")
        self.userinfo_endpoint: str = data.get("userinfo_endpoint", "")
        self.jwks_uri: str = data.get("jwks_uri", "")
        self.end_session_endpoint: str = data.get("end_session_endpoint", "")
        self.response_types_supported: list = data.get("response_types_supported", [])
        self.scopes_supported: list = data.get("scopes_supported", [])
        self.acr_values_supported: list = data.get("acr_values_supported", [])


class FederationService:
    """OIDC Relying Party for federated login via external identity providers."""

    def __init__(self):
        self.storage = FederationStorage()

    async def discover(self, issuer: str) -> OidcDiscoveryData:
        """Fetch and parse the OIDC discovery document from the issuer."""
        url = f"{issuer.rstrip('/')}/.well-known/openid-configuration"
        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()
            return OidcDiscoveryData(data)

    async def get_authorization_url(
        self,
        provider: ExternalIdpConfig,
        redirect_uri: str,
        state: Optional[str] = None,
        nonce: Optional[str] = None,
        acr_values: Optional[str] = None,
    ) -> Tuple[str, str, str]:
        """Build the authorization URL for redirecting the user to the external IdP.

        Returns:
            Tuple of (authorization_url, state, nonce)
        """
        discovery = await self.discover(provider.issuer)

        _state = state or secrets.token_urlsafe(32)
        _nonce = nonce or secrets.token_urlsafe(32)

        params: Dict[str, str] = {
            "response_type": "code",
            "client_id": provider.client_id,
            "redirect_uri": redirect_uri,
            "scope": " ".join(provider.scopes),
            "state": _state,
            "nonce": _nonce,
        }

        if acr_values:
            params["acr_values"] = acr_values

        auth_url = f"{discovery.authorization_endpoint}?{urlencode(params)}"
        return auth_url, _state, _nonce

    async def exchange_code(
        self,
        provider: ExternalIdpConfig,
        code: str,
        redirect_uri: str,
    ) -> Dict[str, Any]:
        """Exchange an authorization code for tokens at the external IdP."""
        discovery = await self.discover(provider.issuer)

        payload = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": provider.client_id,
            "client_secret": provider.client_secret,
        }

        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            resp = await client.post(
                discovery.token_endpoint,
                data=payload,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            return resp.json()

    async def fetch_userinfo(
        self,
        provider: ExternalIdpConfig,
        access_token: str,
    ) -> Dict[str, Any]:
        """Fetch userinfo claims from the external IdP."""
        discovery = await self.discover(provider.issuer)

        async with httpx.AsyncClient(timeout=httpx.Timeout(15.0)) as client:
            resp = await client.get(
                discovery.userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            resp.raise_for_status()
            return resp.json()

    async def map_claims_to_user(
        self,
        provider: ExternalIdpConfig,
        claims: Dict[str, Any],
    ) -> Dict[str, str]:
        """Map external IdP claims to AuthGlow user fields based on claims_mapping."""
        mapped: Dict[str, str] = {}
        for idp_claim, local_field in provider.claims_mapping.items():
            value = claims.get(idp_claim)
            if value is not None:
                mapped[local_field] = str(value)
        return mapped

    async def get_providers_for_ui(self) -> list:
        """Get a lightweight list of enabled providers for the login UI."""
        providers = await self.storage.list_providers(enabled_only=True)
        return [
            {
                "id": p.id,
                "label": p.label,
                "description": p.description,
                "icon_uri": p.icon_uri,
                "logo_uri": p.logo_uri,
            }
            for p in providers
        ]
