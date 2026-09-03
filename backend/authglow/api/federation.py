"""External Identity Provider federation API.

Provides admin CRUD for external IdP configurations, and the public-facing
login/callback endpoints for federated authentication flows.
"""

import secrets
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

from authglow.api.admin import require_admin
from authglow.core.config import get_settings
from authglow.core.datetime import utcnow
from authglow.core.jwt_singleton import get_jwt_service
from authglow.core.rate_limit import limiter
from authglow.models.federation import (
    ExternalIdpConfig,
    ExternalIdpConfigCreate,
    ExternalIdpConfigResponse,
    ExternalIdpConfigUpdate,
)
from authglow.models.user import User
from authglow.services.audit import AuditService
from authglow.services.federation import FederationService
from authglow.services.federation_provider import (
    FederationProviderService as _FederationProviderService,
)
from authglow.services.federation_state import FederationStateError, FederationStateToken
from authglow.services.login_history import LoginHistoryService
from authglow.services.session import SessionService
from authglow.services.user import UserService as UserStorage

# Back-compat aliases for Fase 21 transition window
FederationProviderService = _FederationProviderService
FederationStorage = _FederationProviderService

router = APIRouter()


def get_audit_service():
    return AuditService()


def get_federation_storage() -> FederationStorage:
    return FederationStorage()


def get_user_storage() -> UserStorage:
    return UserStorage()


# ---------------------------------------------------------------------------
# Public endpoints — used by the OAuth authorize / login page
# ---------------------------------------------------------------------------


@router.get("/api/federation/providers")
@limiter.limit("60/minute")
async def list_public_providers(
    request: Request,
    context: Optional[str] = Query(default=None),
    storage: FederationStorage = Depends(get_federation_storage),
):
    """Return the list of enabled external IdPs for the login UI.

    When ``context`` is provided (``dashboard`` or ``oauth2``), only
    providers whose ``visible_contexts`` includes that value are
    returned.  Without ``context``, all enabled providers are returned.
    """
    service = FederationService()
    return await service.get_providers_for_ui(context=context)


@router.get("/api/federation/login/{provider_id}")
@limiter.limit("5/minute")
async def federation_login(
    request: Request,
    provider_id: str,
    redirect_uri: str = Query(default="/auth/callback"),
    acr_values: Optional[str] = Query(default=None),
    client_id: Optional[str] = Query(default=None),
    oauth_redirect_uri: Optional[str] = Query(default=None),
    scope: Optional[str] = Query(default=None),
    app_state: Optional[str] = Query(default=None),
    code_challenge: Optional[str] = Query(default=None),
    code_challenge_method: Optional[str] = Query(default=None),
    response_type: Optional[str] = Query(default=None),
    oidc_nonce: Optional[str] = Query(default=None),
    storage: FederationStorage = Depends(get_federation_storage),
):
    """Initiate federated login — redirect user to the external IdP.

    The CSRF protection for the OAuth2/OIDC authorization code flow
    (RFC 6749 §10.12) is provided by a signed JWT state token: all
    callback context (provider_id, redirect_uri, nonce, expiry) is
    embedded in the token claims and protected by a signature. This
    keeps the flow stateless — no shared store, no session cookie —
    which is required for serverless deployments.

    When optional OAuth2 authorization context parameters are provided
    (``client_id``, ``oauth_redirect_uri``, ``scope``, …), they are
    embedded in the state token so the callback can bridge back into
    the OAuth2 authorization-code flow instead of returning plain JSON
    tokens.
    """
    provider = await storage.get_provider(provider_id)
    if not provider or not provider.enabled:
        raise HTTPException(status_code=404, detail="Provider not found or disabled")
    if not provider.issuer.startswith(("http://", "https://")):
        raise HTTPException(
            status_code=400, detail="Provider issuer must start with http:// or https://"
        )

    callback_uri = f"{get_settings().base_url.rstrip('/')}/api/federation/callback"
    state_token = FederationStateToken()

    oauth2_context: Optional[dict] = None
    if client_id and oauth_redirect_uri:
        oauth2_context = {
            "client_id": client_id,
            "oauth_redirect_uri": oauth_redirect_uri,
            "scope": scope or "read",
            "app_state": app_state or "",
            "code_challenge": code_challenge or "",
            "code_challenge_method": code_challenge_method or "",
            "response_type": response_type or "code",
            "oidc_nonce": oidc_nonce or "",
        }

    signed = state_token.sign(
        provider_id=provider.id,
        redirect_uri=callback_uri,
        oauth2_context=oauth2_context,
    )

    try:
        service = FederationService()
        auth_url, _state, _nonce = await service.get_authorization_url(
            provider,
            redirect_uri=callback_uri,
            state=signed["state"],
            nonce=signed["nonce"],
            acr_values=acr_values,
        )
        return RedirectResponse(url=auth_url, status_code=302)
    except Exception as e:
        # VAPT-073: upstream IdP response fragments must not reach the
        # client — generic detail, full error server-side.
        await AuditService().log_event(
            event_type="federation_provider_unreachable",
            severity="warning",
            metadata={"error_class": type(e).__name__, "error": str(e)},
        )
        raise HTTPException(
            status_code=502,
            detail="Failed to reach the external provider",
        ) from e


@router.get("/api/federation/callback")
@limiter.limit("10/minute")
async def federation_callback(
    request: Request,
    code: str,
    state: str,
    provider_id: Optional[str] = Query(default=None),
    storage: FederationStorage = Depends(get_federation_storage),
    audit_service: AuditService = Depends(get_audit_service),
    user_storage: UserStorage = Depends(get_user_storage),
):
    """Handle the redirect callback from the external IdP.

    Security (RFC 6749 §10.12, OIDC Core §3.1.2.1 / §15.5.2):
        * ``state`` is a signed JWT generated at ``/api/federation/login``.
          Any tampering, expiry, or signature failure aborts the flow.
        * The ``provider_id`` claim in the state must match the query
          parameter, so a state from one provider cannot be replayed
          against another.
        * When the IdP returns an ``id_token`` (OIDC), the ``nonce``
          claim is verified against the value bound to the state.
    """
    state_claims: dict = {}
    try:
        state_claims = FederationStateToken().verify(state)
    except FederationStateError as e:
        await audit_service.log_event(
            event_type="federation_login_failed",
            email="unknown",
            metadata={"provider_id": provider_id, "error": f"state_invalid: {e}"},
        )
        raise HTTPException(status_code=400, detail=f"Invalid state: {e}") from e

    resolved_provider_id = provider_id or state_claims.get("provider_id")
    if not resolved_provider_id:
        raise HTTPException(status_code=400, detail="Missing provider_id in request or state")

    if (
        provider_id
        and state_claims.get("provider_id")
        and state_claims.get("provider_id") != provider_id
    ):
        await audit_service.log_event(
            event_type="federation_login_failed",
            email="unknown",
            metadata={
                "provider_id": provider_id,
                "error": "provider_mismatch",
                "state_provider_id": state_claims.get("provider_id"),
            },
        )
        raise HTTPException(status_code=400, detail="State provider does not match request")

    provider = await storage.get_provider(resolved_provider_id)
    if not provider or not provider.enabled:
        raise HTTPException(status_code=404, detail="Provider not found or disabled")

    service = FederationService()
    redirect_uri = state_claims["redirect_uri"]

    try:
        token_response = await service.exchange_code(provider, code, redirect_uri)
        access_token = token_response.get("access_token")
        if not access_token:
            raise HTTPException(status_code=400, detail="No access token in response")

        id_token = token_response.get("id_token")
        if id_token:
            try:
                await service.verify_id_token(provider, id_token, nonce=state_claims.get("nonce"))
            except Exception as e:
                # VAPT-073: JWT validation internals must not reach the
                # client — generic detail, full error server-side.
                await audit_service.log_event(
                    event_type="federation_id_token_invalid",
                    severity="warning",
                    metadata={
                        "provider_id": provider.id,
                        "error_class": type(e).__name__,
                        "error": str(e),
                    },
                )
                raise HTTPException(status_code=400, detail="ID token validation failed") from e

        claims = await service.fetch_userinfo(provider, access_token)
        mapped = await service.map_claims_to_user(provider, claims)

        external_id = mapped.get("external_id", "")
        email = mapped.get("email", "")

        # VAPT-035: two-phase identity resolution using (provider_id, external_id)
        # as the canonical identity pair per OIDC Core §2 (sub claim).
        existing_user = await user_storage.get_by_external_id(provider.id, external_id)
        if existing_user:
            user = existing_user
            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Account is deactivated. Contact support for assistance.",
                )
            requires_update = False
            first_name = mapped.get("given_name") or mapped.get("name", "")
            last_name = mapped.get("family_name", "")
            if first_name:
                user.first_name = first_name
                requires_update = True
            if last_name:
                user.last_name = last_name
                requires_update = True
            if requires_update:
                await user_storage.update_user(user)
        elif email:
            # Not found by (provider, sub) — try email as a discovery hint.
            # Auto-link only if the IdP asserts email_verified (VAPT-035).
            existing_user = await user_storage.get_user_by_email(email)
            if existing_user:
                email_verified = claims.get("email_verified")
                if not email_verified:
                    id_token_raw = token_response.get("id_token")
                    if id_token_raw:
                        try:
                            import jwt as _jwt_mod

                            decoded = _jwt_mod.decode(
                                id_token_raw, options={"verify_signature": False}
                            )
                            email_verified = decoded.get("email_verified", False)
                        except Exception:
                            pass

                if email_verified:
                    user = existing_user
                    if not user.is_active:
                        raise HTTPException(
                            status_code=status.HTTP_403_FORBIDDEN,
                            detail="Account is deactivated. Contact support for assistance.",
                        )
                    requires_update = False
                    if not user.is_federated:
                        user.is_federated = True
                        user.email_verified = True
                        requires_update = True
                    first_name = mapped.get("given_name") or mapped.get("name", "")
                    last_name = mapped.get("family_name", "")
                    if first_name:
                        user.first_name = first_name
                        requires_update = True
                    if last_name:
                        user.last_name = last_name
                        requires_update = True
                    if requires_update:
                        await user_storage.update_user(user)
                    await user_storage.link_federated_identity(user.id, provider.id, external_id)
                else:
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=(
                            "An account with this email already exists but the "
                            "identity provider did not verify the email address. "
                            "Please sign in with your existing credentials and "
                            "link this provider from your account settings."
                        ),
                    )

        if existing_user is None:
            from authglow.models.user import User
            from authglow.services.password import hash_password_async

            user = User(
                email=email or f"{external_id}@federated.local",
                hashed_password=await hash_password_async(secrets.token_urlsafe(32)),
                first_name=mapped.get("given_name") or mapped.get("name", ""),
                last_name=mapped.get("family_name", ""),
                scopes=["read"],
                is_federated=True,
                email_verified=True,
            )
            user = await user_storage.create_user(user)
            await user_storage.link_federated_identity(user.id, provider.id, external_id)

        # Check if account is suspended
        if user.suspended_until and utcnow() < user.suspended_until:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account suspended until {user.suspended_until.isoformat()}",
            )

        await user_storage.update_last_login(user.id)

        login_svc = LoginHistoryService()
        await login_svc.record_login(
            user_id=user.id,
            email=user.email,
            success=True,
            ip_address=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        oauth2_ctx = FederationStateToken.get_oauth2_context(state_claims)

        jwt_service = await get_jwt_service()

        from authglow.services.refresh_token import RefreshTokenService

        refresh_svc = RefreshTokenService()
        stored_rt = await refresh_svc.create_refresh_token(
            user_id=user.id,
            client_id="federation_grant",
            scopes=user.scopes,
            issued_ip=request.client.host if request.client else None,
            # VAPT-058: lifetime is policy, not a hardcoded constant
            expires_in_days=get_settings().refresh_token_expire_days,
        )
        assert stored_rt.token is not None  # narrowed: always set on creation

        # Federation callbacks always hit the default first-party
        # policy (the federation IdP is the caller, the AuthGlow
        # session is the user). Pass ``client_id=None`` to fall
        # back to the default rule set.
        from authglow.models.claim_policy import ClaimTarget
        from authglow.services.claim_policy import ClaimPolicyService

        claim_policy_service = ClaimPolicyService()
        extra_claims = await claim_policy_service.build_claims(
            user,
            client_id=None,
            scopes=list(user.scopes),
            target=ClaimTarget.ACCESS_TOKEN,
        )

        auth_tokens = jwt_service.create_token_response(
            user_id=user.id,
            email=user.email,
            scopes=user.scopes,
            include_refresh=True,
            extra_claims=extra_claims,
        )
        assert auth_tokens.refresh_token is not None  # narrowed: include_refresh=True

        if oauth2_ctx:
            from authglow.services.oauth2 import OAuth2Service
            from authglow.services.oauth_client import OAuth2ClientStorage
            from authglow.services.oauth_consent import OAuth2ConsentService
            from authglow.services.session import SessionService

            oauth2_svc = OAuth2Service()

            client = await OAuth2ClientStorage().get_client(oauth2_ctx["client_id"])
            if not client or not client.is_active:
                raise HTTPException(status_code=400, detail="Invalid OAuth2 client_id")

            if not await oauth2_svc.verify_redirect_uri(
                oauth2_ctx["client_id"], oauth2_ctx["oauth_redirect_uri"]
            ):
                raise HTTPException(status_code=400, detail="Invalid OAuth2 redirect_uri")

            requested_scopes = oauth2_ctx["scope"].split() if oauth2_ctx.get("scope") else ["read"]
            try:
                processed_scopes = await oauth2_svc.process_scopes(
                    oauth2_ctx["client_id"], requested_scopes
                )
                validated_scope = " ".join(processed_scopes)
            except ValueError:
                raise HTTPException(status_code=400, detail="Invalid scope")

            consent_svc = OAuth2ConsentService()
            has_consent, _ = await consent_svc.check_consent(
                user_id=user.id,
                client_id=oauth2_ctx["client_id"],
                required_scopes=validated_scope.split() if validated_scope else ["read"],
            )

            if has_consent:
                auth_code = await oauth2_svc.create_authorization_code(
                    client_id=oauth2_ctx["client_id"],
                    user_id=user.id,
                    redirect_uri=oauth2_ctx["oauth_redirect_uri"],
                    scope=validated_scope,
                    code_challenge=oauth2_ctx.get("code_challenge"),
                    code_challenge_method=oauth2_ctx.get("code_challenge_method"),
                    nonce=oauth2_ctx.get("oidc_nonce"),
                )
                redirect_url = f"{oauth2_ctx['oauth_redirect_uri']}?code={auth_code.code}"
                if oauth2_ctx.get("app_state"):
                    redirect_url += f"&state={oauth2_ctx['app_state']}"

                settings = get_settings()
                response = RedirectResponse(url=redirect_url, status_code=302)
                response.set_cookie(
                    key=settings.auth_cookie_access_name,
                    value=auth_tokens.access_token,
                    httponly=True,
                    secure=settings.auth_cookie_secure,
                    samesite="lax",
                    max_age=int(settings.access_token_expire_minutes * 60),
                    path=settings.auth_cookie_path,
                )
                response.set_cookie(
                    key=settings.auth_cookie_refresh_name,
                    value=auth_tokens.refresh_token,
                    httponly=True,
                    secure=settings.auth_cookie_secure,
                    samesite="lax",
                    max_age=settings.refresh_token_expire_days * 24 * 3600,
                    path=settings.auth_cookie_path,
                )
                await audit_service.log_event(
                    event_type="federation_login_success",
                    user_id=user.id,
                    email=user.email,
                    metadata={
                        "provider_id": resolved_provider_id,
                        "provider_label": provider.label,
                        "external_id": external_id,
                        "oauth2_client_id": oauth2_ctx["client_id"],
                        "consent_cached": True,
                    },
                )
                return response

            consent_session = await SessionService().create_consent_session(
                user_id=user.id,
                client_id=oauth2_ctx["client_id"],
                redirect_uri=oauth2_ctx["oauth_redirect_uri"],
                scope=validated_scope,
                state=oauth2_ctx.get("app_state") or None,
                code_challenge=oauth2_ctx.get("code_challenge") or None,
                code_challenge_method=oauth2_ctx.get("code_challenge_method") or None,
                nonce=oauth2_ctx.get("oidc_nonce") or None,
            )

            settings = get_settings()
            cookie_name = settings.auth_cookie_access_name

            response = RedirectResponse(
                url=f"{settings.frontend_base_url}/oauth2/authorize?fed=1",
                status_code=302,
            )
            response.set_cookie(
                key=cookie_name,
                value=auth_tokens.access_token,
                httponly=True,
                secure=settings.auth_cookie_secure,
                samesite="lax",
                max_age=int(settings.access_token_expire_minutes * 60),
                path=settings.auth_cookie_path,
            )
            response.set_cookie(
                key="__Host-authglow-consent-session",
                value=consent_session["session_token"],
                httponly=True,
                secure=True,
                samesite="lax",
                max_age=600,
                path="/",
            )

            await audit_service.log_event(
                event_type="federation_login_success",
                user_id=user.id,
                email=user.email,
                metadata={
                    "provider_id": resolved_provider_id,
                    "provider_label": provider.label,
                    "external_id": external_id,
                    "state_jti": state_claims.get("jti"),
                    "oauth2_client_id": oauth2_ctx["client_id"],
                },
            )

            return response

        await audit_service.log_event(
            event_type="federation_login_success",
            user_id=user.id,
            email=user.email,
            metadata={
                "provider_id": resolved_provider_id,
                "provider_label": provider.label,
                "external_id": external_id,
                "state_jti": state_claims.get("jti"),
            },
        )

        settings = get_settings()
        response = RedirectResponse(
            url=f"{settings.frontend_base_url}/dashboard?fed=1",
            status_code=302,
        )
        response.set_cookie(
            key=settings.auth_cookie_access_name,
            value=auth_tokens.access_token,
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite="lax",
            max_age=int(settings.access_token_expire_minutes * 60),
            path=settings.auth_cookie_path,
        )
        response.set_cookie(
            key=settings.auth_cookie_refresh_name,
            value=stored_rt.token,
            httponly=True,
            secure=settings.auth_cookie_secure,
            samesite="lax",
            max_age=int(settings.refresh_token_expire_days * 86400),
            path=settings.auth_cookie_path,
        )
        return response

    except HTTPException:
        raise
    except Exception as e:
        await audit_service.log_event(
            event_type="federation_login_failed",
            email="unknown",
            metadata={
                "provider_id": provider_id,
                "provider_label": provider.label,
                "error": str(e),
            },
        )
        # VAPT-073: generic detail — str(e) stays server-side (audit above).
        raise HTTPException(status_code=400, detail="Federation login failed") from e


# ---------------------------------------------------------------------------
# Admin CRUD
# ---------------------------------------------------------------------------


@router.post("/api/oauth2/federated-consent")
async def federated_consent_check(
    request: Request,
    session_service: SessionService = Depends(lambda: SessionService()),
):
    """Check for a pending federated-login consent session.

    Called by the OAuth authorize page after a federation callback
    redirect. Reads the ``__Host-authglow-consent-session`` httpOnly
    cookie, validates the session, and returns consent data the frontend
    can render. Deletes the cookie on success.
    """
    session_token = request.cookies.get("__Host-authglow-consent-session")
    if not session_token:
        return {"consent_required": False}

    session = await session_service.get_consent_session(session_token)
    if not session:
        return {"consent_required": False}

    from authglow.services.oauth_client import OAuth2ClientStorage

    client_storage = OAuth2ClientStorage()
    client = await client_storage.get_client(session["client_id"])
    if not client or not client.is_active:
        await session_service.delete_consent_session(session_token)
        return {"consent_required": False}

    scope_labels: dict = {
        "openid": "Verify your identity",
        "profile": "Access your profile information (name, picture)",
        "email": "Access your email address",
        "offline_access": "Allow offline access (refresh tokens)",
        "read": "Read access to your data",
        "write": "Write access to your data",
    }
    scope_items = [
        {"name": s, "description": scope_labels.get(s, f"Access to {s}")}
        for s in (session["scope"].split() if session.get("scope") else ["read"])
    ]

    return {
        "consent_required": True,
        "session_token": session["session_token"],
        "client_name": client.client_name,
        "client_description": client.description,
        "client_logo_uri": client.logo_uri,
        "client_homepage_uri": client.homepage_uri,
        "client_terms_uri": client.terms_uri,
        "client_privacy_uri": client.privacy_uri,
        "branding": client.branding.model_dump() if client.branding else None,
        "scopes": scope_items,
    }


@router.post("/api/federation/providers", response_model=ExternalIdpConfigResponse)
@limiter.limit("10/minute")
async def create_provider(
    request: Request,
    provider_data: ExternalIdpConfigCreate,
    current_user: User = Depends(require_admin),
    storage: FederationStorage = Depends(get_federation_storage),
):
    """Admin: create a new external IdP provider."""

    if not provider_data.issuer.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Issuer must start with http:// or https://")

    provider = ExternalIdpConfig(
        label=provider_data.label,
        description=provider_data.description,
        issuer=provider_data.issuer,
        client_id=provider_data.client_id,
        client_secret=provider_data.client_secret,
        scopes=provider_data.scopes,
        icon_uri=provider_data.icon_uri,
        logo_uri=provider_data.logo_uri,
        enabled=provider_data.enabled,
        auth_levels=provider_data.auth_levels,
        claims_mapping=provider_data.claims_mapping
        or ExternalIdpConfig.model_fields["claims_mapping"].default,
        rate_limit_per_minute=provider_data.rate_limit_per_minute,
    )
    created = await storage.create_provider(provider)
    return created


@router.get("/api/federation/admin/providers", response_model=List[ExternalIdpConfigResponse])
async def list_all_providers(
    current_user: User = Depends(require_admin),
    storage: FederationStorage = Depends(get_federation_storage),
):
    """Admin: list all providers (including disabled)."""
    return await storage.list_providers(enabled_only=False)


@router.get(
    "/api/federation/admin/providers/{provider_id}", response_model=ExternalIdpConfigResponse
)
async def get_provider(
    provider_id: str,
    current_user: User = Depends(require_admin),
    storage: FederationStorage = Depends(get_federation_storage),
):
    """Admin: get a single provider."""
    provider = await storage.get_provider(provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    return provider


@router.put(
    "/api/federation/admin/providers/{provider_id}", response_model=ExternalIdpConfigResponse
)
@limiter.limit("30/minute")
async def update_provider(
    request: Request,
    provider_id: str,
    updates: ExternalIdpConfigUpdate,
    current_user: User = Depends(require_admin),
    storage: FederationStorage = Depends(get_federation_storage),
):
    """Admin: update a provider."""
    update_data = updates.model_dump(exclude_unset=True)
    updated = await storage.update_provider(provider_id, update_data)
    if not updated:
        raise HTTPException(status_code=404, detail="Provider not found")
    return updated


@router.delete("/api/federation/admin/providers/{provider_id}")
@limiter.limit("20/minute")
async def delete_provider(
    request: Request,
    provider_id: str,
    current_user: User = Depends(require_admin),
    storage: FederationStorage = Depends(get_federation_storage),
):
    """Admin: delete a provider."""
    deleted = await storage.delete_provider(provider_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Provider not found")
    return {"status": "deleted", "provider_id": provider_id}


@router.patch("/api/federation/admin/providers/{provider_id}/toggle")
async def toggle_provider(
    provider_id: str,
    current_user: User = Depends(require_admin),
    storage: FederationStorage = Depends(get_federation_storage),
):
    """Admin: toggle provider enabled/disabled."""
    provider = await storage.get_provider(provider_id)
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    updated = await storage.update_provider(provider_id, {"enabled": not provider.enabled})
    return updated
