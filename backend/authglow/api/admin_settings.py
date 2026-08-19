"""Admin settings API endpoints.

Exposes a read-only view of the application settings grouped by
category, with metadata for building a dynamic settings UI. Secrets
are excluded. Settings are managed via environment variables and
require a redeploy to take effect.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query, Request

from authglow.api.admin import require_admin
from authglow.core.config import Settings, get_settings
from authglow.core.rate_limit import limiter
from authglow.models.user import User

router = APIRouter()

_FIELD_META: Dict[str, Dict[str, Any]] = {
    # fmt: off
    # --- General ---
    "app_name": {"category": "general", "label": "Application name", "restart_required": False},
    "app_env": {"category": "general", "label": "Environment", "restart_required": True},
    "debug": {"category": "general", "label": "Debug mode", "restart_required": True},
    "enable_docs": {"category": "general", "label": "Enable API docs", "restart_required": True},
    "company_name": {"category": "general", "label": "Company name", "restart_required": False},
    "base_url": {"category": "general", "label": "Base server URL", "restart_required": True},
    "frontend_base_url": {
        "category": "general",
        "label": "Frontend base URL",
        "restart_required": True,
    },
    "logo_url": {"category": "general", "label": "Logo URL", "restart_required": False},
    "favicon_url": {"category": "general", "label": "Favicon URL", "restart_required": False},
    # --- Security ---
    "jwt_algorithm": {"category": "security", "label": "JWT algorithm", "restart_required": True},
    "jwt_key_rotation_days": {
        "category": "security",
        "label": "JWT key rotation (days)",
        "restart_required": True,
    },
    "jwt_auto_rotate": {
        "category": "security",
        "label": "Auto-rotate JWT keys",
        "restart_required": False,
    },
    "timing_leak_protection": {
        "category": "security",
        "label": "Timing leak protection",
        "restart_required": True,
    },
    "enforce_hsts": {"category": "security", "label": "Enforce HSTS", "restart_required": True},
    "hsts_max_age": {
        "category": "security",
        "label": "HSTS max age (seconds)",
        "restart_required": True,
    },
    "hsts_include_subdomains": {
        "category": "security",
        "label": "HSTS include subdomains",
        "restart_required": True,
    },
    "enforce_https": {"category": "security", "label": "Enforce HTTPS", "restart_required": True},
    "https_redirect_status": {
        "category": "security",
        "label": "HTTPS redirect status",
        "restart_required": True,
    },
    "trusted_proxies": {
        "category": "security",
        "label": "Trusted proxies (comma-separated)",
        "restart_required": True,
    },
    "api_key_max_failed_attempts": {
        "category": "security",
        "label": "API key max failed attempts",
        "restart_required": True,
    },
    "api_key_lockout_minutes": {
        "category": "security",
        "label": "API key lockout minutes",
        "restart_required": True,
    },
    "backup_code_max_failed_attempts": {
        "category": "security",
        "label": "Backup code max failed attempts",
        "restart_required": True,
    },
    "backup_code_lockout_seconds": {
        "category": "security",
        "label": "Backup code lockout seconds",
        "restart_required": True,
    },
    "blacklist_backend": {
        "category": "security",
        "label": "Token blacklist backend",
        "restart_required": True,
    },
    # --- Sessions ---
    "access_token_expire_minutes": {
        "category": "sessions",
        "label": "Access token expiry (min)",
        "restart_required": False,
    },
    "refresh_token_expire_days": {
        "category": "sessions",
        "label": "Refresh token expiry (days)",
        "restart_required": False,
    },
    "auth_cookie_access_name": {
        "category": "sessions",
        "label": "Access cookie name",
        "restart_required": True,
    },
    "auth_cookie_refresh_name": {
        "category": "sessions",
        "label": "Refresh cookie name",
        "restart_required": True,
    },
    "auth_cookie_path": {
        "category": "sessions",
        "label": "Auth cookie path",
        "restart_required": True,
    },
    "auth_cookie_samesite": {
        "category": "sessions",
        "label": "Auth cookie SameSite",
        "restart_required": True,
    },
    "auth_cookie_domain": {
        "category": "sessions",
        "label": "Auth cookie domain",
        "restart_required": True,
    },
    # --- CORS ---
    "cors_allowed_origins": {
        "category": "cors",
        "label": "Allowed origins (comma-separated)",
        "restart_required": True,
    },
    "cors_allow_credentials": {
        "category": "cors",
        "label": "Allow credentials",
        "restart_required": True,
    },
    "cors_allowed_methods": {
        "category": "cors",
        "label": "Allowed methods",
        "restart_required": True,
    },
    "cors_allowed_headers": {
        "category": "cors",
        "label": "Allowed headers",
        "restart_required": True,
    },
    # --- Security Headers ---
    "csp_header": {
        "category": "headers",
        "label": "Content-Security-Policy",
        "restart_required": True,
    },
    "x_frame_options": {
        "category": "headers",
        "label": "X-Frame-Options",
        "restart_required": True,
    },
    "x_content_type_options": {
        "category": "headers",
        "label": "X-Content-Type-Options",
        "restart_required": True,
    },
    "referrer_policy": {
        "category": "headers",
        "label": "Referrer-Policy",
        "restart_required": True,
    },
    "x_permitted_cross_domain_policies": {
        "category": "headers",
        "label": "X-Permitted-Cross-Domain-Policies",
        "restart_required": True,
    },
    "permissions_policy": {
        "category": "headers",
        "label": "Permissions-Policy",
        "restart_required": True,
    },
    # --- Password Policy ---
    "password_min_length": {
        "category": "password_policy",
        "label": "Minimum password length",
        "restart_required": False,
    },
    "password_require_uppercase": {
        "category": "password_policy",
        "label": "Require uppercase",
        "restart_required": False,
    },
    "password_require_lowercase": {
        "category": "password_policy",
        "label": "Require lowercase",
        "restart_required": False,
    },
    "password_require_digits": {
        "category": "password_policy",
        "label": "Require digits",
        "restart_required": False,
    },
    "password_require_special": {
        "category": "password_policy",
        "label": "Require special chars",
        "restart_required": False,
    },
    "bcrypt_rounds": {
        "category": "password_policy",
        "label": "Bcrypt cost factor (VAPT-038)",
        "restart_required": True,
    },
    # --- Registration ---
    "allow_public_registration": {
        "category": "registration",
        "label": "Allow public registration",
        "restart_required": False,
    },
    # --- OAuth2 ---
    "oauth2_authorization_code_expire_minutes": {
        "category": "oauth2",
        "label": "Auth code expiry (min)",
        "restart_required": True,
    },
    "enforce_pkce": {"category": "oauth2", "label": "Enforce PKCE", "restart_required": False},
    "oauth2_reject_unknown_scopes": {
        "category": "oauth2",
        "label": "Reject unknown scopes",
        "restart_required": True,
    },
    "issuer": {"category": "oauth2", "label": "OIDC Issuer URL", "restart_required": True},
    "oidc_claims_supported": {
        "category": "oauth2",
        "label": "OIDC claims supported (csv)",
        "restart_required": True,
    },
    "oidc_scopes_supported": {
        "category": "oauth2",
        "label": "OIDC scopes supported (csv)",
        "restart_required": True,
    },
    "oidc_grant_types_supported": {
        "category": "oauth2",
        "label": "OIDC grant types supported (csv)",
        "restart_required": True,
    },
    "oidc_response_types_supported": {
        "category": "oauth2",
        "label": "OIDC response types (csv)",
        "restart_required": True,
    },
    "oidc_service_documentation": {
        "category": "oauth2",
        "label": "OIDC service documentation URI",
        "restart_required": True,
    },
    "oidc_op_policy_uri": {
        "category": "oauth2",
        "label": "OIDC policy URI",
        "restart_required": True,
    },
    "oidc_op_tos_uri": {
        "category": "oauth2",
        "label": "OIDC terms of service URI",
        "restart_required": True,
    },
    # --- OAuth2 Client Defaults ---
    "oauth2_client_id": {
        "category": "oauth2_client",
        "label": "Default OAuth2 Client ID",
        "restart_required": True,
    },
    "cache_backend": {
        "category": "cache",
        "label": "Cache backend",
        "restart_required": True,
    },
    "redis_url": {
        "category": "cache",
        "label": "Redis URL",
        "restart_required": True,
        "sensitive": True,
    },
    "redis_key_prefix": {
        "category": "cache",
        "label": "Redis key prefix",
        "restart_required": True,
    },
    "oauth2_first_party_redirect_uri": {
        "category": "oauth2_client",
        "label": "First-party dashboard redirect URI",
        "restart_required": True,
    },
    # --- Device Auth ---
    "device_code_expire_seconds": {
        "category": "devices",
        "label": "Device code expiry (seconds)",
        "restart_required": True,
    },
    "device_poll_interval_seconds": {
        "category": "devices",
        "label": "Device poll interval (seconds)",
        "restart_required": True,
    },
    "claim_namespace": {
        "category": "oauth2",
        "label": "OIDC claim namespace",
        "restart_required": True,
    },
    # --- Email ---
    "email_backend": {"category": "email", "label": "Email backend", "restart_required": True},
    "email_provider": {"category": "email", "label": "Email provider", "restart_required": True},
    "email_from_address": {"category": "email", "label": "From address", "restart_required": False},
    "email_from_name": {"category": "email", "label": "From name", "restart_required": False},
    "email_storage_path": {
        "category": "email",
        "label": "Email storage path",
        "restart_required": True,
    },
    "smtp_host": {"category": "email", "label": "SMTP host", "restart_required": True},
    "smtp_port": {"category": "email", "label": "SMTP port", "restart_required": True},
    "smtp_use_tls": {"category": "email", "label": "SMTP use TLS", "restart_required": True},
    "mailgun_base_url": {
        "category": "email",
        "label": "Mailgun API base URL",
        "restart_required": True,
    },
    "resend_api_key": {
        "category": "email",
        "label": "Resend API key",
        "restart_required": True,
    },
    "resend_base_url": {
        "category": "email",
        "label": "Resend API base URL",
        "restart_required": True,
    },
    # --- Storage ---
    "storage_backend": {
        "category": "storage",
        "label": "Storage backend",
        "restart_required": True,
    },
    "storage_path": {"category": "storage", "label": "Storage path", "restart_required": True},
    # --- Cache ---
    "cache_refresh_token_maxsize": {
        "category": "cache",
        "label": "Refresh token cache max size",
        "restart_required": True,
    },
    "cache_refresh_token_ttl": {
        "category": "cache",
        "label": "Refresh token cache TTL (s)",
        "restart_required": True,
    },
    "cache_user_maxsize": {
        "category": "cache",
        "label": "User cache max size",
        "restart_required": True,
    },
    "cache_user_ttl": {
        "category": "cache",
        "label": "User cache TTL (s)",
        "restart_required": True,
    },
    "cache_user_by_id_maxsize": {
        "category": "cache",
        "label": "User-by-ID cache max size",
        "restart_required": True,
    },
    "cache_user_by_id_ttl": {
        "category": "cache",
        "label": "User-by-ID cache TTL (s)",
        "restart_required": True,
    },
    "cache_oauth_client_maxsize": {
        "category": "cache",
        "label": "OAuth2 client cache max size",
        "restart_required": True,
    },
    "cache_oauth_client_ttl": {
        "category": "cache",
        "label": "OAuth2 client cache TTL (s)",
        "restart_required": True,
    },
    "cache_api_key_maxsize": {
        "category": "cache",
        "label": "API key cache max size",
        "restart_required": True,
    },
    "cache_api_key_ttl": {
        "category": "cache",
        "label": "API key cache TTL (s)",
        "restart_required": True,
    },
    # --- Passkey ---
    "passkey_rp_id": {"category": "passkey", "label": "WebAuthn RP ID", "restart_required": True},
    "passkey_rp_name": {
        "category": "passkey",
        "label": "WebAuthn RP name",
        "restart_required": False,
    },
    "passkey_origin": {"category": "passkey", "label": "WebAuthn origin", "restart_required": True},
    # --- Audit ---
    "audit_email_log_level": {
        "category": "audit",
        "label": "Audit email log level",
        "restart_required": True,
    },
    # --- Request ---
    "max_request_body_size_mb": {
        "category": "general",
        "label": "Max request body size (MB)",
        "restart_required": True,
    },
    # --- Client JWT auth replay-protection cache (T.2) ---
    "cache_jti_maxsize": {
        "category": "cache",
        "label": "JTI replay-protection cache max entries",
        "restart_required": True,
    },
    "cache_jti_ttl": {
        "category": "cache",
        "label": "JTI replay-protection cache TTL (seconds)",
        "restart_required": True,
    },
    # --- Demo ---
    "demo_mode": {"category": "demo", "label": "Demo mode", "restart_required": True},
    "demo_banner_text": {
        "category": "demo",
        "label": "Demo warning banner text",
        "restart_required": False,
    },
    "demo_user_email": {
        "category": "demo",
        "label": "Demo admin user email",
        "restart_required": True,
    },
    # fmt: on
}

_CATEGORY_ORDER = [
    "general",
    "demo",
    "security",
    "sessions",
    "cors",
    "headers",
    "password_policy",
    "registration",
    "oauth2",
    "oauth2_client",
    "devices",
    "email",
    "storage",
    "cache",
    "passkey",
    "audit",
]

_EXCLUDED_FIELDS = frozenset(
    {
        "secret_key",
        "setup_token",
        "oauth2_client_secret",
        "smtp_password",
        "sendgrid_api_key",
        "mailgun_api_key",
        "mailgun_domain",
        "resend_api_key",
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_region",
        "google_application_credentials",
        "azure_storage_account_name",
        "azure_storage_account_key",
        "host",
        "port",
        "keys_dir",
        "private_key_path",
        "public_key_path",
        "frontend_dist_dir",
    }
)


def _get_settings_fields(settings: Settings) -> List[Dict[str, Any]]:
    """Build a list of setting objects with metadata."""
    fields: List[Dict[str, Any]] = []
    for field_name, meta in _FIELD_META.items():
        if field_name in _EXCLUDED_FIELDS:
            continue
        raw_value = getattr(settings, field_name, None)
        field_type = _type_name(raw_value)
        fields.append(
            {
                "key": field_name,
                "value": raw_value,
                "type": field_type,
                "default": meta.get("default"),
                "label": meta["label"],
                "category": meta["category"],
                "restart_required": meta["restart_required"],
            }
        )
    return fields


def _type_name(value: Any) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "number"
    if isinstance(value, float):
        return "number"
    return "string"


def _format_limit_list(limit_list: Any) -> str:
    """Convert a slowapi Limit list to human-readable string."""
    if not limit_list:
        return "none"
    if not isinstance(limit_list, (list, tuple)):
        return str(limit_list)
    parts = []
    for limit in limit_list:
        limit_str = getattr(limit, "limit", None)
        if callable(limit_str):
            limit_str = limit_str()
        parts.append(str(limit_str) if limit_str else str(limit))
    return ", ".join(parts) if parts else "none"


@router.get("/api/admin/settings")
@limiter.limit("30/minute")
async def get_settings_list(
    request: Request,
    category: Optional[str] = Query(None),
    _admin: User = Depends(require_admin),
):
    """List all application settings grouped by category."""
    settings = get_settings()
    fields = _get_settings_fields(settings)

    if category:
        fields = [f for f in fields if f["category"] == category]

    return {
        "categories": _CATEGORY_ORDER,
        "settings": fields,
    }


@router.get("/api/admin/settings/schema")
@limiter.limit("30/minute")
async def get_settings_schema(
    request: Request,
    _admin: User = Depends(require_admin),
):
    """Return settings schema metadata for building a dynamic UI."""
    settings = get_settings()
    fields = _get_settings_fields(settings)

    categories: Dict[str, List[Dict[str, Any]]] = {}
    for field in fields:
        cat = field["category"]
        categories.setdefault(cat, []).append(field)

    return {
        "categories": _CATEGORY_ORDER,
        "settings_by_category": categories,
    }


@router.get("/api/admin/rate-limits")
@limiter.limit("30/minute")
async def get_rate_limits(
    request: Request,
    _admin: User = Depends(require_admin),
):
    """List all rate-limited routes with their limits."""
    limiter_obj = request.app.state.limiter
    results: List[Dict[str, Any]] = []

    # Build a lookup: (path, method) from FastAPI route -> handler name
    handler_to_route: Dict[str, Dict[str, str]] = {}
    for route in request.app.routes:
        if hasattr(route, "endpoint") and hasattr(route, "methods") and hasattr(route, "path"):
            handler_to_route[route.endpoint.__name__] = {
                "path": route.path,
                "method": next(iter(route.methods), "*") if route.methods else "*",
            }

    # Per-route limits (from @limiter.limit decorators)
    route_limits: Dict = getattr(limiter_obj, "_route_limits", {})
    for key, limit_list in route_limits.items():
        limits_str = _format_limit_list(limit_list)
        func_name = key.rsplit(".", 1)[-1] if isinstance(key, str) and "." in key else str(key)
        route_info = handler_to_route.get(func_name, {})
        results.append(
            {
                "route": route_info.get("path", str(key)),
                "method": route_info.get("method", "*"),
                "limit": limits_str,
                "source": "decorator",
            }
        )

    # Per-route dynamic limits
    dynamic_limits: Dict = getattr(limiter_obj, "_dynamic_route_limits", {})
    for key, limit_list in dynamic_limits.items():
        limits_str = _format_limit_list(limit_list)
        func_name = key.rsplit(".", 1)[-1] if isinstance(key, str) and "." in key else str(key)
        route_info = handler_to_route.get(func_name, {})
        results.append(
            {
                "route": route_info.get("path", str(key)),
                "method": route_info.get("method", "*"),
                "limit": limits_str,
                "source": "dynamic",
            }
        )

    # Application-wide default limits
    default_limits: list = getattr(limiter_obj, "_default_limits", [])
    default_str = _format_limit_list(default_limits)
    if default_str != "none":
        results.append(
            {
                "route": "*",
                "method": "*",
                "limit": default_str,
                "source": "default",
            }
        )

    return {
        "total_routes": len(results),
        "rate_limits": results,
    }


@router.get("/api/admin/rate-limits/status")
@limiter.limit("30/minute")
async def get_rate_limits_status(
    request: Request,
    _admin: User = Depends(require_admin),
):
    """Return global rate-limit statistics."""
    limiter_obj = request.app.state.limiter
    route_limits: Dict = getattr(limiter_obj, "_route_limits", {})
    dynamic_limits: Dict = getattr(limiter_obj, "_dynamic_route_limits", {})
    default_limits: list = getattr(limiter_obj, "_default_limits", [])
    exempt_routes: list = getattr(limiter_obj, "_exempt_routes", [])

    return {
        "total_routes_limited": len(route_limits) + len(dynamic_limits),
        "default_limits_count": len(default_limits),
        "exempt_routes_count": len(exempt_routes),
        "storage_type": type(limiter_obj._storage).__name__
        if hasattr(limiter_obj, "_storage")
        else "unknown",
        "enabled": getattr(limiter_obj, "enabled", True),
    }
