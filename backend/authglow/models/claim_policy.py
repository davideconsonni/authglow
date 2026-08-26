"""Per-client claim policy for OAuth2 token issuance.

A ``ClientClaimPolicy`` is a list of declarative rules that tell
the JWT issuance path which custom claims to embed in access
tokens / ID tokens / UserInfo responses, where the value comes
from (user attribute, RBAC role list, RBAC permission list,
static literal, JWT metadata), and which token the claim is
allowed to appear in.

Standard references
-------------------

The model is designed to comply with two OIDC / OAuth2 specs:

* **OIDC Core §5.1.2** — "All other Claims MUST be namespaced."
  The list of standard OIDC claims that do not require a
  namespace is encoded in :data:`OIDC_STANDARD_CLAIMS`. Any
  claim name not in that set must be a URI.
* **RFC 9068 §2.2** — "JWT Profile for OAuth 2.0 Access
  Tokens" — which lists common custom claims (``roles``,
  ``permissions``, ``groups``, ``tenant``, ``tenant_id``,
  ``entitlements``) and reiterates the namespacing rule.

Per the project decision (build phase, no back-compat with
the pre-policy plain ``permissions`` / ``roles`` claims):
* No legacy plain claim is ever emitted.
* Namespacing is enforced at the model layer (the
  ``_validate_claim_name`` validator).
* The default namespace for built-in templates is the
  ``settings.claim_namespace`` value (URI, configured per
  installation).
"""

from __future__ import annotations

import re
from datetime import datetime
from enum import Enum
from typing import Any, List, Literal, Optional
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from authglow.core.datetime import utcnow

# ---------------------------------------------------------------------------
# OIDC Core §5.1 — standard claims that DO NOT require a namespace.
# ---------------------------------------------------------------------------
#
# Sourced from OIDC Core §5.1 ("Standard Claims") + OIDC Core §2 ("ID
# Token") + RFC 9068 §2.2 ("Access Token JWT"). The list is closed:
# any claim name not in this set is treated as a custom claim and
# MUST be a URI.
OIDC_STANDARD_CLAIMS: frozenset[str] = frozenset(
    {
        # --- OIDC Core §2 (ID Token) ---
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "auth_time",
        "nonce",
        "acr",
        "amr",
        "azp",
        "sid",
        # --- OIDC Core §5.1 (Standard Claims) ---
        "name",
        "given_name",
        "family_name",
        "middle_name",
        "nickname",
        "preferred_username",
        "profile",
        "picture",
        "website",
        "gender",
        "birthdate",
        "zoneinfo",
        "locale",
        "updated_at",
        "email",
        "email_verified",
        "phone_number",
        "phone_number_verified",
        "address",
        # --- OIDC Core §3.1.3.6 / §3.3.2.11 ---
        "at_hash",
        "c_hash",
        # --- RFC 9068 §2.2 (Access Token JWT) ---
        "client_id",
        "jti",
        "nbf",
        "scope",
        "scp",
        # --- RFC 9449 (DPoP) ---
        "cnf",
        # --- General JWT / OAuth2 ---
        "iat",
        "token_type",
    }
)

# RFC 3986 — a claim name that is not in the OIDC whitelist MUST
# be an absolute URI. We accept either ``http(s)://`` (the only
# shapes RFC 9068 §2.2 examples) or ``urn:`` (used for SAML-style
# namespacing, also valid per RFC 3986).
_URI_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*:[^\s]+$")


class ClaimSource(str, Enum):
    """Where the claim value comes from.

    * ``USER_FIELD`` — read an attribute off the ``User`` model.
    * ``RBAC_ROLES`` — list of role names assigned to the user.
    * ``RBAC_PERMISSIONS`` — list of permission names aggregated
      from the user's roles.
    * ``STATIC`` — a literal value baked into the rule.
    * ``JWT_META`` — a metadata field of the JWT itself (``iss``,
      ``aud``, ``azp``, ``sub``, ``client_id``).
    * ``API_KEY_FIELD`` — read an attribute off the ``APIKey``
      model (only meaningful for API key claim policies). The
      allowed attribute names are enumerated in
      :data:`APIKeyField` so the Pydantic layer rejects typos
      at the admin API boundary.
    """

    USER_FIELD = "user_field"
    RBAC_ROLES = "rbac_roles"
    RBAC_PERMISSIONS = "rbac_permissions"
    STATIC = "static"
    JWT_META = "jwt_meta"
    API_KEY_FIELD = "api_key_field"


# Closed list of attribute names the admin can expose from an
# ``APIKey`` via the ``API_KEY_FIELD`` source. Adding a new
# option here is the only way to widen the surface — keep this
# list aligned with the public / non-sensitive attributes of
# ``authglow.models.api_key.APIKey`` (do not include the
# ``key_hash`` / ``key_prefix`` is OK, it is already on the
# API, but the full key is never on the model so this is moot).
ApiKeyField = Literal["name", "key_prefix", "scopes", "allowed_ips", "tier"]


class ClaimTarget(str, Enum):
    """Where the claim is allowed to appear.

    * ``ACCESS_TOKEN`` — JWT access token.
    * ``ID_TOKEN`` — OIDC ID token (only when ``openid`` scope is
      requested).
    * ``USERINFO`` — response body of the ``/oauth2/userinfo``
      endpoint, filtered by the requested scope.
    """

    ACCESS_TOKEN = "access_token"
    ID_TOKEN = "id_token"
    USERINFO = "userinfo"


# Fields of the JWT that the ``JWT_META`` source can copy into a
# claim. Kept in sync with what ``services/jwt.py`` writes.
JwtMetaField = Literal["iss", "aud", "azp", "sub", "client_id"]


class ClaimSourceConfig(BaseModel):
    """Type-safe payload for :class:`ClaimRule.source_config`.

    The shape depends on the rule's :class:`ClaimSource`:

    * ``USER_FIELD`` — ``user_field`` is required (attribute name
      on the ``User`` model).
    * ``STATIC`` — ``value`` is required (literal to embed).
    * ``JWT_META`` — ``jwt_meta`` is required (one of
      :data:`JwtMetaField`).
    * ``API_KEY_FIELD`` — ``api_key_field`` is required (one of
      :data:`ApiKeyField`).
    * ``RBAC_ROLES`` / ``RBAC_PERMISSIONS`` — no config needed,
      the source is implicitly "all of them".
    """

    model_config = ConfigDict(extra="forbid")

    user_field: Optional[str] = None
    value: Optional[Any] = None
    jwt_meta: Optional[JwtMetaField] = None
    api_key_field: Optional[ApiKeyField] = None


def _validate_claim_name(name: str) -> str:
    """Enforce OIDC §5.1.2 — claim must be standard or namespaced URI.

    The set of "standard" claim names is closed: see
    :data:`OIDC_STANDARD_CLAIMS`. Any other claim MUST be a URI
    (RFC 3986) — typically ``https://<controlled-by-issuer>/...``.
    """
    if not name:
        raise ValueError("claim_name must not be empty")
    if name in OIDC_STANDARD_CLAIMS:
        return name
    if not _URI_RE.match(name):
        raise ValueError(
            f"claim_name {name!r} is not a standard OIDC claim and "
            "must be a URI per OIDC Core §5.1.2 "
            "(e.g. 'https://authglow.example.com/roles')."
        )
    return name


class ClaimRule(BaseModel):
    """One declarative rule: "this claim, from this source, in these tokens".

    The rule is intentionally small — there is no transformation
    pipeline. The value is read from ``source_config`` verbatim
    and written to the token payload under ``claim_name``. If
    multiple rules produce the same claim name, the last one
    wins (deterministic order = list order in the policy).
    """

    model_config = ConfigDict(extra="forbid")

    claim_name: str
    source: ClaimSource
    source_config: ClaimSourceConfig = Field(default_factory=ClaimSourceConfig)
    include_in: List[ClaimTarget] = Field(default_factory=list)
    required_scope: Optional[str] = None
    description: Optional[str] = Field(None, max_length=500)

    @field_validator("claim_name")
    @classmethod
    def _check_claim_name(cls, v: str) -> str:
        return _validate_claim_name(v)

    @field_validator("include_in")
    @classmethod
    def _check_include_in_not_empty(cls, v: List[ClaimTarget]) -> List[ClaimTarget]:
        if not v:
            raise ValueError("include_in must contain at least one target")
        return v

    @model_validator(mode="after")
    def _check_source_config_matches_source(self) -> "ClaimRule":
        """Ensure the typed ``source_config`` carries the right key
        for the declared ``source``. Wrong shape → 422 from the
        Pydantic layer, not a silent None downstream.

        ``STATIC`` is the one exception: ``value=None`` is a
        legal "emit nothing" sentinel (useful for templates the
        admin wants to enable but later customise). The
        :class:`ClaimPolicyService` filters ``None`` values
        out of the extra_claims dict at resolve time.
        """
        cfg = self.source_config
        if self.source == ClaimSource.USER_FIELD and not cfg.user_field:
            raise ValueError(
                "source=USER_FIELD requires source_config.user_field "
                "(attribute name on the User model)."
            )
        if self.source == ClaimSource.STATIC and cfg.value is None:
            # value=None is legal — it just means "do not emit".
            pass
        if self.source == ClaimSource.JWT_META and not cfg.jwt_meta:
            raise ValueError(
                "source=JWT_META requires source_config.jwt_meta "
                "(one of: iss, aud, azp, sub, client_id)."
            )
        if self.source == ClaimSource.API_KEY_FIELD and not cfg.api_key_field:
            raise ValueError(
                "source=API_KEY_FIELD requires source_config.api_key_field "
                "(one of: name, key_prefix, scopes, allowed_ips, tier)."
            )
        if self.source in (ClaimSource.RBAC_ROLES, ClaimSource.RBAC_PERMISSIONS):
            if (
                cfg.user_field
                or cfg.value is not None
                or cfg.jwt_meta
                or cfg.api_key_field
            ):
                raise ValueError(
                    f"source={self.source.value} takes no source_config "
                    "fields (user_field, value, jwt_meta, api_key_field "
                    "must all be None)."
                )
        return self


class ClientClaimPolicy(BaseModel):
    """Per-client declarative claim policy.

    One policy per OAuth2 client, identified by ``client_id``.
    The repository is the source of truth; the service
    layer (see :class:`ClaimPolicyService`) interprets the rules
    at token-issuance time.
    """

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(default_factory=lambda: str(uuid4()))
    client_id: str
    rules: List[ClaimRule] = Field(default_factory=list)
    schema_version: int = 1
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @field_validator("client_id")
    @classmethod
    def _check_client_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("client_id must not be empty")
        return v

    @model_validator(mode="after")
    def _check_no_duplicate_claim_names(self) -> "ClientClaimPolicy":
        """Two rules with the same ``claim_name`` would be ambiguous
        (last-wins silently). Refuse the input at the model layer
        so the admin UI gets a clear error."""
        seen: set[str] = set()
        for rule in self.rules:
            if rule.claim_name in seen:
                raise ValueError(
                    f"Duplicate claim_name {rule.claim_name!r} in policy. "
                    "Combine the rules into one or pick a different claim name."
                )
            seen.add(rule.claim_name)
        return self


# ---------------------------------------------------------------------------
# Built-in templates — the public list surfaced by the admin API.
#
# The actual claim name is built from ``settings.claim_namespace``
# at template-render time (so the namespace can be reconfigured
# per installation without touching the templates themselves).
# ---------------------------------------------------------------------------


class ClaimTemplate(BaseModel):
    """A pre-built claim rule template the admin can enable with one click.

    The ``claim_name`` field is the *unresolved* form: it is
    rendered against :class:`authglow.core.config.Settings.claim_namespace`
    at apply time. The default templates use a relative
    name (e.g. ``"roles"``) which becomes
    ``"<namespace>/roles"`` after rendering. Templates that
    already carry a URI (like ``"https://w3id.org/roles"``)
    are passed through unchanged.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    label: str
    description: str
    claim_name: str
    source: ClaimSource
    include_in: List[ClaimTarget]
    required_scope: Optional[str] = None
    source_config: ClaimSourceConfig = Field(default_factory=ClaimSourceConfig)


def render_template_claim_name(template_name: str, namespace: str) -> str:
    """Resolve a template's ``claim_name`` against the configured namespace.

    If the template name already contains ``:`` it is treated as
    an absolute URI and returned as-is. Otherwise it is
    concatenated to the namespace with a ``/`` separator.
    """
    if not template_name:
        raise ValueError("template claim_name must not be empty")
    if _URI_RE.match(template_name):
        return template_name
    if not namespace:
        raise ValueError(
            "claim_namespace must be configured when using relative "
            "template claim names."
        )
    ns = namespace.rstrip("/")
    return f"{ns}/{template_name.lstrip('/')}"


# Built-in templates, in display order. The ``claim_name`` here is
# the *relative* form; the service layer expands it against
# ``Settings.claim_namespace`` at apply time.
BUILTIN_TEMPLATES: List[ClaimTemplate] = [
    ClaimTemplate(
        id="rbac-roles",
        label="RBAC Roles (namespaced)",
        description=(
            "The list of RBAC role names assigned to the user, "
            "namespaced per OIDC §5.1.2 (e.g. "
            "'https://authglow.example.com/claims/roles')."
        ),
        claim_name="roles",
        source=ClaimSource.RBAC_ROLES,
        include_in=[ClaimTarget.ACCESS_TOKEN, ClaimTarget.USERINFO],
    ),
    ClaimTemplate(
        id="rbac-permissions",
        label="RBAC Permissions (namespaced)",
        description=(
            "The aggregated list of permission names from all of "
            "the user's roles, namespaced per OIDC §5.1.2."
        ),
        claim_name="permissions",
        source=ClaimSource.RBAC_PERMISSIONS,
        include_in=[ClaimTarget.ACCESS_TOKEN],
    ),
    # --- API key claim templates ---
    # The following templates expose attributes of the API key
    # used at exchange time (name, key_prefix, scopes,
    # allowed_ips, tier). They are only meaningful inside an
    # API key claim policy; the ClaimPolicyService ignores
    # them when the build_claims call has ``api_key_id=None``.
    ClaimTemplate(
        id="api-key-name",
        label="API Key Name",
        description=(
            "Exposes the API key's display name as a namespaced "
            "claim. Useful for audit / log correlation on the "
            "resource server side."
        ),
        claim_name="api_key_name",
        source=ClaimSource.API_KEY_FIELD,
        source_config=ClaimSourceConfig(api_key_field="name"),
        include_in=[ClaimTarget.ACCESS_TOKEN],
    ),
    ClaimTemplate(
        id="api-key-prefix",
        label="API Key Prefix",
        description=(
            "Exposes the public key prefix (e.g. 'ak_ABCDEFGHIJ') "
            "as a namespaced claim. Non-sensitive: the prefix is "
            "already shown in the admin UI and in audit logs."
        ),
        claim_name="api_key_prefix",
        source=ClaimSource.API_KEY_FIELD,
        source_config=ClaimSourceConfig(api_key_field="key_prefix"),
        include_in=[ClaimTarget.ACCESS_TOKEN],
    ),
    ClaimTemplate(
        id="api-key-scopes",
        label="API Key Scopes",
        description=(
            "Exposes the list of OAuth scopes the API key was "
            "granted. Useful when the resource server wants to "
            "decide between 'this key has read+write' and 'this "
            "key is read-only' without re-checking the database."
        ),
        claim_name="api_key_scopes",
        source=ClaimSource.API_KEY_FIELD,
        source_config=ClaimSourceConfig(api_key_field="scopes"),
        include_in=[ClaimTarget.ACCESS_TOKEN],
    ),
    ClaimTemplate(
        id="api-key-allowed-ips",
        label="API Key Allowed IPs",
        description=(
            "Exposes the list of IP addresses the key is bound to. "
            "Useful when the resource server wants to skip its "
            "own IP-allowlist check (the gateway already enforces it)."
        ),
        claim_name="api_key_allowed_ips",
        source=ClaimSource.API_KEY_FIELD,
        source_config=ClaimSourceConfig(api_key_field="allowed_ips"),
        include_in=[ClaimTarget.ACCESS_TOKEN],
    ),
    ClaimTemplate(
        id="api-key-tier",
        label="API Key Tier",
        description=(
            "Exposes the API key's free-form tier label "
            "(e.g. 'production', 'staging', 'internal'). The key "
            "must have the 'tier' field set; emit nothing when "
            "unset."
        ),
        claim_name="api_key_tier",
        source=ClaimSource.API_KEY_FIELD,
        source_config=ClaimSourceConfig(api_key_field="tier"),
        include_in=[ClaimTarget.ACCESS_TOKEN],
    ),
]
