"""Service layer for the per-OAuth2-client and per-API-key claim
policy system.

The claim policy is a list of declarative rules (see
:class:`authglow.models.claim_policy.ClientClaimPolicy` and
:class:`authglow.models.api_key_claim_policy.APIKeyClaimPolicy`)
that decide which custom claims are embedded in access
tokens, ID tokens, and UserInfo responses. The service
interprets the rules at token-issuance time and produces a
flat ``dict`` of ``claim_name -> value`` that the JWT service
then merges into the token payload via the ``extra_claims``
parameter.

Design notes
------------

* **No back-compat with the pre-policy plain ``permissions`` /
  ``roles`` claims** (build-phase decision). The default
  emitted claims for any client without an explicit policy
  are the *namespaced* RBAC claims, never the plain ones.
* **Reserved claim protection.** The JWT service refuses to
  let ``extra_claims`` override the cryptographic anchors
  (``iss``, ``sub``, ``aud``, ``exp``, ``iat``, ``jti``,
  ``azp``, ``cnf``) — they are baked in by the JWT service
  and stay there.
* **Scope gating.** A rule with ``required_scope`` is skipped
  if the requested scope is not in the scope set the user /
  client has approved. The filter happens in this service
  before the dict is returned, so the JWT service does not
  need to know about scopes-vs-claim-policies.
* **Merge semantics — DIFFERENT per issuer:**
  - OAuth client policy REPLACES the default first-party
    rules (the saved rules are the entire emission set).
  - API key policy MERGES with the default first-party
    rules (the standard RBAC roles + permissions claims
    are always emitted in addition to the key-specific
    ones). The operational reason: an admin who configures
    an API key typically wants RBAC claims PLUS a couple of
    key-specific ones, not the loss of the standard
    claims.
* **Lazy imports.** The RBAC service is imported lazily inside
  :meth:`build_claims` to avoid the historical circular
  dependency between ``services.user`` and ``services.rbac``.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from authglow.core.config import Settings, get_settings
from authglow.core.datetime import utcnow
from authglow.models.api_key import APIKey
from authglow.models.api_key_claim_policy import APIKeyClaimPolicy
from authglow.models.claim_policy import (
    BUILTIN_TEMPLATES,
    ClaimRule,
    ClaimSource,
    ClaimSourceConfig,
    ClaimTarget,
    ClaimTemplate,
    ClientClaimPolicy,
    render_template_claim_name,
)
from authglow.models.user import User
from authglow.repositories.protocols import (
    APIKeyClaimPolicyRepository,
    ClientClaimPolicyRepository,
)

# Claims the JWT service bakes in itself. The claim policy
# MUST NOT be able to override them — the policy can only add
# new claims. The set is the same across access token, ID
# token, and refresh token.
RESERVED_CLAIMS: frozenset[str] = frozenset(
    {
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nbf",
        "jti",
        "azp",
        "cnf",
        "token_type",
    }
)


class ClaimPolicyService:
    """Build the claim dict the JWT service merges into a token.

    The service is stateless — it loads the policy from the
    repositories on each :meth:`build_claims` call. Admin writes
    go through :meth:`save_policy` / :meth:`save_api_key_policy`
    and :meth:`delete_policy` / :meth:`delete_api_key_policy`,
    which refresh ``updated_at`` before persisting.
    """

    def __init__(
        self,
        repository: Optional[ClientClaimPolicyRepository] = None,
        api_key_repository: Optional[APIKeyClaimPolicyRepository] = None,
        *,
        settings: Optional[Settings] = None,
    ) -> None:
        self.settings: Settings = settings or get_settings()
        if repository is not None:
            self._repository: ClientClaimPolicyRepository = repository
        else:
            from authglow.repositories.dependencies import (
                get_claim_policy_repository,
            )

            self._repository = get_claim_policy_repository(settings=self.settings)
        if api_key_repository is not None:
            self._api_key_repository: APIKeyClaimPolicyRepository = (
                api_key_repository
            )
        else:
            from authglow.repositories.dependencies import (
                get_api_key_claim_policy_repository,
            )

            self._api_key_repository = get_api_key_claim_policy_repository(
                settings=self.settings,
            )

    # ------------------------------------------------------------------
    # Read path — used at every token-issuance call site
    # ------------------------------------------------------------------

    async def get_policy(self, client_id: str) -> Optional[ClientClaimPolicy]:
        """Return the saved policy for *client_id*, or ``None``."""
        return await self._repository.get_by_client(client_id)

    async def get_api_key_policy(
        self, api_key_id: str
    ) -> Optional[APIKeyClaimPolicy]:
        """Return the saved policy for *api_key_id*, or ``None``."""
        return await self._api_key_repository.get_by_api_key(api_key_id)

    async def build_claims(
        self,
        user: Optional[User] = None,
        *,
        client_id: Optional[str] = None,
        api_key_id: Optional[str] = None,
        api_key: Optional[APIKey] = None,
        scopes: Optional[List[str]] = None,
        target: ClaimTarget = ClaimTarget.ACCESS_TOKEN,
    ) -> Dict[str, Any]:
        """Return the ``extra_claims`` dict for the given target.

        Two issuer flows are supported, mutually exclusive at
        call time:

        * **OAuth client** (``client_id`` set): the saved
          ``ClientClaimPolicy`` REPLACES the default rule
          set (the admin's saved rules are the entire
          emission).
        * **API key** (``api_key_id`` set): the saved
          ``APIKeyClaimPolicy`` MERGES with the default rule
          set (the standard RBAC roles + permissions are
          always emitted, plus the key-specific rules).

        For first-party flows with neither parameter set the
        default first-party rules are used as-is.

        Args:
            user: The authenticated user the token is issued
                for. May be ``None`` for the
                ``client_credentials`` grant where the
                subject is the client itself, not a user —
                in that case ``RBAC_ROLES``,
                ``RBAC_PERMISSIONS`` and ``USER_FIELD``
                rules produce no value.
            client_id: The OAuth2 client (None for first-party
                flows and for API key flows).
            api_key_id: The API key id (None unless the token
                is issued via ``/api/token/api-key``).
            api_key: The ``APIKey`` instance — must be passed
                alongside ``api_key_id`` so the
                ``API_KEY_FIELD`` source can read attributes
                from it. The service does not re-fetch the
                key (the route handler already has it from
                ``validate_and_track``).
            scopes: The scopes the user / client / key has
                approved for this token (used for
                ``required_scope`` filtering).
            target: Which token the dict will be merged into.

        Returns:
            A ``dict`` of ``claim_name -> value`` to be merged
            into the JWT payload by :class:`JWTService`. Empty
            dict if no rule produces a value. Reserved claims
            (``iss``, ``sub``, ``aud``, ...) are filtered out.
        """
        if client_id is not None and api_key_id is not None:
            # Programming error — the two issuer paths are
            # mutually exclusive. The JWT layer treats this as
            # a bug.
            raise ValueError(
                "build_claims accepts at most one of client_id / api_key_id"
            )

        scope_set = set(scopes or [])

        if client_id is not None:
            # OAuth client flow: saved policy REPLACES default
            saved = await self._repository.get_by_client(client_id)
            active_rules = saved.rules if saved is not None else self._default_rules()
        elif api_key_id is not None:
            # API key flow: default rules are ALWAYS applied,
            # the saved policy rules are merged on top.
            # The "merge" semantic is implemented by
            # concatenating the rule lists and processing both.
            # When a saved rule emits a claim that the default
            # rules also emit, the saved rule wins (last-wins
            # on dict assignment).
            saved_api_key = await self._api_key_repository.get_by_api_key(api_key_id)
            saved_rules = saved_api_key.rules if saved_api_key is not None else []
            active_rules = self._default_rules() + saved_rules
        else:
            # First-party default (cookie auth, password
            # login, MFA completion, etc.).
            active_rules = self._default_rules()

        # Pre-compute RBAC role + permission lists once per
        # call. When there is no user, both lists stay
        # empty — RBAC sources have no subject to look up.
        if user is not None:
            rbac_roles, rbac_permissions = await self._resolve_rbac(user.id)
        else:
            rbac_roles, rbac_permissions = [], []

        claims: Dict[str, Any] = {}
        for rule in active_rules:
            if target not in rule.include_in:
                continue
            if rule.required_scope and rule.required_scope not in scope_set:
                continue
            if rule.claim_name in RESERVED_CLAIMS:
                continue
            value = self._resolve_source(
                rule, user, api_key, rbac_roles, rbac_permissions
            )
            if value is None:
                continue
            # Last-wins semantics — saved rules (evaluated
            # after the default) override default emissions
            # on conflict. This is the API key merge semantic.
            claims[rule.claim_name] = value

        return claims

    # ------------------------------------------------------------------
    # Write path — used by the admin API
    # ------------------------------------------------------------------

    async def save_policy(
        self,
        client_id: str,
        rules: List[ClaimRule],
    ) -> ClientClaimPolicy:
        """Replace the saved policy for *client_id*.

        If *rules* is empty, the saved policy is deleted
        (reverting to the default). This keeps "no rules" and
        "no policy file" indistinguishable from the consumer's
        point of view.
        """
        if rules:
            existing = await self._repository.get_by_client(client_id)
            policy = ClientClaimPolicy(
                client_id=client_id,
                rules=rules,
                schema_version=1,
                created_at=existing.created_at if existing else utcnow(),
                updated_at=utcnow(),
            )
            await self._repository.save(policy)
            return policy
        await self._repository.delete(client_id)
        # Caller asked for the "no policy" semantics — return
        # a fresh ClientClaimPolicy with the default rules so
        # the admin UI has something to display / diff against.
        return ClientClaimPolicy(
            client_id=client_id,
            rules=self._default_rules(),
        )

    async def delete_policy(self, client_id: str) -> bool:
        """Remove the saved policy for *client_id*. Returns
        ``True`` on success, ``False`` if no policy was set."""
        return await self._repository.delete(client_id)

    # ------------------------------------------------------------------
    # Write path — API key policy
    # ------------------------------------------------------------------

    async def save_api_key_policy(
        self,
        api_key_id: str,
        rules: List[ClaimRule],
    ) -> APIKeyClaimPolicy:
        """Replace the saved policy for *api_key_id*.

        If *rules* is empty, the saved policy is deleted
        (reverting to the default first-party rule set on
        its own).
        """
        if rules:
            existing = await self._api_key_repository.get_by_api_key(api_key_id)
            policy = APIKeyClaimPolicy(
                api_key_id=api_key_id,
                rules=rules,
                schema_version=1,
                created_at=existing.created_at if existing else utcnow(),
                updated_at=utcnow(),
            )
            await self._api_key_repository.save(policy)
            return policy
        await self._api_key_repository.delete(api_key_id)
        # Return a synthetic "no policy" view so the admin UI
        # can show "this key uses the default" instead of an
        # empty state.
        return APIKeyClaimPolicy(
            api_key_id=api_key_id,
            rules=self._default_rules(),
        )

    async def delete_api_key_policy(self, api_key_id: str) -> bool:
        """Remove the saved policy for *api_key_id*. Returns
        ``True`` on success, ``False`` if no policy was set."""
        return await self._api_key_repository.delete(api_key_id)

    # ------------------------------------------------------------------
    # Template helpers
    # ------------------------------------------------------------------

    def list_templates(self) -> List[ClaimTemplate]:
        """Return the built-in templates (display order)."""
        return list(BUILTIN_TEMPLATES)

    def apply_template(
        self,
        template_id: str,
        *,
        include_in: Optional[List[ClaimTarget]] = None,
        required_scope: Optional[str] = None,
    ) -> ClaimRule:
        """Materialise a built-in template into a :class:`ClaimRule`.

        The relative ``claim_name`` of the template is expanded
        against :attr:`Settings.claim_namespace`. The caller may
        override ``include_in`` / ``required_scope`` to specialise
        the template (e.g. "only emit RBAC roles into the ID
        token when the ``roles`` scope is approved").
        """
        template = next((t for t in BUILTIN_TEMPLATES if t.id == template_id), None)
        if template is None:
            raise ValueError(f"Unknown claim template: {template_id!r}")
        resolved_name = render_template_claim_name(
            template.claim_name, self.settings.claim_namespace
        )
        return ClaimRule(
            claim_name=resolved_name,
            source=template.source,
            source_config=template.source_config.model_copy(deep=True),
            include_in=include_in if include_in is not None else list(template.include_in),
            required_scope=(
                required_scope
                if required_scope is not None
                else template.required_scope
            ),
            description=template.description,
        )

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _default_rules(self) -> List[ClaimRule]:
        """The default rule set applied to clients without a
        saved policy and to first-party flows with no
        ``client_id``.

        The default is a single OIDC-compliant rule pair: the
        namespaced RBAC roles + permissions claims, both into
        the access token. ID token + UserInfo are not in the
        default — the admin opts in via the UI for those
        targets, per OIDC §5.5 (the resource server can also
        call the UserInfo endpoint for the same data).
        """
        ns = self.settings.claim_namespace.rstrip("/")
        return [
            ClaimRule(
                claim_name=f"{ns}/roles",
                source=ClaimSource.RBAC_ROLES,
                include_in=[ClaimTarget.ACCESS_TOKEN],
                description=None,
            ),
            ClaimRule(
                claim_name=f"{ns}/permissions",
                source=ClaimSource.RBAC_PERMISSIONS,
                include_in=[ClaimTarget.ACCESS_TOKEN],
                description=None,
            ),
        ]

    @staticmethod
    async def _resolve_rbac(user_id: str) -> tuple[List[str], List[str]]:
        """Resolve RBAC roles and permissions for a user.

        Returns ``(roles, permissions)`` as plain lists. Both may
        be empty. The RBAC service is imported lazily to avoid
        the circular dep with ``services.user``.
        """
        try:
            from authglow.services.rbac import RBACService

            rbac = RBACService()
            permissions: List[str] = sorted(await rbac.get_user_permissions(user_id))
            user_roles = await rbac.get_user_roles(user_id)
            role_names: List[str] = []
            for ur in user_roles or []:
                role = await rbac.get_role(ur.role_id)
                if role:
                    role_names.append(role.name)
            role_names = sorted(set(role_names))
            return role_names, permissions
        except Exception:
            return [], []

    @staticmethod
    def _resolve_source(
        rule: ClaimRule,
        user: Optional[User],
        api_key: Optional[APIKey],
        rbac_roles: List[str],
        rbac_permissions: List[str],
    ) -> Any:
        """Read the value for a single rule from its declared
        source. ``None`` means "skip — do not emit this claim"
        (used by :class:`USER_FIELD` when the user / attribute
        is absent, by :class:`API_KEY_FIELD` when the API key
        / attribute is absent, and by :class:`STATIC` when
        the literal is ``None``).
        """
        cfg: ClaimSourceConfig = rule.source_config
        if rule.source == ClaimSource.USER_FIELD:
            if user is None:
                return None
            assert cfg.user_field is not None  # guaranteed by validator
            return getattr(user, cfg.user_field, None)
        if rule.source == ClaimSource.RBAC_ROLES:
            return list(rbac_roles)
        if rule.source == ClaimSource.RBAC_PERMISSIONS:
            return list(rbac_permissions)
        if rule.source == ClaimSource.STATIC:
            return cfg.value
        if rule.source == ClaimSource.API_KEY_FIELD:
            if api_key is None:
                return None
            assert cfg.api_key_field is not None  # guaranteed by validator
            return getattr(api_key, cfg.api_key_field, None)
        if rule.source == ClaimSource.JWT_META:
            # The JWT service handles its own meta — for now we
            # do not duplicate the ``iss`` / ``aud`` / ``azp``
            # writes. If a future rule wants to alias them
            # under a namespaced claim, the JWT service will
            # receive the request as an extra_claim and skip
            # it (reserved). This branch is kept as a hook for
            # the (rare) case of wanting ``sub`` mirrored into
            # a custom claim — that needs a richer value, so
            # the service returns None for now.
            return None
        return None
