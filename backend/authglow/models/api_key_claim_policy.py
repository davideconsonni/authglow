"""Per-API-key claim policy — declarative rules for the namespaced
custom claims emitted in the access token that results from an
``/api/token/api-key`` exchange.

The model is the API key counterpart of
:class:`authglow.models.claim_policy.ClientClaimPolicy`:
* Identical ``rules`` payload (same :class:`ClaimRule` /
  :class:`ClaimSource` / :class:`ClaimTarget` Pydantic
  classes are reused — only the owner key changes).
* Different owner key (``api_key_id`` instead of ``client_id``).
* Different merge semantics: an API key policy is **merged**
  with the first-party default rule set (RBAC roles +
  permissions) at resolve time, so a saved API key policy
  ADDS claims on top of the standard ones. An OAuth client
  policy by contrast REPLACES the default. The rationale is
  operational: an admin who configures an API key typically
  wants the standard RBAC claims plus a couple of
  API-key-specific ones, not the loss of the standard
  claims.
"""

from __future__ import annotations

from datetime import datetime
from typing import List
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

from authglow.core.datetime import utcnow
from authglow.models.claim_policy import ClaimRule


class APIKeyClaimPolicy(BaseModel):
    """Per-API-key declarative claim policy.

    One policy per API key, identified by ``api_key_id``. The
    repository is the source of truth; the service layer
    (:class:`ClaimPolicyService`) interprets the rules at
    access-token-issue time.

    When an admin saves a policy with an empty ``rules`` list
    the policy is deleted from disk (the empty-policy state is
    indistinguishable from "no policy"), so the default first-party
    rules (RBAC roles + permissions) apply on their own.
    """

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(default_factory=lambda: str(uuid4()))
    api_key_id: str
    rules: List[ClaimRule] = Field(default_factory=list)
    schema_version: int = 1
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    @field_validator("api_key_id")
    @classmethod
    def _check_api_key_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("api_key_id must not be empty")
        return v

    @field_validator("rules")
    @classmethod
    def _check_no_duplicate_claim_names(cls, v: List[ClaimRule]) -> List[ClaimRule]:
        """Two rules with the same ``claim_name`` would be
        ambiguous (last-wins silently). Refuse the input at the
        model layer so the admin UI gets a clear error."""
        seen: set[str] = set()
        for rule in v:
            if rule.claim_name in seen:
                raise ValueError(
                    f"Duplicate claim_name {rule.claim_name!r} in policy. "
                    "Combine the rules into one or pick a different claim name."
                )
            seen.add(rule.claim_name)
        return v
