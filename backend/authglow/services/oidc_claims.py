"""OIDC Core §5.5 — ``claims`` request parameter parser.

The ``claims`` parameter is a JSON object the RP can include in
the authorization request to ask for specific claims. Example::

    {
        "userinfo": {
            "given_name": {"essential": true},
            "nickname": null
        },
        "id_token": {
            "acr": {"essential": true, "value": "urn:mace:incommon:iap:silver"}
        }
    }

The parameter is a hint — it does NOT grant new scopes or new
permissions. AuthGlow applies it to:

* **ID token** — filters the OIDC standard claims that go into
  the ID token (the ``user_claims`` dict passed to
  ``create_id_token``). If a claim is requested as
  ``{"essential": true}`` and is not available, the token
  endpoint fails with ``claims_request_invalid`` (the client
  is asking for something the server cannot provide).
* **UserInfo** — same idea, on the UserInfo response.

If the client requests a claim that is NOT in the OIDC
standard list AND is not in the saved claim policy for the
client, the claim is silently dropped (the policy is the
authority for non-standard claims per OIDC §5.1.2).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple


class ClaimsParameterError(ValueError):
    """Raised when the ``claims`` parameter is malformed (not
    JSON, wrong top-level keys, etc.). Maps to HTTP 400
    ``invalid_request`` per OIDC §5.5."""


class ClaimsEssentialMissingError(ValueError):
    """Raised when the ``claims`` parameter marks a claim as
    ``essential: true`` and the claim is not available. Maps to
    HTTP 400 ``claims_request_invalid`` per OIDC §5.5."""


# OIDC Core §5.1.1 — only ``userinfo`` and ``id_token`` are
# allowed as top-level keys in the claims request parameter.
_ALLOWED_TOP_KEYS = frozenset({"userinfo", "id_token"})


def parse_claims_parameter(raw: Optional[str]) -> Optional[Dict[str, Any]]:
    """Parse the raw ``claims`` form value into the structured
    dict the rest of the code consumes.

    Returns ``None`` when the parameter is absent (the common
    case). Raises :class:`ClaimsParameterError` when the input
    is present but malformed.
    """
    if not raw:
        return None
    if not raw.strip():
        return None
    try:
        import json

        parsed = json.loads(raw)
    except Exception as exc:
        raise ClaimsParameterError(
            "claims parameter is not valid JSON"
        ) from exc
    if not isinstance(parsed, dict):
        raise ClaimsParameterError(
            "claims parameter must be a JSON object at the top level"
        )
    invalid_top = set(parsed.keys()) - _ALLOWED_TOP_KEYS
    if invalid_top:
        raise ClaimsParameterError(
            f"claims parameter has invalid top-level keys: {sorted(invalid_top)}. "
            "Allowed: userinfo, id_token."
        )
    # Validate each sub-dict shape
    for top_key, sub in parsed.items():
        if not isinstance(sub, dict):
            raise ClaimsParameterError(
                f"claims parameter '{top_key}' must be a JSON object of "
                "claim_name -> request"
            )
        for claim_name, request in sub.items():
            if request is None:
                # ``{"nickname": null}`` is a valid "request the
                # claim if available" form per OIDC §5.5.
                continue
            if not isinstance(request, dict):
                raise ClaimsParameterError(
                    f"claims parameter '{top_key}.{claim_name}' must be a "
                    "JSON object or null"
                )
            if "essential" in request and not isinstance(
                request["essential"], bool
            ):
                raise ClaimsParameterError(
                    f"claims parameter '{top_key}.{claim_name}.essential' "
                    "must be a boolean"
                )
            if "value" in request and "values" in request:
                raise ClaimsParameterError(
                    f"claims parameter '{top_key}.{claim_name}' has both "
                    "'value' and 'values' — exactly one is allowed"
                )
    return parsed


def apply_claims_request(
    target: str,
    requested: Optional[Dict[str, Any]],
    available_claims: Dict[str, Any],
) -> Tuple[Dict[str, Any], List[str]]:
    """Apply the ``target`` portion of the parsed claims
    request to the available claims dict.

    Args:
        target: ``"id_token"`` or ``"userinfo"`` — which sub-dict
            of the claims request to apply.
        requested: The parsed claims request dict (output of
            :func:`parse_claims_parameter`), or ``None``.
        available_claims: The full set of claims the server
            can emit (the OIDC standard claims mapped from
            scope + the namespaced custom claims from the
            claim policy).

    Returns:
        A ``(filtered, missing_essential)`` tuple:

        * ``filtered`` is a new dict containing only the
          claims the client requested (intersected with
          ``available_claims``). When ``requested`` is
          ``None``, the result is a copy of
          ``available_claims`` (no filtering).
        * ``missing_essential`` is a list of claim names the
          client marked as ``essential: true`` but that are
          not in ``available_claims``. Empty when the request
          is well-formed and satisfiable. The caller is
          expected to raise :class:`ClaimsEssentialMissingError`
          when this list is non-empty.

    Note: a client can mark a non-standard claim as essential
    — the server only emits the claim if it is in
    ``available_claims`` (i.e. the claim policy includes it
    as a namespaced custom claim). If the policy does not
    include the claim, the request is unsatisfiable for that
    claim regardless of the ``essential`` flag.
    """
    if not requested:
        return dict(available_claims), []
    sub = requested.get(target) or {}
    if not sub:
        return dict(available_claims), []

    filtered: Dict[str, Any] = {}
    missing_essential: List[str] = []
    for claim_name, request in sub.items():
        if claim_name in available_claims:
            value = available_claims[claim_name]
            # Honour ``value`` / ``values`` filters: when the
            # request specifies a literal value (or a list of
            # allowed values), drop the claim from the
            # response if the actual value does not match.
            if isinstance(request, dict):
                if "value" in request and value != request["value"]:
                    if request.get("essential"):
                        missing_essential.append(claim_name)
                    continue
                if "values" in request and value not in request["values"]:
                    if request.get("essential"):
                        missing_essential.append(claim_name)
                    continue
            filtered[claim_name] = value
        else:
            # Claim requested but not in available_claims. The
            # client marked it essential → must fail.
            if isinstance(request, dict) and request.get("essential"):
                missing_essential.append(claim_name)
    return filtered, missing_essential
