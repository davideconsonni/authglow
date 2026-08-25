"""RFC 6749 §5.2 error envelope for the OAuth2 protocol endpoints.

Every protocol endpoint (``/oauth2/token``, ``/oauth2/introspect``,
``/oauth2/revoke``, ...) MUST signal failures with a machine-readable
top-level body::

    {
      "error": "invalid_grant",
      "error_description": "...",
      "error_code": "<diagnostic code>"   # optional, AuthGlow extension
    }

Historically AuthGlow leaked FastAPI's default envelope
(``{"detail": "..."}`` or ``{"detail": {"error": ...}}``), which no
standard client library can parse. :class:`OAuth2Error` replaces both.

Design notes
------------
* :class:`OAuth2Error` subclasses :class:`fastapi.HTTPException` so any
  existing ``pytest.raises(HTTPException)`` keeps working.
* ``detail`` carries the *flat wire body*; the exception handler
  registered by :func:`register_oauth2_error_handler` serialises it as
  the top-level JSON object (NOT wrapped under ``"detail"``).
* ``error_code`` is an additional diagnostic member (permitted by
  RFC 6749 §5.2: "Additional parameters MAY be included") preserving
  the previous ``detail.error_code`` information.
* Apps built without the registration (bare ``FastAPI()`` +
  ``include_router`` in some tests) fall back to the default
  HTTPException envelope — production wiring always registers it.
"""

from typing import Any, Dict, Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

# Canonical error codes — RFC 6749 §5.2.
INVALID_REQUEST = "invalid_request"
INVALID_CLIENT = "invalid_client"
INVALID_GRANT = "invalid_grant"
UNAUTHORIZED_CLIENT = "unauthorized_client"
UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
INVALID_SCOPE = "invalid_scope"


class OAuth2Error(HTTPException):
    """Protocol error carrying an RFC 6749 §5.2 shaped body.

    Parameters
    ----------
    error:
        One of the canonical §5.2 codes (see module constants).
    description:
        Human-readable ``error_description`` (ASCII per RFC 6749 §5.2).
    status_code:
        400 unless the code mandates otherwise (``invalid_client`` →
        401 when authentication was attempted via the ``Authorization``
        header, per RFC 6749 §5.3.1).
    error_code:
        Optional diagnostic sub-code kept as an extra top-level body
        member (e.g. ``missing_dpop_proof``, ``replay_detected``).
    headers:
        Optional response headers (e.g. ``WWW-Authenticate``).
    """

    def __init__(
        self,
        error: str,
        description: Optional[str] = None,
        *,
        status_code: int = 400,
        error_code: Optional[str] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> None:
        body: Dict[str, Any] = {"error": error}
        if description:
            body["error_description"] = description
        if error_code:
            body["error_code"] = error_code
        super().__init__(status_code=status_code, detail=body, headers=headers)
        self.error = error

    @property
    def body(self) -> Dict[str, Any]:
        """The flat RFC 6749 §5.2 response body."""
        body = self.detail
        return body if isinstance(body, dict) else {"error": str(body)}


def register_oauth2_error_handler(app: Any) -> None:
    """Serialise :class:`OAuth2Error` with a top-level §5.2 body.

    Must be called once per application (done in ``backend/main.py``).
    Test apps that mount the OAuth2 routers on a bare ``FastAPI()``
    instance should call it too so asserted shapes match production.
    """

    @app.exception_handler(OAuth2Error)
    async def _oauth2_error_handler(request: Request, exc: OAuth2Error) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.body,
            headers=exc.headers,
        )
