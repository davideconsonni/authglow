"""AuthGlow Test Playground - Interactive web app for testing all AuthGlow features.

Run with:    python user_test_app.py
Access at:   http://localhost:6060

Make sure AuthGlow is running on port 8001 first:
  python main.py
"""

import os
import sys
from pathlib import Path
from urllib.parse import urlparse, parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

try:
    import httpx
except ImportError:
    print("httpx is required. Install with: pip install httpx")
    sys.exit(1)

AUTHGLOW_BASE_URL = os.environ.get("AUTHGLOW_URL", "http://localhost:8001")
PLAYGROUND_PORT = int(os.environ.get("PLAYGROUND_PORT", "6060"))

app = FastAPI(title="AuthGlow Test Playground", version="0.1.0")

BASE_DIR = Path(__file__).parent
app.mount(
    "/test-static",
    StaticFiles(directory=str(BASE_DIR / "user_test_static")),
    name="test-static",
)

INDEX_HTML = (BASE_DIR / "user_test_templates" / "index.html").read_text(encoding="utf-8")


def _extract_code_from_redirect_url(redirect_url: str) -> dict:
    parsed = urlparse(redirect_url)
    params = parse_qs(parsed.query)
    code = params.get("code", [None])
    state = params.get("state", [None])
    error = params.get("error", [None])
    result = {}
    if code and code[0]:
        result["authorization_code"] = code[0]
    if state and state[0]:
        result["state"] = state[0]
    if error and error[0]:
        result["error"] = error[0]
        error_desc = params.get("error_description", [None])
        if error_desc and error_desc[0]:
            result["error_description"] = error_desc[0]
    return result


@app.post("/auto-oauth2-authorize")
async def auto_oauth2_authorize(request: Request):
    """Orchestrate the full OAuth2 authorize + consent flow server-side.

    Accepts JSON body: { email, password, client_id, redirect_uri, scope, state?,
                         code_challenge?, code_challenge_method? }
    Returns JSON: { authorization_code, state? } or { error, ... }
    """
    body = await request.json()
    email = body.get("email")
    password = body.get("password")
    client_id = body.get("client_id", "default-client-id")
    redirect_uri = body.get("redirect_uri", "http://localhost:5000/callback")
    scope = body.get("scope", "openid profile email read")
    state = body.get("state", "")
    code_challenge = body.get("code_challenge")
    code_challenge_method = body.get("code_challenge_method")

    if not email or not password:
        return JSONResponse(status_code=400, content={"error": "email and password are required"})

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=False) as client:
        # Step 0: GET /oauth2/authorize to obtain csrf_token + session cookie
        get_params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
        }
        if state:
            get_params["state"] = state
        if code_challenge:
            get_params["code_challenge"] = code_challenge
        if code_challenge_method:
            get_params["code_challenge_method"] = code_challenge_method

        get_resp = await client.get(
            f"{AUTHGLOW_BASE_URL}/oauth2/authorize",
            params=get_params,
        )

        if get_resp.status_code != 200:
            try:
                error_data = get_resp.json()
            except Exception:
                error_data = {"error": get_resp.text[:500]}
            return JSONResponse(status_code=get_resp.status_code, content=error_data)

        # Extract csrf_token from the login form HTML
        import re
        from html import unescape

        csrf_match = re.search(r'<input[^>]*name="csrf_token"[^>]*value="([^"]*)"', get_resp.text)
        csrf_token = unescape(csrf_match.group(1)) if csrf_match else None

        # Step 1: POST /oauth2/authorize with credentials + csrf_token
        form_data = {
            "email": email,
            "password": password,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "csrf_token": csrf_token or "",
        }
        if state:
            form_data["state"] = state
        if code_challenge:
            form_data["code_challenge"] = code_challenge
        if code_challenge_method:
            form_data["code_challenge_method"] = code_challenge_method

        try:
            auth_resp = await client.post(
                f"{AUTHGLOW_BASE_URL}/oauth2/authorize",
                data=form_data,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            return JSONResponse(status_code=502, content={"error": f"Cannot reach AuthGlow: {exc}"})

        # Handle auth errors (401, 400, etc.)
        if auth_resp.status_code not in (200, 303):
            try:
                error_data = auth_resp.json()
            except Exception:
                error_data = {"error": auth_resp.text[:500]}
            return JSONResponse(status_code=auth_resp.status_code, content=error_data)

        # Step 2: Extract session_token from the redirect
        if auth_resp.status_code == 303:
            location = auth_resp.headers.get("location", "")
        elif auth_resp.status_code == 200:
            # MFA required — auth_resp is an HTML page, not a redirect
            content_type = auth_resp.headers.get("content-type", "")
            if "html" in content_type or "mfa" in auth_resp.text.lower():
                return JSONResponse(
                    status_code=200,
                    content={"error": "MFA required", "mfa_required": True},
                )
            # If it's JSON, return as-is
            try:
                return JSONResponse(status_code=200, content=auth_resp.json())
            except Exception:
                return JSONResponse(
                    status_code=200,
                    content={
                        "content_type": content_type,
                        "body": auth_resp.text[:2000],
                    },
                )
        else:
            return JSONResponse(status_code=500, content={"error": "Unexpected auth response"})

        # Parse session_token from the redirect URL
        parsed = urlparse(location)
        qs_params = parse_qs(parsed.query)
        session_token = qs_params.get("session_token", [None])

        if not session_token or not session_token[0]:
            # Might be a direct redirect to redirect_uri with code (auto-consent)
            if parsed.netloc or "code=" in location:
                result = _extract_code_from_redirect_url(location)
                if "authorization_code" in result:
                    return JSONResponse(status_code=200, content=result)
            return JSONResponse(
                status_code=400,
                content={
                    "error": "No session_token in redirect",
                    "redirect_url": location,
                },
            )

        session_token = session_token[0]

        # Step 3: GET /oauth2/consent?session_token=... (check if already consented)
        try:
            consent_resp = await client.get(
                f"{AUTHGLOW_BASE_URL}/oauth2/consent",
                params={"session_token": session_token},
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            return JSONResponse(status_code=502, content={"error": f"Cannot reach AuthGlow: {exc}"})

        # If consent endpoint redirects (user already consented), extract the code
        if consent_resp.status_code in (301, 302, 303, 307, 308):
            consent_location = consent_resp.headers.get("location", "")
            result = _extract_code_from_redirect_url(consent_location)
            if "authorization_code" in result:
                return JSONResponse(status_code=200, content=result)

        # Extract csrf_token from consent form if HTML was returned
        consent_csrf = ""
        if consent_resp.status_code == 200 and "text/html" in consent_resp.headers.get(
            "content-type", ""
        ):
            consent_csrf_match = re.search(
                r'<input[^>]*name="csrf_token"[^>]*value="([^"]*)"', consent_resp.text
            )
            if consent_csrf_match:
                consent_csrf = unescape(consent_csrf_match.group(1))

        # Step 4: POST /oauth2/consent to approve (auto-approve)
        consent_form = {
            "session_token": session_token,
            "approved": "true",
            "remember": "true",
            "csrf_token": consent_csrf,
        }

        try:
            approve_resp = await client.post(
                f"{AUTHGLOW_BASE_URL}/oauth2/consent",
                data=consent_form,
            )
        except (httpx.ConnectError, httpx.TimeoutException) as exc:
            return JSONResponse(status_code=502, content={"error": f"Cannot reach AuthGlow: {exc}"})

        # Handle errors
        if approve_resp.status_code not in (200, 303):
            try:
                error_data = approve_resp.json()
            except Exception:
                error_data = {"error": approve_resp.text[:500]}
            return JSONResponse(status_code=approve_resp.status_code, content=error_data)

        # Extract the final redirect URL with the authorization code
        if approve_resp.status_code == 303:
            final_location = approve_resp.headers.get("location", "")
            result = _extract_code_from_redirect_url(final_location)
            if "authorization_code" in result:
                return JSONResponse(status_code=200, content=result)
            return JSONResponse(
                status_code=400,
                content={
                    "error": "No authorization_code in final redirect",
                    "redirect_url": final_location,
                },
            )

        # 200 response might be an HTML page or JSON
        content_type = approve_resp.headers.get("content-type", "")
        if "json" in content_type:
            try:
                return JSONResponse(
                    status_code=approve_resp.status_code, content=approve_resp.json()
                )
            except Exception:
                pass

        return JSONResponse(
            status_code=approve_resp.status_code,
            content={"content_type": content_type, "body": approve_resp.text[:2000]},
        )


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(content=INDEX_HTML)


@app.api_route("/proxy/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
async def proxy(path: str, request: Request):
    """Proxy requests to AuthGlow backend, forwarding all headers including Authorization."""
    target_url = f"{AUTHGLOW_BASE_URL}/{path}"

    headers = {}
    for key, value in request.headers.items():
        if key.lower() not in ("host", "content-length", "transfer-encoding"):
            headers[key] = value

    body = await request.body()
    query_params = dict(request.query_params)

    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body if body else None,
                params=query_params if query_params else None,
            )
        except httpx.ConnectError:
            return JSONResponse(
                status_code=502,
                content={
                    "error": "Cannot connect to AuthGlow server",
                    "detail": f"Tried to reach {AUTHGLOW_BASE_URL}/{path}. Make sure AuthGlow is running.",
                },
            )
        except httpx.TimeoutException:
            return JSONResponse(
                status_code=504,
                content={"error": "AuthGlow server timed out"},
            )

    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return JSONResponse(
                status_code=response.status_code,
                content=response.json(),
            )
        except Exception:
            return JSONResponse(
                status_code=response.status_code,
                content={"raw_response": response.text},
            )
    else:
        return JSONResponse(
            status_code=response.status_code,
            content={
                "content_type": content_type,
                "status": response.status_code,
                "body": response.text[:5000],
            },
        )


@app.get("/health")
async def health():
    """Check if AuthGlow backend is reachable."""
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{AUTHGLOW_BASE_URL}/health")
            return {
                "playground": "ok",
                "authglow": "reachable"
                if response.status_code == 200
                else f"status_{response.status_code}",
                "authglow_url": AUTHGLOW_BASE_URL,
            }
    except httpx.ConnectError:
        return JSONResponse(
            status_code=502,
            content={
                "playground": "ok",
                "authglow": "unreachable",
                "authglow_url": AUTHGLOW_BASE_URL,
            },
        )


if __name__ == "__main__":
    import uvicorn

    print()
    print("  \033[35mAuthGlow\033[0m Test Playground")
    print("  ========================================")
    print(f"  Playground:  http://localhost:{PLAYGROUND_PORT}")
    print(f"  AuthGlow:    {AUTHGLOW_BASE_URL}")
    print()
    print("  Make sure AuthGlow is running before testing!")
    print("  ========================================\n")
    uvicorn.run(app, host="127.0.0.1", port=PLAYGROUND_PORT)
