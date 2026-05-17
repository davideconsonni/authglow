"""AuthGlow Test Playground - Interactive web app for testing all AuthGlow features.

Run with:    python user_test_app.py
Access at:   http://localhost:6060

Make sure AuthGlow is running on port 8001 first:
  python main.py
"""

import os
import sys
from pathlib import Path

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

INDEX_HTML = (BASE_DIR / "user_test_templates" / "index.html").read_text(
    encoding="utf-8"
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
    print("  ========================================")
    print("  AuthGlow Test Playground")
    print("  ========================================")
    print(f"  Playground:  http://localhost:{PLAYGROUND_PORT}")
    print(f"  AuthGlow:    {AUTHGLOW_BASE_URL}")
    print()
    print("  Make sure AuthGlow is running before testing!")
    print("  ========================================\n")
    uvicorn.run(app, host="127.0.0.1", port=PLAYGROUND_PORT)
