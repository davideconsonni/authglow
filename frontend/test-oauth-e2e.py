"""E2E: Create OAuth client through actual UI (no relogin)."""

from playwright.sync_api import sync_playwright

BASE = "http://localhost:5173"
failed = 0


def check(n, c, m=""):
    global failed
    if c:
        print(f"  PASS: {n}")
    else:
        print(f"  FAIL: {n} - {m}")
        failed += 1


with sync_playwright() as p:
    ctx = p.chromium.launch_persistent_context(
        user_data_dir="C:/Users/dcons/Desktop/authglow-playground/authglow/frontend/.playwright-data",
        headless=True,
    )
    page = ctx.new_page()

    # Use existing auth from prior runs
    # Directly inject auth token
    import http.client, json

    conn = http.client.HTTPConnection("localhost", 8001, timeout=5)
    conn.request(
        "POST",
        "/api/token",
        "username=admin@example.com&password=AdminP@ss123!",
        {"Content-Type": "application/x-www-form-urlencoded"},
    )
    resp = conn.getresponse()
    token = json.loads(resp.read())["access_token"]

    page.goto(f"{BASE}/auth/login")
    page.evaluate(f"""
        localStorage.setItem('auth-storage', JSON.stringify({{ state: {{ token: "{token}", isAuthenticated: true, user: {{ first_name: "Admin", last_name: "User", email: "admin@example.com", scopes: ["admin"] }} }} }}))
    """)
    page.goto(f"{BASE}/admin/oauth-clients")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)

    body = page.text_content("body") or ""
    check("page loads", len(body) > 50)

    # Click Create Client
    page.click('button:has-text("Create Client")')
    page.wait_for_timeout(300)
    body = page.text_content("body") or ""
    check("modal opens", "New OAuth Client" in body)

    # Select Web Application
    page.click('button:has-text("Web Application")')
    page.wait_for_timeout(300)

    # Fill form
    page.fill('input[placeholder="My Application"]', "E2E Test App")
    page.wait_for_timeout(100)
    page.fill('input[placeholder*="callback"]', "https://e2e-test.example.com/callback")
    page.wait_for_timeout(100)

    # Submit
    page.click('button:text("Create")')
    page.wait_for_timeout(2000)

    body = page.text_content("body") or ""
    check(
        "no pydantic error",
        "Field required" not in body and "List should have at least" not in body,
    )
    check(
        "success",
        "Client Created" in body or "E2E Test App" in body or "secret" in body.lower(),
    )

    if "Field required" in body:
        print(f"\n  ERROR: {body}")

    page.screenshot(
        path="C:/Users/dcons/Desktop/authglow-playground/authglow/frontend/test-screenshots/oauth-e2e-result.png"
    )

    print(f"\n{'=' * 40}")
    print(f"ALL PASSED" if not failed else f"{failed} FAILED")
    ctx.close()
    exit(0 if failed == 0 else 1)
