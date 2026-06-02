"""Debug: test OAuth client creation."""

from playwright.sync_api import sync_playwright

BASE = "http://localhost:5173"

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.on("pageerror", lambda e: print(f"[JS ERROR] {e.message}"))

    # Login
    page.goto(f"{BASE}/auth/login")
    page.wait_for_load_state("networkidle")
    page.fill('input[type="email"]', "admin@example.com")
    page.fill("#password", "AdminP@ss123!")
    page.click('button[type="submit"]')
    page.wait_for_timeout(2000)
    print(f"URL: {page.url}")

    # Go to oauth clients
    page.goto(f"{BASE}/admin/oauth-clients")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)

    # Click Create Client
    page.click('button:has-text("Create Client")')
    page.wait_for_timeout(500)
    body = page.text_content("body") or ""
    print("Modal visible:", "New OAuth Client" in body)

    # Click Web Application type
    page.click('button:has-text("Web Application")')
    page.wait_for_timeout(300)
    body = page.text_content("body") or ""
    print("Web type selected:", "Web Application" in body)

    # Fill name
    name_input = page.locator('input[placeholder="My Application"]')
    name_input.fill("Test Debug App")

    # Fill redirect URI
    uri_input = page.locator('input[placeholder*="callback"]').first
    uri_input.fill("https://example.com/callback")

    # Debug: show all form data
    print("\nForm state before submit:")
    page.screenshot(
        path="C:/Users/dcons/Desktop/authglow-playground/authglow/frontend/test-screenshots/oauth-form.png"
    )

    # Intercept the network request
    def handle_request(request):
        if "/api/oauth-clients" in request.url and request.method == "POST":
            print(f"\nREQUEST URL: {request.url}")
            print(f"REQUEST BODY: {request.post_data}")

    page.on("request", handle_request)

    # Click Create
    page.click('button:has-text("Create")')
    page.wait_for_timeout(2000)

    # Check for errors
    body = page.text_content("body") or ""
    if "Field required" in body:
        idx = body.index("Field required")
        print(f"\nERROR TEXT (200 chars): {body[max(0, idx - 30) : idx + 200]}")
    elif "Unprocessable" in body or "List should have" in body:
        idx = body.index("List should have") if "List should have" in body else 0
        print(f"\nERROR TEXT (200 chars): {body[max(0, idx - 30) : idx + 200]}")
    else:
        print("\nNo error visible on page")
        print(f"Body (first 300): {body[:300]}")

    page.screenshot(
        path="C:/Users/dcons/Desktop/authglow-playground/authglow/frontend/test-screenshots/oauth-error.png"
    )
    browser.close()
