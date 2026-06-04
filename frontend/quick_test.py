"""Full flow: setup + login + CORS check."""

from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()

    network_errors = []

    def on_failed(req):
        network_errors.append(f"{req.failure} | {req.method} {req.url}")

    def on_response(resp):
        if resp.status >= 400:
            network_errors.append(f"{resp.status} {resp.request.method} {resp.url}")

    page.on("requestfailed", on_failed)
    page.on("response", on_response)

    # Step 1: Check setup
    page.goto("http://localhost:5173/setup")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)

    content = page.content()
    if "setup-email" in content:
        print("[SETUP] Creating admin...")
        page.fill("#setup-email", "admin@example.com")
        page.fill("#setup-password", "AdminP@ss123!")
        page.click("button:has-text('Create admin account')")
        page.wait_for_timeout(3000)
        print(f"[SETUP] Result URL: {page.url}")
    elif "Setup already completed" in content:
        print("[SETUP] Already done")

    # Step 2: Login
    print("\n[LOGIN] Navigating to login...")
    page.goto("http://localhost:5173/auth/login")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)

    page.fill('[data-testid="login-email"]', "admin@example.com")
    page.fill('[data-testid="login-password"]', "AdminP@ss123!")
    page.click('[data-testid="login-submit"]')
    page.wait_for_timeout(5000)

    print(f"[LOGIN] Final URL: {page.url}")

    # Step 3: Navigation test
    for route in ["/security", "/profile", "/sessions"]:
        page.goto(f"http://localhost:5173{route}")
        page.wait_for_timeout(2000)
        print(f"[NAV] {route} → {page.url}")

    print(f"\n[NERWORK ERRORS] ({len(network_errors)}):")
    for e in network_errors:
        print(f"  {e}")

    browser.close()
