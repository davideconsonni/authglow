"""Test login flow and capture any errors."""

from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()

    # Capture console errors
    console_errors = []
    page.on(
        "console",
        lambda msg: (
            console_errors.append(f"[{msg.type}] {msg.text}")
            if msg.type in ("error", "warning")
            else None
        ),
    )
    page.on(
        "pageerror", lambda err: console_errors.append(f"[PAGE_ERROR] {err.message}")
    )

    print("=== Go to login page ===")
    page.goto("http://localhost:5173/auth/login", timeout=10000)
    page.wait_for_load_state("networkidle")
    page.screenshot(
        path="C:/Users/dcons/Desktop/authglow-playground/authglow/frontend/test-screenshots/01-login-page.png",
        full_page=True,
    )
    print("Screenshot: 01-login-page.png")

    print("=== Fill login form ===")
    page.fill('input[type="email"]', "admin@example.com")
    page.fill("#password", "AdminP@ss123!")
    page.screenshot(
        path="C:/Users/dcons/Desktop/authglow-playground/authglow/frontend/test-screenshots/02-form-filled.png",
        full_page=True,
    )

    print("=== Submit login ===")
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(2000)
    page.screenshot(
        path="C:/Users/dcons/Desktop/authglow-playground/authglow/frontend/test-screenshots/03-after-login.png",
        full_page=True,
    )

    print(f"\n=== Current URL: {page.url} ===")
    print(f"\n=== Page text (first 500 chars): {page.text_content('body')[:500]} ===")

    print(f"\n=== Console Errors ===")
    for err in console_errors:
        print(f"  {err}")

    if not console_errors:
        print("  (none)")

    page.screenshot(
        path="C:/Users/dcons/Desktop/authglow-playground/authglow/frontend/test-screenshots/04-final.png",
        full_page=True,
    )
    browser.close()
