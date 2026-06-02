"""Comprehensive E2E test: login, dashboard, and form validation."""

from playwright.sync_api import sync_playwright
import sys

BASE_URL = "http://localhost:5173"
SCREENSHOTS = (
    "C:/Users/dcons/Desktop/authglow-playground/authglow/frontend/test-screenshots"
)

failed = 0


def check(name, condition, message=""):
    global failed
    if condition:
        print(f"  PASS: {name}")
    else:
        print(f"  FAIL: {name} - {message}")
        failed += 1


def text_has(page, text):
    body = page.text_content("body") or ""
    return text in body


def logout(page):
    """Clear auth state by removing localStorage."""
    page.goto(f"{BASE_URL}/auth/login")
    page.evaluate("localStorage.removeItem('auth-storage')")
    page.reload()
    page.wait_for_load_state("networkidle")


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()

    console_errors = []
    page.on(
        "console",
        lambda msg: (
            console_errors.append(f"[{msg.type}] {msg.text}")
            if msg.type == "error"
            else None
        ),
    )
    page.on("pageerror", lambda err: console_errors.append(f"[PAGE] {err.message}"))

    # Always start fresh
    logout(page)

    # ==========================================
    # TEST 1: Login page renders correctly
    # ==========================================
    print("\n--- TEST 1: Login page ---")
    page.goto(f"{BASE_URL}/auth/login")
    page.wait_for_load_state("networkidle")

    check("has 'Welcome back'", "Welcome back" in page.text_content("body"))
    check("has email field", page.locator('input[type="email"]').is_visible())
    check("has password field", page.locator("#password").is_visible())
    check("has submit button", page.locator('button[type="submit"]').is_visible())
    check("has 'Create one' link", "Create one" in page.text_content("body"))
    check(
        "has 'Forgot your password?' link",
        "Forgot your password" in page.text_content("body"),
    )
    page.screenshot(path=f"{SCREENSHOTS}/test1-login-page.png", full_page=True)

    # ==========================================
    # TEST 2: Login with valid credentials
    # ==========================================
    print("\n--- TEST 2: Login success ---")
    page.fill('input[type="email"]', "admin@example.com")
    page.fill("#password", "AdminP@ss123!")
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)

    body_text = page.text_content("body")
    check("URL is /dashboard", page.url == f"{BASE_URL}/dashboard")
    check("has sidebar", page.locator("aside").first.is_visible())
    check("shows dashboard content", "Dashboard" in body_text)
    check("has 'AuthGlow' brand", "AuthGlow" in body_text)
    check("has admin sections (Users link)", "Users" in body_text)
    check("has user avatar in topbar", "Admin User" in body_text)
    page.screenshot(path=f"{SCREENSHOTS}/test2-dashboard.png", full_page=True)

    # ==========================================
    # TEST 3: Login with invalid credentials
    # ==========================================
    print("\n--- TEST 3: Login failure ---")
    logout(page)

    page.fill('input[type="email"]', "admin@example.com")
    page.fill("#password", "WrongPassword1!")
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)

    body_text = page.text_content("body")
    check("stays on login page", "/auth/login" in page.url)
    check("shows error message", "Invalid email" in body_text)
    page.screenshot(path=f"{SCREENSHOTS}/test3-login-error.png", full_page=True)

    # ==========================================
    # TEST 4: Register page renders
    # ==========================================
    print("\n--- TEST 4: Register page ---")
    logout(page)
    page.goto(f"{BASE_URL}/auth/register")
    page.wait_for_load_state("networkidle")

    body_text = page.text_content("body")
    check("has 'Create your account'", "Create your account" in body_text)
    check("has first_name field", page.locator("#first_name").is_visible())
    check("has last_name field", page.locator("#last_name").is_visible())
    check("has 'Already have an account?'", "Already have an account" in body_text)
    page.screenshot(path=f"{SCREENSHOTS}/test4-register.png", full_page=True)

    # ==========================================
    # TEST 5: Forgot password page
    # ==========================================
    print("\n--- TEST 5: Forgot password page ---")
    logout(page)
    page.goto(f"{BASE_URL}/auth/forgot-password")
    page.wait_for_load_state("networkidle")

    body_text = page.text_content("body")
    check("has 'Reset your password'", "Reset your password" in body_text)
    check("has email field", page.locator("#reset-email").is_visible())
    page.screenshot(path=f"{SCREENSHOTS}/test5-forgot-password.png", full_page=True)

    # ==========================================
    # TEST 6: Console errors check
    # ==========================================
    print("\n--- TEST 6: Console errors ---")
    # Filter expected errors: browser logs 4xx even when handled
    real_errors = [e for e in console_errors if "401" not in e]
    check("no console errors", len(real_errors) == 0, f"Errors: {real_errors}")

    if console_errors:
        for e in console_errors:
            print(f"  CONSOLE: {e}")

    # ==========================================
    # SUMMARY
    # ==========================================
    print(f"\n{'=' * 50}")
    if failed == 0:
        print("ALL TESTS PASSED")
    else:
        print(f"{failed} TEST(S) FAILED")
    print(f"{'=' * 50}")

    browser.close()
    sys.exit(0 if failed == 0 else 1)
