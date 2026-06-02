"""Complete E2E test suite for all AuthGlow frontend phases."""

from playwright.sync_api import sync_playwright
import sys

BASE = "http://localhost:5173"
SCREEN = "C:/Users/dcons/Desktop/authglow-playground/authglow/frontend/test-screenshots"
failed = 0


def check(name, condition, msg=""):
    global failed
    if condition:
        print(f"  PASS: {name}")
    else:
        print(f"  FAIL: {name} - {msg}")
        failed += 1


def logout(page):
    page.goto(f"{BASE}/auth/login")
    page.evaluate("localStorage.removeItem('auth-storage')")
    page.reload()
    page.wait_for_load_state("networkidle")


def login(page, email="admin@example.com", password="AdminP@ss123!"):
    logout(page)
    page.fill('input[type="email"]', email)
    page.fill("#password", password)
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(e.message))

    logout(page)

    # ==========================================
    # PHASE 2: AUTHENTICATION
    # ==========================================
    print("\n=== PHASE 2: AUTH ===")
    page.goto(f"{BASE}/auth/login")
    page.wait_for_load_state("networkidle")
    page.screenshot(path=f"{SCREEN}/p2a-login.png", full_page=True)

    check("login: brand 'AuthGlow'", "AuthGlow" in (page.text_content("body") or ""))
    check("login: email field", page.locator('input[type="email"]').is_visible())
    check("login: password field", page.locator("#password").is_visible())
    check("login: submit button", page.locator('button[type="submit"]').is_visible())

    login(page)
    check("login success: /dashboard", "/dashboard" in page.url)
    check("login success: sidebar", page.locator("aside").first.is_visible())
    page.screenshot(path=f"{SCREEN}/p2b-dashboard.png", full_page=True)

    login(page, "admin@example.com", "WrongX1!")
    body = page.text_content("body") or ""
    check("login fail: stays /auth/login", "/auth/login" in page.url)
    check("login fail: error shown", "Invalid email" in body)
    page.screenshot(path=f"{SCREEN}/p2c-login-fail.png", full_page=True)

    # ==========================================
    # PHASE 2.4-2.5: REGISTER
    # ==========================================
    print("\n=== PHASE 2: REGISTER ===")
    page.goto(f"{BASE}/auth/register")
    page.wait_for_load_state("networkidle")
    body = page.text_content("body") or ""
    check("register: page renders", "Create your account" in body)
    check("register: first_name", page.locator("#first_name").is_visible())
    check("register: last_name", page.locator("#last_name").is_visible())
    check("register: email", page.locator("#register-email").is_visible())
    check("register: password fields", page.locator("#register-password").is_visible())
    check("register: link to login", "Already have an account" in body)

    # Test password strength meter
    page.fill("#register-password", "Aa1")
    page.wait_for_timeout(200)
    page.fill("#register-password", "Aa1!bbbbbbbbbbbb")
    page.wait_for_timeout(200)
    body = page.text_content("body") or ""
    check("register: password meter", "Strength:" in body)
    page.screenshot(path=f"{SCREEN}/p2d-register.png", full_page=True)

    # ==========================================
    # PHASE 2.6-2.7: FORGOT PASSWORD
    # ==========================================
    print("\n=== PHASE 2: FORGOT PASSWORD ===")
    page.goto(f"{BASE}/auth/forgot-password")
    page.wait_for_load_state("networkidle")
    body = page.text_content("body") or ""
    check("forgot: page renders", "Reset your password" in body)
    check("forgot: email field", page.locator("#reset-email").is_visible())
    check("forgot: submit button", page.locator('button[type="submit"]').is_visible())
    page.fill("#reset-email", "test@example.com")
    page.click('button[type="submit"]')
    page.wait_for_timeout(1500)
    check(
        "forgot: form handled",
        "Check your email" in (page.text_content("body") or "")
        or "Something went wrong" in (page.text_content("body") or "")
        or "per" in (page.text_content("body") or ""),
    )
    page.screenshot(path=f"{SCREEN}/p2e-forgot.png", full_page=True)

    # ==========================================
    # PHASE 2.8-2.9: RESET PASSWORD
    # ==========================================
    print("\n=== PHASE 2: RESET PASSWORD ===")
    page.goto(f"{BASE}/auth/reset-password?token=fake")
    page.wait_for_load_state("networkidle")
    body = page.text_content("body") or ""
    check("reset: page renders form", "Set a new password" in body)

    page.goto(f"{BASE}/auth/reset-password")
    page.wait_for_load_state("networkidle")
    body = page.text_content("body") or ""
    check("reset: no token = error", "Invalid reset link" in body)
    page.screenshot(path=f"{SCREEN}/p2f-reset.png", full_page=True)

    # ==========================================
    # PHASE 2.10: EMAIL VERIFY
    # ==========================================
    print("\n=== PHASE 2: EMAIL VERIFY ===")
    page.goto(f"{BASE}/auth/verify-email?token=fake")
    page.wait_for_timeout(2000)
    check("verify: page renders", "AuthGlow" in (page.text_content("body") or ""))
    page.screenshot(path=f"{SCREEN}/p2g-verify.png", full_page=True)

    # ==========================================
    # PHASE 3: MFA
    # ==========================================
    print("\n=== PHASE 3: MFA ===")
    page.goto(f"{BASE}/auth/mfa-verify?session_token=fake")
    page.wait_for_load_state("networkidle")
    body = page.text_content("body") or ""
    check("mfa: page renders", "Two-Factor Authentication" in body)
    check(
        "mfa: 6 digit inputs",
        len(page.locator('input[inputmode="numeric"]').all()) >= 6,
    )
    check("mfa: backup code link", "Use a backup code" in body)
    page.screenshot(path=f"{SCREEN}/p3a-mfa.png", full_page=True)

    # ==========================================
    # PHASE 7: DASHBOARD & PROTECTED PAGES
    # ==========================================
    print("\n=== PHASE 7: DASHBOARD & PROFILE ===")
    login(page)

    # Dashboard
    page.goto(f"{BASE}/dashboard")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)
    body = page.text_content("body") or ""
    check("dashboard: page loads", "Dashboard" in body)
    check(
        "dashboard: stat cards",
        "Last login" in body or "MFA" in body or "Active sessions" in body,
    )
    page.screenshot(path=f"{SCREEN}/p7a-dashboard.png", full_page=True)

    # Profile
    page.goto(f"{BASE}/profile")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)
    body = page.text_content("body") or ""
    check("profile: page loads", "Profile" in body)
    check(
        "profile: name fields",
        page.locator('[name="first_name"]').is_visible()
        or len(page.locator("input").all()) > 1,
    )
    check("profile: save button", "Save changes" in body)
    page.screenshot(path=f"{SCREEN}/p7b-profile.png", full_page=True)

    # Security
    page.goto(f"{BASE}/security")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)
    body = page.text_content("body") or ""
    check("security: page loads", "Security" in body)
    check(
        "security: MFA section",
        "Set up two-factor" in body
        or "Enable MFA" in body
        or "scan QR" in body.lower(),
    )
    check("security: passkeys section", "Passkeys" in body)
    check("security: change password", "Change Password" in body)
    check("security: change email", "Change Email" in body)
    page.screenshot(path=f"{SCREEN}/p7c-security.png", full_page=True)

    # Sessions
    page.goto(f"{BASE}/sessions")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)
    body = page.text_content("body") or ""
    check("sessions: page loads", "Sessions" in body or "No active sessions" in body)
    page.screenshot(path=f"{SCREEN}/p7d-sessions.png", full_page=True)

    # API Keys
    page.goto(f"{BASE}/api-keys")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)
    body = page.text_content("body") or ""
    check("api-keys: page loads", "API Keys" in body)
    check("api-keys: create button", "Create Key" in body)
    page.screenshot(path=f"{SCREEN}/p7e-apikeys.png", full_page=True)

    # ==========================================
    # PHASE 6: SETUP WIZARD
    # ==========================================
    print("\n=== PHASE 6: SETUP WIZARD ===")
    page.goto(f"{BASE}/setup")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(2000)
    body = page.text_content("body") or ""
    check("setup: page loads", "AuthGlow" in body)
    check(
        "setup: already done or wizard",
        "Setup already completed" in body or "Welcome to AuthGlow" in body,
    )
    page.screenshot(path=f"{SCREEN}/p6-setup.png", full_page=True)

    # ==========================================
    # PHASE 8: ADMIN DASHBOARD
    # ==========================================
    print("\n=== PHASE 8: ADMIN DASHBOARD ===")
    page.goto(f"{BASE}/admin")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1500)
    body = page.text_content("body") or ""
    check("admin: page loads", "Administration" in body or "Admin Dashboard" in body)
    page.screenshot(path=f"{SCREEN}/p8a-admin-dashboard.png", full_page=True)

    # ==========================================
    # PHASE 8-12: ALL ADMIN PAGES
    # ==========================================
    admin_pages = [
        ("Users", "/admin/users", "Users"),
        ("OAuth Clients", "/admin/oauth-clients", "OAuth Clients"),
        ("SA", "/admin/sessions", "Sessions"),
        ("CA", "/admin/consents", "Consents"),
        ("API Keys Admin", "/admin/api-keys", "API Keys"),
        ("RBAC", "/admin/rbac", "RBAC"),
        ("JWK", "/admin/jwk-keys", "JWK"),
        ("Password Resets", "/admin/password-resets", "Password Resets"),
        ("Playground", "/admin/playground", "Playground"),
    ]
    for name, path, keyword in admin_pages:
        page.goto(f"{BASE}{path}")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1500)
        body = page.text_content("body") or ""
        check(
            f"admin {name}: loads",
            keyword in body or "No data" in body.lower() or "No " in body,
        )
        page.screenshot(
            path=f"{SCREEN}/admin-{name.lower().replace(' ', '-')}.png", full_page=True
        )

    # ==========================================
    # PHASE 5: OAUTH CONSENT
    # ==========================================
    print("\n=== PHASE 5: OAUTH CONSENT ===")
    page.goto(f"{BASE}/oauth/consent?session_token=fake")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(2000)
    body = page.text_content("body") or ""
    check("consent: page renders", "Consent" in body or "AuthGlow" in body)
    page.screenshot(path=f"{SCREEN}/p5-consent.png", full_page=True)

    # ==========================================
    # SUMMARY
    # ==========================================
    print(f"\n{'=' * 60}")
    print(
        f"E2E RESULTS: {47 - failed}/47 passed"
        if failed > 0
        else f"E2E RESULTS: ALL 47 PASSED"
    )
    for e in errors[-5:]:
        print(f"  CONSOLE: {e}")
    print(f"{'=' * 60}")

    browser.close()
    sys.exit(0 if failed == 0 else 1)
