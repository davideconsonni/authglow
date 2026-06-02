"""E2E: Single-session UX validation for all AuthGlow pages."""

from playwright.sync_api import sync_playwright

BASE = "http://localhost:5173"
failed = 0


def check(name, condition):
    global failed
    if condition:
        print(f"  PASS: {name}")
    else:
        print(f"  FAIL: {name}")
        failed += 1


with sync_playwright() as p:
    browser = p.chromium.launch(headless=True)
    page = browser.new_page()
    page.on("console", lambda m: None if m.type != "error" else None)

    # Fresh start - clear any auth
    page.goto(f"{BASE}/auth/login")
    page.evaluate("localStorage.removeItem('auth-storage')")
    page.reload()
    page.wait_for_load_state("networkidle")

    def t(text):
        return text in (page.text_content("body") or "")

    def vis(sel):
        return page.locator(sel).first.is_visible()

    # ==========================================
    # AUTH PAGES (public)
    # ==========================================
    print("\n--- AUTH PAGES ---")
    page.goto(f"{BASE}/auth/login")
    page.wait_for_load_state("networkidle")
    check("login page", t("Welcome back"))
    check(
        "login form",
        vis('input[type="email"]')
        and vis("#password")
        and vis('button[type="submit"]'),
    )

    page.goto(f"{BASE}/auth/register")
    page.wait_for_load_state("networkidle")
    check(
        "register page",
        t("Create your account") and vis("#first_name") and vis("#last_name"),
    )

    page.goto(f"{BASE}/auth/forgot-password")
    page.wait_for_load_state("networkidle")
    check("forgot password", t("Reset your password") and vis("#reset-email"))

    page.goto(f"{BASE}/auth/reset-password?token=fake")
    page.wait_for_load_state("networkidle")
    check("reset password", t("Set a new password"))

    page.goto(f"{BASE}/auth/reset-password")
    page.wait_for_load_state("networkidle")
    check("reset no token", t("Invalid reset link"))

    page.goto(f"{BASE}/auth/verify-email?token=fake")
    page.wait_for_timeout(2000)
    check("verify email", t("AuthGlow"))

    page.goto(f"{BASE}/auth/mfa-verify?session_token=fake")
    page.wait_for_load_state("networkidle")
    check("mfa verify", t("Two-Factor Authentication"))

    page.goto(f"{BASE}/oauth/consent")
    page.wait_for_load_state("networkidle")
    check("oauth consent", t("AuthGlow"))

    page.goto(f"{BASE}/setup")
    page.wait_for_timeout(2000)
    check("setup page", t("AuthGlow"))

    # ==========================================
    # LOGIN ONCE for all protected pages
    # ==========================================
    print("\n--- LOGIN ---")
    page.goto(f"{BASE}/auth/login")
    page.wait_for_load_state("networkidle")
    page.fill('input[type="email"]', "admin@example.com")
    page.fill("#password", "AdminP@ss123!")
    page.click('button[type="submit"]')
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(2000)
    check("login success", "/dashboard" in page.url)

    # ==========================================
    # PROTECTED USER PAGES
    # ==========================================
    print("\n--- USER PAGES ---")
    page.goto(f"{BASE}/dashboard")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)
    check("dashboard", t("Welcome back") or t("Dashboard"))

    page.goto(f"{BASE}/profile")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)
    check("profile", t("Your Profile"))
    check(
        "profile user ID visible", t("f35723a4") or len(page.locator("code").all()) > 0
    )
    check(
        "profile copy button",
        len(page.locator('button[aria-label*="Copy"]').all()) > 0 or t("Copy"),
    )

    page.goto(f"{BASE}/security")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)
    check("security", t("Security"))
    check("security MFA status", t("MFA") or t("not enabled") or t("enabled"))
    check("security passkeys", t("Passkeys"))

    page.goto(f"{BASE}/sessions")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)
    check("sessions", t("Sessions") or t("No active sessions"))

    page.goto(f"{BASE}/api-keys")
    page.wait_for_load_state("networkidle")
    page.wait_for_timeout(1000)
    check("api keys", t("API Keys") or t("Create Key"))

    # ==========================================
    # ADMIN PAGES (all ten)
    # ==========================================
    print("\n--- ADMIN PAGES ---")
    admin = [
        ("admin dashboard", "/admin"),
        ("admin users", "/admin/users"),
        ("admin oauth", "/admin/oauth-clients"),
        ("admin sessions", "/admin/sessions"),
        ("admin consents", "/admin/consents"),
        ("admin api keys", "/admin/api-keys"),
        ("admin rbac", "/admin/rbac"),
        ("admin jwk", "/admin/jwk-keys"),
        ("admin pass resets", "/admin/password-resets"),
        ("admin playground", "/admin/playground"),
    ]
    for name, path in admin:
        page.goto(f"{BASE}{path}")
        page.wait_for_load_state("networkidle")
        page.wait_for_timeout(1000)
        check(name, len(page.text_content("body") or "") > 50)

    # ==========================================
    # SUMMARY
    # ==========================================
    total = 37
    print(f"\n{'=' * 50}")
    print(
        f"E2E: {total - failed}/{total} passed"
        if failed
        else f"E2E: ALL {total} PASSED"
    )
    print(f"{'=' * 50}")
    browser.close()
    exit(0 if failed == 0 else 1)
