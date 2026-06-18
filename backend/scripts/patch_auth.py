"""Patch script to apply workstreams B/C/F/G/H changes to auth.py."""
import re

path = "authglow/api/auth.py"
with open(path, encoding="utf-8") as f:
    content = f.read()

# --- Patch 1: imports ---
content = content.replace(
    "import hashlib\nfrom typing import Dict, NoReturn, Optional, Tuple",
    "import hashlib\nfrom datetime import timedelta\nfrom typing import Dict, List, NoReturn, Optional, Tuple",
)

# --- Patch 2: form params ---
content = content.replace(
    "    nonce: Optional[str] = Form(None),\n    storage: UserStorage",
    "    nonce: Optional[str] = Form(None),\n    csrf_token: Optional[str] = Form(None),\n    prompt: Optional[str] = Form(None),\n    max_age: Optional[int] = Form(None),\n    storage: UserStorage",
)

# --- Patch 3: PKCE gate + prompt validation + auth vars ---
old_auth_start = '    user = None\n\n    settings = get_settings()'
new_auth_start = '''    # --- OIDC prompt parameter (OIDC Core §3.1.2) ---
    _VALID_PROMPT_VALUES = {"none", "login", "consent", "select_account"}
    parsed_prompts: set[str] = set()

    if prompt:
        parsed_prompts = set(prompt.split())
        invalid = parsed_prompts - _VALID_PROMPT_VALUES
        if invalid:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid prompt value(s): {', '.join(sorted(invalid))}. "
                "Allowed: none, login, consent, select_account.",
            )
        if "none" in parsed_prompts and len(parsed_prompts) > 1:
            raise HTTPException(
                status_code=400,
                detail="'none' cannot be combined with other prompt values.",
            )

    # --- Authentication (cookie-first, then email/password) ---
    user = None
    auth_acr: Optional[str] = None
    auth_amr: Optional[List[str]] = None

    access_token = request.cookies.get(settings.auth_cookie_access_name)'''
content = content.replace(old_auth_start, new_auth_start)

# --- Patch 4: CSRF + max_age in cookie-auth path ---
old_if_user = '    if user:\n        if not user.is_active:'
new_if_user = '''    # --- Prompt parameter handling (OIDC Core §3.1.2) ---
    if "none" in parsed_prompts and not user:
        error_redirect = f"{redirect_uri}?error=login_required"
        error_redirect += "&error_description=User+is+not+authenticated"
        if state:
            error_redirect += f"&state={state}"
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=error_redirect, status_code=302)

    if "none" in parsed_prompts and user:
        if not user.is_active:
            raise HTTPException(status_code=400, detail="Inactive user")
        if user.suspended_until and utcnow() < user.suspended_until:
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Account suspended until {user.suspended_until.isoformat()}",
            )
        auth_code = await oauth2_service.create_authorization_code(
            client_id=client_id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            scope=validated_scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
        )
        redirect_url = f"{redirect_uri}?code={auth_code.code}"
        if state:
            redirect_url += f"&state={state}"
        from fastapi.responses import RedirectResponse
        return RedirectResponse(url=redirect_url, status_code=302)

    # --- max_age enforcement (OIDC Core §3.1.2.1) ---
    if user and max_age is not None:
        if max_age == 0 or (user.last_login is not None and utcnow() > user.last_login + timedelta(seconds=max_age)):
            user = None

    if user:
        from authglow.services.csrf import CSRFTokenService, get_or_create_session_id

        session_id = get_or_create_session_id(request)
        csrf_service = CSRFTokenService()
        if csrf_token is None:
            await AuditService().log_event(
                event_type="csrf_token_mismatch",
                user_id=user.id,
                email=user.email,
                ip_address=request.client.host if request.client else None,
                metadata={"reason": "csrf_token_missing"},
                severity="high",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="CSRF token required when authenticated via session cookie.",
            )

        csrf_valid = await csrf_service.validate_token(session_id, csrf_token)
        if not csrf_valid:
            await AuditService().log_event(
                event_type="csrf_token_mismatch",
                user_id=user.id,
                email=user.email,
                ip_address=request.client.host if request.client else None,
                metadata={"reason": "csrf_token_invalid"},
                severity="high",
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid or expired CSRF token.",
            )

        if not user.is_active:'''
content = content.replace(old_if_user, new_if_user)

# --- Patch 5: acr/amr in password path ---
content = content.replace(
    "        await storage.update_last_login(user.id)\n",
    "        await storage.update_last_login(user.id)\n        auth_acr = \"1\"\n        auth_amr = [\"pwd\"]\n",
)

# --- Patch 6: consent block with prompt=consent and acr/amr ---
old_consent = """    if not client.require_consent:
        auth_code = await oauth2_service.create_authorization_code(
            client_id=client_id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            scope=validated_scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
        )
        redirect_url = f"{redirect_uri}?code={auth_code.code}"
        if state:
            redirect_url += f"&state={state}"
        return {"redirect_url": redirect_url}

    from authglow.services.oauth_consent import OAuth2ConsentService

    consent_svc = OAuth2ConsentService()
    has_consent, _ = await consent_svc.check_consent(
        user_id=user.id,
        client_id=client_id,
        required_scopes=validated_scope.split() if validated_scope else ["read"],
    )

    if has_consent:
        auth_code = await oauth2_service.create_authorization_code(
            client_id=client_id,
            user_id=user.id,
            redirect_uri=redirect_uri,
            scope=validated_scope,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
            nonce=nonce,
        )
        redirect_url = f"{redirect_uri}?code={auth_code.code}"
        if state:
            redirect_url += f"&state={state}"
        return {"redirect_url": redirect_url}

    consent_session = await session_service.create_consent_session("""

new_consent = """    if "consent" not in parsed_prompts:
        if not client.require_consent:
            auth_code = await oauth2_service.create_authorization_code(
                client_id=client_id,
                user_id=user.id,
                redirect_uri=redirect_uri,
                scope=validated_scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                nonce=nonce,
                acr=auth_acr,
                amr=auth_amr,
            )
            redirect_url = f"{redirect_uri}?code={auth_code.code}"
            if state:
                redirect_url += f"&state={state}"
            return {"redirect_url": redirect_url}

        from authglow.services.oauth_consent import OAuth2ConsentService

        consent_svc = OAuth2ConsentService()
        has_consent, _ = await consent_svc.check_consent(
            user_id=user.id,
            client_id=client_id,
            required_scopes=validated_scope.split() if validated_scope else ["read"],
        )

        if has_consent:
            auth_code = await oauth2_service.create_authorization_code(
                client_id=client_id,
                user_id=user.id,
                redirect_uri=redirect_uri,
                scope=validated_scope,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
                nonce=nonce,
                acr=auth_acr,
                amr=auth_amr,
            )
            redirect_url = f"{redirect_uri}?code={auth_code.code}"
            if state:
                redirect_url += f"&state={state}"
            return {"redirect_url": redirect_url}

    # Show consent screen (forced by prompt=consent, or no prior consent)
    consent_session = await session_service.create_consent_session("""

content = content.replace(old_consent, new_consent)

# --- Patch 7: PKCE in token_endpoint ---
content = content.replace(
    """        elif not is_confidential:
            # Public clients without PKCE are insecure; reject the token exchange
            raise HTTPException(
                status_code=400,
                detail="Public clients must use PKCE (code_challenge required)",
            )""",
    """        else:
            raise HTTPException(
                status_code=400,
                detail="PKCE is required for all clients (RFC 7636, Security BCP).",
            )""",
)

# --- Patch 8: acr/amr in create_id_token ---
content = content.replace(
    '                nonce=getattr(auth_code, "nonce", None),  # If nonce was stored\n                auth_time=user.last_login,',
    '                nonce=getattr(auth_code, "nonce", None),\n                auth_time=user.last_login,\n                acr=auth_code.acr,\n                amr=auth_code.amr,',
)

# --- Patch 9: csrf_token endpoint ---
old_csrf_section = """# OAuth2 Authorization Code Flow Endpoints


@router.post("/api/oauth2/authorize")"""

new_csrf_section = """# OAuth2 Authorization Code Flow Endpoints


@router.get("/api/oauth2/csrf-token")
async def csrf_token_endpoint(request: Request):
    \"\"\"Issue a CSRF token bound to a ``csrf_session_id`` cookie.\"\"\"
    from authglow.core.config import get_settings

    from authglow.services.csrf import (
        CSRFTokenService,
        SESSION_ID_COOKIE,
        get_or_create_session_id,
    )

    settings = get_settings()
    session_id = get_or_create_session_id(request)
    csrf_service = CSRFTokenService(settings=settings)
    token = await csrf_service.generate_token(session_id)

    from fastapi.responses import JSONResponse

    response = JSONResponse(content={"csrf_token": token})
    response.set_cookie(
        key=SESSION_ID_COOKIE,
        value=session_id,
        httponly=True,
        samesite="lax",
        secure=settings.is_production,
        max_age=1800,
    )
    return response


@router.post("/api/oauth2/authorize")"""

content = content.replace(old_csrf_section, new_csrf_section)

# --- Patch 10: acr/amr in oauth2_mfa_verify ---
content = content.replace(
    """        code_challenge=mfa_session.code_challenge,
        code_challenge_method=mfa_session.code_challenge_method,
        nonce=mfa_session.nonce,
    )""",
    """        code_challenge=mfa_session.code_challenge,
        code_challenge_method=mfa_session.code_challenge_method,
        nonce=mfa_session.nonce,
        acr="2",
        amr=["pwd", "mfa"],
    )""",
)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print("All patches applied successfully")
