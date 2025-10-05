import json
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, Request
from requests_oauthlib import OAuth2Session
from starlette.responses import RedirectResponse, HTMLResponse
from oauthlib.oauth2.rfc6749.errors import OAuth2Error

# --- CONFIGURATION ---
# Inserisci qui i dati forniti dal tuo provider OAuth2 (es. AuthGlow, Google, GitHub)

# 1. Credenziali del Client
CLIENT_ID = "34a3cc58-54cc-438a-a3f2-4096619a440f"
CLIENT_SECRET = "1V1L9JjKVgiv_rjE0kuGtbr2VlDab1M6mvRqUyOesT8"

# 2. URI di redirect (deve corrispondere esattamente a quello registrato sul provider)
REDIRECT_URI = "http://localhost:5000/callback"

# 3. Endpoint del provider OAuth2
AUTHORIZATION_URL = "http://localhost:8000/oauth2/authorize"
TOKEN_URL = "http://localhost:8000/oauth2/token"
USER_INFO_URL = "http://localhost:8000/oauth2/userinfo" # Usiamo l'endpoint OIDC standard

# 4. Scopes (permessi) che la tua applicazione richiede
SCOPE = ["openid", "profile", "email", "read", "write"] # Usiamo scopes OIDC standard

# --- APPLICAZIONE FASTAPI ---

app = FastAPI()

# Simple in-memory storage usando lo STATE come chiave
STATE_STORAGE = {}


def cleanup_old_states():
    """Rimuove state scaduti."""
    now = datetime.now(timezone.utc)
    expired = [k for k, v in STATE_STORAGE.items() if v.get('expires', now) < now]
    for k in expired:
        del STATE_STORAGE[k]


def save_state(state: str, data: dict):
    """Salva dati associati a uno state OAuth2."""
    cleanup_old_states()
    STATE_STORAGE[state] = {
        'data': data,
        'expires': datetime.now(timezone.utc) + timedelta(minutes=30)
    }


def get_state_data(state: str) -> Optional[dict]:
    """Recupera dati associati a uno state OAuth2."""
    if state and state in STATE_STORAGE:
        entry = STATE_STORAGE[state]
        if entry['expires'] > datetime.now(timezone.utc):
            return entry['data']
        else:
            del STATE_STORAGE[state]
    return None


def delete_state(state: str):
    """Rimuove uno state dopo l'uso."""
    if state in STATE_STORAGE:
        del STATE_STORAGE[state]


# --- Template HTML ---
HTML_HOME = """
<!DOCTYPE html>
<html><head><title>Client OAuth2 (FastAPI)</title></head>
<body><h1>Benvenuto!</h1><p>Client di esempio per OAuth2 con PKCE.</p><a href="{login_url}">Accedi con AuthGlow</a></body></html>
"""

HTML_PROFILE = """
<!DOCTYPE html>
<html><head><title>Profilo Utente</title></head>
<body><h1>Profilo Utente</h1><p>Dati ricevuti dal server:</p><pre>{user_data}</pre><br><a href="{logout_url}">Logout</a></body></html>
"""


@app.get("/")
async def index(request: Request):
    login_url = request.url_for('login')
    return HTMLResponse(HTML_HOME.format(login_url=login_url))


@app.get("/login")
async def login(request: Request):
    """
    Step 1: Redirige l'utente al provider, generando i parametri PKCE.
    """
    oauth = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=SCOPE)

    # --- NUOVA LOGICA PKCE ---
    # 1. Genera un code_verifier casuale
    code_verifier = secrets.token_urlsafe(64)

    # 2. Crea il code_challenge (hash SHA256 del verifier)
    import hashlib
    import base64
    digest = hashlib.sha256(code_verifier.encode('utf-8')).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode('utf-8')

    authorization_url, state = oauth.authorization_url(
        AUTHORIZATION_URL,
        code_challenge=code_challenge,
        code_challenge_method="S256"
    )

    # Salva sia lo state che il code_verifier per usarli nel callback
    save_state(state, {"code_verifier": code_verifier})

    return RedirectResponse(authorization_url)


@app.get("/callback")
async def callback(request: Request):
    """
    Step 2: Scambia il codice di autorizzazione per un access token, inviando il code_verifier.
    """
    received_state = request.query_params.get('state')
    state_data = get_state_data(received_state)

    if state_data is None:
        return HTMLResponse("Errore: state non valido o scaduto!", status_code=400)

    # --- NUOVA LOGICA PKCE ---
    # Recupera il code_verifier che avevamo salvato
    code_verifier = state_data.get("code_verifier")
    if not code_verifier:
        return HTMLResponse("Errore: code_verifier non trovato nella sessione!", status_code=500)

    delete_state(received_state)

    oauth = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, state=received_state)

    try:
        token = oauth.fetch_token(
            TOKEN_URL,
            client_secret=CLIENT_SECRET,
            authorization_response=str(request.url),
            # Invia il verifier per la validazione PKCE sul server
            code_verifier=code_verifier
        )
    except OAuth2Error as e:
        return HTMLResponse(f"<h1>Errore durante il fetch del token</h1><p>{e.description}</p>", status_code=400)


    user_session_token = secrets.token_urlsafe(32)
    save_state(user_session_token, {'oauth_token': token})

    redirect = RedirectResponse(url=request.url_for('profile'))
    redirect.set_cookie(key='user_session', value=user_session_token, httponly=True)
    return redirect


@app.get("/profile")
async def profile(request: Request):
    """
    Step 3: Usa l'access token per richiedere i dati dell'utente.
    """
    user_session_token = request.cookies.get('user_session')
    if not user_session_token:
        return RedirectResponse(url=request.url_for('index'))

    session_data = get_state_data(user_session_token)
    if not session_data or 'oauth_token' not in session_data:
        return RedirectResponse(url=request.url_for('index'))

    oauth = OAuth2Session(CLIENT_ID, token=session_data['oauth_token'])

    try:
        user_info = oauth.get(USER_INFO_URL).json()
        user_data_formatted = json.dumps(user_info, indent=4)
        logout_url = request.url_for('logout')
        return HTMLResponse(HTML_PROFILE.format(user_data=user_data_formatted, logout_url=logout_url))
    except Exception as e:
        return HTMLResponse(f"Errore durante il recupero delle informazioni utente: {e}", status_code=500)


@app.get("/logout")
async def logout(request: Request):
    user_session_token = request.cookies.get('user_session')
    if user_session_token:
        delete_state(user_session_token)

    redirect = RedirectResponse(url=request.url_for('index'))
    redirect.delete_cookie('user_session')
    return redirect


if __name__ == "__main__":
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5000)
