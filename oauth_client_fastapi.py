import json
import os
import secrets
from datetime import datetime, timedelta
from typing import Optional

from fastapi import FastAPI, Request
from requests_oauthlib import OAuth2Session
from starlette.responses import RedirectResponse, HTMLResponse

# --- CONFIGURAZIONE ---
# Inserisci qui i dati forniti dal tuo provider OAuth2 (es. AuthGlow, Google, GitHub)

# 1. Credenziali del Client
CLIENT_ID = "34a3cc58-54cc-438a-a3f2-4096619a440f"
CLIENT_SECRET = "1V1L9JjKVgiv_rjE0kuGtbr2VlDab1M6mvRqUyOesT8"

# 2. URI di redirect (deve corrispondere esattamente a quello registrato sul provider)
REDIRECT_URI = "http://localhost:5000/callback"

# 3. Endpoint del provider OAuth2
# (Questi sono esempi per un server AuthGlow in esecuzione locale)
AUTHORIZATION_URL = "http://localhost:8000/oauth2/authorize"
TOKEN_URL = "http://localhost:8000/oauth2/token"
USER_INFO_URL = "http://localhost:8000/api/profile/me"

# 4. Scopes (permessi) che la tua applicazione richiede
SCOPE = ["read", "write", "TEST"]

# --- APPLICAZIONE FASTAPI ---

app = FastAPI()

# Simple in-memory storage usando lo STATE come chiave (evita problemi con i cookie)
# Questo è il modo più affidabile per OAuth2
STATE_STORAGE = {}


def cleanup_old_states():
    """Rimuove state scaduti."""
    now = datetime.utcnow()
    expired = [k for k, v in STATE_STORAGE.items() if v.get('expires', now) < now]
    for k in expired:
        del STATE_STORAGE[k]


def save_state(state: str, data: dict):
    """Salva dati associati a uno state OAuth2."""
    cleanup_old_states()
    STATE_STORAGE[state] = {
        'data': data,
        'expires': datetime.utcnow() + timedelta(minutes=30)
    }
    print(f"DEBUG - Saved state: {state}")
    print(f"DEBUG - State storage now has: {list(STATE_STORAGE.keys())}")


def get_state_data(state: str) -> Optional[dict]:
    """Recupera dati associati a uno state OAuth2."""
    if state and state in STATE_STORAGE:
        entry = STATE_STORAGE[state]
        if entry['expires'] > datetime.utcnow():
            return entry['data']
        else:
            # Rimuovi state scaduto
            del STATE_STORAGE[state]
    return None


def delete_state(state: str):
    """Rimuove uno state dopo l'uso."""
    if state in STATE_STORAGE:
        del STATE_STORAGE[state]


# --- Template HTML per semplicità ---
HTML_HOME = """
<!DOCTYPE html>
<html>
<head>
    <title>Client OAuth2 (FastAPI)</title>
    <style>
        body {{ font-family: sans-serif; text-align: center; padding-top: 50px; }}
        a {{ text-decoration: none; background-color: #007bff; color: white; padding: 10px 20px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>Benvenuto!</h1>
    <p>Questo è un client di esempio per il flusso di autorizzazione OAuth2 con FastAPI.</p>
    <a href="{login_url}">Accedi con il tuo Provider</a>
</body>
</html>
"""

HTML_PROFILE = """
<!DOCTYPE html>
<html>
<head>
    <title>Profilo Utente</title>
    <style>
        body {{ font-family: sans-serif; padding: 20px; }}
        pre {{ background-color: #f4f4f4; padding: 15px; border-radius: 5px; white-space: pre-wrap; }}
        a {{ color: #007bff; }}
    </style>
</head>
<body>
    <h1>Profilo Utente</h1>
    <p>Dati ricevuti dal server dopo l'autenticazione:</p>
    <pre>{user_data}</pre>
    <br>
    <a href="{logout_url}">Logout</a>
</body>
</html>
"""


@app.get("/")
async def index(request: Request):
    """Pagina iniziale con il link per il login."""
    login_url = request.url_for('login')
    return HTMLResponse(HTML_HOME.format(login_url=login_url))


@app.get("/login")
async def login(request: Request):
    """
    Step 1: Redirige l'utente al provider OAuth2 per l'autorizzazione.
    """
    oauth = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=SCOPE)
    authorization_url, state = oauth.authorization_url(AUTHORIZATION_URL)

    # Salva lo state in memoria (senza dipendere dai cookie!)
    save_state(state, {})

    print(f"DEBUG /login - Generated state: {state}")
    print(f"DEBUG /login - Redirecting to: {authorization_url}")

    return RedirectResponse(authorization_url, status_code=302)


@app.get("/callback")
async def callback(request: Request):
    """
    Step 2: L'utente viene reindirizzato qui dal provider dopo il login.
    Qui scambiamo il codice di autorizzazione per un access token.
    """
    # Check if user denied authorization
    error = request.query_params.get('error')
    if error:
        error_description = request.query_params.get('error_description', 'User denied authorization')
        return HTMLResponse(
            f"<h1>Authorization Denied</h1>"
            f"<p>You have denied the authorization request.</p>"
            f"<p>Error: {error}</p>"
            f"<p>Description: {error_description}</p>"
            f"<br><a href='/'>Go back to home</a>",
            status_code=200
        )

    received_state = request.query_params.get('state')

    print(f"DEBUG /callback - Received state: {received_state}")
    print(f"DEBUG /callback - States in storage: {list(STATE_STORAGE.keys())}")

    # Verifica che lo state esista (= è stato generato da noi)
    state_data = get_state_data(received_state)

    if state_data is None:
        return HTMLResponse(
            f"Errore: state non valido o scaduto!<br>Received: {received_state}<br>"
            f"Available states: {list(STATE_STORAGE.keys())}",
            status_code=400
        )

    print(f"DEBUG /callback - State validated successfully!")

    # Rimuovi lo state dopo l'uso (protezione contro replay)
    delete_state(received_state)

    oauth = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, state=received_state)

    # Otteniamo l'access token usando il codice di autorizzazione fornito nell'URL
    # Usiamo str(request.url) perché requests_oauthlib si aspetta l'URL completo
    token = oauth.fetch_token(
        TOKEN_URL,
        client_secret=CLIENT_SECRET,
        authorization_response=str(request.url)
    )

    # Salviamo il token usando lo state come chiave temporanea
    # Generiamo un nuovo token per la sessione utente
    user_session_token = secrets.token_urlsafe(32)
    save_state(user_session_token, {'oauth_token': token})

    # Redirect al profile con il token nella query (poi lo spostiamo in cookie)
    redirect = RedirectResponse(url=request.url_for('profile'))
    redirect.set_cookie(
        key='user_session',
        value=user_session_token,
        max_age=1800,
        httponly=True,
        samesite='lax',
        path='/'
    )
    return redirect


@app.get("/profile")
async def profile(request: Request):
    """
    Step 3: Usiamo l'access token per richiedere i dati dell'utente a un'API protetta.
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
        # Formattiamo il JSON per una visualizzazione più pulita
        user_data_formatted = json.dumps(user_info, indent=4)
        logout_url = request.url_for('logout')
        return HTMLResponse(HTML_PROFILE.format(user_data=user_data_formatted, logout_url=logout_url))
    except Exception as e:
        return HTMLResponse(f"Errore durante il recupero delle informazioni utente: {e}", status_code=500)


@app.get("/logout")
async def logout(request: Request):
    """Effettua il logout pulendo la sessione."""
    user_session_token = request.cookies.get('user_session')
    if user_session_token:
        delete_state(user_session_token)

    redirect = RedirectResponse(url=request.url_for('index'))
    redirect.delete_cookie('user_session')
    return redirect


if __name__ == "__main__":
    # IMPORTANTE: Questa riga è necessaria per testare in locale (HTTP).
    # In produzione, il tuo client DEVE usare HTTPS.
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

    import uvicorn

    # Eseguiamo il server con Uvicorn
    uvicorn.run(app, host="127.0.0.1", port=5000)
