Voglio implementare un CIAM. Nome: AuthGlow
Deve supportare lo standard oauth2
Linguaggio: Python
Libreria API: FastAPI
Libreria per database utenti: fsspec
L’applicazione deve essere stateless, pronta per essere pacchettizzata serverless

L’applicazione deve anche avere un frontend (usa i template FastAPI) per far inserire le credenziali e fare un redirect su callback come fanno le app CIAM standard e deve essere compatibile con lo standard oauth2.
Tutti i frontend devono essere personalizzabili a livello di css e alcuni contenuti chiave, via variabili di ambiente.

Altre funzioni da implementare solo dopo aver creato una implementazione di base e averla testata funzionante.

Per ogni funzionalità fammi domande per meglio definirla, prima di implementarla, una volta implementate la dobbiamo testare per assicurarci che funzioni.

## Funzionalità base:
- MFA con TOTP (Google Authenticator, Authy)
- SSO con OpenID Connect
- Passwordless Authentication con Passkeys (WebAuthn)
- Admin portal per vedere statistiche e fare azioni sugli utenti
- Security:
    - Protezione contro brute force
    - Risk-based authentication
    - Anomaly detection
    - CAPTCHA intelligente
- Audit Logging: Log di tutti gli accessi

## User Experience
- Customizable UI/UX
- Branding personalizzato
- Temi e colori configurabili
- Multi-lingua (i18n)
- Responsive design

## Integrazione e API
- Webhook System
    - Eventi su registrazione
    - Eventi su login/logout
    - Modifiche profilo
    - Eventi di sicurezza

## REST API Completa
- User management API
- Token management API
- Admin API
- Analytics API

## Funzionalità Enterprise
- User/Organization Management: Gruppi e ruoli (RBAC)
- Admin Dashboard
    - User search e filtering
    - Bulk user management
    - Configuration UI
    - Reporting e export

## Data Portability
- Export dati utente (GDPR)
- Import/export bulk
- Backup e restore
- Migration tools

## Performance
- Caching (Memcached)
- Token caching
