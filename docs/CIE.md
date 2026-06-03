# Carta d'Identità Elettronica (CIE) Integration

## Overview

The Italian Electronic Identity Card (CIE 3.0) is distributed to over 90% of Italian territory. Every card contains an NFC microchip with an X.509 client certificate that can be used for strong authentication.

AuthGlow supports CIE as a **federated OpenID Connect provider**. AuthGlow never touches the NFC chip — the user's browser is redirected to the official CIE IdP, which handles the card reading. AuthGlow only receives the authentication result via standard OIDC protocol.

- **Official reference**: [CIE on Developers Italia](https://developers.italia.it/en/cie/)
- **OIDC technical specifications**: [spid-cie-oidc-docs](https://github.com/italia/spid-cie-oidc-docs)
- **Chip specifications**: [CIE 3.0 chip specification (PDF)](https://www.cartaidentita.interno.gov.it/downloads/2021/03/cie_3.0_-_specifiche_chip.pdf)

## Architecture — Where the Redirect Happens

This is the most important concept to understand. **All redirects happen in the user's browser**, never server-to-server:

```
                        Browser (User's device)
                         |              ^
          1. Click "CIE" |              | 4. Redirect back with code
                         v              |
                    +----------+    +----------+
                    | AuthGlow |    | CIE IdP  |  ← Publicly accessible
                    | (your    |    | (gov't   |     on the internet
                    |  server) |    |  server) |
                    +----------+    +----------+
                           |              ^
            5. Server-to-server:        |
               exchange code for tokens |
               fetch userinfo           |
                           |            3. Read chip via NFC
                           v              on user's phone/reader
                      CIE IdP token       (handled by IdP,
                      endpoint            NOT by AuthGlow)
```

- **Steps 1-4** happen in the user's browser — HTTP redirects between AuthGlow and the CIE IdP
- **Step 5** is the only server-to-server communication — AuthGlow exchanges the code for tokens
- **The CIE IdP in production is a public internet service** — citizens access it every day from home

## Environments

| Environment | Access | Registration |
|---|---|---|
| **Test/Collaudo** | Private network (federated infrastructure only) | Request credentials from AgID/IPZS |
| **Production** | **Public internet** — accessible by any citizen | Request credentials from AgID/IPZS |

> The production CIE IdP URL is provided by IPZS (Istituto Poligrafico e Zecca dello Stato) during accreditation. It is a publicly accessible HTTPS endpoint that serves millions of Italian citizens.

## Prerequisites

### Registering as a Relying Party

To use CIE, you must register your application with the CIE IdP:

1. Request accreditation as a Service Provider through [AgID](https://www.agid.gov.it/) or [IPZS](https://www.ipzs.it/)
2. Obtain `client_id`, `client_secret`, and the production Issuer URL
3. Register your `redirect_uri`:
   ```
   https://your-domain.com/api/federation/callback?provider_id=YOUR-PROVIDER-ID
   ```
4. Specify the required security levels (L1, L2, L3)

> **Official documentation**: see the [CIE Technical Manual](https://docs.italia.it/italia/cie/cie-manuale-tecnico-docs/) for the complete accreditation procedure.

## Configuration in AuthGlow

### Via Admin UI

1. Go to **Admin** > **Federation** (`/admin/federation`)
2. Click **"Add Provider"**
3. Fill in the fields:

| Field | Value |
|---|---|
| Label | `CIE` |
| Description | `Italian Electronic Identity Card` |
| Issuer URL | *(Production URL provided by IPZS)* |
| Client ID | Your `client_id` from IPZS |
| Client Secret | Your `client_secret` from IPZS |
| Scopes | `openid profile email` |
| Auth Levels | `L1, L2, L3` |

### Via API

```bash
curl -X POST https://your-domain.com/api/federation/providers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "label": "CIE",
    "description": "Italian Electronic Identity Card",
    "issuer": "https://cie-idp.production.gov.it",
    "client_id": "your-client-id-from-ipzs",
    "client_secret": "your-client-secret-from-ipzs",
    "scopes": ["openid", "profile", "email"],
    "auth_levels": ["L1", "L2", "L3"]
  }'
```

### Verify Discovery

Once you have the production issuer URL from IPZS, verify it's reachable:

```bash
curl https://cie-idp.production.gov.it/.well-known/openid-configuration | jq .
```

You should see endpoints like `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`.

> For local development and testing, use **Google OIDC** (see [docs/GOOGLE.md](GOOGLE.md)) — it takes 2 minutes to set up and works from any network.

## Security Levels (acr_values)

CIE defines three security levels. The level is chosen during authentication based on what the user's device supports:

| Level | Name | Mechanism |
|---|---|---|
| L1 | Username/Password | Basic credentials (SPID Level 1) |
| L2 | CIE with optical reading | NFC + MRZ scan or PIN |
| L3 | CIE with certificate | NFC + PIN + client certificate |

AuthGlow passes the requested level via the `acr_values` parameter to the CIE IdP.

Standard `acr_values` according to SPID/CIE specifications:
- `https://www.spid.gov.it/SpidL1` — Level 1
- `https://www.spid.gov.it/SpidL2` — Level 2
- `https://www.spid.gov.it/SpidL3` — Level 3

## Authentication Flow — End to End

```
1. Citizen visits your service → redirected to AuthGlow /oauth2/authorize
   → Login page shows "Entra con CIE" button

2. Citizen clicks "Entra con CIE"
   → AuthGlow sends 302 redirect to user's browser
   → Browser navigates to CIE IdP (public internet URL)
   → CIE IdP asks citizen to tap CIE card on phone NFC

3. Citizen taps card, enters PIN (for L3)
   → All chip interaction handled by CIE IdP, NOT by AuthGlow
   → CIE IdP validates certificate against national CA

4. CIE IdP redirects browser back to AuthGlow:
   GET /api/federation/callback?provider_id=cie&code=AUTH_CODE&state=...

5. AuthGlow (server-to-server) exchanges code for tokens
   → Receives access_token + id_token from CIE IdP
   → Fetches citizen data from userinfo endpoint
   → Maps claims to local user account (creates if first time)

6. Citizen is logged in — AuthGlow issues its own tokens
   → Redirect back to your application with authorization code
```

## Claims Mapping

Claims returned by the CIE IdP are mapped to AuthGlow user fields:

| CIE/SPID Claim | AuthGlow Field |
|---|---|
| `sub` (NIS code) | `external_id` |
| `email` | `email` |
| `name` | `name` |
| `family_name` | (included in `name` if `name` absent) |
| `picture` | `picture` |

### CIE-Specific Claims

Additional fields available (if authorized via scopes):

| Claim | Description |
|---|---|
| `codice_fiscale` | Italian tax identification number |
| `nis` | Service Identification Number |
| `data_nascita` | Date of birth |
| `luogo_nascita` | Place of birth |
| `sesso` | Gender |
| `cittadinanza` | Citizenship |
| `indirizzo_residenza` | Residential address (at time of issuance) |
| `numero_serie_CIE` | Card serial number |
| `data_rilascio_CIE` | Card issuance date |
| `scadenza_CIE` | Card expiration date |

Custom mapping is defined in the `claims_mapping` field of the provider configuration.

## Enabling/Disabling

Toggle a provider from the admin UI:
- **Admin UI**: click the power icon on any provider row
- **API**: `PATCH /api/federation/admin/providers/{id}/toggle`

## Testing Locally

CIE production endpoints are only available after accreditation. For local development:

1. **Use Google OIDC** ([docs/GOOGLE.md](GOOGLE.md)) to test the federation infrastructure — identical flow, 2-minute setup
2. Once accredited with IPZS, replace the Google config with your CIE credentials
3. The federation code is provider-agnostic — if Google works, CIE works

## Direct Login (non-OAuth)

The standard login page (`/auth/login`) also shows federation buttons. Citizens can use CIE to log into AuthGlow directly without going through an OAuth client.

## References

- [CIE on Developers Italia](https://developers.italia.it/en/cie/) — Official documentation, SDKs, examples
- [SPID/CIE OIDC Technical Specifications](https://github.com/italia/spid-cie-oidc-docs) — Protocol and claims mapping
- [CIE Technical Manual](https://docs.italia.it/italia/cie/cie-manuale-tecnico-docs/) — Complete chip and middleware specs
- [CIE Middleware](https://github.com/italia/cie-middleware) — Official middleware for Windows, macOS, Linux
- [CIE Android SDK](https://github.com/italia/cieid-android-sdk) — "Entra con CIE" SDK for Android
- [CIE iOS SDK](https://github.com/italia/cieid-ios-sdk) — "Entra con CIE" SDK for iOS
- [CIE Graphics](https://github.com/italia/cie-graphics) — Official CIE icons, logos and buttons
- [spid-cie-oidc-php Proxy](https://github.com/italia/spid-cie-oidc-php) — Reference OIDC proxy for SPID/CIE