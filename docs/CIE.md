# Carta d'Identità Elettronica (CIE) Integration

## Overview

The Italian Electronic Identity Card (CIE 3.0) is distributed to over 90% of Italian territory. Every card contains an NFC microchip with an X.509 client certificate that can be used for strong authentication.

AuthGlow supports CIE as a **federated OpenID Connect provider** — there is no need to implement direct chip reading. The official CIE IdP (`idserver.servizicie.interno.gov.it`) handles chip interaction, and AuthGlow receives user data via standard OIDC protocol.

- **Official reference**: [CIE on Developers Italia](https://developers.italia.it/en/cie/)
- **OIDC technical specifications**: [spid-cie-oidc-docs](https://github.com/italia/spid-cie-oidc-docs)
- **Chip specifications**: [CIE 3.0 chip specification (PDF)](https://www.cartaidentita.interno.gov.it/downloads/2021/03/cie_3.0_-_specifiche_chip.pdf)

## How It Works

CIE uses the standard OIDC Authorization Code flow. AuthGlow never touches the NFC chip — it delegates the entire authentication to the CIE IdP, which handles:

1. NFC reading of the card
2. MRZ scanning or PIN entry (depending on security level)
3. Certificate validation against the national CA
4. Returning user claims via standard OIDC token/userinfo endpoints

```
User                 AuthGlow              CIE IdP               CIE Card
 |                       |                     |                     |
 |  1. Click "CIE"       |                     |                     |
 |---------------------->|                     |                     |
 |                       |  2. Redirect to     |                     |
 |                       |     /authorize       |                     |
 |                       |-------------------->|                     |
 |                       |                     |  3. Read chip (NFC) |
 |                       |                     |<===================>|
 |                       |                     |                     |
 |  4. Enter PIN (L3)    |                     |                     |
 |<----------------------|                     |                     |
 |---------------------->|                     |                     |
 |                       |  5. Return code     |                     |
 |                       |<--------------------|                     |
 |                       |                     |                     |
 |                       |  6. Exchange code   |                     |
 |                       |     for tokens      |                     |
 |                       |-------------------->|                     |
 |                       |                     |                     |
 |                       |  7. Fetch userinfo  |                     |
 |                       |-------------------->|                     |
 |                       |<--------------------|                     |
 |                       |                     |                     |
 |  8. Logged in         |                     |                     |
 |<----------------------|                     |                     |
```

## Prerequisites

### Registering as a Relying Party

To use CIE in production, you must register your application with the CIE IdP:

| Environment | IdP URL | Registration |
|---|---|---|
| Test | `https://idserver.servizicie.interno.gov.it` | Request credentials from AgID/IPZS |
| Production | URL provided by IPZS | Request credentials from AgID/IPZS |

**Registration process**:

1. Request accreditation as a Service Provider through AgID or IPZS
2. Obtain `client_id` and `client_secret`
3. Register your `redirect_uri` (e.g. `https://your-domain.com/api/federation/callback?provider_id=cie`)
4. Specify the required security levels (L1, L2, L3)

> **Official documentation**: see the [CIE Technical Manual](https://docs.italia.it/italia/cie/cie-manuale-tecnico-docs/) for the complete accreditation procedure.

## Configuration in AuthGlow

### Via Admin UI

1. Go to **Admin** > **Federation** (`/admin/federation`)
2. Click **"Add Provider"**
3. Fill in the fields:

| Field | Value for CIE Test Environment |
|---|---|
| Label | `CIE` |
| Description | `Italian Electronic Identity Card` |
| Issuer URL | `https://idserver.servizicie.interno.gov.it` |
| Client ID | Your `client_id` |
| Client Secret | Your `client_secret` |
| Scopes | `openid profile email` |
| Auth Levels | `L1, L2, L3` |

### Via API

```bash
curl -X POST http://localhost:8000/api/federation/providers \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer <admin-token>" \
  -d '{
    "label": "CIE",
    "description": "Italian Electronic Identity Card",
    "issuer": "https://idserver.servizicie.interno.gov.it",
    "client_id": "your-client-id",
    "client_secret": "your-client-secret",
    "scopes": ["openid", "profile", "email"],
    "auth_levels": ["L1", "L2", "L3"]
  }'
```

### Verify Discovery

After configuration, verify the CIE IdP is reachable:

```bash
curl https://idserver.servizicie.interno.gov.it/.well-known/openid-configuration | jq .
```

You should see endpoints like `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`.

## Security Levels (acr_values)

CIE defines three security levels for authentication:

| Level | Name | Description | Mechanism |
|---|---|---|---|
| L1 | Username/Password | Basic authentication | SPID Level 1 equivalent |
| L2 | CIE with optical reading | Two-factor authentication | NFC + MRZ scanning or PIN |
| L3 | CIE with certificate | Maximum security | NFC + PIN + client certificate |

In AuthGlow, levels are configured in the provider's `auth_levels` field. During authentication, the `acr_values` parameter is passed to the CIE IdP:

```
GET /authorize?...&acr_values=https://www.spid.gov.it/SpidL2
```

Standard `acr_values` according to SPID/CIE specifications:
- `https://www.spid.gov.it/SpidL1` — Level 1
- `https://www.spid.gov.it/SpidL2` — Level 2
- `https://www.spid.gov.it/SpidL3` — Level 3

## Authentication Flow

### End-to-end

```
1. User lands on /oauth2/authorize?client_id=...&scope=...
   → Login page shows "Entra con CIE" button below the password form

2. User clicks "Entra con CIE"
   → GET /api/federation/login/cie?redirect_uri=...
   → Redirects to https://idserver.servizicie.interno.gov.it/authorize
     ?response_type=code
     &client_id=...
     &redirect_uri={authglow}/api/federation/callback?provider_id=cie
     &scope=openid+profile+email
     &state={random}
     &nonce={random}
     &acr_values=https://www.spid.gov.it/SpidL2

3. CIE IdP handles authentication:
   - User taps CIE card on NFC reader
   - Enters PIN (for L3)
   - IdP validates certificate against national CA

4. CIE IdP redirects back to AuthGlow:
   GET /api/federation/callback?provider_id=cie&code={code}&state={state}

5. AuthGlow exchanges the code for tokens:
   POST {token_endpoint}
   → receives access_token, id_token (optional)

6. AuthGlow fetches userinfo:
   GET {userinfo_endpoint} with Bearer token
   → receives: sub (NIS), name, family_name, email, codice_fiscale, ...

7. AuthGlow maps claims to local user:
   - sub → external_id
   - email → email
   - name → name
   → Creates or links the user account

8. AuthGlow issues its own tokens and completes the flow
```

## Claims Mapping

Claims returned by the CIE IdP are mapped to AuthGlow user fields. Default mapping:

| CIE/SPID Claim | AuthGlow Field |
|---|---|
| `sub` (NIS code) | `external_id` |
| `email` | `email` |
| `name` | `name` |
| `family_name` | (included in `name` if `name` is absent) |
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

To include these claims, add the corresponding scopes in the provider configuration. Custom mapping is defined in the `claims_mapping` field.

## Testing with Playground

AuthGlow includes an **OAuth Playground** (`/admin/playground`) to test the full federated flow:

1. Configure an OAuth client with `authorization_code` grant type
2. In the playground, select "Authorization Code Flow"
3. Enter `client_id`, `redirect_uri`, and scopes
4. At the "Authorize" step, click "Open in Browser" to reach `/oauth2/authorize`
5. The login page will show the "Entra con CIE" button (if configured and enabled)
6. Complete authentication and verify the returned `code`

## Direct Login (non-OAuth)

The standard login page (`/auth/login`) also shows federation buttons when configured. Users can use CIE to access AuthGlow directly without going through an OAuth client.

## Enabling/Disabling

Toggle a provider from the admin UI without deleting its configuration:
- **Admin UI**: click the power icon (green/gray) on any provider row
- **API**: `PATCH /api/federation/admin/providers/{id}/toggle`

Disabled providers are hidden from the login UI and reject authentication requests.

## References

- [CIE on Developers Italia](https://developers.italia.it/en/cie/) — Official documentation, SDKs, examples
- [SPID/CIE OIDC Technical Specifications](https://github.com/italia/spid-cie-oidc-docs) — Protocol and claims mapping
- [CIE Technical Manual](https://docs.italia.it/italia/cie/cie-manuale-tecnico-docs/) — Complete chip and middleware specs
- [CIE Middleware](https://github.com/italia/cie-middleware) — Official middleware for Windows, macOS, Linux
- [CIE Android SDK](https://github.com/italia/cieid-android-sdk) — "Entra con CIE" SDK for Android
- [CIE iOS SDK](https://github.com/italia/cieid-ios-sdk) — "Entra con CIE" SDK for iOS
- [spid-cie-oidc-php Proxy](https://github.com/italia/spid-cie-oidc-php) — Reference OIDC proxy for SPID/CIE
- [CIE Graphics](https://github.com/italia/cie-graphics) — Official CIE icons, logos and buttons
- [CIE NIS Python SDK](https://github.com/italia/cie-nis-python-sdk) — Python library for reading NIS directly from the chip (not required by AuthGlow)
- [CNS Apache Docker](https://github.com/italia/cie-cns-apache-docker) — Docker for server-side CIE/CNS authentication