# Guide: SPA Authentication (Authorization Code + PKCE)

This guide details the best-practice approach for integrating a Single Page Application (SPA) with AuthGlow using the **Authorization Code Flow with PKCE**.

## The Core Security Principle: The BFF Pattern

For maximum security, a modern SPA should **not** handle tokens directly in JavaScript. Instead, we use a **Backend for Frontend (BFF)** pattern.
-   Your SPA is served by a lightweight backend (e.g., Node.js/Express).
-   The SPA (frontend) initiates the login flow.
-   The BFF (backend) securely handles the token exchange with AuthGlow and stores the tokens in a **secure, `HttpOnly` cookie**.
-   The SPA code itself cannot access the cookie, protecting it from XSS attacks.

The backend logic for the token exchange is identical to the one described in the [Web App Authentication Guide](./05-oauth-flow-webapp.md). This guide focuses on the **frontend implementation** for popular frameworks.

---

## Implementation Examples

Here you'll find framework-specific examples for implementing the login flow.

### React Example

This example uses React Hooks and `react-router-dom`.

#### 1. PKCE Utility (`src/utils/pkce.js`)
This helper file contains the logic for generating PKCE codes.

```javascript
// Helper function to Base64-URL-encode a string from an ArrayBuffer
function base64UrlEncode(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Generates a random string for the code verifier
export function generateCodeVerifier() {
  const randomBytes = new Uint8Array(32);
  window.crypto.getRandomValues(randomBytes);
  return base64UrlEncode(randomBytes);
}

// Hashes the verifier to create the code challenge
export async function generateCodeChallenge(verifier) {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(digest);
}
```

#### 2. Login Component (`src/components/Login.js`)
This component handles the redirect to AuthGlow.

```jsx
import React from 'react';
import { generateCodeVerifier, generateCodeChallenge } from '../utils/pkce';

const AUTHGLOW_URL = "http://localhost:8000";
const CLIENT_ID = "your-spa-client-id";
const REDIRECT_URI = "http://localhost:3000/callback";

export default function Login() {
  const handleLogin = async () => {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);

    sessionStorage.setItem('code_verifier', verifier);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      scope: 'openid profile email',
      state: 'random-state-string', // Should be generated and verified
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });

    window.location.href = `${AUTHGLOW_URL}/oauth/authorize?${params.toString()}`;
  };

  return <button onClick={handleLogin}>Login with AuthGlow</button>;
}
```

#### 3. Callback Component (`src/components/Callback.js`)
This component handles the redirect from AuthGlow and calls your BFF.

```jsx
import React, { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';

export default function Callback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  useEffect(() => {
    const exchangeCode = async () => {
      const code = searchParams.get('code');
      const verifier = sessionStorage.getItem('code_verifier');

      if (code && verifier) {
        try {
          const response = await fetch('/api/login', { // Your BFF endpoint
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ code, verifier }),
          });

          if (!response.ok) throw new Error('Login failed');
          
          sessionStorage.removeItem('code_verifier');
          navigate('/profile'); // Redirect to a protected route
        } catch (error) {
          console.error(error);
          navigate('/login-error');
        }
      }
    };

    exchangeCode();
  }, [searchParams, navigate]);

  return <div>Loading...</div>;
}
```

---

### Angular Example

This example uses an injectable service and components.

#### 1. Auth Service (`src/app/auth.service.ts`)
A dedicated service to handle all authentication logic.

```typescript
import { Injectable } from '@angular/core';
import { HttpClient } from '@angular/common/http';
import { firstValueFrom } from 'rxjs';

// PKCE functions can be placed here or in a separate utility file
async function generateCodeChallenge(verifier: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(verifier);
  const digest = await window.crypto.subtle.digest('SHA-256', data);
  
  const base64 = btoa(String.fromCharCode(...new Uint8Array(digest)));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function generateCodeVerifier(): string {
  const randomBytes = new Uint8Array(32);
  window.crypto.getRandomValues(randomBytes);
  const base64 = btoa(String.fromCharCode(...randomBytes));
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}


@Injectable({ providedIn: 'root' })
export class AuthService {
  private AUTHGLOW_URL = "http://localhost:8000";
  private CLIENT_ID = "your-spa-client-id";
  private REDIRECT_URI = "http://localhost:4200/callback";

  constructor(private http: HttpClient) {}

  async redirectToLogin() {
    const verifier = generateCodeVerifier();
    const challenge = await generateCodeChallenge(verifier);

    sessionStorage.setItem('code_verifier', verifier);

    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.CLIENT_ID,
      redirect_uri: this.REDIRECT_URI,
      scope: 'openid profile email',
      state: 'random-state-string',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });

    window.location.href = `${this.AUTHGLOW_URL}/oauth/authorize?${params.toString()}`;
  }

  exchangeCodeForToken(code: string, verifier: string) {
    // This calls your BFF, which then calls AuthGlow
    return firstValueFrom(
      this.http.post('/api/login', { code, verifier })
    );
  }
}
```

#### 2. Login Component (`src/app/login/login.component.ts`)

```typescript
import { Component } from '@angular/core';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-login',
  template: `<button (click)="login()">Login with AuthGlow</button>`,
})
export class LoginComponent {
  constructor(private authService: AuthService) {}

  login() {
    this.authService.redirectToLogin();
  }
}
```

#### 3. Callback Component (`src/app/callback/callback.component.ts`)

```typescript
import { Component, OnInit } from '@angular/core';
import { ActivatedRoute, Router } from '@angular/router';
import { AuthService } from '../auth.service';

@Component({
  selector: 'app-callback',
  template: `<p>Loading...</p>`,
})
export class CallbackComponent implements OnInit {
  constructor(
    private route: ActivatedRoute,
    private router: Router,
    private authService: AuthService
  ) {}

  ngOnInit(): void {
    const code = this.route.snapshot.queryParamMap.get('code');
    const verifier = sessionStorage.getItem('code_verifier');

    if (code && verifier) {
      this.authService.exchangeCodeForToken(code, verifier)
        .then(() => {
          sessionStorage.removeItem('code_verifier');
          this.router.navigate(['/profile']);
        })
        .catch(err => {
          console.error(err);
          this.router.navigate(['/login-error']);
        });
    }
  }
}
```