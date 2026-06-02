# Introduction to AuthGlow

Welcome to the official documentation for AuthGlow! This document provides a high-level overview of what AuthGlow is, its core philosophy, and what you can achieve with it.

## What is AuthGlow?

AuthGlow is a self-hostable Customer Identity and Access Management (CIAM) solution. In simpler terms, it's a centralized service you can run on your own server to manage user identities for your applications.

It handles everything from user registration and login to advanced features like Multi-Factor Authentication (MFA), passwordless logins with Passkeys, and Role-Based Access Control (RBAC). Crucially, it also acts as a fully compliant **OAuth 2.0 and OpenID Connect (OIDC) provider**, allowing you to easily and securely authenticate users in your frontend applications, mobile apps, or third-party services.

## The Core Philosophy

The development of AuthGlow is guided by a few key principles:

1.  **Simplicity and Control**: Modern identity solutions can be overly complex, requiring extensive setup and maintenance (databases, caching layers, etc.). AuthGlow simplifies this by using a **file-based storage system**. All your data—users, clients, roles—is stored in a structured hierarchy of JSON files. This makes the entire system transparent, incredibly easy to back up (just copy the `data` directory!), and portable.

2.  **Self-Hosting First**: While third-party auth services are convenient, they can be expensive and lock you into a specific vendor. AuthGlow is designed to be run on your own infrastructure, giving you complete control over your users' data, costs, and the authentication experience.

3.  **Modern Security by Default**: AuthGlow implements current security best practices. It provides modern authentication methods like Passkeys (FIDO2/WebAuthn) and enforces secure standards like the OAuth 2.0 Authorization Code Flow with PKCE for OIDC clients.

4.  **Developer-Friendly**: The goal is to provide a robust identity solution that is easy to deploy and integrate. With Docker support and a clear configuration-over-code approach (via environment variables), getting started is a matter of minutes.

## Who is AuthGlow For?

AuthGlow is an excellent fit for:

*   **Developers and Hobbyists**: Perfect for personal projects or for learning about authentication and OIDC.
*   **Teams needing a centralized auth service**: If you manage multiple applications, AuthGlow can act as the single source of truth for user identities, providing a seamless Single Sign-On (SSO) experience.

However, due to its file-based nature, it may not be the best choice for extremely large-scale applications with very high concurrent write loads.

## What's Next?

You've got the big picture. Here’s where to go next:

*   **[Installation](./installation.md)**: A detailed guide to get your AuthGlow instance up and running.
*   **[Configuration](./configuration.md)**: Learn about all the available settings to customize your setup.
*   **[OAuth/OIDC Guide](./guides/02-oauth-oidc.md)**: The essential guide for connecting your applications to AuthGlow.
