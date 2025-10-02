# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**AuthGlow** is a serverless Customer Identity and Access Management (CIAM) system designed to be stateless and cloud-native.

### Tech Stack
- **Language**: Python
- **API Framework**: FastAPI
- **User Database**: fsspec (filesystem-based storage for serverless compatibility)
- **Frontend**: FastAPI templates (Jinja2) with customizable CSS via environment variables
- **Authentication Standard**: OAuth2

### Design Principles
- **Stateless architecture**: Ready for serverless deployment (AWS Lambda, Azure Functions, etc.)
- **OAuth2 compliant**: Standard authorization flows with callback redirects
- **Customizable UI**: CSS and key content configurable via environment variables

## Planned Feature Roadmap

Features are to be implemented incrementally with testing after each phase.

### Phase 1: Core OAuth2 Implementation
- Basic OAuth2 authorization server
- Login/registration flow with callback redirects
- Token generation and validation
- User storage via fsspec

### Phase 2: Security & MFA
- TOTP-based MFA (Google Authenticator)
- Brute force protection
- Risk-based authentication
- Anomaly detection
- Intelligent CAPTCHA

### Phase 3: Advanced Authentication
- SSO with OpenID Connect
- Passwordless authentication with Passkeys (WebAuthn)
- Audit logging for all access events

### Phase 4: Enterprise Features
- RBAC (Role-Based Access Control)
- User/Organization management
- Admin portal with user statistics and management
- Webhook system for user lifecycle events
- REST APIs (user management, token management, admin, analytics)

### Phase 5: Compliance & Performance
- GDPR-compliant data export
- Bulk import/export and migration tools
- Caching layer (Memcached for tokens and sessions)
- Multi-language support (i18n)

## Development Workflow

Since this is a new project, the codebase will be built iteratively:

1. **Requirements Clarification**: Ask detailed questions before implementing each feature
2. **Implementation**: Build the feature following serverless best practices
3. **Testing**: Verify functionality before moving to the next feature
4. **Iteration**: Refine based on test results

## Important Constraints

- All features must remain **stateless** (no in-memory session storage)
- User data storage must use **fsspec** for cloud storage compatibility (S3, Azure Blob, GCS, etc.)
- Frontend templates must support **runtime customization** via environment variables
- Security features must not introduce state dependencies
