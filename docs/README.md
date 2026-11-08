# AuthGlow Documentation

Welcome to the AuthGlow documentation. The documentation is organized into three distinct pillars:

```
docs/
├── product/          # 1. Product & Protocol Documentation
│   ├── getting-started/   # Zero-to-signed-in setup guides
│   ├── reference/         # Complete feature and endpoint catalog (features.md, FAPI.md)
│   ├── flows/             # OAuth2/OIDC protocol flows (PKCE, DPoP, Device Auth, etc.)
│   └── guides/            # Integrator guides (CIE, Google Federation, SMS/Phone)
│
├── project/          # 2. Operations & Project Tracking
│   ├── plans/             # Engineering roadmaps & work items (active/ and archive/)
│   ├── vapt/              # Security audit reports and penetration testing results
│   └── analysis/          # Technical feasibility assessments (e.g. SAML)
│
└── internals/        # 3. Engineering & Progressive Context (AI Agents & Core Devs)
    ├── architecture/      # Deep dives: repository-pattern, rbac, claim-policy, deployment
    ├── security/          # Secret management policy, test fixture isolation, GitGuardian
    └── guides/            # Developer implementation guides (audit-logging, custom-resolvers)
```

---

## Where to Look First

| Role / Intent | Target Area | Recommended Starting Point |
|---|---|---|
| **I want to run or integrate with AuthGlow** | `docs/product/` | [`product/getting-started/quick-setup.md`](product/getting-started/quick-setup.md) |
| **I want to implement or review an OAuth2/OIDC flow** | `docs/product/` | [`product/flows/README.md`](product/flows/README.md) |
| **I want to check supported standards & features** | `docs/product/` | [`product/reference/features.md`](product/reference/features.md) |
| **I am an AI agent / Developer extending AuthGlow** | `docs/internals/` | [`../ARCHITECTURE.md`](../ARCHITECTURE.md) and [`internals/architecture/`](internals/architecture/) |
| **I need to write audit logs or custom claims** | `docs/internals/` | [`internals/guides/audit-logging.md`](internals/guides/audit-logging.md) |
| **I am working on an active task or security finding** | `docs/project/` | [`project/plans/active/README.md`](project/plans/active/README.md) |
| **I am reviewing security audit findings (VAPT)** | `docs/project/` | [`project/vapt/README.md`](project/vapt/README.md) |

---

## Documentation Conventions

- **File Naming**: Kebab-case English (`quick-setup.md`, `repository-pattern.md`).
- **Operational Plans**: Located in `docs/project/plans/`, carry YAML frontmatter (`type: plan`, `status: active|done|superseded`) and stable item IDs (`VAPT-NNN`, `OIDC-NNN`).
- **Architecture & Internals**: Kept modular under `docs/internals/` to support Progressive Context Disclosure for AI coding agents.
- **Root Files**: High-level summaries stay at the repository root (`README.md`, `AGENTS.md`, `ARCHITECTURE.md`, `DESIGN.md`, `SECURITY.md`).
