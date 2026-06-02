
# AUTH GLOW
## Enterprise Design System v1.0

> Premium Identity Platform Design Language

---

# 1. DESIGN PHILOSOPHY

AUTH GLOW is not a generic enterprise application.

It combines:

- Enterprise Trust
- Cyber Security
- Modern SaaS
- AI-Native Experiences
- Premium Visual Identity

Target perception:

- Secure
- Intelligent
- Fast
- Elegant
- Innovative
- Reliable

Comparable visual references:

- Okta
- Auth0
- WorkOS
- Clerk
- Stripe Dashboard
- Linear
- Vercel

AUTH GLOW should feel more premium than traditional IAM products.

---

# 2. CORE DESIGN PRINCIPLES

1. Trust First
2. Security Visible
3. Minimal Cognitive Load
4. Dark-First Experience
5. Premium Motion
6. Accessibility By Default
7. Enterprise Scalability
8. AI-Native Interaction Patterns

---

# 3. BRAND ATTRIBUTES

Security: 10/10
Modernity: 10/10
Professionalism: 10/10
Playfulness: 2/10
Luxury: 7/10
Technical Sophistication: 10/10

---

# 4. COLOR TOKENS

## Background

BG_PRIMARY=#050816
BG_SECONDARY=#0A1024
BG_TERTIARY=#11182F

## Surface

SURFACE_1=#121A32
SURFACE_2=#182345
SURFACE_3=#202D56

## Brand

BRAND_VIOLET=#8B5CF6
BRAND_MAGENTA=#D946EF
BRAND_BLUE=#60A5FA

## Semantic

SUCCESS=#22C55E
WARNING=#F59E0B
ERROR=#EF4444
INFO=#38BDF8

## Text

TEXT_PRIMARY=#FFFFFF
TEXT_SECONDARY=#CBD5E1
TEXT_MUTED=#94A3B8

---

# 5. GRADIENTS

PRIMARY_GRADIENT:
violet → magenta

SECONDARY_GRADIENT:
blue → violet

AI_GRADIENT:
cyan → violet → magenta

AUTH_GLOW MUST use gradients only for:

- CTA buttons
- Brand elements
- Important highlights

Never use gradients on body text.

---

# 6. TYPOGRAPHY

Primary Font:
Inter

Fallback:
Inter, Segoe UI, Roboto, sans-serif

Scale:

Display XL = 72
Display L = 64
H1 = 48
H2 = 36
H3 = 30
H4 = 24
H5 = 20
Body = 16
Small = 14
Caption = 12

Line height:

Display = 1.1
Headings = 1.2
Body = 1.6

---

# 7. SPACING SYSTEM

Base Unit = 8px

Spacing Scale

4
8
12
16
24
32
40
48
64
80
96
128

Never invent arbitrary spacing.

---

# 8. GRID SYSTEM

Desktop:

12 columns

Tablet:

8 columns

Mobile:

4 columns

Max Width:

1440px

Content Width:

1280px

---

# 9. ELEVATION MODEL

Level 0
Flat

Level 1
Card

Level 2
Interactive

Level 3
Modal

Level 4
Critical Dialog

---

# 10. SHADOWS

Soft Glow
Medium Glow
Premium Glow

Glow colors:

violet
magenta
blue

Avoid black heavy shadows.

---

# 11. GLASSMORPHISM

Allowed:

- subtle blur
- subtle transparency
- subtle border

Forbidden:

- extreme blur
- frosted backgrounds everywhere

Use sparingly.

---

# 12. ICONOGRAPHY

Library:

Lucide

Style:

outline
minimal
rounded

Sizes:

16
20
24
32

---

# 13. MOTION SYSTEM

Micro Interaction:
150ms

Default:
250ms

Complex:
400ms

Page Transition:
500ms

Easing:

cubic-bezier(0.4,0,0.2,1)

---

# 14. BUTTON SYSTEM

Primary

Gradient background
White text

Secondary

Transparent
Outlined

Tertiary

Text button

Danger

Red

Success

Green

Loading State mandatory.

---

# 15. INPUT SYSTEM

States:

Default
Hover
Focus
Disabled
Error
Success

Inputs must never have hard black borders.

Focus must always be visible.

---

# 16. FORM DESIGN

Authentication forms:

- login
- register
- MFA
- password reset
- passwordless

Always:

single primary action
minimal distractions

---

# 17. AUTHENTICATION EXPERIENCE

Login Page

Left:
branding

Right:
form

Mobile:
stacked layout

---

# 18. MFA EXPERIENCE

Supported UI patterns:

- OTP
- Email Code
- SMS
- TOTP
- WebAuthn
- Passkeys

Passkeys should be visually promoted.

---

# 19. PASSKEY DESIGN

Passkeys are strategic.

Use:

- glow accent
- security icon
- premium treatment

---

# 20. DASHBOARD FRAMEWORK

Layout:

Sidebar
Top Bar
Content Area

Cards:
24px radius

---

# 21. SIDEBAR

Floating appearance

Sections:

Dashboard
Applications
Users
Groups
Policies
Audit
Settings

---

# 22. TABLE DESIGN

Enterprise-grade tables.

Features:

sorting
filtering
column visibility
pagination
bulk actions

---

# 23. DATA VISUALIZATION

Allowed:

Line
Bar
Area
Donut

Avoid:
3D charts

---

# 24. EMPTY STATES

Every empty state requires:

- illustration
- explanation
- CTA

---

# 25. ERROR STATES

Friendly language.

Never expose stack traces.

---

# 26. AI FEATURES

AI sections use:

AI gradient
sparkle icon
elevated visual hierarchy

---

# 27. SECURITY VISUAL LANGUAGE

Icons:

shield
lock
fingerprint
key

Visual cues:

trust
clarity
auditability

---

# 28. ACCESSIBILITY

WCAG AA minimum

Keyboard navigation mandatory

Screen reader support mandatory

Focus visibility mandatory

---

# 29. RESPONSIVE STRATEGY

Desktop First

Breakpoints:

640
768
1024
1280
1536

---

# 30. SHADCN/UI MAPPING

Preferred Components:

Button
Card
Input
Dialog
Drawer
Dropdown
Popover
Tabs
Table
Tooltip
Command

Use shadcn as foundation.

---

# 31. TAILWIND GUIDELINES

Prefer utility-first.

No inline styles.

Use design tokens.

---

# 32. REACT GUIDELINES

Component hierarchy:

atoms
molecules
organisms
templates
pages

---

# 33. DESIGN TOKENS

All colors
spacing
radius
shadows
durations

must exist as tokens.

Hardcoded values are forbidden.

---

# 34. PAGE BLUEPRINTS

Required templates:

Login
Register
Forgot Password
MFA
Dashboard
Users
Groups
Applications
Audit Logs
Policies
Settings

---

# 35. ADMIN EXPERIENCE

Should feel:

powerful
safe
predictable

---

# 36. AUDIT EXPERIENCE

Audit logs are a first-class feature.

Visual priority must be high.

---

# 37. FUTURE AI AGENT RULES

When generating AUTH GLOW UI:

ALWAYS

- Dark theme
- Inter font
- Glassmorphism light
- Violet/Magenta identity
- Premium spacing
- Visible focus states
- Enterprise-grade layouts

NEVER

- Bootstrap aesthetics
- Material default aesthetics
- Sharp corners
- Cartoon graphics
- Neon overload
- Heavy gradients everywhere
- Dense crowded screens

---

# 38. VISUAL NORTH STAR

AUTH GLOW should look like:

"Stripe Dashboard meets Auth0 meets Linear with a premium cyber-security identity layer."
