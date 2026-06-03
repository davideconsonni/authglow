# Plan: Redesign OAuth Client Modal — Two-Column Layout

## File: `frontend/src/pages/admin/AdminOAuthClientsPage.tsx`

## Problem
The modal is ~1200px of content stacked vertically in a single column. Users always see a scrollbar. Need to reduce height by ~40-50% to fit viewport.

## Changes

### 1. Add `Check` icon import
Add `Check` to the lucide-react import line (used for the selected template indicator).

### 2. Replace entire modal body (lines ~402-618) with two-column layout

**Container**: `max-w-3xl` (768px, up from 2xl/672px) to accommodate two columns without cramping.

#### Left Column (w-1/2) — "Application identity"
```
Application name *
  └─ TextInput + error
Description
  └─ textarea
Grant types *
  └─ 3 checkbox items, compact (no description text, just label + icon)
```

#### Right Column (w-1/2) — "Security configuration"
Templates become compact horizontal chips:
```
[ Web App | Service / API | Mobile / SPA ]   ← icon-only, on one line
```
When a template is selected, show a subtle `Check` + brand-violet border.

Client type + Auth method: keep the 2-column grid inside this column.

Redirect URIs (conditional): compact inputs.

PKCE + Consent: two checkboxes stacked vertically (not 2-col) inside this column.

#### Full-width bottom section
**Advanced settings** (collapsible, same as now but reorganized):
- When expanded, use a 3-column grid for scopes + URIs + token lifetimes
- Scopes: full-width first row
- URIs: homepage, logo, terms, privacy in 2x2 grid
- Token lifetimes: access + refresh in 2 columns

### 3. Template chip component (inline in the right column)
Instead of the 3 big vertical cards, render as small horizontal buttons:
```tsx
{TEMPLATES.map(t => (
  <button onClick={() => applyTemplate(t)} className={cn(
    'flex items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[11px] transition-all',
    /* selected state: border-brand-violet bg-brand-violet/10 */
  )}>
    <t.icon size={14} />
    {t.label}
  </button>
))}
```
Track selected template with `useState<string | null>`.

### 4. Ensure spacing is consistent
- Column gap: `gap-4` between left/right
- Section spacing inside columns: `space-y-3`
- Modal padding: keep `p-6`
- Section header + content: `space-y-2`

### 5. No functional changes
- All `useState` hooks remain the same
- All handlers (`applyTemplate`, `toggleGrantType`, `updateRedirectUri`, etc.) unchanged
- Validation logic unchanged
- Submit buttons unchanged
- Secret modal unchanged
- Table unchanged

### 6. Breaking change warning
Moves to full-width at the top of the modal body (above the two columns).

## Expected Result
- Modal height ~650px in create mode (no scroll on 1080p screens)
- Modal height ~750px in edit mode with advanced expanded
- Significantly denser but still premium feel per DESIGN.md
- Quick-start templates are discoverable but not dominant