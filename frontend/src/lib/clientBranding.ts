import type { CSSProperties } from 'react'

/**
 * Public client-branding contract (OIDC-styled).
 *
 * A registered OAuth client may set a `branding` object (typed/validated
 * server-side by `ClientBranding`, VAPT-037). The SPA injects it as CSS
 * custom properties on the authorize/consent page root; every consumer
 * falls back to the active theme token when a property is absent:
 *
 *   --brand-primary  client brand color   → var(--color-brand-accent)
 *   --brand-surface  card background      → var(--color-surface-1)
 *   --brand-text     on-brand text color  → #FFFFFF
 *   --brand-font     font family          → Inter stack
 *   --brand-radius   card/button radius   → theme radius scale
 */
export function brandingStyle(branding: Record<string, unknown> | null | undefined): CSSProperties {
  if (!branding) return {}
  const style: Record<string, string> = {}
  const set = (key: string, value: unknown) => {
    if (typeof value === 'string' && value) style[key] = value
  }
  set('--brand-primary', branding.primary_color)
  set('--brand-surface', branding.surface_color)
  set('--brand-text', branding.text_color)
  set('--brand-font', branding.font_family)
  set('--brand-radius', branding.border_radius)
  return style as CSSProperties
}
