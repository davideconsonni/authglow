import type { CSSProperties } from 'react'

/**
 * Public client-branding contract (OIDC-styled, Auth0-style light/dark).
 *
 * A registered OAuth client may set a `branding` object (typed/validated
 * server-side by `ClientBranding`, VAPT-037). The SPA resolves it into
 * per-mode custom properties injected inline on the page root:
 *
 *   --brand-primary-{light,dark}    client brand color
 *   --brand-surface-{light,dark}    card background
 *   --brand-text-{light,dark}       on-brand text color
 *   --brand-radius-{light,dark}     card/button radius
 *   --brand-font                    shared font family (both modes)
 *
 * The mode mapping (which `--brand-*` is active) is resolved in CSS via
 * the `.dark` class, so switching theme updates branding with no re-render.
 *
 * Safety nets for clients that only configured the flat base:
 *   - a light `surface_color` used in dark mode is blended toward the
 *     dark surface (brand tint preserved, contrast guaranteed);
 *   - missing `text_color` is derived from `primary_color` luminance (WCAG).
 */

export type BrandingMode = 'light' | 'dark'

interface MergedVariant {
  primary?: string
  surface?: string
  text?: string
  radius?: string
}

const FIELD_KEYS = {
  primary: 'primary_color',
  surface: 'surface_color',
  text: 'text_color',
  radius: 'border_radius',
} as const

// Must match the Ruby Dark `--color-surface-1` token (blend target).
const DARK_SURFACE = '#211F1C'

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value ? value : undefined
}

function hexToRgb(hex: string): [number, number, number] | null {
  const m = /^#([0-9a-f]{6})$/i.exec(hex)
  if (!m) return null
  const n = parseInt(m[1], 16)
  return [(n >> 16) & 255, (n >> 8) & 255, n & 255]
}

function luminance(hex: string): number | null {
  const rgb = hexToRgb(hex)
  if (!rgb) return null
  const [r, g, b] = rgb.map((c) => {
    const s = c / 255
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4
  })
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

/** Black or white foreground for a given brand color (WCAG relative luminance). */
export function autoContrastText(primary: string): string {
  const l = luminance(primary)
  if (l === null) return '#FFFFFF'
  return l > 0.4 ? '#191919' : '#FFFFFF'
}

/** Blend `fg` into `bg` at weight `w` (0..1). Returns #RRGGBB or null. */
export function blendColors(fg: string, bg: string, w: number): string | null {
  const a = hexToRgb(fg)
  const b = hexToRgb(bg)
  if (!a || !b) return null
  const toHex = (c: number) => Math.round(c).toString(16).padStart(2, '0')
  return `#${toHex(a[0] * w + b[0] * (1 - w))}${toHex(a[1] * w + b[1] * (1 - w))}${toHex(a[2] * w + b[2] * (1 - w))}`
}

function resolveVariant(
  branding: Record<string, unknown>,
  variant: unknown,
  mode: BrandingMode,
): MergedVariant {
  const v = (variant ?? {}) as Record<string, unknown>
  const pick = (key: keyof typeof FIELD_KEYS) => str(v[FIELD_KEYS[key]]) ?? str(branding[FIELD_KEYS[key]])
  const merged: MergedVariant = {
    primary: pick('primary'),
    surface: pick('surface'),
    text: pick('text'),
    radius: pick('radius'),
  }
  // Safety net: a light-only surface in dark mode is tinted, not applied raw.
  if (mode === 'dark' && merged.surface && !str(v.surface_color)) {
    const lum = luminance(merged.surface)
    if (lum !== null && lum > 0.5) {
      merged.surface = blendColors(merged.surface, DARK_SURFACE, 0.14) ?? merged.surface
    }
  }
  // Auto-contrast for the primary surface when text isn't configured.
  if (!merged.text && merged.primary) {
    merged.text = autoContrastText(merged.primary)
  }
  return merged
}

export function brandingStyle(
  branding: Record<string, unknown> | null | undefined,
): CSSProperties {
  if (!branding) return {}
  const style: Record<string, string> = {}
  const font = str(branding.font_family)
  if (font) style['--brand-font'] = font

  const modes: BrandingMode[] = ['light', 'dark']
  for (const mode of modes) {
    const merged = resolveVariant(branding, branding[mode], mode)
    if (merged.primary) style[`--brand-primary-${mode}`] = merged.primary
    if (merged.surface) style[`--brand-surface-${mode}`] = merged.surface
    if (merged.text) style[`--brand-text-${mode}`] = merged.text
    if (merged.radius) style[`--brand-radius-${mode}`] = merged.radius
  }
  return style as CSSProperties
}
