import { describe, it, expect } from 'vitest'
import { brandingStyle, autoContrastText, blendColors } from './clientBranding'

type Style = Record<string, string>

describe('autoContrastText', () => {
  it('picks dark text on light primaries', () => {
    expect(autoContrastText('#FFF9C4')).toBe('#191919')
  })

  it('picks white text on dark/saturated primaries', () => {
    expect(autoContrastText('#2E5BFF')).toBe('#FFFFFF')
    expect(autoContrastText('#C2261A')).toBe('#FFFFFF')
  })

  it('falls back to white for invalid hex', () => {
    expect(autoContrastText('not-a-color')).toBe('#FFFFFF')
  })
})

describe('blendColors', () => {
  it('mid-blends two hex colors', () => {
    expect(blendColors('#FFFFFF', '#000000', 0.5)?.toLowerCase()).toBe('#808080')
  })

  it('returns null for invalid input', () => {
    expect(blendColors('#FFF', '#000000', 0.5)).toBeNull()
  })
})

describe('brandingStyle', () => {
  it('returns empty object for null/undefined', () => {
    expect(brandingStyle(null)).toEqual({})
    expect(brandingStyle(undefined)).toEqual({})
    expect(brandingStyle({})).toEqual({})
  })

  it('emits merged light+dark sets from base-only (legacy) branding', () => {
    const style = brandingStyle({
      primary_color: '#2E5BFF',
      surface_color: '#F4F6FF',
      font_family: 'Georgia',
      border_radius: '18px',
    }) as Style
    expect(style['--brand-primary-light']).toBe('#2E5BFF')
    expect(style['--brand-primary-dark']).toBe('#2E5BFF')
    expect(style['--brand-surface-light']).toBe('#F4F6FF')
    expect(style['--brand-font']).toBe('Georgia')
    expect(style['--brand-radius-light']).toBe('18px')
    expect(style['--brand-radius-dark']).toBe('18px')
    // text auto-derived from primary luminance in both modes
    expect(style['--brand-text-light']).toBe(autoContrastText('#2E5BFF'))
    expect(style['--brand-text-dark']).toBe(autoContrastText('#2E5BFF'))
  })

  it('blends a light base surface toward dark for the dark mode (safety net)', () => {
    const style = brandingStyle({ surface_color: '#F4F6FF' }) as Style
    expect(style['--brand-surface-light']).toBe('#F4F6FF')
    expect(style['--brand-surface-dark']).toBeDefined()
    expect(style['--brand-surface-dark']).not.toBe('#F4F6FF')
    expect(style['--brand-surface-dark']).toMatch(/^#[0-9a-f]{6}$/i)
  })

  it('respects explicit light/dark variants over the base per property', () => {
    const style = brandingStyle({
      primary_color: '#AAAAAA',
      light: { primary_color: '#BBBBBB', border_radius: '8px' },
      dark: { surface_color: '#172040' },
    }) as Style
    expect(style['--brand-primary-light']).toBe('#BBBBBB')
    expect(style['--brand-primary-dark']).toBe('#AAAAAA')
    expect(style['--brand-radius-light']).toBe('8px')
    expect(style['--brand-surface-dark']).toBe('#172040')
  })

  it('honours an explicit text_color over the auto-contrast', () => {
    const style = brandingStyle({
      primary_color: '#2E5BFF',
      text_color: '#FFD700',
    }) as Style
    expect(style['--brand-text-light']).toBe('#FFD700')
    expect(style['--brand-text-dark']).toBe('#FFD700')
  })

  it('skips non-string and empty values', () => {
    const style = brandingStyle({
      primary_color: '#2E5BFF',
      surface_color: null,
      text_color: '',
      font_family: 42,
    }) as Style
    expect(style['--brand-primary-light']).toBe('#2E5BFF')
    expect(style['--brand-surface-light']).toBeUndefined()
    expect(style['--brand-font']).toBeUndefined()
  })
})
