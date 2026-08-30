import { describe, it, expect } from 'vitest'
import { brandingStyle } from './clientBranding'

describe('brandingStyle', () => {
  it('returns empty object for null/undefined', () => {
    expect(brandingStyle(null)).toEqual({})
    expect(brandingStyle(undefined)).toEqual({})
  })

  it('maps typed branding fields to --brand-* custom properties', () => {
    expect(
      brandingStyle({
        primary_color: '#2E5BFF',
        surface_color: '#F4F6FF',
        text_color: '#FFFFFF',
        font_family: 'Georgia',
        border_radius: '18px',
      }),
    ).toEqual({
      '--brand-primary': '#2E5BFF',
      '--brand-surface': '#F4F6FF',
      '--brand-text': '#FFFFFF',
      '--brand-font': 'Georgia',
      '--brand-radius': '18px',
    })
  })

  it('skips nullish and non-string values', () => {
    expect(
      brandingStyle({
        primary_color: '#2E5BFF',
        surface_color: null,
        text_color: '',
        font_family: 42,
        border_radius: '10px',
      }),
    ).toEqual({
      '--brand-primary': '#2E5BFF',
      '--brand-radius': '10px',
    })
  })
})
