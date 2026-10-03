// @vitest-environment jsdom
import { describe, it, expect } from 'vitest'
import { cn, formatDate, formatDateTime, formatRelativeTime, truncate } from './utils'

const DATE_PATTERN = /^\d{2}\/\d{2}\/\d{4}$/
const DATETIME_PATTERN = /^\d{2}\/\d{2}\/\d{4}, \d{2}:\d{2} [AP]M$/

describe('cn', () => {
  it('merges class names and resolves Tailwind conflicts', () => {
    expect(cn('px-2', 'px-4')).toBe('px-4')
    expect(cn('text-red-500', 'text-blue-500')).toBe('text-blue-500')
  })

  it('drops falsy values and keeps conditionals', () => {
    const condition = false
    expect(cn('base', condition && 'hidden', undefined, 'extra')).toBe('base extra')
  })
})

describe('formatDate', () => {
  it('returns a dash for empty input', () => {
    expect(formatDate(null)).toBe('-')
    expect(formatDate(undefined)).toBe('-')
    expect(formatDate('')).toBe('-')
  })

  it('formats a valid date', () => {
    expect(formatDate('2026-01-15T12:00:00Z')).toMatch(DATE_PATTERN)
  })

  it('returns a dash for an unparseable date', () => {
    expect(formatDate('not-a-date')).toBe('-')
  })
})

describe('formatDateTime', () => {
  it('returns a dash for empty input', () => {
    expect(formatDateTime(null)).toBe('-')
    expect(formatDateTime(undefined)).toBe('-')
  })

  it('formats a valid date with the time', () => {
    expect(formatDateTime('2026-01-15T12:30:00Z')).toMatch(DATETIME_PATTERN)
  })

  it('returns a dash for an unparseable date', () => {
    expect(formatDateTime('garbage')).toBe('-')
  })
})

describe('formatRelativeTime', () => {
  it('returns Never for empty input', () => {
    expect(formatRelativeTime(null)).toBe('Never')
    expect(formatRelativeTime(undefined)).toBe('Never')
  })

  it('returns a dash for an unparseable date', () => {
    expect(formatRelativeTime('nope')).toBe('-')
  })

  it('renders Now for a just-now timestamp', () => {
    expect(formatRelativeTime(new Date())).toBe('Now')
  })

  it('renders minutes, hours and days', () => {
    expect(formatRelativeTime(new Date(Date.now() - 5.5 * 60_000))).toBe('5m ago')
    expect(formatRelativeTime(new Date(Date.now() - 3.5 * 3_600_000))).toBe('3h ago')
    expect(formatRelativeTime(new Date(Date.now() - 5.5 * 86_400_000))).toBe('5d ago')
  })

  it('falls back to the absolute date beyond 30 days', () => {
    expect(formatRelativeTime(new Date(Date.now() - 40 * 86_400_000))).toMatch(DATE_PATTERN)
  })
})

describe('truncate', () => {
  it('keeps strings within the limit', () => {
    expect(truncate('hello', 10)).toBe('hello')
    expect(truncate('abc', 3)).toBe('abc')
  })

  it('appends an ellipsis when the string is too long', () => {
    expect(truncate('hello world', 5)).toBe('hello...')
  })
})