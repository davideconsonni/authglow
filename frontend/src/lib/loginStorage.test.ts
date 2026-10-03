// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { getSavedEmail, saveEmail, LOGIN_EMAIL_KEY } from './loginStorage'

beforeEach(() => {
  localStorage.clear()
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('loginStorage', () => {
  it('exposes the storage key', () => {
    expect(LOGIN_EMAIL_KEY).toBe('auth-last-email')
  })

  it('returns an empty string when nothing is stored', () => {
    expect(getSavedEmail()).toBe('')
  })

  it('round-trips the saved email', () => {
    saveEmail('user@example.com')
    expect(localStorage.getItem(LOGIN_EMAIL_KEY)).toBe('user@example.com')
    expect(getSavedEmail()).toBe('user@example.com')
  })

  it('returns an empty string when reading throws', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('denied')
    })
    expect(getSavedEmail()).toBe('')
  })

  it('swallows write errors', () => {
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('quota exceeded')
    })
    expect(() => saveEmail('user@example.com')).not.toThrow()
  })
})