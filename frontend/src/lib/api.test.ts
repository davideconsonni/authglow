import { describe, it, expect, vi, beforeEach } from 'vitest'
import { api, ApiError } from '../lib/api'

describe('api', () => {
  beforeEach(() => {
    vi.restoreAllMocks()
  })

  describe('sends credentials: include', () => {
    it('GET includes credentials: include', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ data: 'test' }),
      })
      globalThis.fetch = mockFetch

      await api.get('/api/users/me')

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/users/me'),
        expect.objectContaining({
          credentials: 'include',
        }),
      )
    })

    it('POST includes credentials: include', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ csrf_token: 'csrf-token' }),
      })
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve({ csrf_token: 'csrf-token' }) })
      mockFetch.mockResolvedValueOnce({ ok: true, status: 200, json: () => Promise.resolve({ ok: true }) })
      globalThis.fetch = mockFetch

      await api.post('/api/auth/logout')

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/auth/logout'),
        expect.objectContaining({
          credentials: 'include',
          method: 'POST',
        }),
      )
    })

    it('does not inject Authorization header from localStorage', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () => Promise.resolve({ data: 'test' }),
      })
      globalThis.fetch = mockFetch

      await api.get('/api/data')

      const callArgs = mockFetch.mock.calls[0][1] as RequestInit
      const headers = callArgs.headers as Record<string, string>
      expect(headers).not.toHaveProperty('Authorization')
    })
  })

  describe('silent refresh', () => {
    it('attempts refresh on 401 and retries', async () => {
      let callCount = 0
      const mockFetch = vi.fn().mockImplementation(() => {
        callCount++
        if (callCount === 1) {
          return Promise.resolve({ ok: false, status: 401, json: () => Promise.resolve({}) })
        }
        if (callCount === 2) {
          return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ csrf_token: 'csrf-token' }) })
        }
        if (callCount === 3) {
          return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ ok: true }) })
        }
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ data: 'retried' }) })
      })
      globalThis.fetch = mockFetch

      const result = await api.get('/api/protected')

      expect(result).toEqual({ data: 'retried' })
      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringContaining('/api/auth/refresh'),
        expect.objectContaining({ method: 'POST', credentials: 'include' }),
      )
    })

    it('dispatches auth:session-expired event when refresh fails', async () => {
      vi.useFakeTimers()
      let eventFired = false
      const handler = () => { eventFired = true }
      window.addEventListener('auth:session-expired', handler)

      let callCount = 0
      globalThis.fetch = vi.fn().mockImplementation(() => {
        callCount++
        if (callCount === 2) return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve({ csrf_token: 'csrf-token' }) })
        return Promise.resolve({ ok: false, status: 401, json: () => Promise.resolve({}) })
      })

      try {
        await api.get('/api/protected')
      } catch {
        // Expected
      }

      // The event is delayed by 2.5s so the user can see the toast first.
      expect(eventFired).toBe(false)
      vi.advanceTimersByTime(2500)
      expect(eventFired).toBe(true)

      window.removeEventListener('auth:session-expired', handler)
      vi.useRealTimers()
    })

    it('does not fire event on 401 when already on login page', async () => {
      const originalLocation = window.location
      Object.defineProperty(window, 'location', {
        value: { ...originalLocation, pathname: '/auth/login' },
        writable: true,
        configurable: true,
      })

      let eventFired = false
      const handler = () => { eventFired = true }
      window.addEventListener('auth:session-expired', handler)

      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        json: () => Promise.resolve({}),
      })

      try {
        await api.get('/api/protected')
      } catch {
        // Expected
      }

      expect(eventFired).toBe(false)
      window.removeEventListener('auth:session-expired', handler)
      Object.defineProperty(window, 'location', {
        value: originalLocation,
        writable: true,
        configurable: true,
      })
    })

    it('does not trigger refresh for the refresh endpoint itself', async () => {
      const mockFetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        json: () => Promise.resolve({}),
      })
      globalThis.fetch = mockFetch

      try {
        await api.post('/api/auth/refresh')
      } catch {
        // Expected
      }

      // Should only have one call (no retry loop for refresh endpoint)
      expect(mockFetch).toHaveBeenCalledTimes(1)
    })
  })

  describe('ApiError', () => {
    it('extracts detail from error response', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ detail: 'Bad request' }),
      })

      await expect(api.get('/api/bad')).rejects.toThrow('Bad request')
    })

    it('includes status code', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 404,
        json: () => Promise.resolve({ detail: 'Not found' }),
      })

      try {
        await api.get('/api/missing')
      } catch (err) {
        expect(err).toBeInstanceOf(ApiError)
        expect((err as ApiError).status).toBe(404)
      }
    })
  })
})
