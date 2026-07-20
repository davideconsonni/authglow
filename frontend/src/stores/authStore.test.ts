import { describe, it, expect, beforeEach, vi } from 'vitest'
import { useAuthStore } from '../stores/authStore'

describe('authStore', () => {
  beforeEach(() => {
    const store = useAuthStore.getState()
    store.setAuthenticated(false)
    store.setUser(null as unknown as Parameters<typeof store.setUser>[0])
  })

  describe('no token stored in localStorage', () => {
    it('does not persist tokens', () => {
      const stored = localStorage.getItem('auth-storage')
      if (stored) {
        const parsed = JSON.parse(stored)
        expect(parsed.state).not.toHaveProperty('token')
        expect(parsed.state).not.toHaveProperty('refreshToken')
      }
    })

    it('persists user and isAuthenticated', () => {
      const store = useAuthStore.getState()
      store.setUser({
        id: '1',
        email: 'test@test.com',
        first_name: 'Test',
        last_name: 'User',
        mfa_enabled: false,
        roles: [],
        scopes: [],
        permissions: [],
        is_federated: false,
      })
      store.setAuthenticated(true)

      const stored = JSON.parse(localStorage.getItem('auth-storage') || '{}')
      expect(stored.state.user).toBeTruthy()
      expect(stored.state.isAuthenticated).toBe(true)
      expect(stored.state).not.toHaveProperty('token')
      expect(stored.state).not.toHaveProperty('refreshToken')
    })
  })

  describe('setAuthenticated', () => {
    it('sets isAuthenticated to true', () => {
      useAuthStore.getState().setAuthenticated(true)
      expect(useAuthStore.getState().isAuthenticated).toBe(true)
    })

    it('clears user when setting isAuthenticated to false', () => {
      useAuthStore.getState().setUser({
        id: '1',
        email: 'test@test.com',
        first_name: 'Test',
        last_name: 'User',
        mfa_enabled: false,
        roles: [],
        scopes: [],
        permissions: [],
        is_federated: false,
      })
      useAuthStore.getState().setAuthenticated(false)
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
      expect(useAuthStore.getState().user).toBeNull()
    })
  })

  describe('setUser', () => {
    it('sets the user object', () => {
      const user = {
        id: '1',
        email: 'test@test.com',
        first_name: 'Test',
        last_name: 'User',
        mfa_enabled: false,
        roles: [],
        scopes: [],
        permissions: [],
        is_federated: false,
      }
      useAuthStore.getState().setUser(user)
      expect(useAuthStore.getState().user).toEqual(user)
    })
  })

  describe('login', () => {
    it('sets isAuthenticated on success', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            token_type: 'Bearer',
          }),
      })

      await useAuthStore.getState().login('test@test.com', 'password123')
      expect(useAuthStore.getState().isAuthenticated).toBe(true)
    })

    it('loading is false after success', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: () =>
          Promise.resolve({
            access_token: 'test-token',
            token_type: 'Bearer',
          }),
      })

      await useAuthStore.getState().login('test@test.com', 'password123')
      expect(useAuthStore.getState().isLoading).toBe(false)
    })

    it('throws on login failure (non-401)', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: () => Promise.resolve({ detail: 'Invalid credentials' }),
      })

      await expect(
        useAuthStore.getState().login('test@test.com', 'bad'),
      ).rejects.toThrow('Invalid credentials')
    })

    it('throws on login failure (401)', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        json: () => Promise.resolve({}),
      })

      await expect(
        useAuthStore.getState().login('test@test.com', 'bad'),
      ).rejects.toThrow('Unauthorized')
    })
  })

  describe('logout', () => {
    it('clears isAuthenticated and user', async () => {
      globalThis.fetch = vi.fn().mockResolvedValue({ ok: true, status: 200, json: () => Promise.resolve({ ok: true }) })

      useAuthStore.getState().setAuthenticated(true)
      useAuthStore.getState().setUser({
        id: '1',
        email: 'test@test.com',
        first_name: 'Test',
        last_name: 'User',
        mfa_enabled: false,
        roles: [],
        scopes: [],
        permissions: [],
        is_federated: false,
      })

      await useAuthStore.getState().logout()
      expect(useAuthStore.getState().isAuthenticated).toBe(false)
      expect(useAuthStore.getState().user).toBeNull()
    })
  })
})
