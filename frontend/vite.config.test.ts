// @vitest-environment node
import { describe, expect, it } from 'vitest'
import config from './vite.config'

const proxyContexts = Object.keys(config.server?.proxy ?? {})

function isProxied(path: string): boolean {
  return proxyContexts.some((context) =>
    context.startsWith('^')
      ? new RegExp(context).test(path)
      : path.startsWith(context),
  )
}

describe('development API proxy', () => {
  it.each(['/api-keys', '/api-keys?sort=name', '/api-keys/', '/admin/api-keys'])(
    'serves the SPA for %s',
    (path) => {
      expect(isProxied(path)).toBe(false)
    },
  )

  it.each(['/api', '/api?limit=10', '/api/api-keys', '/api/admin/api-keys?limit=10'])(
    'proxies API requests for %s',
    (path) => {
      expect(isProxied(path)).toBe(true)
    },
  )
})
