import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import { resolve, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const SRC_DIR = resolve(dirname(fileURLToPath(import.meta.url)), 'src').replace(/\\/g, '/')

function rewriteAliasPlugin() {
  return {
    name: 'rewrite-alias',
    enforce: 'pre' as const,
    transform(code: string, id: string) {
      if (id.includes('node_modules')) return null
      if (!code.includes('@/')) return null
      const rewritten = code.replace(
        /(from\s+['"])@\/([^'"]+)(['"])/g,
        (_, p1, p2, p3) => `${p1}${SRC_DIR}/${p2}${p3}`,
      )
      return { code: rewritten, map: null }
    },
  }
}

export default defineConfig({
  plugins: [rewriteAliasPlugin(), react()],
  resolve: {
    tsconfigPaths: true,
  },
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
    exclude: ['e2e/**', 'node_modules/**'],
    // Some phase tests dynamic-import the whole App graph; under full-suite
    // parallel load the default 5s is flaky on slower machines.
    testTimeout: 15000,
  },
})
