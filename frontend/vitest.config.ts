import { defineConfig } from 'vitest/config'
import { resolve } from 'node:path'

export default defineConfig({
  test: {
    exclude: ['e2e/**', 'node_modules/**'],
    alias: {
      '@': resolve(import.meta.dirname, 'src'),
    },
  },
})
