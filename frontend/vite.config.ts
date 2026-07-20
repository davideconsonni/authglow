import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { visualizer } from 'rollup-plugin-visualizer'
import { join } from 'node:path'
import { existsSync, statSync } from 'node:fs'

function resolveAtAlias() {
  const src = join(process.cwd(), 'src')
  const exts = ['.ts', '.tsx', '.js', '.jsx', '.json', '/index.ts', '/index.tsx', '/index.js']
  return {
    name: 'resolve-at-alias',
    resolveId(id: string) {
      if (!id.startsWith('@/')) return null
      const absolute = join(src, id.slice(2))
      // direct file match
      if (existsSync(absolute) && statSync(absolute).isFile()) return absolute
      // try extensions
      for (const ext of exts) {
        const candidate = absolute + ext
        if (existsSync(candidate) && statSync(candidate).isFile()) return candidate
      }
      return null
    },
  }
}

export default defineConfig({
  plugins: [
    resolveAtAlias(),
    react(),
    visualizer({
      open: false,
      gzipSize: true,
      brotliSize: true,
      filename: 'dist/stats.html',
    }),
  ],
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('node_modules/react-dom') || id.includes('node_modules/react/') || id.includes('node_modules/react-router-dom')) {
            return 'react-vendor'
          }
          if (id.includes('node_modules/@radix-ui') || id.includes('node_modules/lucide-react')) {
            return 'ui-vendor'
          }
        },
      },
    },
  },
})