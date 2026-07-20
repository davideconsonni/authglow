import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { visualizer } from 'rollup-plugin-visualizer'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

function resolveAtAlias() {
  const src = join(__dirname, 'src')
  return {
    name: 'resolve-at-alias',
    resolveId(id: string) {
      if (id.startsWith('@/')) {
        return join(src, id.slice(2))
      }
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
