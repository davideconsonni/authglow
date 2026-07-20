import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { visualizer } from 'rollup-plugin-visualizer'
import { join } from 'node:path'

function resolveAtAlias() {
  const src = join(process.cwd(), 'src')
  console.error('[resolve-at-alias] cwd:', process.cwd())
  console.error('[resolve-at-alias] src:', src)
  return {
    name: 'resolve-at-alias',
    async resolveId(id: string, importer: string | undefined, opts: { skipSelf?: boolean }) {
      if (!id.startsWith('@/')) return null
      const absolute = join(src, id.slice(2))
      const result = await this.resolve(absolute, importer, { ...opts, skipSelf: true })
      if (!result) console.error('[resolve-at-alias] FAILED:', id, '->', absolute)
      return result || null
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
