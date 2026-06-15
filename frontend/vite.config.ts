import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { visualizer } from 'rollup-plugin-visualizer'
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
  plugins: [
    rewriteAliasPlugin(),
    react(),
    visualizer({
      open: false,
      gzipSize: true,
      brotliSize: true,
      filename: 'dist/stats.html',
    }),
  ],
  resolve: {
    tsconfigPaths: true,
  },
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
