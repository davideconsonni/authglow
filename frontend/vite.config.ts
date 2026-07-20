import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { visualizer } from 'rollup-plugin-visualizer'
import { resolve } from 'node:path'

const srcDir = resolve(process.cwd(), 'src')

export default defineConfig({
  plugins: [
    react(),
    visualizer({
      open: false,
      gzipSize: true,
      brotliSize: true,
      filename: 'dist/stats.html',
    }),
  ],
  resolve: {
    alias: {
      '@': srcDir,
    },
  },
  build: {
    rolldownOptions: {
      resolve: {
        alias: {
          '@': srcDir,
        },
      },
    },
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
})