import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { visualizer } from 'rollup-plugin-visualizer'

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
  server: {
    // Allow the dev server to be reached as host.docker.internal (ZAP Docker scans).
    allowedHosts: ['localhost', 'host.docker.internal'],
    // Same-origin API proxy: lets a browser-based scan avoid cross-origin/CORS.
    // Unused during normal `npm run dev` (the SPA calls VITE_API_URL directly).
    // `/oauth2/authorize` and `/oauth2/device/verify` are client-side SPA pages
    // (see main.py `_SPA_OAUTH_PAGES`) — they must NOT be proxied to the API.
    proxy: {
      '/api': 'http://localhost:8001',
      '^/oauth2/(?!authorize|device/verify)': 'http://localhost:8001',
      '/.well-known': 'http://localhost:8001',
      '/health': 'http://localhost:8001',
    },
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