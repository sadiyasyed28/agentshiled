import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

const backendTarget = process.env.VITE_BACKEND_TARGET || process.env.VITE_API_URL || 'http://127.0.0.1:8000'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  build: {
    emptyOutDir: false,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: backendTarget,
        changeOrigin: true,
        secure: false,
      },
      '/health': {
        target: backendTarget,
        changeOrigin: true,
        secure: false,
      },
      '/events': {
        target: backendTarget,
        changeOrigin: true,
        secure: false,
      },
      '/incident': {
        target: backendTarget,
        changeOrigin: true,
        secure: false,
      },
      '/audit': {
        target: backendTarget,
        changeOrigin: true,
        secure: false,
      },
      '/authorize': {
        target: backendTarget,
        changeOrigin: true,
        secure: false,
      },
      '/execute': {
        target: backendTarget,
        changeOrigin: true,
        secure: false,
      },
      '/metrics': {
        target: backendTarget,
        changeOrigin: true,
        secure: false,
      },
    },
  },
})
