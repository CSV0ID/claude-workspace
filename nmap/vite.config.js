import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Dev server proxies API calls to the FastAPI backend on :8000, so the browser
// makes same-origin requests and no CORS config is needed on the backend.
// In production, serve the built `dist/` behind the same host as the API (or a
// reverse proxy) — see RUN.md §5.
const API = process.env.VITE_API_TARGET || 'http://localhost:8000'

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/scans': API,
      '/health': API,
    },
  },
})
