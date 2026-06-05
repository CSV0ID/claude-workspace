// Thin axios wrapper over the FastAPI backend. Paths are relative so the Vite
// dev proxy (vite.config.js) forwards them to the backend on :8000.
import axios from 'axios'

// In dev, baseURL is '' so the Vite proxy forwards relative paths to :8000.
// In production (e.g. Vercel), set VITE_API_BASE to the backend's public URL.
const http = axios.create({
  baseURL: import.meta.env.VITE_API_BASE || '',
  timeout: 30000,
})

export const api = {
  health: () => http.get('/health').then((r) => r.data),

  listScans: (params = {}) =>
    http.get('/scans', { params }).then((r) => r.data),

  createScan: (body) =>
    http.post('/scans', body).then((r) => r.data),

  getScan: (id) => http.get(`/scans/${id}`).then((r) => r.data),

  getFindings: (id) =>
    http.get(`/scans/${id}/findings`).then((r) => r.data),

  // report is rendered HTML/markdown text, not JSON
  getReport: (id, format = 'html') =>
    http
      .get(`/scans/${id}/report`, { params: { format }, responseType: 'text' })
      .then((r) => r.data),

  deleteScan: (id) => http.delete(`/scans/${id}`).then((r) => r.data),
}
