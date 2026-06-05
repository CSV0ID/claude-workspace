import React, { useCallback, useEffect, useState } from 'react'
import { api } from './api.js'
import ScanForm from './components/ScanForm.jsx'
import ScanList from './components/ScanList.jsx'
import ScanDetail from './components/ScanDetail.jsx'

export default function App() {
  const [scans, setScans] = useState([])
  const [selectedId, setSelectedId] = useState(null)
  const [health, setHealth] = useState('…')

  const refresh = useCallback(async () => {
    try {
      const rows = await api.listScans({ limit: 100 })
      setScans(rows)
    } catch {
      /* backend down; health indicator shows it */
    }
  }, [])

  // Initial load + health check, then poll the list every 3s so running scans
  // update their status badge without a manual refresh.
  useEffect(() => {
    api.health().then(() => setHealth('ok')).catch(() => setHealth('down'))
    refresh()
    const t = setInterval(refresh, 3000)
    return () => clearInterval(t)
  }, [refresh])

  function onCreated(id) {
    setSelectedId(id)
    refresh()
  }

  function onDeleted(id) {
    if (selectedId === id) setSelectedId(null)
    refresh()
  }

  return (
    <div className="app">
      <header className="topbar">
        <h1>🛡️ AI Pentest / Recon Assistant</h1>
        <span className={'health ' + (health === 'ok' ? 'ok' : 'down')}>
          backend: {health}
        </span>
      </header>

      <div className="layout">
        <div>
          <div className="panel">
            <h2>New scan</h2>
            <ScanForm onCreated={onCreated} />
          </div>
          <div className="panel" style={{ marginTop: '1rem' }}>
            <h2>Scans</h2>
            <ScanList scans={scans} selectedId={selectedId} onSelect={setSelectedId} />
          </div>
        </div>

        <div className="panel">
          <ScanDetail scanId={selectedId} onDeleted={onDeleted} onStatus={refresh} />
        </div>
      </div>
    </div>
  )
}
