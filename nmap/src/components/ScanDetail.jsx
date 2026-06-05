import React, { useEffect, useState } from 'react'
import { api } from '../api.js'
import FindingsTable from './FindingsTable.jsx'

const SEVS = ['critical', 'high', 'medium', 'low', 'info']

// Detail panel for one scan: status, severity counts, findings table, and the
// rendered HTML report (in a sandboxed iframe). Polls while the scan runs.
export default function ScanDetail({ scanId, onDeleted, onStatus }) {
  const [scan, setScan] = useState(null)
  const [findings, setFindings] = useState([])
  const [report, setReport] = useState('')
  const [tab, setTab] = useState('findings')

  useEffect(() => {
    if (!scanId) return
    let stop = false
    let timer

    async function poll() {
      try {
        const s = await api.getScan(scanId)
        if (stop) return
        setScan(s)
        onStatus?.(s)
        if (s.status === 'done' || s.status === 'failed') {
          const f = await api.getFindings(scanId).catch(() => [])
          if (!stop) setFindings(f)
          if (s.status === 'done') {
            const r = await api.getReport(scanId, 'html').catch(() => '')
            if (!stop) setReport(r)
          }
        } else {
          timer = setTimeout(poll, 2000) // queued/running -> keep polling
        }
      } catch {
        /* scan may have been deleted; stop polling */
      }
    }

    setScan(null); setFindings([]); setReport(''); setTab('findings')
    poll()
    return () => { stop = true; clearTimeout(timer) }
  }, [scanId])

  if (!scanId) return <div className="detail-empty">Select a scan to see details.</div>
  if (!scan) return <p className="muted">Loading…</p>

  const counts = scan.sev_counts || {}

  async function del() {
    if (!confirm(`Delete scan #${scan.id}?`)) return
    await api.deleteScan(scan.id)
    onDeleted?.(scan.id)
  }

  return (
    <div>
      <div className="toolbar">
        <h2 style={{ margin: 0 }}>#{scan.id} {scan.target}</h2>
        <span className={'status ' + scan.status}>{scan.status}</span>
        <span className="muted">{scan.mode}{scan.provider ? ` · ${scan.provider}` : ''}</span>
        <span style={{ flex: 1 }} />
        <button className="btn danger" onClick={del}>Delete</button>
      </div>

      {scan.error && <p style={{ color: 'var(--crit)' }}>Error: {scan.error}</p>}
      {scan.stopped_reason && <p className="muted">Stopped: {scan.stopped_reason}</p>}

      <div className="sev-counts">
        {SEVS.map((sev) => (
          <span key={sev} className={'badge ' + sev}>{sev}: {counts[sev] || 0}</span>
        ))}
      </div>

      <div className="toolbar">
        <button className={'btn ghost' + (tab === 'findings' ? ' active' : '')} onClick={() => setTab('findings')}>Findings ({findings.length})</button>
        <button className={'btn ghost' + (tab === 'report' ? ' active' : '')} onClick={() => setTab('report')} disabled={!report}>Report</button>
        {report && (
          <a className="btn ghost" href={`/scans/${scan.id}/report?format=md`} target="_blank" rel="noreferrer">Download .md</a>
        )}
      </div>

      {tab === 'findings'
        ? <FindingsTable findings={findings} />
        : report
          ? <iframe className="report-frame" srcDoc={report} sandbox="" title="report" />
          : <p className="muted">Report available once the scan is done.</p>}
    </div>
  )
}
