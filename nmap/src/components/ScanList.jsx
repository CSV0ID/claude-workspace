import React from 'react'

// List of scans (newest first). Clicking selects one for the detail panel.
export default function ScanList({ scans, selectedId, onSelect }) {
  if (!scans.length) {
    return <p className="muted">No scans yet. Queue one on the left.</p>
  }
  return (
    <div>
      {scans.map((s) => (
        <div
          key={s.id}
          className={'scan-row' + (s.id === selectedId ? ' active' : '')}
          onClick={() => onSelect(s.id)}
        >
          <div>
            <div className="target">#{s.id} {s.target}</div>
            <div className="meta">{s.mode}{s.provider ? ` · ${s.provider}` : ''} · {s.steps} steps</div>
          </div>
          <span className={'status ' + s.status}>{s.status}</span>
        </div>
      ))}
    </div>
  )
}
