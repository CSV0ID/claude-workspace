import React from 'react'

const ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

// Structured findings, sorted by severity (critical first).
export default function FindingsTable({ findings }) {
  if (!findings.length) {
    return <p className="muted">No structured findings (binaries may be missing, or nothing found).</p>
  }
  const sorted = [...findings].sort(
    (a, b) => (ORDER[a.severity] ?? 9) - (ORDER[b.severity] ?? 9))
  return (
    <table>
      <thead>
        <tr><th>Severity</th><th>Tool</th><th>Name</th></tr>
      </thead>
      <tbody>
        {sorted.map((f) => (
          <tr key={f.id}>
            <td><span className={'badge ' + f.severity}>{f.severity}</span></td>
            <td>{f.tool}</td>
            <td title={f.detail}>{f.name}</td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
