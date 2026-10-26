import { useState } from 'react'
import { Alert, Button } from '../../components/ui'
import { supabase } from '../../lib/supabase'
import { runAccessSelfTest, type ProbeResult } from '../../services/accessSelfTest'

interface AccessCheckPanelProps {
  vaultId: string | null
  run?: (vaultId: string | null) => Promise<ProbeResult[]>
}

const defaultRun = (vaultId: string | null) =>
  supabase ? runAccessSelfTest(supabase, vaultId) : Promise.resolve<ProbeResult[]>([])

export function AccessCheckPanel({ vaultId, run = defaultRun }: AccessCheckPanelProps) {
  const [running, setRunning] = useState(false)
  const [results, setResults] = useState<ProbeResult[] | null>(null)

  async function handleRun() {
    setRunning(true)
    setResults(null)
    try {
      setResults(await run(vaultId))
    } finally {
      setRunning(false)
    }
  }

  const failures = results?.filter((r) => r.outcome === 'fail').length ?? 0

  return (
    <div className="stack">
      <p className="muted small">
        Probes the live server with your current session: things you must not be able to do are attempted and must be
        refused.
        {vaultId && ' As a member, it also uploads, downloads, and then deletes a tiny file of random bytes (never a photo).'}
      </p>
      <Button variant="secondary" busy={running} onClick={handleRun}>
        {running ? 'Checking…' : 'Run access check'}
      </Button>
      {results && (
        <>
          {failures === 0 ? (
            <Alert tone="info">All {results.length} checks behaved as expected for this account.</Alert>
          ) : (
            <Alert tone="error">
              {failures} of {results.length} checks failed. Do not store anything until this is fixed.
            </Alert>
          )}
          <ul className="check-list" aria-label="Access check results">
            {results.map((result) => (
              <li key={result.name} className={`check check--${result.outcome}`}>
                <span className="check__mark" aria-hidden="true">
                  {result.outcome === 'pass' ? '✓' : result.outcome === 'fail' ? '✕' : '–'}
                </span>
                <span>
                  <span className="visually-hidden">{result.outcome}: </span>
                  {result.name}
                  {result.detail && <span className="check__detail">{result.detail}</span>}
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </div>
  )
}
