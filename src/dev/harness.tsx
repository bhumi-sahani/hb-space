/* eslint-disable react-refresh/only-export-components -- standalone dev entry point, not a module */
/**
 * DEV-ONLY browser harness: the real vault UI and real Web Crypto / Argon2id,
 * wired to the in-memory test backend instead of Supabase. No network calls.
 * Served by `npm run dev` at /dev/harness.html; it is not an input of the
 * production build and refuses to run outside dev mode.
 */
import { StrictMode, useEffect, useState } from 'react'
import { createRoot } from 'react-dom/client'
import '../styles/global.css'
import { toByteaHex } from '../lib/crypto/bytes'
import { MemoryBackend } from '../services/testing/memoryBackend'
import { VaultSecurityPanel } from '../screens/settings/VaultSecurityPanel'
import { lockVault } from '../services/vaultSession'
import { VaultScreen } from '../screens/vault/VaultScreen'
import { useRoute } from '../lib/router'

const VAULT = '00000000-0000-4000-8000-00000000d3a0'
const backend = new MemoryBackend(VAULT)

function ServerView() {
  const [, setTick] = useState(0)
  useEffect(() => {
    const id = setInterval(() => setTick((n) => n + 1), 1000)
    return () => clearInterval(id)
  }, [])
  const objects = [...backend.objects.entries()]
  return (
    <section className="panel stack" aria-labelledby="server-view">
      <h2 id="server-view" className="panel__title">
        What the fake server stores
      </h2>
      <p className="muted small">
        {backend.envelopes.size} key envelope(s) · {backend.media.size} media row(s) · {backend.folders.size} folder(s) ·{' '}
        {objects.length} object(s)
      </p>
      <ul className="item-list" aria-label="Stored objects">
        {objects.map(([path, bytes]) => (
          <li key={path} className="item">
            <div className="item__body">
              <span className="item__title" data-testid="object-path">
                {path}
              </span>
              <span className="item__meta" data-testid="object-head">
                {bytes.length} bytes · first 24: {toByteaHex(bytes.subarray(0, 24))}
              </span>
            </div>
          </li>
        ))}
      </ul>
    </section>
  )
}

function Harness() {
  const [route, navigate] = useRoute()
  const vaultRoute = route.name === 'vault' ? route : ({ name: 'vault', folderId: null } as const)
  return (
    <div className="shell">
      <main className="shell__main">
        <div className="alert alert--warning">DEV HARNESS: in-memory fake backend, no network. Synthetic files only.</div>
        <div className="toolbar">
          <button type="button" className="btn btn--secondary" onClick={() => navigate({ name: 'vault', folderId: null })}>
            <span>Vault</span>
          </button>
          <button type="button" className="btn btn--secondary" onClick={lockVault}>
            <span>Lock Vault</span>
          </button>
        </div>
        <VaultScreen
          vaultId={VAULT}
          backend={backend}
          route={vaultRoute}
          navigate={navigate}
        />
        <section className="panel">
          <h2 className="panel__title">Vault security</h2>
          <VaultSecurityPanel vaultId={VAULT} backend={backend} />
        </section>
        <ServerView />
      </main>
    </div>
  )
}

if (!import.meta.env.DEV) throw new Error('The dev harness only runs under `npm run dev`.')

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <Harness />
  </StrictMode>,
)
