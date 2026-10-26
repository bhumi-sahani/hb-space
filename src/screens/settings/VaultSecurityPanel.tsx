import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Alert, Button, LockIcon, SecretField, Spinner } from '../../components/ui'
import { useVaultStatus } from '../../hooks/useVaultStatus'
import { DEFAULT_ARGON2_PARAMS } from '../../lib/crypto/kdf'
import type { VaultBackend } from '../../services/vaultBackend'
import {
  changePassphrase,
  KEY_MESSAGES,
  loadKeyState,
  prepareNewRecoveryCode,
  VaultKeyError,
  type KeyState,
} from '../../services/vaultKeys'
import { lockVault } from '../../services/vaultSession'
import { takeSecrets } from '../vault/formFields'

interface VaultSecurityPanelProps {
  vaultId: string | null
  backend: VaultBackend | null
}

type PendingCode = { recoveryCode: string; commit(): Promise<void>; discard(): void }

function messageOf(error: unknown): string {
  return error instanceof VaultKeyError ? error.userMessage : KEY_MESSAGES.generic
}

export function VaultSecurityPanel({ vaultId, backend }: VaultSecurityPanelProps) {
  const status = useVaultStatus()
  const [keys, setKeys] = useState<KeyState | 'loading' | 'error'>('loading')
  const [mode, setMode] = useState<'idle' | 'change' | 'recovery'>('idle')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [pendingCode, setPendingCode] = useState<PendingCode | null>(null)
  const [saved, setSaved] = useState(false)

  const refresh = useCallback(async () => {
    if (!vaultId || !backend) return
    try {
      setKeys(await loadKeyState(backend, vaultId))
    } catch {
      setKeys('error')
    }
  }, [vaultId, backend])

  useEffect(() => {
    void refresh()
  }, [refresh])

  useEffect(() => () => pendingCode?.discard(), [pendingCode])

  if (!vaultId || !backend) return <p className="muted">Vault security settings are available to approved members.</p>

  async function handleChange(event: FormEvent<HTMLFormElement>) {
    const { current, next, confirm } = takeSecrets(event, ['current', 'next', 'confirm'])
    if (busy || !vaultId || !backend) return
    if (next !== confirm) {
      setError(KEY_MESSAGES.mismatch)
      return
    }
    setBusy(true)
    setError(null)
    try {
      await changePassphrase(backend, vaultId, current, next)
      setMode('idle')
      setNotice('Vault passphrase changed. Tell the other member the new passphrase in person. Existing items were not re-encrypted and still open.')
      await refresh()
    } catch (err) {
      setError(messageOf(err))
    } finally {
      setBusy(false)
    }
  }

  async function handleNewCode(event: FormEvent<HTMLFormElement>) {
    const { current } = takeSecrets(event, ['current'])
    if (busy || !vaultId || !backend) return
    setBusy(true)
    setError(null)
    try {
      setPendingCode(await prepareNewRecoveryCode(backend, vaultId, current))
      setSaved(false)
    } catch (err) {
      setError(messageOf(err))
    } finally {
      setBusy(false)
    }
  }

  async function commitCode() {
    if (!pendingCode || !saved) return
    setBusy(true)
    setError(null)
    try {
      await pendingCode.commit()
      setPendingCode(null)
      setMode('idle')
      setNotice('New recovery code saved. The old code no longer works.')
      await refresh()
    } catch (err) {
      setError(messageOf(err))
      setPendingCode(null)
    } finally {
      setBusy(false)
    }
  }

  const ready = keys !== 'loading' && keys !== 'error' && keys.status === 'ready' ? keys : null
  const kdf = ready?.passphrase.kdfParams ?? DEFAULT_ARGON2_PARAMS

  return (
    <div className="stack">
      <dl className="facts">
        <dt>Vault status</dt>
        <dd>{status === 'unlocked' ? '🔒 Unlocked on this device' : 'Locked'}</dd>
        <dt>Key status</dt>
        <dd>
          {keys === 'loading' ? (
            <Spinner label="Loading key status" />
          ) : keys === 'error' ? (
            'Could not load key status'
          ) : keys.status === 'uninitialized' ? (
            'Not set up yet'
          ) : keys.status === 'inconsistent' ? (
            'Inconsistent: the vault will not open'
          ) : (
            <>
              Passphrase key (revision {keys.passphrase.revision})
              {keys.recovery ? ` · Recovery code (revision ${keys.recovery.revision})` : ' · No recovery code'}
            </>
          )}
        </dd>
        <dt>Encryption</dt>
        <dd>
          AES-256-GCM, format v1, per-item keys · Argon2id ({kdf.m / 1024} MiB, {kdf.t} passes, 1 lane)
        </dd>
      </dl>

      {notice && <Alert tone="info">{notice}</Alert>}

      {status === 'unlocked' && (
        <Button variant="secondary" icon={<LockIcon />} onClick={lockVault}>
          Lock vault
        </Button>
      )}

      {ready && mode === 'idle' && (
        <div className="row">
          <Button variant="secondary" onClick={() => { setMode('change'); setError(null); setNotice(null) }}>
            Change vault passphrase
          </Button>
          <Button variant="ghost" onClick={() => { setMode('recovery'); setError(null); setNotice(null) }}>
            {ready.recovery ? 'Create a new recovery code' : 'Create a recovery code'}
          </Button>
        </div>
      )}

      {ready && mode === 'change' && (
        <form className="auth-form sub-panel" onSubmit={handleChange} noValidate>
          <SecretField label="Current vault passphrase" name="current" autoComplete="current-password" disabled={busy} required />
          <SecretField label="New vault passphrase" name="next" autoComplete="new-password" disabled={busy} required />
          <SecretField label="Repeat new passphrase" name="confirm" autoComplete="new-password" disabled={busy} required />
          <p className="muted small">
            The vault key itself does not change, so nothing is re-encrypted. The other member will need the new
            passphrase.
          </p>
          {error && <Alert tone="error">{error}</Alert>}
          <div className="row">
            <Button type="submit" busy={busy}>
              Change passphrase
            </Button>
            <Button variant="ghost" disabled={busy} onClick={() => setMode('idle')}>
              Cancel
            </Button>
          </div>
        </form>
      )}

      {ready && mode === 'recovery' && !pendingCode && (
        <form className="auth-form sub-panel" onSubmit={handleNewCode} noValidate>
          <SecretField label="Vault passphrase" name="current" autoComplete="current-password" disabled={busy} required />
          <p className="muted small">A new code replaces the old one. The old code stops working once you confirm.</p>
          {error && <Alert tone="error">{error}</Alert>}
          <div className="row">
            <Button type="submit" busy={busy}>
              Continue
            </Button>
            <Button variant="ghost" disabled={busy} onClick={() => setMode('idle')}>
              Cancel
            </Button>
          </div>
        </form>
      )}

      {pendingCode && (
        <div className="stack sub-panel">
          <p>Write this code down and keep it offline. It is shown once.</p>
          <p className="recovery-code" aria-label="Recovery code">
            {pendingCode.recoveryCode}
          </p>
          <label className="checkbox">
            <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} disabled={busy} />
            <span>I have written down the new recovery code.</span>
          </label>
          {error && <Alert tone="error">{error}</Alert>}
          <div className="row">
            <Button disabled={!saved} busy={busy} onClick={() => void commitCode()}>
              Save new code
            </Button>
            <Button
              variant="ghost"
              disabled={busy}
              onClick={() => {
                pendingCode.discard()
                setPendingCode(null)
                setMode('idle')
              }}
            >
              Cancel (keep the old code)
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
