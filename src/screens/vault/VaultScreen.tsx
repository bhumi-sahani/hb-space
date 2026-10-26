import { useCallback, useEffect, useState, type FormEvent } from 'react'
import { Alert, Button, LockIcon, SecretField, Spinner } from '../../components/ui'
import { useVaultStatus } from '../../hooks/useVaultStatus'
import type { VaultBackend } from '../../services/vaultBackend'
import {
  KEY_MESSAGES,
  loadKeyState,
  prepareNewVault,
  resetPassphraseWithRecoveryCode,
  unlockWithPassphrase,
  VaultKeyError,
  type KeyState,
  type PreparedVault,
} from '../../services/vaultKeys'
import { takeSecrets } from './formFields'
import { VaultHome } from './VaultHome'
import { navigate as defaultNavigate, type Route } from '../../lib/router'

const ROOT_ROUTE_VAULT: Extract<Route, { name: 'vault' }> = { name: 'vault', folderId: null }

interface VaultScreenProps {
  vaultId: string
  backend: VaultBackend
  /** Where the user is (from the URL). Shown only after unlock; a locked vault always shows the unlock screen. */
  route?: Extract<Route, { name: 'vault' }>
  navigate?: (route: Route, options?: { replace?: boolean }) => void
}

type Load = { status: 'loading' } | { status: 'error'; message: string } | { status: 'ok'; keys: KeyState }

function messageOf(error: unknown): string {
  return error instanceof VaultKeyError ? error.userMessage : KEY_MESSAGES.generic
}

/** Logged in != unlocked. This screen decides between setup, locked, and unlocked. */
export function VaultScreen({ vaultId, backend, route = ROOT_ROUTE_VAULT, navigate = defaultNavigate }: VaultScreenProps) {
  const status = useVaultStatus()
  const [load, setLoad] = useState<Load>({ status: 'loading' })

  const refresh = useCallback(async () => {
    setLoad({ status: 'loading' })
    try {
      setLoad({ status: 'ok', keys: await loadKeyState(backend, vaultId) })
    } catch (error) {
      setLoad({ status: 'error', message: messageOf(error) })
    }
  }, [backend, vaultId])

  useEffect(() => {
    if (status === 'locked') void refresh()
  }, [status, refresh])

  if (status === 'unlocked') return <VaultHome vaultId={vaultId} backend={backend} route={route} navigate={navigate} />

  if (load.status === 'loading') {
    return (
      <div className="panel inline-status">
        <Spinner label="Checking the vault" />
      </div>
    )
  }
  if (load.status === 'error') {
    return (
      <section className="panel stack" aria-labelledby="vault-load-error">
        <h2 id="vault-load-error" className="panel__title">
          Couldn't open the vault
        </h2>
        <Alert tone="error">{load.message}</Alert>
        <Button variant="secondary" onClick={() => void refresh()}>
          Try again
        </Button>
      </section>
    )
  }
  if (load.keys.status === 'inconsistent') {
    return (
      <section className="panel stack" aria-labelledby="vault-inconsistent">
        <h2 id="vault-inconsistent" className="panel__title">
          The vault keys look wrong
        </h2>
        <Alert tone="error">
          The stored key information is incomplete or inconsistent, so the vault will not open. Nothing has been changed.
          Do not upload anything; check the key rows in the Supabase dashboard.
        </Alert>
      </section>
    )
  }
  if (load.keys.status === 'uninitialized') {
    return <SetupVault vaultId={vaultId} backend={backend} onCancelled={() => void refresh()} />
  }
  return <LockedVault vaultId={vaultId} backend={backend} hasRecovery={load.keys.recovery !== null} />
}

// ---------------------------------------------------------------------------

function LockedVault({
  vaultId,
  backend,
  hasRecovery,
}: {
  vaultId: string
  backend: VaultBackend
  hasRecovery: boolean
}) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [useRecovery, setUseRecovery] = useState(false)

  async function handleUnlock(event: FormEvent<HTMLFormElement>) {
    const { passphrase } = takeSecrets(event, ['passphrase'])
    if (busy) return
    if (!passphrase) {
      setError('Enter the vault passphrase.')
      return
    }
    setBusy(true)
    setError(null)
    try {
      await unlockWithPassphrase(backend, vaultId, passphrase)
    } catch (err) {
      setError(messageOf(err))
      setBusy(false)
    }
  }

  async function handleRecovery(event: FormEvent<HTMLFormElement>) {
    const { code, next, confirm } = takeSecrets(event, ['code', 'next', 'confirm'])
    if (busy) return
    if (next !== confirm) {
      setError(KEY_MESSAGES.mismatch)
      return
    }
    setBusy(true)
    setError(null)
    try {
      await resetPassphraseWithRecoveryCode(backend, vaultId, code, next)
    } catch (err) {
      setError(messageOf(err))
      setBusy(false)
    }
  }

  return (
    <section className="panel stack vault-lock" aria-labelledby="vault-locked-title">
      <div className="vault-lock__badge" aria-hidden="true">
        <LockIcon />
      </div>
      <h2 id="vault-locked-title" className="panel__title vault-lock__title">
        Vault locked
      </h2>
      {!useRecovery ? (
        <form className="auth-form" onSubmit={handleUnlock} noValidate>
          <SecretField
            label="Vault passphrase"
            name="passphrase"
            autoComplete="current-password"
            hint="This is separate from your login password."
            disabled={busy}
            required
          />
          {error && <Alert tone="error">{error}</Alert>}
          <Button type="submit" block busy={busy} icon={<LockIcon />}>
            {busy ? 'Unlocking…' : 'Unlock Vault'}
          </Button>
        </form>
      ) : (
        <form className="auth-form" onSubmit={handleRecovery} noValidate>
          <p className="muted small">
            Enter the recovery code you wrote down when the vault was created, and choose a new vault passphrase. Tell
            the other member the new passphrase in person.
          </p>
          <SecretField label="Recovery code" name="code" autoComplete="off" disabled={busy} required />
          <SecretField label="New vault passphrase" name="next" autoComplete="new-password" disabled={busy} required />
          <SecretField label="Repeat new passphrase" name="confirm" autoComplete="new-password" disabled={busy} required />
          {error && <Alert tone="error">{error}</Alert>}
          <Button type="submit" block busy={busy}>
            {busy ? 'Working…' : 'Reset passphrase and unlock'}
          </Button>
        </form>
      )}
      {hasRecovery && (
        <Button
          variant="ghost"
          disabled={busy}
          onClick={() => {
            setUseRecovery((v) => !v)
            setError(null)
          }}
        >
          {useRecovery ? 'Use the vault passphrase instead' : 'Forgot the passphrase? Use the recovery code'}
        </Button>
      )}
    </section>
  )
}

// ---------------------------------------------------------------------------

function SetupVault({ vaultId, backend, onCancelled }: { vaultId: string; backend: VaultBackend; onCancelled: () => void }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [prepared, setPrepared] = useState<PreparedVault | null>(null)
  const [saved, setSaved] = useState(false)

  useEffect(() => () => prepared?.discard(), [prepared])

  async function handlePrepare(event: FormEvent<HTMLFormElement>) {
    const { passphrase, confirm } = takeSecrets(event, ['passphrase', 'confirm'])
    if (busy) return
    if (passphrase !== confirm) {
      setError(KEY_MESSAGES.mismatch)
      return
    }
    setBusy(true)
    setError(null)
    try {
      setPrepared(await prepareNewVault(backend, vaultId, passphrase))
    } catch (err) {
      setError(messageOf(err))
    } finally {
      setBusy(false)
    }
  }

  async function handleCommit() {
    if (!prepared || !saved) return
    setBusy(true)
    setError(null)
    try {
      await prepared.commit() // unlocks on success; this component then unmounts
    } catch (err) {
      setError(messageOf(err))
      setPrepared(null)
      setSaved(false)
      setBusy(false)
    }
  }

  if (prepared) {
    return (
      <section className="panel stack" aria-labelledby="vault-recovery-title">
        <h2 id="vault-recovery-title" className="panel__title">
          Write down your recovery code
        </h2>
        <p>
          This code is shown <strong>once</strong>. It can reset the vault passphrase if it is ever forgotten. Write it on
          paper and keep it somewhere safe and offline. Do not screenshot it, email it, or store it in a chat.
        </p>
        <p className="recovery-code" aria-label="Recovery code">
          {prepared.recoveryCode}
        </p>
        <Alert tone="warning">
          If both the vault passphrase and this recovery code are lost, the photos cannot be recovered by anyone,
          including the people who run the servers.
        </Alert>
        <label className="checkbox">
          <input type="checkbox" checked={saved} onChange={(e) => setSaved(e.target.checked)} disabled={busy} />
          <span>I have written down the recovery code and stored it safely.</span>
        </label>
        {error && <Alert tone="error">{error}</Alert>}
        <Button block disabled={!saved} busy={busy} onClick={() => void handleCommit()}>
          Finish setup
        </Button>
        <Button
          variant="ghost"
          disabled={busy}
          onClick={() => {
            prepared.discard()
            setPrepared(null)
            setSaved(false)
            onCancelled()
          }}
        >
          Cancel (nothing has been saved)
        </Button>
      </section>
    )
  }

  return (
    <section className="panel stack" aria-labelledby="vault-setup-title">
      <h2 id="vault-setup-title" className="panel__title">
        Set up vault encryption
      </h2>
      <p>
        Choose a vault passphrase. It encrypts everything in the vault on this device before upload. It is separate
        from your login password and is never sent to the server.
      </p>
      <ul className="notice-list small">
        <li>Both members use the same vault passphrase. Agree on it in person; don't send it by message or email.</li>
        <li>Any passphrase works. A longer one is much harder for anyone else to guess.</li>
        <li>You'll get a one-time recovery code next.</li>
      </ul>
      <form className="auth-form" onSubmit={handlePrepare} noValidate>
        <SecretField label="Vault passphrase" name="passphrase" autoComplete="new-password" disabled={busy} required />
        <SecretField label="Repeat passphrase" name="confirm" autoComplete="new-password" disabled={busy} required />
        {error && <Alert tone="error">{error}</Alert>}
        <Button type="submit" block busy={busy}>
          {busy ? 'Creating keys…' : 'Create vault key'}
        </Button>
      </form>
    </section>
  )
}
