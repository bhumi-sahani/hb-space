import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react'
import { Alert, Button, PasskeyIcon, SecretField, Spinner, TextField } from '../../components/ui'
import type { AuthResult, AuthUser } from '../../services/auth'
import {
  addPasskeyWithPasswordConfirmation,
  deletePasskey,
  listPasskeys,
  PASSKEY_NAME_MAX,
  renamePasskey,
  type PasskeySummary,
} from '../../services/passkeys'

export interface PasskeyService {
  list: typeof listPasskeys
  add: (user: AuthUser, password: string, signal: AbortSignal) => Promise<AuthResult>
  rename: (id: string, name: string) => Promise<AuthResult>
  remove: (id: string) => Promise<AuthResult>
}

const realService: PasskeyService = {
  list: listPasskeys,
  add: addPasskeyWithPasswordConfirmation,
  rename: renamePasskey,
  remove: deletePasskey,
}

type ListState = { status: 'loading' } | { status: 'ready'; passkeys: PasskeySummary[] } | { status: 'error'; message: string }

type ItemMode = { id: string; kind: 'rename' | 'confirm-delete' } | null

const dateFormat = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium' })

function formatDate(value: string | null): string {
  if (!value) return 'never'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? 'unknown' : dateFormat.format(date)
}

interface PasskeyManagerProps {
  user: AuthUser
  supported: boolean
  service?: PasskeyService
}

export function PasskeyManager({ user, supported, service = realService }: PasskeyManagerProps) {
  const [list, setList] = useState<ListState>({ status: 'loading' })
  const [adding, setAdding] = useState(false)
  const [password, setPassword] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [mode, setMode] = useState<ItemMode>(null)
  const [draftName, setDraftName] = useState('')
  const abortRef = useRef<AbortController | null>(null)

  const refresh = useCallback(async () => {
    const result = await service.list()
    setList(result.ok ? { status: 'ready', passkeys: result.passkeys } : { status: 'error', message: result.message })
  }, [service])

  useEffect(() => {
    if (supported) void refresh()
    return () => abortRef.current?.abort()
  }, [supported, refresh])

  if (!supported) {
    return (
      <p className="muted">
        Passkeys are not available here. They need to be enabled for this site, and your browser must support them
        over HTTPS.
      </p>
    )
  }

  async function handleAdd(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (busy) return
    if (!password) {
      setError('Enter your account password to continue.')
      return
    }
    setBusy(true)
    setError(null)
    setNotice(null)
    const controller = new AbortController()
    abortRef.current = controller
    const result = await service.add(user, password, controller.signal)
    abortRef.current = null
    setPassword('')
    setBusy(false)
    if (!result.ok) {
      setError(result.message)
      return
    }
    setAdding(false)
    setNotice('Passkey added. You can now sign in with it on this device.')
    await refresh()
  }

  async function handleRename(id: string) {
    setBusy(true)
    setError(null)
    const result = await service.rename(id, draftName)
    setBusy(false)
    if (!result.ok) {
      setError(result.message)
      return
    }
    setMode(null)
    await refresh()
  }

  async function handleDelete(id: string) {
    setBusy(true)
    setError(null)
    const result = await service.remove(id)
    setBusy(false)
    if (!result.ok) {
      setError(result.message)
      return
    }
    setMode(null)
    setNotice('Passkey removed.')
    await refresh()
  }

  return (
    <div className="stack">
      {error && <Alert tone="error">{error}</Alert>}
      {notice && !error && <Alert tone="info">{notice}</Alert>}

      {list.status === 'loading' && (
        <div className="inline-status">
          <Spinner label="Loading passkeys" />
        </div>
      )}
      {list.status === 'error' && <Alert tone="error">{list.message}</Alert>}
      {list.status === 'ready' && list.passkeys.length === 0 && <p className="muted">No passkeys yet.</p>}
      {list.status === 'ready' && list.passkeys.length > 0 && (
        <ul className="item-list" aria-label="Your passkeys">
          {list.passkeys.map((passkey) => (
            <li key={passkey.id} className="item">
              {mode?.id === passkey.id && mode.kind === 'rename' ? (
                <form
                  className="stack"
                  onSubmit={(event) => {
                    event.preventDefault()
                    void handleRename(passkey.id)
                  }}
                >
                  <TextField
                    label="Passkey name"
                    value={draftName}
                    maxLength={PASSKEY_NAME_MAX}
                    onChange={(event) => setDraftName(event.target.value)}
                    autoFocus
                  />
                  <div className="row">
                    <Button type="submit" variant="secondary" busy={busy}>
                      Save
                    </Button>
                    <Button variant="ghost" onClick={() => setMode(null)} disabled={busy}>
                      Cancel
                    </Button>
                  </div>
                </form>
              ) : (
                <>
                  <div className="item__body">
                    <span className="item__title">{passkey.name}</span>
                    <span className="item__meta">
                      Added {formatDate(passkey.createdAt)} · Last used {formatDate(passkey.lastUsedAt)}
                    </span>
                  </div>
                  {mode?.id === passkey.id && mode.kind === 'confirm-delete' ? (
                    <div className="confirm" role="group" aria-label={`Remove ${passkey.name}?`}>
                      <p className="confirm__text">Remove this passkey? It will stop working for sign-in.</p>
                      <div className="row">
                        <Button variant="danger" busy={busy} onClick={() => void handleDelete(passkey.id)}>
                          Remove
                        </Button>
                        <Button variant="ghost" onClick={() => setMode(null)} disabled={busy}>
                          Cancel
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <div className="row">
                      <Button
                        variant="ghost"
                        disabled={busy}
                        aria-label={`Rename ${passkey.name}`}
                        onClick={() => {
                          setDraftName(passkey.name)
                          setMode({ id: passkey.id, kind: 'rename' })
                        }}
                      >
                        Rename
                      </Button>
                      <Button
                        variant="ghost"
                        disabled={busy}
                        aria-label={`Remove ${passkey.name}`}
                        onClick={() => setMode({ id: passkey.id, kind: 'confirm-delete' })}
                      >
                        Remove
                      </Button>
                    </div>
                  )}
                </>
              )}
            </li>
          ))}
        </ul>
      )}

      {adding ? (
        <form className="stack sub-panel" onSubmit={handleAdd} noValidate>
          <SecretField
            label="Account password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            disabled={busy}
            hint="Confirming your password stops someone holding your unlocked phone from adding their own passkey."
          />
          <div className="row">
            <Button type="submit" icon={<PasskeyIcon />} busy={busy}>
              {busy ? 'Follow your device prompt…' : 'Create passkey'}
            </Button>
            <Button
              variant="ghost"
              disabled={busy}
              onClick={() => {
                setAdding(false)
                setPassword('')
                setError(null)
              }}
            >
              Cancel
            </Button>
          </div>
        </form>
      ) : (
        <Button
          variant="secondary"
          icon={<PasskeyIcon />}
          onClick={() => {
            setAdding(true)
            setNotice(null)
            setError(null)
          }}
        >
          Add a passkey
        </Button>
      )}
    </div>
  )
}
