import { useEffect, useId, useRef, useState, type FormEvent } from 'react'
import type { AuthResult } from '../services/auth'
import { Alert, Button, PasskeyIcon, SecretField, TextField } from '../components/ui'

interface SignInRequiredProps {
  passkeyAvailable: boolean
  notice?: string
  onPasswordSignIn: (email: string, password: string) => Promise<AuthResult>
  onPasskeySignIn: (signal: AbortSignal) => Promise<AuthResult>
}

type Pending = 'none' | 'password' | 'passkey'

/**
 * Shown ONLY when this device has no valid Supabase session (first use on a
 * device, signed out, or the session was revoked/expired). The normal flow
 * never shows it: an existing session goes straight to the vault passphrase.
 *
 * There is deliberately no passphrase-only path: the vault data is reachable
 * only with an authenticated session that RLS recognises as a vault member.
 * Which accounts exist is decided by Supabase Auth (invite-only, sign-ups off),
 * never by anything in this page.
 *
 * Sign-in: a passkey when available; otherwise (or as a fallback) the account
 * password, kept behind "Account recovery" rather than shown as a login form.
 */
export function LoginScreen({ passkeyAvailable, notice, onPasswordSignIn, onPasskeySignIn }: SignInRequiredProps) {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [pending, setPending] = useState<Pending>('none')
  const [error, setError] = useState<string | null>(null)
  const [recoveryOpen, setRecoveryOpen] = useState(false)
  const passkeyAbort = useRef<AbortController | null>(null)
  const recoveryId = useId()

  // Cancel an in-flight passkey prompt if the screen goes away.
  useEffect(() => () => passkeyAbort.current?.abort(), [])

  async function handlePasswordSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    if (pending !== 'none') return
    if (!email.trim() || !password) {
      setError('Enter your account email and password.')
      return
    }
    setError(null)
    setPending('password')
    const result = await onPasswordSignIn(email, password)
    if (!result.ok) {
      setError(result.message)
      setPending('none')
    }
    // On success the auth listener swaps the screen; keep the busy state until then.
  }

  async function handlePasskey() {
    if (pending !== 'none') return
    setError(null)
    setPending('passkey')
    const controller = new AbortController()
    passkeyAbort.current = controller
    const result = await onPasskeySignIn(controller.signal)
    passkeyAbort.current = null
    if (!result.ok) {
      setError(result.message)
      setPending('none')
    }
  }

  return (
    <main className="auth-page">
      <div className="auth-card">
        <header className="auth-card__header">
          <h1 className="brand-title">
            HB Space <span aria-hidden="true"></span>
          </h1>
          <p className="auth-card__lede">
            <strong>Sign-in needed on this device.</strong> This device isn't signed in to HB Space, or its session ended. The
            vault passphrase alone can't open the vault.
          </p>
        </header>

        {notice && !error && <Alert tone="info">{notice}</Alert>}
        {error && <Alert tone="error">{error}</Alert>}

        {passkeyAvailable && (
          <Button
            variant="primary"
            block
            icon={<PasskeyIcon />}
            busy={pending === 'passkey'}
            disabled={pending === 'password'}
            onClick={handlePasskey}
          >
            {pending === 'passkey' ? 'Waiting for your passkey…' : 'Sign in with passkey'}
          </Button>
        )}

        <Button
          variant="ghost"
          block
          aria-expanded={recoveryOpen}
          aria-controls={recoveryId}
          onClick={() => {
            setRecoveryOpen((open) => !open)
            setError(null)
          }}
          disabled={pending !== 'none'}
        >
          {recoveryOpen ? 'Hide account recovery' : passkeyAvailable ? 'No passkey on this device? Account recovery' : 'Account recovery'}
        </Button>

        {recoveryOpen && (
          <section id={recoveryId} className="stack" aria-label="Account recovery">
            <p className="muted small">
              Use the account password only when this device has no session and no passkey. After signing in, add a passkey in
              Settings so you won't need it again.
            </p>
            <form className="auth-form" onSubmit={handlePasswordSubmit} noValidate>
              <TextField
                label="Account email"
                type="email"
                name="email"
                inputMode="email"
                autoComplete="username"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                disabled={pending !== 'none'}
                required
              />
              <SecretField
                label="Account password"
                name="password"
                autoComplete="current-password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                disabled={pending !== 'none'}
                required
              />
              <Button type="submit" variant="secondary" block busy={pending === 'password'} disabled={pending === 'passkey'}>
                {pending === 'password' ? 'Signing in…' : 'Sign in to this device'}
              </Button>
            </form>
            <ul className="small muted">
              <li>Forgot the account password? The vault owner can send a password reset from the Supabase dashboard.</li>
              <li>
                The vault passphrase is separate. Signing in never unlocks the vault, and resetting the account password does not
                reset the passphrase.
              </li>
            </ul>
          </section>
        )}

        <p className="auth-card__footnote">Only the two invited accounts can use HB Space.</p>
      </div>
    </main>
  )
}
