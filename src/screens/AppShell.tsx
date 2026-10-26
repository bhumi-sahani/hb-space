import type { ReactNode } from 'react'
import { Alert, Button, HeartMark, SettingsIcon, Spinner } from '../components/ui'
import type { MembershipState } from '../hooks/useMembership'
import type { AuthUser } from '../services/auth'

export type ShellView = 'vault' | 'settings'

interface AppShellProps {
  user: AuthUser
  offline: boolean
  view: ShellView
  onNavigate: (view: ShellView) => void
  children: ReactNode
}

/**
 * Signed-in frame: one top bar (brand, settings),
 * then the content. Safe-area aware. There is no sign-out button here: the
 * device stays signed in and the vault is protected by its passphrase.
 * Signing out is in Settings.
 */
export function AppShell({ user, offline, view, onNavigate, children }: AppShellProps) {
  return (
    <div className="shell">
      <header className="topbar">
        <button type="button" className="topbar__brand" onClick={() => onNavigate('vault')} aria-label="HB Space, go to the vault">
          <HeartMark size={26} />
          <span className="topbar__title">HB Space</span>
        </button>
        <div className="topbar__actions">
          <button
            type="button"
            className="topbar__icon"
            aria-label="Settings"
            title="Settings"
            aria-current={view === 'settings' ? 'page' : undefined}
            onClick={() => onNavigate(view === 'settings' ? 'vault' : 'settings')}
          >
            <SettingsIcon />
          </button>
        </div>
      </header>
      <main className="shell__main" id="main">
        {offline && <Alert tone="warning">You appear to be offline. Some actions will not work until you reconnect.</Alert>}
        {children}
        <p className="muted small shell__whoami">Signed in as {user.email ?? 'an account without email'}</p>
      </main>
    </div>
  )
}

/** Vault tab content. Membership shown here is a UI hint; RLS enforces access. */
export function VaultPanel({ membership, onRetry }: { membership: MembershipState; onRetry: () => void }) {
  if (membership.status === 'loading') {
    return (
      <div className="panel inline-status">
        <Spinner label="Checking vault access" />
      </div>
    )
  }
  if (membership.status === 'error') {
    return (
      <section className="panel stack" aria-labelledby="vault-error-title">
        <h2 id="vault-error-title" className="panel__title">
          Couldn't open the vault
        </h2>
        <Alert tone="error">{membership.message}</Alert>
        <Button variant="secondary" onClick={onRetry}>
          Try again
        </Button>
      </section>
    )
  }
  if (membership.status === 'not-member') {
    return (
      <section className="panel" aria-labelledby="vault-denied-title">
        <h2 id="vault-denied-title" className="panel__title">
          No access to this vault
        </h2>
        <p>This account is not one of the two approved members, so the server returns no vault data to it.</p>
        <p className="muted">If you think this is a mistake, ask the vault owner to check the membership list.</p>
      </section>
    )
  }
  // Member, but the vault backend is unavailable (configuration problem). Never shows vault data.
  return (
    <section className="panel" aria-labelledby="vault-not-ready-title">
      <h2 id="vault-not-ready-title" className="panel__title">
        The vault isn't available
      </h2>
      <p>Your account is an approved member, but this build cannot reach the vault service.</p>
    </section>
  )
}
