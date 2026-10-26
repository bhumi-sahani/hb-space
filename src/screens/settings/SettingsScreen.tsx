import { useState, type ReactNode } from 'react'
import { Button, LockIcon } from '../../components/ui'
import type { AuthUser } from '../../services/auth'
import type { VaultBackend } from '../../services/vaultBackend'
import { canManagePasskeys } from '../../services/passkeys'
import { AccessCheckPanel } from './AccessCheckPanel'
import { PasskeyManager } from './PasskeyManager'
import { VaultSecurityPanel } from './VaultSecurityPanel'

interface SettingsScreenProps {
  user: AuthUser
  vaultId: string | null
  backend: VaultBackend | null
  onSignOut: (scope: 'local' | 'global') => Promise<void>
}

function Section({ id, title, children }: { id: string; title: string; children: ReactNode }) {
  return (
    <section className="panel" aria-labelledby={id}>
      <h2 id={id} className="panel__title">
        {title}
      </h2>
      {children}
    </section>
  )
}

export function SettingsScreen({ user, vaultId, backend, onSignOut }: SettingsScreenProps) {
  const [signingOut, setSigningOut] = useState<'local' | 'global' | null>(null)

  async function handleSignOut(scope: 'local' | 'global') {
    setSigningOut(scope)
    try {
      await onSignOut(scope)
    } finally {
      setSigningOut(null)
    }
  }

  return (
    <div className="stack stack--loose">
      <Section id="settings-vault" title="Vault security">
        <VaultSecurityPanel vaultId={vaultId} backend={backend} />
      </Section>

      <Section id="settings-passkeys" title="Passkeys">
        <p className="muted small">
          Sign in with Face ID, fingerprint, Windows Hello or your device PIN. A passkey signs you in to your account. It
          does not unlock the vault, which needs your vault passphrase.
        </p>
        <PasskeyManager user={user} supported={canManagePasskeys()} />
      </Section>

      <Section id="settings-session" title="Session">
        <div className="stack">
          <Button
            variant="secondary"
            icon={<LockIcon />}
            busy={signingOut === 'local'}
            disabled={signingOut !== null}
            onClick={() => void handleSignOut('local')}
          >
            Sign out of this device
          </Button>
          <Button
            variant="ghost"
            busy={signingOut === 'global'}
            disabled={signingOut !== null}
            onClick={() => void handleSignOut('global')}
          >
            Sign out of all devices
          </Button>
          <p className="muted small">
            You normally never need to sign out: this device stays signed in, and the vault stays protected by its
            passphrase (use Lock Vault). After signing out, this device needs a passkey or account recovery to sign in
            again. Use “all devices” if a phone is lost. Other devices may stay signed in for up to an hour, until their
            access token expires.
          </p>
        </div>
      </Section>

      <Section id="settings-access" title="Access check">
        <AccessCheckPanel vaultId={vaultId} />
      </Section>

      <Section id="settings-privacy" title="Privacy & recovery">
        <ul className="notice-list">
          <li>Only the two approved accounts can reach vault data. The server enforces this, not the app.</li>
          <li>
            Everything in the vault is encrypted on your device before upload. The server only ever stores ciphertext.
          </li>
          <li>
            Signing in does not unlock the vault; the vault passphrase does. Locking the vault keeps you signed in.
          </li>
          <li>
            If both the vault passphrase and the recovery code are lost, nobody can recover the photos, including the
            people who run the servers. There is no backdoor.
          </li>
          <li>Forgot your login password? Ask the vault owner to send a reset from the Supabase dashboard.</li>
        </ul>
      </Section>
    </div>
  )
}
