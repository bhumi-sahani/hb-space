import { useCallback, useEffect } from 'react'
import { configResult } from './config/env'
import { useAuth } from './hooks/useAuth'
import { useMembership } from './hooks/useMembership'
import { useRoute } from './lib/router'
import { vaultBackend } from './lib/vaultBackendInstance'
import { canOfferPasskeySignIn, signInWithPasskey, signInWithPassword, signOut, type AuthUser } from './services/auth'
import type { VaultBackend } from './services/vaultBackend'
import { lockVault } from './services/vaultSession'
import { AppShell, VaultPanel, type ShellView } from './screens/AppShell'
import { LoginScreen } from './screens/LoginScreen'
import { SettingsScreen } from './screens/settings/SettingsScreen'
import { ConfigErrorScreen, LoadingScreen } from './screens/StatusScreens'
import { VaultScreen } from './screens/vault/VaultScreen'

export default function App() {
  if (!configResult.ok) return <ConfigErrorScreen problems={configResult.problems} />
  return <ConfiguredApp />
}

function ConfiguredApp() {
  const auth = useAuth()

  // Signing out (or the session ending) always locks the vault first.
  useEffect(() => {
    if (auth.status !== 'signed-in') lockVault()
  }, [auth.status])

  switch (auth.status) {
    case 'loading':
      return <LoadingScreen />
    case 'signed-out':
      return (
        <LoginScreen
          passkeyAvailable={canOfferPasskeySignIn()}
          notice={auth.notice}
          onPasswordSignIn={signInWithPassword}
          onPasskeySignIn={signInWithPasskey}
        />
      )
    case 'signed-in':
      // Keyed by user id so nothing from one account's session survives into another's.
      return <SignedInApp key={auth.user.id} user={auth.user} offline={auth.offline} />
  }
}

/**
 * Signed-in app. The current page comes from the URL hash (#/, #/folder/<id>,
 * #/settings), so a refresh keeps the user where they were. The route
 * only selects a screen: a locked vault always shows the unlock screen first,
 * and nothing about the vault key is stored to survive a refresh.
 */
export function SignedInApp({ user, offline, backend = vaultBackend }: { user: AuthUser; offline: boolean; backend?: VaultBackend | null }) {
  const [route, navigate] = useRoute()
  const { membership, retry } = useMembership(user.id)
  const vaultId = membership.status === 'member' ? membership.vaultId : null
  const view: ShellView = route.name

  // Leaving this account's session (sign-out, account switch) locks the vault.
  useEffect(() => () => lockVault(), [])

  const handleSignOut = useCallback(async (scope: 'local' | 'global' = 'local') => {
    lockVault()
    await signOut(scope)
  }, [])

  const onNavigate = useCallback(
    (next: ShellView) => navigate(next === 'vault' ? { name: 'vault', folderId: null } : { name: next }),
    [navigate],
  )

  return (
    <AppShell user={user} offline={offline} view={view} onNavigate={onNavigate}>
      {route.name === 'settings' ? (
        <SettingsScreen user={user} vaultId={vaultId} backend={backend} onSignOut={handleSignOut} />
      ) : vaultId && backend ? (
        <VaultScreen vaultId={vaultId} backend={backend} route={route} navigate={navigate} />
      ) : (
        <VaultPanel membership={membership} onRetry={retry} />
      )}
    </AppShell>
  )
}
