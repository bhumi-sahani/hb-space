import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'
import { getInitialSession, signOut, toAuthUser, verifySessionWithServer, type AuthUser } from '../services/auth'

export type AuthState =
  | { status: 'loading' }
  | { status: 'signed-out'; notice?: string }
  | { status: 'signed-in'; user: AuthUser; offline: boolean }

/**
 * Tracks the Supabase session. The UI uses this only to decide which screen to
 * show; it is not a security boundary. Data access is enforced by RLS.
 */
export function useAuth(): AuthState {
  const [state, setState] = useState<AuthState>({ status: 'loading' })

  useEffect(() => {
    if (!supabase) return
    let cancelled = false

    async function bootstrap() {
      const session = await getInitialSession()
      if (cancelled) return
      if (!session) {
        setState({ status: 'signed-out' })
        return
      }
      const result = await verifySessionWithServer()
      if (cancelled) return
      if (result.status === 'valid') {
        setState({ status: 'signed-in', user: toAuthUser(result.user), offline: false })
      } else if (result.status === 'invalid') {
        await signOut()
        if (!cancelled) setState({ status: 'signed-out', notice: 'Your session has expired. Please sign in again.' })
      } else {
        // Offline: show the signed-in shell, but every data request will still be
        // checked by the server once connectivity returns.
        setState({ status: 'signed-in', user: toAuthUser(session.user), offline: true })
      }
    }

    void bootstrap()

    // Keep this callback synchronous: awaiting Supabase calls inside it can deadlock the auth lock.
    const { data } = supabase.auth.onAuthStateChange((event, session) => {
      if (cancelled) return
      if (event === 'INITIAL_SESSION') return // handled (and server-verified) by bootstrap()
      if (!session) {
        setState((previous) =>
          previous.status === 'signed-in'
            ? { status: 'signed-out', notice: event === 'SIGNED_OUT' ? undefined : 'Your session has expired. Please sign in again.' }
            : { status: 'signed-out' },
        )
        return
      }
      setState({ status: 'signed-in', user: toAuthUser(session.user), offline: false })
    })

    return () => {
      cancelled = true
      data.subscription.unsubscribe()
    }
  }, [])

  return state
}
