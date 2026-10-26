import { useCallback, useEffect, useState } from 'react'
import { getMembership, type Membership } from '../services/vault'

export type MembershipState = { status: 'loading' } | Membership

/** UI-only view of vault membership. RLS is the actual enforcement. */
export function useMembership(userId: string): { membership: MembershipState; retry: () => void } {
  const [membership, setMembership] = useState<MembershipState>({ status: 'loading' })
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    let cancelled = false
    setMembership({ status: 'loading' })
    void getMembership().then((result) => {
      if (!cancelled) setMembership(result)
    })
    return () => {
      cancelled = true
    }
  }, [userId, attempt])

  const retry = useCallback(() => setAttempt((n) => n + 1), [])
  return { membership, retry }
}
