import { supabase } from '../lib/supabase'

/**
 * Vault membership lookup. This only decides which screen to show; the actual
 * authorization is enforced by RLS on every query (see supabase/migrations).
 * RLS returns at most the caller's own membership row, so no user id is sent.
 */

export type Membership =
  | { status: 'member'; vaultId: string }
  | { status: 'not-member' }
  | { status: 'error'; message: string }

export const MEMBERSHIP_MESSAGES = {
  notSetUp: 'The vault database has not been set up yet. Apply the Supabase migrations, then try again.',
  network: 'Cannot reach the server. Check your connection and try again.',
  generic: 'Could not check vault access. Please try again.',
} as const

interface PostgrestLikeError {
  code?: string
  message?: string
}

export function describeDataError(error: PostgrestLikeError | null | undefined): string {
  const code = error?.code ?? ''
  // PGRST205: table not in schema cache; 42P01: undefined table.
  if (code === 'PGRST205' || code === '42P01') return MEMBERSHIP_MESSAGES.notSetUp
  if (!code && /fetch|network/i.test(error?.message ?? '')) return MEMBERSHIP_MESSAGES.network
  return MEMBERSHIP_MESSAGES.generic
}

export async function getMembership(): Promise<Membership> {
  if (!supabase) return { status: 'error', message: MEMBERSHIP_MESSAGES.generic }
  try {
    const { data, error } = await supabase.from('vault_members').select('vault_id').limit(2)
    if (error) return { status: 'error', message: describeDataError(error) }
    if (!data || data.length === 0) return { status: 'not-member' }
    // The schema allows only one vault; more than one row means something is wrong. Fail closed.
    if (data.length > 1) return { status: 'error', message: MEMBERSHIP_MESSAGES.generic }
    const vaultId = (data[0] as { vault_id: unknown }).vault_id
    if (typeof vaultId !== 'string') return { status: 'error', message: MEMBERSHIP_MESSAGES.generic }
    return { status: 'member', vaultId }
  } catch {
    return { status: 'error', message: MEMBERSHIP_MESSAGES.network }
  }
}
