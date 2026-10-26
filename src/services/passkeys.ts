import { supabase } from '../lib/supabase'
import { AUTH_MESSAGES, describeAuthError } from './authErrors'
import { canOfferPasskeySignIn, type AuthResult } from './auth'

/**
 * Passkey management via the documented supabase-js API (pinned 2.109.0,
 * `auth.experimental.passkey: true`): auth.registerPasskey(),
 * auth.passkey.list(), auth.passkey.update(), auth.passkey.delete().
 *
 * Passkeys authenticate the account only. They never unlock the vault.
 */

export interface PasskeySummary {
  id: string
  name: string
  createdAt: string
  lastUsedAt: string | null
}

export const PASSKEY_NAME_MAX = 120

export const PASSKEY_MESSAGES = {
  wrongPassword: 'That password is not correct.',
  accountMismatch: 'Could not confirm your identity. Please sign in again.',
  invalidName: `Use 1–${PASSKEY_NAME_MAX} characters.`,
} as const

export function canManagePasskeys(): boolean {
  return canOfferPasskeySignIn()
}

function requireClient() {
  if (!supabase) throw new Error('Supabase is not configured')
  return supabase
}

export async function listPasskeys(): Promise<{ ok: true; passkeys: PasskeySummary[] } | { ok: false; message: string }> {
  try {
    const { data, error } = await requireClient().auth.passkey.list()
    if (error) return { ok: false, message: describeAuthError(error) }
    return {
      ok: true,
      passkeys: (data ?? []).map((item) => ({
        id: item.id,
        name: item.friendly_name?.trim() || 'Passkey',
        createdAt: item.created_at,
        lastUsedAt: item.last_used_at ?? null,
      })),
    }
  } catch (error) {
    return { ok: false, message: describeAuthError(error) }
  }
}

/**
 * Adds a passkey after re-confirming the account password (step-up).
 *
 * Supabase only requires an active session to register a passkey. Without this
 * step, anyone holding an unlocked, signed-in phone could add their own passkey
 * and keep access after the phone is recovered. The password check is done
 * against the CURRENT session's email (never a typed one) and the returned user
 * id must match the current user.
 */
export async function addPasskeyWithPasswordConfirmation(
  current: { id: string; email: string | null },
  password: string,
  signal?: AbortSignal,
): Promise<AuthResult> {
  const client = requireClient()
  if (!current.email) return { ok: false, message: PASSKEY_MESSAGES.accountMismatch }
  try {
    const confirm = await client.auth.signInWithPassword({ email: current.email, password })
    if (confirm.error) {
      const message = describeAuthError(confirm.error)
      return { ok: false, message: message === AUTH_MESSAGES.invalidCredentials ? PASSKEY_MESSAGES.wrongPassword : message }
    }
    if (confirm.data.user?.id !== current.id) {
      await client.auth.signOut({ scope: 'local' })
      return { ok: false, message: PASSKEY_MESSAGES.accountMismatch }
    }
    const { error } = await client.auth.registerPasskey({ options: { signal } })
    if (error) return { ok: false, message: describeAuthError(error) }
    return { ok: true }
  } catch (error) {
    return { ok: false, message: describeAuthError(error) }
  }
}

export function normalisePasskeyName(raw: string): string | null {
  const name = raw.trim().replace(/\s+/g, ' ')
  if (name.length === 0 || name.length > PASSKEY_NAME_MAX) return null
  return name
}

export async function renamePasskey(passkeyId: string, rawName: string): Promise<AuthResult> {
  const friendlyName = normalisePasskeyName(rawName)
  if (!friendlyName) return { ok: false, message: PASSKEY_MESSAGES.invalidName }
  try {
    const { error } = await requireClient().auth.passkey.update({ passkeyId, friendlyName })
    if (error) return { ok: false, message: describeAuthError(error) }
    return { ok: true }
  } catch (error) {
    return { ok: false, message: describeAuthError(error) }
  }
}

export async function deletePasskey(passkeyId: string): Promise<AuthResult> {
  try {
    const { error } = await requireClient().auth.passkey.delete({ passkeyId })
    if (error) return { ok: false, message: describeAuthError(error) }
    return { ok: true }
  } catch (error) {
    return { ok: false, message: describeAuthError(error) }
  }
}
