import type { Session, User } from '@supabase/supabase-js'
import { passkeysEnabled, supabase } from '../lib/supabase'
import { describeAuthError } from './authErrors'

/**
 * Authentication only. A successful sign-in proves identity; it does NOT grant
 * access to vault data (that is enforced by RLS membership policies) and it does
 * NOT unlock any encryption key (that needs the separate vault passphrase).
 */

export type AuthResult = { ok: true } | { ok: false; message: string }

export interface AuthUser {
  id: string
  email: string | null
}

export function toAuthUser(user: User): AuthUser {
  return { id: user.id, email: user.email ?? null }
}

function requireClient() {
  if (!supabase) throw new Error('Supabase is not configured')
  return supabase
}

export function isPasskeySupportedByBrowser(): boolean {
  return (
    typeof window !== 'undefined' &&
    window.isSecureContext &&
    typeof window.PublicKeyCredential === 'function' &&
    typeof navigator.credentials?.get === 'function'
  )
}

export function canOfferPasskeySignIn(): boolean {
  return passkeysEnabled && isPasskeySupportedByBrowser()
}

export async function signInWithPassword(email: string, password: string): Promise<AuthResult> {
  try {
    const { error } = await requireClient().auth.signInWithPassword({ email: email.trim(), password })
    if (error) return { ok: false, message: describeAuthError(error) }
    return { ok: true }
  } catch (error) {
    return { ok: false, message: describeAuthError(error) }
  }
}

export async function signInWithPasskey(signal?: AbortSignal): Promise<AuthResult> {
  try {
    const { error } = await requireClient().auth.signInWithPasskey({ options: { signal } })
    if (error) return { ok: false, message: describeAuthError(error) }
    return { ok: true }
  } catch (error) {
    return { ok: false, message: describeAuthError(error) }
  }
}

/**
 * Signs out. 'local' ends this device's session; 'global' also revokes every
 * other device's refresh token (their current access tokens stay valid until
 * they expire). If the server can't be reached, this device is still cleared.
 */
export async function signOut(scope: 'local' | 'global' = 'local'): Promise<void> {
  const client = requireClient()
  const { error } = await client.auth.signOut({ scope })
  if (error) await client.auth.signOut({ scope: 'local' })
}

export async function getInitialSession(): Promise<Session | null> {
  const { data } = await requireClient().auth.getSession()
  return data.session
}

/**
 * Confirms the stored session with the Auth server rather than trusting the
 * locally cached token. Returns 'invalid' when the server rejects it, and
 * 'unreachable' when we can't tell (offline).
 */
export async function verifySessionWithServer(): Promise<{ status: 'valid'; user: User } | { status: 'invalid' } | { status: 'unreachable' }> {
  try {
    const { data, error } = await requireClient().auth.getUser()
    if (data.user && !error) return { status: 'valid', user: data.user }
    return { status: isDefinitelyInvalidSession(error) ? 'invalid' : 'unreachable' }
  } catch {
    return { status: 'unreachable' }
  }
}

/** Auth error codes that mean the stored session can never work again. */
const INVALID_SESSION_CODES = new Set([
  'session_not_found',
  'session_expired',
  'refresh_token_not_found',
  'refresh_token_already_used',
  'user_not_found',
  'user_banned',
  'bad_jwt',
  'no_authorization',
])

/**
 * Phase 4 refresh fix. Previously ANY 4xx from the Auth server signed the user
 * out on page load, including transient ones (429 rate limit, 408 timeout, a
 * 400 from a token refresh racing in another tab). Now only a definite
 * "this session is invalid" answer signs out; anything else keeps the session
 * and shows the offline notice. This does not widen access: every data request
 * is still authorized by the server (RLS) with the current token.
 */
export function isDefinitelyInvalidSession(error: unknown): boolean {
  if (!error || typeof error !== 'object') return false
  const { status, code } = error as { status?: unknown; code?: unknown }
  if (typeof code === 'string' && INVALID_SESSION_CODES.has(code)) return true
  return status === 401 || status === 403
}
