/**
 * Validated, browser-safe runtime configuration.
 *
 * Every VITE_* variable is embedded in the public JavaScript bundle, so only
 * values that are safe for anyone to read may appear here. This module fails
 * closed: if a secret-looking key is supplied, the app refuses to start the
 * Supabase client rather than shipping it.
 *
 * Problem messages name the variable but never echo its value.
 */

export interface AppConfig {
  supabaseUrl: string
  supabasePublishableKey: string
  passkeysEnabled: boolean
}

export type ConfigResult =
  | { ok: true; config: AppConfig }
  | { ok: false; problems: string[] }

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]'])

function readString(raw: Record<string, unknown>, name: string): string {
  const value = raw[name]
  return typeof value === 'string' ? value.trim() : ''
}

function decodeJwtRole(token: string): string | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
    const payload: unknown = JSON.parse(atob(padded))
    if (payload && typeof payload === 'object' && 'role' in payload) {
      const role = (payload as { role: unknown }).role
      return typeof role === 'string' ? role : null
    }
    return null
  } catch {
    return null
  }
}

function validateUrl(value: string, problems: string[]): string | null {
  if (!value) {
    problems.push('VITE_SUPABASE_URL is not set.')
    return null
  }
  let url: URL
  try {
    url = new URL(value)
  } catch {
    problems.push('VITE_SUPABASE_URL is not a valid URL.')
    return null
  }
  const isLoopback = LOOPBACK_HOSTS.has(url.hostname)
  if (url.protocol !== 'https:' && !(url.protocol === 'http:' && isLoopback)) {
    problems.push('VITE_SUPABASE_URL must use https:// (http:// is allowed only for a local Supabase instance).')
    return null
  }
  if (url.username || url.password || url.search || url.hash || (url.pathname !== '/' && url.pathname !== '')) {
    problems.push('VITE_SUPABASE_URL must be the bare project URL with no path, query, or credentials.')
    return null
  }
  return url.origin
}

function validateKey(value: string, problems: string[]): string | null {
  if (!value) {
    problems.push('VITE_SUPABASE_PUBLISHABLE_KEY is not set.')
    return null
  }
  if (value.startsWith('sb_secret_')) {
    problems.push(
      'VITE_SUPABASE_PUBLISHABLE_KEY contains a SECRET key. Remove it immediately, rotate it in the Supabase dashboard, and use the publishable key instead.',
    )
    return null
  }
  if (value.startsWith('sb_publishable_')) return value

  const role = decodeJwtRole(value)
  if (role === 'anon') return value
  if (role !== null) {
    problems.push(
      `VITE_SUPABASE_PUBLISHABLE_KEY is a privileged "${role === 'service_role' ? 'service_role' : 'non-anon'}" key. Remove it immediately, rotate it in the Supabase dashboard, and use the publishable (or legacy anon) key instead.`,
    )
    return null
  }
  problems.push('VITE_SUPABASE_PUBLISHABLE_KEY is not a recognised Supabase publishable or anon key.')
  return null
}

export function parseEnv(raw: Record<string, unknown>): ConfigResult {
  const problems: string[] = []
  const supabaseUrl = validateUrl(readString(raw, 'VITE_SUPABASE_URL'), problems)
  const supabasePublishableKey = validateKey(readString(raw, 'VITE_SUPABASE_PUBLISHABLE_KEY'), problems)
  const passkeysEnabled = readString(raw, 'VITE_ENABLE_PASSKEYS').toLowerCase() === 'true'

  if (problems.length > 0 || !supabaseUrl || !supabasePublishableKey) {
    return { ok: false, problems }
  }
  return { ok: true, config: { supabaseUrl, supabasePublishableKey, passkeysEnabled } }
}

export const configResult: ConfigResult = parseEnv(import.meta.env)
