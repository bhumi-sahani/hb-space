import { describe, expect, it } from 'vitest'
import { parseEnv } from './env'

function fakeJwt(payload: Record<string, unknown>): string {
  const encode = (value: object) => btoa(JSON.stringify(value)).replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_')
  return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode(payload)}.signature`
}

const URL_OK = 'https://abcdefghijklmnop.supabase.co'
const PUBLISHABLE = 'sb_publishable_test_value_not_real'

describe('parseEnv', () => {
  it('accepts a project URL and publishable key', () => {
    const result = parseEnv({ VITE_SUPABASE_URL: URL_OK, VITE_SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE })
    expect(result).toEqual({
      ok: true,
      config: { supabaseUrl: URL_OK, supabasePublishableKey: PUBLISHABLE, passkeysEnabled: false },
    })
  })

  it('accepts a legacy anon JWT', () => {
    const result = parseEnv({ VITE_SUPABASE_URL: URL_OK, VITE_SUPABASE_PUBLISHABLE_KEY: fakeJwt({ role: 'anon' }) })
    expect(result.ok).toBe(true)
  })

  it('enables passkeys only for the exact value "true"', () => {
    const on = parseEnv({ VITE_SUPABASE_URL: URL_OK, VITE_SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE, VITE_ENABLE_PASSKEYS: 'TRUE' })
    const off = parseEnv({ VITE_SUPABASE_URL: URL_OK, VITE_SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE, VITE_ENABLE_PASSKEYS: '1' })
    expect(on.ok && on.config.passkeysEnabled).toBe(true)
    expect(off.ok && off.config.passkeysEnabled).toBe(false)
  })

  it('reports missing variables', () => {
    const result = parseEnv({})
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.problems).toHaveLength(2)
  })

  it.each([
    ['sb_secret_abc123', 'SECRET'],
    [fakeJwt({ role: 'service_role' }), 'service_role'],
    [fakeJwt({ role: 'authenticated' }), 'non-anon'],
  ])('refuses privileged key %#', (key, expected) => {
    const result = parseEnv({ VITE_SUPABASE_URL: URL_OK, VITE_SUPABASE_PUBLISHABLE_KEY: key })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.problems.join(' ')).toContain(expected)
  })

  it('never echoes the supplied key value in problems', () => {
    const secret = 'sb_secret_SHOULD_NOT_APPEAR'
    const result = parseEnv({ VITE_SUPABASE_URL: URL_OK, VITE_SUPABASE_PUBLISHABLE_KEY: secret })
    expect(result.ok).toBe(false)
    if (!result.ok) expect(result.problems.join(' ')).not.toContain('SHOULD_NOT_APPEAR')
  })

  it('rejects unrecognised key formats', () => {
    const result = parseEnv({ VITE_SUPABASE_URL: URL_OK, VITE_SUPABASE_PUBLISHABLE_KEY: 'hello' })
    expect(result.ok).toBe(false)
  })

  it.each([
    'http://abcdefghijklmnop.supabase.co',
    'https://abcdefghijklmnop.supabase.co/rest/v1',
    'https://user:pass@abcdefghijklmnop.supabase.co',
    'not a url',
  ])('rejects unsafe URL %s', (url) => {
    expect(parseEnv({ VITE_SUPABASE_URL: url, VITE_SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE }).ok).toBe(false)
  })

  it('allows http only for a local Supabase instance', () => {
    expect(parseEnv({ VITE_SUPABASE_URL: 'http://127.0.0.1:54321', VITE_SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE }).ok).toBe(true)
    expect(parseEnv({ VITE_SUPABASE_URL: 'http://localhost:54321', VITE_SUPABASE_PUBLISHABLE_KEY: PUBLISHABLE }).ok).toBe(true)
  })
})
