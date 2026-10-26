import { renderHook, waitFor } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * Auth bootstrap on page load (refresh). The Supabase client and auth service
 * are mocked; this checks only how the bootstrap decides between signed in,
 * signed in but offline, and signed out.
 */

const auth = vi.hoisted(() => ({
  getInitialSession: vi.fn(),
  verifySessionWithServer: vi.fn(),
  signOut: vi.fn(async () => undefined),
}))

vi.mock('../lib/supabase', () => ({
  supabase: { auth: { onAuthStateChange: () => ({ data: { subscription: { unsubscribe: () => undefined } } }) } },
  passkeysEnabled: false,
}))

vi.mock('../services/auth', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../services/auth')>()
  return { ...actual, getInitialSession: auth.getInitialSession, verifySessionWithServer: auth.verifySessionWithServer, signOut: auth.signOut }
})

import { isDefinitelyInvalidSession } from '../services/auth'
import { useAuth } from './useAuth'

const USER = { id: '11111111-1111-4111-8111-111111111111', email: 'member@test' }

beforeEach(() => {
  auth.getInitialSession.mockReset()
  auth.verifySessionWithServer.mockReset()
  auth.signOut.mockClear()
})

describe('refresh while authenticated', () => {
  it('a valid stored session stays signed in', async () => {
    auth.getInitialSession.mockResolvedValue({ user: USER })
    auth.verifySessionWithServer.mockResolvedValue({ status: 'valid', user: USER })
    const { result } = renderHook(() => useAuth())
    await waitFor(() => expect(result.current.status).toBe('signed-in'))
    expect(auth.signOut).not.toHaveBeenCalled()
  })

  it('a transient server problem (rate limit, timeout, offline) does NOT send the user to login', async () => {
    auth.getInitialSession.mockResolvedValue({ user: USER })
    auth.verifySessionWithServer.mockResolvedValue({ status: 'unreachable' })
    const { result } = renderHook(() => useAuth())
    await waitFor(() => expect(result.current).toMatchObject({ status: 'signed-in', offline: true }))
    expect(auth.signOut).not.toHaveBeenCalled()
  })

  it('a session the server definitely rejects is signed out', async () => {
    auth.getInitialSession.mockResolvedValue({ user: USER })
    auth.verifySessionWithServer.mockResolvedValue({ status: 'invalid' })
    const { result } = renderHook(() => useAuth())
    await waitFor(() => expect(result.current.status).toBe('signed-out'))
    expect(auth.signOut).toHaveBeenCalled()
  })

  it('no stored session means signed out (protected routes show login)', async () => {
    auth.getInitialSession.mockResolvedValue(null)
    const { result } = renderHook(() => useAuth())
    await waitFor(() => expect(result.current.status).toBe('signed-out'))
    expect(auth.verifySessionWithServer).not.toHaveBeenCalled()
  })
})

describe('isDefinitelyInvalidSession', () => {
  it.each([
    [{ status: 401 }, true],
    [{ status: 403 }, true],
    [{ status: 400, code: 'session_not_found' }, true],
    [{ status: 400, code: 'refresh_token_not_found' }, true],
    [{ status: 403, code: 'bad_jwt' }, true],
    [{ status: 429, code: 'over_request_rate_limit' }, false],
    [{ status: 408 }, false],
    [{ status: 400 }, false],
    [{ status: 500 }, false],
    [{ status: 503 }, false],
    [null, false],
    [new Error('Failed to fetch'), false],
  ])('%j -> %s', (error, expected) => {
    expect(isDefinitelyInvalidSession(error)).toBe(expected)
  })
})
