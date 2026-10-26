import { act, cleanup, render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

/**
 * Routing and refresh behaviour of the signed-in app. A "refresh" is simulated
 * the way a real page reload behaves: everything in memory is gone (the vault
 * key is dropped with lockVault() and the tree is unmounted), and the app is
 * rendered again from the same URL.
 */

const state = vi.hoisted(() => ({ auth: { status: 'loading' } as unknown }))

vi.mock('./config/env', () => ({
  configResult: { ok: true, config: { supabaseUrl: 'https://example.supabase.co', supabasePublishableKey: 'sb_publishable_test', passkeysEnabled: false } },
}))
vi.mock('./lib/supabase', () => ({ supabase: null, passkeysEnabled: false }))
vi.mock('./lib/vaultBackendInstance', () => ({ vaultBackend: null }))
vi.mock('./hooks/useAuth', () => ({ useAuth: () => state.auth }))
vi.mock('./hooks/useMembership', () => ({
  useMembership: () => ({ membership: { status: 'member', vaultId: '5a5a5a5a-1111-4222-8333-444444444444' }, retry: () => undefined }),
}))

import App, { SignedInApp } from './App'
import { createFolder, listVaultFolders } from './services/folders'
import { uploadFile } from './services/media'
import { MemoryBackend } from './services/testing/memoryBackend'
import { testFile } from './services/testing/testFile'
import { prepareNewVault, unlockWithPassphrase } from './services/vaultKeys'
import { getVaultStatus, lockVault } from './services/vaultSession'

const VAULT = '5a5a5a5a-1111-4222-8333-444444444444'
const PASSPHRASE = 'HB_SPACE_TEST_PASSPHRASE river otter lantern'
const USER = { id: '11111111-1111-4111-8111-111111111111', email: 'member@test' }
const jpeg = (s: string) => new Uint8Array([0xff, 0xd8, 0xff, 0xe0, ...new TextEncoder().encode(s)])
const file = (name: string, s: string) => testFile(name, jpeg(s))

let backend: MemoryBackend
let folderId: string

async function seed() {
  backend = new MemoryBackend(VAULT)
  const prepared = await prepareNewVault(backend, VAULT, PASSPHRASE, { m: 16384, t: 1, p: 1 })
  await prepared.commit()
  folderId = await createFolder(backend, VAULT, null, 'HB_SPACE_TEST Album')
  await uploadFile(backend, VAULT, file('in-album.jpg', 'a'), { folderId })
  await uploadFile(backend, VAULT, file('at-root.jpg', 'b'))
  lockVault() // a page load always starts locked
}

function go(hash: string) {
  window.history.replaceState(null, '', `/${hash}`)
}

async function unlock() {
  await act(async () => {
    await unlockWithPassphrase(backend, VAULT, PASSPHRASE)
  })
}

beforeEach(async () => {
  let n = 0
  URL.createObjectURL = vi.fn(() => `blob:test/${n++}`)
  URL.revokeObjectURL = vi.fn()
  localStorage.clear()
  sessionStorage.clear()
  await seed()
})

afterEach(() => {
  cleanup()
  lockVault()
  go('')
})

describe('protected routes', () => {
  it('a signed-out user on a protected route sees only the login screen', () => {
    state.auth = { status: 'signed-out' }
    go('#/settings')
    render(<App />)
    expect(screen.getByRole('heading', { level: 1, name: /HB Space/ })).toBeTruthy()
    expect(screen.queryByRole('heading', { name: 'Vault security' })).toBeNull()
    go(`#/folder/${folderId}`)
    cleanup()
    render(<App />)
    expect(screen.queryByText('HB_SPACE_TEST Album')).toBeNull()
  })

  it('while the session is being restored, a loading screen is shown (not the login screen)', () => {
    state.auth = { status: 'loading' }
    go('#/settings')
    render(<App />)
    expect(screen.queryByRole('heading', { level: 1, name: /HB Space/ })).toBeNull()
  })

  it('an authenticated refresh renders the signed-in app on the same route', () => {
    state.auth = { status: 'signed-in', user: USER, offline: false }
    go('#/settings')
    render(<App />)
    expect(screen.getByRole('heading', { name: 'Vault security' })).toBeTruthy()
  })
})

describe('refresh behaviour (signed in)', () => {
  it('settings: stays on settings', () => {
    go('#/settings')
    render(<SignedInApp user={USER} offline={false} backend={backend} />)
    expect(screen.getByRole('heading', { name: 'Vault security' })).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Settings' }).getAttribute('aria-current')).toBe('page')
  })

  it('locked vault inside a folder: requires unlock first, shows nothing private, then restores the folder', async () => {
    go(`#/folder/${folderId}`)
    render(<SignedInApp user={USER} offline={false} backend={backend} />)
    expect(await screen.findByRole('heading', { name: 'Vault locked' })).toBeTruthy()
    expect(screen.queryByText('HB_SPACE_TEST Album')).toBeNull()
    expect(screen.queryByText('in-album.jpg')).toBeNull()
    await unlock()
    expect(await screen.findByRole('heading', { name: 'HB_SPACE_TEST Album' })).toBeTruthy()
    expect(await screen.findByText('in-album.jpg')).toBeTruthy()
    expect(screen.queryByText('at-root.jpg')).toBeNull() // folder isolation
  })

  it('unlocked vault: a refresh does not restore the key (comes back locked, nothing stored), then returns to the same place', async () => {
    go(`#/folder/${folderId}`)
    const first = render(<SignedInApp user={USER} offline={false} backend={backend} />)
    await unlock()
    expect(await screen.findByText('in-album.jpg')).toBeTruthy()
    // Refresh: memory is wiped, the page is rendered again from the same URL.
    first.unmount()
    lockVault()
    render(<SignedInApp user={USER} offline={false} backend={backend} />)
    expect(await screen.findByRole('heading', { name: 'Vault locked' })).toBeTruthy()
    expect(getVaultStatus()).toBe('locked')
    expect(localStorage.length + sessionStorage.length).toBe(0)
    await unlock()
    expect(await screen.findByRole('heading', { name: 'HB_SPACE_TEST Album' })).toBeTruthy()
  })

  it('normal flow: an existing session goes straight to the vault passphrase (no login form, no sign-out button)', async () => {
    go('#/')
    render(<SignedInApp user={USER} offline={false} backend={backend} />)
    expect(await screen.findByRole('heading', { name: 'Vault locked' })).toBeTruthy()
    expect(screen.getByLabelText('Vault passphrase')).toBeTruthy()
    expect(screen.queryByLabelText(/email/i)).toBeNull()
    expect(screen.queryByRole('button', { name: /sign out/i })).toBeNull()
  })

  it('an old #/trash bookmark (Trash was removed) safely lands on the vault root', async () => {
    go('#/trash')
    render(<SignedInApp user={USER} offline={false} backend={backend} />)
    expect(await screen.findByRole('heading', { name: 'Vault locked' })).toBeTruthy()
    await unlock()
    expect(await screen.findByRole('heading', { name: 'Vault' })).toBeTruthy()
    await waitFor(() => expect(window.location.hash).toBe('#/'))
    expect(screen.queryByRole('button', { name: /Trash/ })).toBeNull()
  })

  it('a folder that no longer exists shows a safe fallback', async () => {
    go('#/folder/9a9a9a9a-1111-4222-8333-444444444444')
    render(<SignedInApp user={USER} offline={false} backend={backend} />)
    await unlock()
    expect(await screen.findByRole('heading', { name: 'Folder not found' })).toBeTruthy()
  })

  it('an invalid route falls back to the vault root', async () => {
    go('#/definitely/not/a/route')
    render(<SignedInApp user={USER} offline={false} backend={backend} />)
    await unlock()
    expect(await screen.findByText('at-root.jpg')).toBeTruthy()
    await waitFor(() => expect(window.location.hash).toBe('#/'))
  })

  it('the folder name is decrypted locally and never appears in the URL', async () => {
    go(`#/folder/${folderId}`)
    render(<SignedInApp user={USER} offline={false} backend={backend} />)
    await unlock()
    await screen.findByRole('heading', { name: 'HB_SPACE_TEST Album' })
    expect(window.location.href).not.toMatch(/Album/)
    expect((await listVaultFolders(backend, VAULT)).folders[0].name).toBe('HB_SPACE_TEST Album')
  })
})
