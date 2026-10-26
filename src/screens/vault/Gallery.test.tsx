import { StrictMode } from 'react'
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { Route } from '../../lib/router'
import { createFolder } from '../../services/folders'
import { uploadFile } from '../../services/media'
import { MemoryBackend } from '../../services/testing/memoryBackend'
import { testFile } from '../../services/testing/testFile'
import { prepareNewVault } from '../../services/vaultKeys'
import { activeObjectUrlCount, lockVault } from '../../services/vaultSession'
import { UploadQueue } from '../../services/uploadQueue'
import { VaultHome } from './VaultHome'

const VAULT = '5a5a5a5a-1111-4222-8333-444444444444'
const jpeg = (s: string) => new Uint8Array([0xff, 0xd8, 0xff, 0xe0, ...new TextEncoder().encode(s)])
const file = (name: string, s: string) => testFile(name, jpeg(s))

let backend: MemoryBackend
let folderId: string
const noThumbs = async () => null

async function seed() {
  backend = new MemoryBackend(VAULT)
  const prepared = await prepareNewVault(backend, VAULT, 'HB_SPACE_TEST_PASSPHRASE river otter lantern', { m: 16384, t: 1, p: 1 })
  await prepared.commit() // leaves the vault unlocked
  folderId = await createFolder(backend, VAULT, null, 'Album')
  await uploadFile(backend, VAULT, file('album-1.jpg', '1'), { folderId })
  await uploadFile(backend, VAULT, file('album-2.jpg', '2'), { folderId })
  await uploadFile(backend, VAULT, file('root-1.jpg', '3'))
}

function renderAt(route: Extract<Route, { name: 'vault' | 'trash' }>) {
  const navigate = vi.fn()
  const saver = vi.fn()
  const utils = render(<VaultHome vaultId={VAULT} backend={backend} route={route} navigate={navigate} thumbnailMaker={noThumbs} saver={saver} />)
  return { ...utils, navigate, saver }
}

function trashedIds(): string[] {
  return [...backend.media.values()].filter((r) => r.trashed_at !== null).map((r) => r.id as string)
}

beforeEach(async () => {
  let n = 0
  URL.createObjectURL = vi.fn(() => `blob:test/${n++}`)
  URL.revokeObjectURL = vi.fn()
  await seed()
})

afterEach(() => {
  cleanup()
  lockVault()
})

describe('gallery', () => {
  it('shows folders and decrypted names; the folder view shows only that folder', async () => {
    renderAt({ name: 'vault', folderId: null })
    expect(await screen.findByRole('button', { name: /Open folder Album/ })).toBeTruthy()
    expect(screen.getByText('root-1.jpg')).toBeTruthy()
    expect(screen.queryByText('album-1.jpg')).toBeNull()
    cleanup()
    renderAt({ name: 'vault', folderId })
    expect(await screen.findByText('album-1.jpg')).toBeTruthy()
    expect(screen.getByText('album-2.jpg')).toBeTruthy()
    expect(screen.queryByText('root-1.jpg')).toBeNull()
  })

  it('select all in a folder + Delete permanently deletes exactly those items, after a confirmation naming them', async () => {
    const user = userEvent.setup()
    renderAt({ name: 'vault', folderId })
    await screen.findByText('album-1.jpg')
    await user.click(screen.getByRole('button', { name: 'Select' }))
    await user.click(screen.getByRole('button', { name: 'Select all 2 in this folder' }))
    expect(screen.getByText('2 selected')).toBeTruthy()
    await user.click(screen.getByRole('button', { name: 'Delete' }))
    const dialog = await screen.findByRole('dialog', { name: 'Delete 2 items permanently?' })
    expect(within(dialog).getByText(/cannot be undone/)).toBeTruthy()
    expect(within(dialog).getByText('album-1.jpg')).toBeTruthy()
    expect(within(dialog).getByText('album-2.jpg')).toBeTruthy()
    await user.click(within(dialog).getByRole('button', { name: 'Delete 2 permanently' }))
    await waitFor(() => expect(backend.media.size).toBe(1))
    // Rows AND encrypted objects are gone; the item in another folder is untouched.
    expect([...backend.media.values()][0].folder_id).toBeNull()
    expect(backend.objects.size).toBe(1)
    expect(await screen.findByText('2 items permanently deleted.')).toBeTruthy()
    expect(screen.queryByText('album-1.jpg')).toBeNull()
  })

  it('cancelling the confirmation changes nothing', async () => {
    const user = userEvent.setup()
    renderAt({ name: 'vault', folderId })
    await screen.findByText('album-1.jpg')
    await user.click(screen.getByRole('button', { name: 'Select' }))
    await user.click(screen.getByRole('button', { name: /Select photo album-1.jpg/ }))
    await user.click(screen.getByRole('button', { name: 'Delete' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Cancel' }))
    expect(backend.media.size).toBe(3)
  })

  it('a non-empty folder cannot be deleted from the UI', async () => {
    const user = userEvent.setup()
    renderAt({ name: 'vault', folderId })
    await screen.findByText('album-1.jpg')
    await user.click(screen.getByRole('button', { name: 'Delete folder' }))
    const dialog = await screen.findByRole('dialog', { name: 'Delete this folder?' })
    expect(within(dialog).getByText(/Only empty folders can be deleted/)).toBeTruthy()
    await user.click(within(dialog).getByRole('button', { name: 'Delete folder' }))
    expect(await within(dialog).findByText(/This folder is not empty/)).toBeTruthy()
    expect(backend.folders.size).toBe(1)
  })

  it('opening an item shows the full-screen viewer; closing it revokes the decrypted URL', async () => {
    const user = userEvent.setup()
    renderAt({ name: 'vault', folderId: null })
    await user.click(await screen.findByRole('button', { name: 'Open photo root-1.jpg' }))
    const viewer = await screen.findByRole('dialog', { name: 'Viewing root-1.jpg' })
    await waitFor(() => expect(within(viewer).getByRole('img', { name: 'root-1.jpg' })).toBeTruthy())
    expect(activeObjectUrlCount()).toBeGreaterThan(0)
    await user.click(within(viewer).getByRole('button', { name: 'Close viewer' }))
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
    expect(activeObjectUrlCount()).toBe(0)
  })

  it('single download saves the decrypted file under its original name', async () => {
    const user = userEvent.setup()
    const { saver } = renderAt({ name: 'vault', folderId: null })
    await user.click(await screen.findByRole('button', { name: 'Open photo root-1.jpg' }))
    await user.click(await screen.findByRole('button', { name: 'Download' }))
    await waitFor(() => expect(saver).toHaveBeenCalledTimes(1))
    expect(saver.mock.calls[0][1]).toBe('root-1.jpg')
  })
})

describe('permanent deletion (no trash)', () => {
  it('Delete in the viewer asks first, then destroys the item and closes the viewer', async () => {
    const user = userEvent.setup()
    renderAt({ name: 'vault', folderId: null })
    await user.click(await screen.findByRole('button', { name: 'Open photo root-1.jpg' }))
    const viewer = await screen.findByRole('dialog', { name: 'Viewing root-1.jpg' })
    await user.click(within(viewer).getByRole('button', { name: 'Delete' }))
    const dialog = await screen.findByRole('dialog', { name: 'Delete permanently?' })
    expect(within(dialog).getByText('root-1.jpg')).toBeTruthy()
    await user.click(within(dialog).getByRole('button', { name: 'Delete permanently' }))
    await waitFor(() => expect(backend.media.size).toBe(2))
    expect(backend.objects.size).toBe(2)
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull())
  })

  it('a partial failure is reported, never claimed as complete', async () => {
    const ids = [...backend.media.keys()] as string[]
    const album1 = ids.find((id) => backend.media.get(id)!.folder_id === folderId)!
    backend.failFor.deleteObjects = new Set([`${VAULT}/${album1}`])
    const user = userEvent.setup()
    renderAt({ name: 'vault', folderId })
    await screen.findByText('album-1.jpg')
    await user.click(screen.getByRole('button', { name: 'Select' }))
    await user.click(screen.getByRole('button', { name: 'Select all 2 in this folder' }))
    await user.click(screen.getByRole('button', { name: 'Delete' }))
    await user.click(within(await screen.findByRole('dialog')).getByRole('button', { name: 'Delete 2 permanently' }))
    expect(await screen.findByText(/1 item could NOT be deleted/)).toBeTruthy()
    expect(backend.media.has(album1)).toBe(true)
  })

  it('there is no Trash anywhere, and items trashed by an earlier version show up again', async () => {
    const ids = [...backend.media.keys()] as string[]
    await backend.setMediaTrashed(VAULT, ids, true)
    expect(trashedIds()).toHaveLength(3)
    renderAt({ name: 'vault', folderId: null })
    expect(await screen.findByText('root-1.jpg')).toBeTruthy()
    expect(screen.queryByText(/trash/i)).toBeNull()
    expect(screen.queryByRole('button', { name: /restore/i })).toBeNull()
  })

  it('offers to remove uploads that never finished (older than an hour), with the same confirmation', async () => {
    const [someId] = [...backend.media.keys()] as string[]
    const stale = crypto.randomUUID()
    const old = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString()
    backend.media.set(stale, { ...backend.media.get(someId)!, id: stale, status: 'pending', folder_id: null, created_at: old, object_path: `${VAULT}/${stale}` })
    const user = userEvent.setup()
    renderAt({ name: 'vault', folderId: null })
    expect(await screen.findByText(/1 upload never finished/)).toBeTruthy()
    await user.click(screen.getByRole('button', { name: 'Remove' }))
    await user.click(within(await screen.findByRole('dialog', { name: 'Delete permanently?' })).getByRole('button', { name: 'Delete permanently' }))
    await waitFor(() => expect(backend.media.has(stale)).toBe(false))
    expect(backend.media.size).toBe(3)
  })
})

describe('under React StrictMode (as in main.tsx)', () => {
  it('uploads chosen files: the dev double-mount must not leave a disposed upload queue behind', async () => {
    render(
      <StrictMode>
        <VaultHome vaultId={VAULT} backend={backend} route={{ name: 'vault', folderId: null }} navigate={vi.fn()} thumbnailMaker={noThumbs} saver={vi.fn()} />
      </StrictMode>,
    )
    await screen.findByText('root-1.jpg')
    const before = backend.media.size
    fireEvent.change(screen.getByLabelText('Choose photos or videos to encrypt and upload'), {
      target: { files: [file('strict-mode.jpg', 'strict')] },
    })
    await waitFor(() => expect(backend.media.size).toBe(before + 1))
    await waitFor(() => expect([...backend.media.values()].every((r) => r.status === 'ready')).toBe(true))
    expect(await screen.findByText('strict-mode.jpg')).toBeTruthy()
  })
})

describe('camera', () => {
  it('Camera opens the in-app camera; a photo goes into the upload queue for the folder being viewed', async () => {
    const stop = vi.fn()
    Object.defineProperty(navigator, 'mediaDevices', {
      configurable: true,
      value: { getUserMedia: vi.fn(async () => ({ getTracks: () => [{ kind: 'video', stop }] })) },
    })
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true })
    Object.defineProperty(HTMLMediaElement.prototype, 'srcObject', { configurable: true, writable: true, value: null })
    HTMLMediaElement.prototype.play = vi.fn(async () => undefined)
    Object.defineProperty(HTMLVideoElement.prototype, 'videoWidth', { configurable: true, get: () => 640 })
    Object.defineProperty(HTMLVideoElement.prototype, 'videoHeight', { configurable: true, get: () => 480 })
    HTMLCanvasElement.prototype.getContext = vi.fn(() => ({ drawImage: vi.fn() })) as never
    HTMLCanvasElement.prototype.toBlob = function (cb: BlobCallback) {
      cb(new Blob([new Uint8Array([0xff, 0xd8, 0xff, 0xe0])], { type: 'image/jpeg' }))
    }
    const add = vi.spyOn(UploadQueue.prototype, 'add').mockReturnValue(['k'])
    try {
      const user = userEvent.setup()
      renderAt({ name: 'vault', folderId })
      await screen.findByText('album-1.jpg')
      await user.click(screen.getByRole('button', { name: 'Camera' }))
      await user.click(await screen.findByRole('button', { name: 'Take photo' }))
      await waitFor(() => expect(add).toHaveBeenCalledTimes(1))
      const [files, target] = add.mock.calls[0]
      expect(target).toBe(folderId)
      expect((files[0] as File).name).toMatch(/^Photo .*\.jpg$/)
      await user.click(screen.getByRole('button', { name: 'Close camera' }))
      expect(screen.queryByRole('button', { name: 'Take photo' })).toBeNull()
      expect(stop).toHaveBeenCalled()
    } finally {
      add.mockRestore()
    }
  })
})

describe('layout', () => {
  it('the vault card holds the title, storage used / limit, Upload and Camera', async () => {
    renderAt({ name: 'vault', folderId: null })
    const title = await screen.findByRole('heading', { name: 'Vault' })
    const card = title.closest('.vault-card') as HTMLElement
    expect(within(card).getByRole('button', { name: 'Upload' })).toBeTruthy()
    expect(within(card).getByRole('button', { name: 'Camera' })).toBeTruthy()
    const used = [...backend.media.values()].reduce((sum, r) => sum + (r.ciphertext_size as number), 0)
    expect(within(card).getByRole('meter', { name: 'Storage used' }).getAttribute('aria-valuetext')).toMatch(new RegExp(`^${used} B / 1 GB`))
    expect(screen.queryByText(/settings/i)).toBeNull()
  })

  it('each photo card shows its name and age, and a "..." menu with Download, Move and Delete', async () => {
    const user = userEvent.setup()
    const { saver } = renderAt({ name: 'vault', folderId: null })
    await screen.findByText('root-1.jpg')
    const card = screen.getByText('root-1.jpg').closest('.tile') as HTMLElement
    expect(card.querySelector('.tile__meta')!.textContent).toMatch(/ago|just now|yesterday|last /)
    await user.click(screen.getByRole('button', { name: 'More actions for root-1.jpg' }))
    const menu = screen.getByRole('menu', { name: 'Actions for root-1.jpg' })
    expect(within(menu).getAllByRole('menuitem').map((m) => m.textContent)).toEqual(['Download', 'Move', 'Delete'])
    await user.click(within(menu).getByRole('menuitem', { name: 'Download' }))
    await waitFor(() => expect(saver).toHaveBeenCalledTimes(1))
    expect(screen.queryByRole('menu')).toBeNull()

    await user.click(screen.getByRole('button', { name: 'More actions for root-1.jpg' }))
    await user.click(screen.getByRole('menuitem', { name: 'Delete' }))
    const dialog = await screen.findByRole('dialog', { name: 'Delete permanently?' })
    await user.click(within(dialog).getByRole('button', { name: 'Delete permanently' }))
    await waitFor(() => expect(backend.media.size).toBe(2))
  })

  it('the "..." menu closes with Escape', async () => {
    const user = userEvent.setup()
    renderAt({ name: 'vault', folderId: null })
    await screen.findByText('root-1.jpg')
    await user.click(screen.getByRole('button', { name: 'More actions for root-1.jpg' }))
    expect(screen.getByRole('menu')).toBeTruthy()
    await user.keyboard('{Escape}')
    expect(screen.queryByRole('menu')).toBeNull()
  })

  it('switches between grid and list view and remembers the choice on this device', async () => {
    const user = userEvent.setup()
    localStorage.removeItem('hbspace.galleryView')
    renderAt({ name: 'vault', folderId: null })
    await screen.findByText('root-1.jpg')
    const list = screen.getByRole('list', { name: 'Vault contents' })
    expect(list.className).not.toContain('grid--list')
    await user.click(screen.getByRole('button', { name: 'List view' }))
    expect(list.className).toContain('grid--list')
    expect(localStorage.getItem('hbspace.galleryView')).toBe('list')
    await user.click(screen.getByRole('button', { name: 'Grid view' }))
    expect(list.className).not.toContain('grid--list')
    localStorage.removeItem('hbspace.galleryView')
  })
})
