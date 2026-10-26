// @vitest-environment node
/**
 * Phase 4 service flows against the in-memory backend (which enforces the same
 * rules as migrations 1-5): thumbnails, video, folders, multi-file upload queue,
 * move, permanent deletion (no trash), downloads and local ZIPs, and leak scans
 * of everything that would leave the browser.
 *
 * Synthetic files only (magic bytes + test payloads); never real media.
 */
import { unzipSync } from 'fflate'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { equalBytes, readBlob, utf8 } from '../lib/crypto/bytes'
import { FORMAT_MAGIC } from '../lib/crypto/mediaFormat'
import { buildZip, downloadItem, downloadSeparately, entriesForFolder, entriesForItems, ZIP_MAX_BYTES } from './downloads'
import { createFolder, deleteFolder, FOLDER_MESSAGES, listVaultFolders, renameFolder } from './folders'
import {
  listVaultItems,
  loadThumbnailUrl,
  MEDIA_MESSAGES,
  moveItems,
  openVaultItem,
  purgeItems,
  uploadFile,
  type ReadyItem,
  type ThumbnailMaker,
  type VaultItem,
} from './media'
import { MemoryBackend } from './testing/memoryBackend'
import { ThumbnailLoader } from './thumbnailLoader'
import { UploadQueue, type QueueEntry } from './uploadQueue'
import { BackendError } from './vaultBackend'
import { prepareNewVault } from './vaultKeys'
import { activeObjectUrlCount, lockVault } from './vaultSession'

const VAULT = '5a5a5a5a-1111-4222-8333-444444444444'
const PASSPHRASE = 'HB_SPACE_TEST_PASSPHRASE river otter lantern'
const FAST = { m: 16384, t: 1, p: 1 }

const JPEG_MAGIC = [0xff, 0xd8, 0xff, 0xe0]
const MP4_MAGIC = [0, 0, 0, 0x18, 0x66, 0x74, 0x79, 0x70, 0x69, 0x73, 0x6f, 0x6d]

function jpeg(payload: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array([...JPEG_MAGIC, ...utf8(payload)])
}
function mp4(payload: string): Uint8Array<ArrayBuffer> {
  return new Uint8Array([...MP4_MAGIC, ...utf8(payload)])
}
function file(name: string, bytes: Uint8Array<ArrayBuffer>) {
  return Object.assign(new Blob([bytes]), { name, lastModified: 1767225600000 })
}

/** A fake local thumbnail generator: a tiny synthetic JPEG derived from nothing private. */
const THUMB_BYTES = jpeg('HB_SPACE_TEST_THUMBNAIL_PIXELS')
const fakeThumbs: ThumbnailMaker = async (_file, type) => ({
  bytes: THUMB_BYTES.slice(),
  facts: type.startsWith('video/') ? { width: 640, height: 360, duration: 4.5 } : { width: 400, height: 300 },
})

function contains(haystack: Uint8Array, needle: Uint8Array): boolean {
  outer: for (let i = 0; i + needle.length <= haystack.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer
    return true
  }
  return false
}

let backend: MemoryBackend
let blobs: Map<string, Blob>
let revoked: string[]

beforeEach(async () => {
  lockVault()
  backend = new MemoryBackend(VAULT)
  blobs = new Map()
  revoked = []
  let n = 0
  vi.spyOn(URL, 'createObjectURL').mockImplementation((blob) => {
    const url = `blob:test/${n++}`
    blobs.set(url, blob as Blob)
    return url
  })
  vi.spyOn(URL, 'revokeObjectURL').mockImplementation((url: string) => {
    revoked.push(url)
  })
  const prepared = await prepareNewVault(backend, VAULT, PASSPHRASE, FAST)
  await prepared.commit()
})

afterEach(() => {
  lockVault()
})

async function items(): Promise<VaultItem[]> {
  return (await listVaultItems(backend, VAULT)).items
}

function ready(list: VaultItem[]): ReadyItem[] {
  return list.filter((i): i is ReadyItem => i.state === 'ready')
}

describe('thumbnails (encrypted, generated locally)', () => {
  it('uploads content then the encrypted thumbnail, then marks ready; the preview never leaves in plaintext', async () => {
    const id = await uploadFile(backend, VAULT, file('HB_SPACE_TEST-beach.jpg', jpeg('HB_SPACE_TEST original pixels')), { makeThumbnail: fakeThumbs })
    const ops = backend.log.map((r) => r.op).filter((op) => !op.includes('Envelope'))
    expect(ops).toEqual(['insertPendingMedia', 'uploadObject', 'uploadObject', 'markReady'])
    const uploads = backend.log.filter((r) => r.op === 'uploadObject').map((r) => r.body as { path: string; bytes: Uint8Array })
    expect(uploads.map((u) => u.path)).toEqual([`${VAULT}/${id}`, `${VAULT}/${id}.t`])
    for (const u of uploads) expect(equalBytes(u.bytes.subarray(0, 4), FORMAT_MAGIC)).toBe(true)
    for (const sent of backend.sentBytes()) {
      expect(contains(sent, utf8('HB_SPACE_TEST_THUMBNAIL_PIXELS'))).toBe(false)
      expect(contains(sent, utf8('beach'))).toBe(false)
    }
    expect(backend.media.get(id)).toMatchObject({ has_thumbnail: true, status: 'ready' })
  })

  it('the gallery decrypts only the thumbnail (never the original) into a revocable URL', async () => {
    await uploadFile(backend, VAULT, file('a.jpg', jpeg('original')), { makeThumbnail: fakeThumbs })
    const [item] = await items()
    backend.log = []
    const url = await loadThumbnailUrl(backend, VAULT, item.record)
    expect(backend.log.map((r) => (r.body as { path?: string }).path)).toEqual([`${VAULT}/${item.id}.t`])
    expect(equalBytes(await readBlob(blobs.get(url)!), THUMB_BYTES)).toBe(true)
    expect(blobs.get(url)!.type).toBe('image/jpeg')
    lockVault()
    expect(revoked).toContain(url)
  })

  it('a failing or bogus thumbnail generator never blocks the upload; the item simply has no thumbnail', async () => {
    await uploadFile(backend, VAULT, file('a.jpg', jpeg('x')), { makeThumbnail: async () => Promise.reject(new Error('decode failed')) })
    await uploadFile(backend, VAULT, file('b.jpg', jpeg('y')), { makeThumbnail: async () => ({ bytes: utf8('<svg/>'), facts: {} }) })
    await uploadFile(backend, VAULT, file('c.jpg', jpeg('z')), { makeThumbnail: async () => null })
    expect([...backend.media.values()].map((r) => r.has_thumbnail)).toEqual([false, false, false])
    expect(backend.objects.size).toBe(3)
  })

  it('a tampered thumbnail object shows nothing', async () => {
    await uploadFile(backend, VAULT, file('a.jpg', jpeg('x')), { makeThumbnail: fakeThumbs })
    const [item] = await items()
    const path = `${VAULT}/${item.id}.t`
    const bytes = backend.objects.get(path)!
    bytes[bytes.length - 1] ^= 1
    await expect(loadThumbnailUrl(backend, VAULT, item.record)).rejects.toMatchObject({ userMessage: MEDIA_MESSAGES.openFailed })
  })

  it('if the thumbnail upload fails, the content object and the row are removed too', async () => {
    const original = backend.uploadObject.bind(backend)
    backend.uploadObject = async (path, bytes) => {
      if (path.endsWith('.t')) throw new BackendError('network')
      return original(path, bytes)
    }
    await expect(uploadFile(backend, VAULT, file('a.jpg', jpeg('x')), { makeThumbnail: fakeThumbs })).rejects.toMatchObject({
      userMessage: MEDIA_MESSAGES.network,
    })
    expect(backend.media.size).toBe(0)
    expect(backend.objects.size).toBe(0)
  })

  it('the thumbnail loader limits concurrency, caches, and revokes evicted/disposed URLs', async () => {
    for (let i = 0; i < 6; i++) await uploadFile(backend, VAULT, file(`p${i}.jpg`, jpeg(`p${i}`)), { makeThumbnail: fakeThumbs })
    const list = await items()
    let active = 0
    let peak = 0
    const realDownload = backend.downloadObject.bind(backend)
    backend.downloadObject = async (path, max) => {
      active++
      peak = Math.max(peak, active)
      await new Promise((resolve) => setTimeout(resolve, 5))
      try {
        return await realDownload(path, max)
      } finally {
        active--
      }
    }
    const loader = new ThumbnailLoader(backend, VAULT, { concurrency: 2, capacity: 3 })
    const urls = await Promise.all(list.map((i) => loader.acquire(i.record)))
    expect(peak).toBeLessThanOrEqual(2)
    expect(urls.every((u) => typeof u === 'string')).toBe(true)
    expect(await loader.acquire(list[0].record)).toBe(urls[0]) // cached
    for (const i of list) loader.release(i.id)
    loader.release(list[0].id)
    expect(loader.size).toBeLessThanOrEqual(3)
    loader.dispose()
    expect(loader.size).toBe(0)
    for (const url of urls) expect(revoked).toContain(url)
  })
})

describe('video', () => {
  it('a synthetic MP4 uploads with a frame thumbnail and its duration, and opens as playable video/mp4', async () => {
    await uploadFile(backend, VAULT, file('HB_SPACE_TEST clip.mp4', mp4('HB_SPACE_TEST video frames')), { makeThumbnail: fakeThumbs })
    const [item] = ready(await items())
    expect(item.meta).toMatchObject({ mime: 'video/mp4', duration: 4.5, width: 640, height: 360 })
    const opened = await openVaultItem(backend, VAULT, item.record)
    expect(opened).toMatchObject({ inline: true, type: 'video/mp4' })
    expect(equalBytes(await readBlob(blobs.get(opened.url)!), mp4('HB_SPACE_TEST video frames'))).toBe(true)
    lockVault()
    expect(activeObjectUrlCount()).toBe(0)
  })

  it('a QuickTime/WebM file is accepted by bytes; a non-media file named .mp4 is refused', async () => {
    const webm = new Uint8Array([0x1a, 0x45, 0xdf, 0xa3, 1, 2, 3])
    await uploadFile(backend, VAULT, file('v.webm', webm))
    await expect(uploadFile(backend, VAULT, file('fake.mp4', utf8('not a video at all')))).rejects.toMatchObject({
      userMessage: MEDIA_MESSAGES.unsupported,
    })
    expect(backend.media.size).toBe(1)
  })
})

describe('folders (encrypted names, opaque ids)', () => {
  it('create, list, rename, and nest; the server only ever sees ids and ciphertext', async () => {
    const tripId = await createFolder(backend, VAULT, null, 'HB_SPACE_TEST Bali trip')
    let { folders } = await listVaultFolders(backend, VAULT)
    const trip = folders.find((f) => f.id === tripId)!
    expect(trip.name).toBe('HB_SPACE_TEST Bali trip')
    const dayId = await createFolder(backend, VAULT, trip, 'HB_SPACE_TEST Day one')
    await renameFolder(backend, VAULT, trip, 'HB_SPACE_TEST Honeymoon')
    ;({ folders } = await listVaultFolders(backend, VAULT))
    expect(folders.find((f) => f.id === tripId)).toMatchObject({ name: 'HB_SPACE_TEST Honeymoon', revision: 2 })
    expect(folders.find((f) => f.id === dayId)).toMatchObject({ parentId: tripId, depth: 1 })
    for (const blob of [...backend.sentBytes(), ...backend.persistedBytes()]) {
      for (const secret of ['Bali', 'Honeymoon', 'Day one']) expect(contains(blob, utf8(secret)), secret).toBe(false)
    }
  })

  it('a stale rename (changed on another device) is refused, not overwritten', async () => {
    const id = await createFolder(backend, VAULT, null, 'One')
    const [folder] = (await listVaultFolders(backend, VAULT)).folders
    await renameFolder(backend, VAULT, folder, 'Two')
    await expect(renameFolder(backend, VAULT, folder, 'Three')).rejects.toMatchObject({ userMessage: FOLDER_MESSAGES.renameConflict })
    expect((await listVaultFolders(backend, VAULT)).folders.find((f) => f.id === id)!.name).toBe('Two')
  })

  it('a tampered folder name shows as unreadable instead of anything attacker-chosen', async () => {
    await createFolder(backend, VAULT, null, 'Private')
    const row = [...backend.folders.values()][0]
    const hex = row.encrypted_meta as string
    row.encrypted_meta = hex.slice(0, 40) + (hex[40] === '0' ? '1' : '0') + hex.slice(41)
    expect((await listVaultFolders(backend, VAULT)).folders[0].name).toBeNull()
  })

  it('uploads go into the selected folder; storage paths never mention it', async () => {
    const id = await createFolder(backend, VAULT, null, 'HB_SPACE_TEST Album')
    const itemId = await uploadFile(backend, VAULT, file('a.jpg', jpeg('x')), { folderId: id })
    expect(backend.media.get(itemId)).toMatchObject({ folder_id: id, object_path: `${VAULT}/${itemId}` })
  })

  it('a folder with items cannot be deleted; once its items are deleted it can', async () => {
    const id = await createFolder(backend, VAULT, null, 'Album')
    await uploadFile(backend, VAULT, file('a.jpg', jpeg('x')), { folderId: id })
    const folder = (await listVaultFolders(backend, VAULT)).folders[0]
    await expect(deleteFolder(backend, VAULT, folder)).rejects.toMatchObject({ userMessage: FOLDER_MESSAGES.notEmpty })
    expect(backend.folders.size).toBe(1)
    await purgeItems(backend, VAULT, (await items()).map((i) => i.record))
    await deleteFolder(backend, VAULT, folder)
    expect(backend.folders.size).toBe(0)
    expect(backend.objects.size).toBe(0)
  })

  it('a folder with subfolders cannot be deleted', async () => {
    await createFolder(backend, VAULT, null, 'Parent')
    const parent = (await listVaultFolders(backend, VAULT)).folders[0]
    await createFolder(backend, VAULT, parent, 'Child')
    await expect(deleteFolder(backend, VAULT, parent)).rejects.toMatchObject({ userMessage: FOLDER_MESSAGES.notEmpty })
  })

  it('folder operations need an unlocked vault', async () => {
    lockVault()
    await expect(createFolder(backend, VAULT, null, 'X')).rejects.toMatchObject({ userMessage: MEDIA_MESSAGES.locked })
    expect(backend.log.some((r) => r.op === 'insertFolder')).toBe(false)
  })
})

describe('multi-file upload queue', () => {
  function queueFor(onDone?: (id: string) => void) {
    return new UploadQueue((f, folderId, signal, onStage) => uploadFile(backend, VAULT, f, { folderId, signal, onStage, makeThumbnail: fakeThumbs }), onDone)
  }

  async function settled(queue: UploadQueue): Promise<QueueEntry[]> {
    for (let i = 0; i < 400 && queue.busy; i++) await new Promise((resolve) => setTimeout(resolve, 5))
    return queue.getSnapshot()
  }

  it('uploads several files one at a time, each exactly once', async () => {
    const done: string[] = []
    const queue = queueFor((id) => done.push(id))
    let concurrent = 0
    let peak = 0
    const realInsert = backend.insertPendingMedia.bind(backend)
    backend.insertPendingMedia = async (row) => {
      concurrent++
      peak = Math.max(peak, concurrent)
      await new Promise((resolve) => setTimeout(resolve, 3))
      await realInsert(row)
      concurrent--
    }
    queue.add([file('1.jpg', jpeg('1')), file('2.mp4', mp4('2')), file('3.jpg', jpeg('3'))], null)
    const entries = await settled(queue)
    expect(entries.map((e) => e.status)).toEqual(['done', 'done', 'done'])
    expect(peak).toBe(1)
    expect(done).toHaveLength(3)
    expect(backend.media.size).toBe(3)
  })

  it('a failed upload can be retried, without creating a duplicate', async () => {
    const queue = queueFor()
    backend.failNext.uploadObject = new BackendError('network')
    queue.add([file('a.jpg', jpeg('a'))], null)
    let [entry] = await settled(queue)
    expect(entry).toMatchObject({ status: 'failed', error: MEDIA_MESSAGES.network, retryable: true })
    expect(backend.media.size).toBe(0)
    queue.retry(entry.key)
    queue.retry(entry.key) // double tap: still one attempt
    ;[entry] = await settled(queue)
    expect(entry.status).toBe('done')
    expect(backend.media.size).toBe(1)
  })

  it('unsupported or oversized files fail without a retry option and send nothing', async () => {
    const queue = queueFor()
    queue.add([file('notes.txt', utf8('hello'))], null)
    const [entry] = await settled(queue)
    expect(entry).toMatchObject({ status: 'failed', error: MEDIA_MESSAGES.unsupported, retryable: false })
    expect(backend.log.some((r) => r.op === 'insertPendingMedia')).toBe(false)
  })

  it('queued uploads can be cancelled; an active one is cancelled and cleaned up', async () => {
    const queue = queueFor()
    let release: () => void = () => undefined
    const gate = new Promise<void>((resolve) => (release = resolve))
    const realInsert = backend.insertPendingMedia.bind(backend)
    backend.insertPendingMedia = async (row) => {
      await realInsert(row)
      await gate
    }
    const [first, second] = queue.add([file('1.jpg', jpeg('1')), file('2.jpg', jpeg('2'))], null)
    queue.cancel(second)
    await new Promise((resolve) => setTimeout(resolve, 20))
    queue.cancel(first) // active: aborts at the next checkpoint
    release()
    const entries = await settled(queue)
    expect(entries.map((e) => e.status)).toEqual(['cancelled', 'cancelled'])
    expect(backend.media.size).toBe(0)
    expect(backend.objects.size).toBe(0)
  })

  it('uploads into the folder chosen when the files were added', async () => {
    const folderId = await createFolder(backend, VAULT, null, 'Target')
    const queue = queueFor()
    queue.add([file('a.jpg', jpeg('a')), file('b.jpg', jpeg('b'))], folderId)
    await settled(queue)
    expect([...backend.media.values()].map((r) => r.folder_id)).toEqual([folderId, folderId])
  })

  it('locking the vault mid-queue stops the remaining uploads before anything more is sent', async () => {
    const queue = queueFor()
    const realInsert = backend.insertPendingMedia.bind(backend)
    let calls = 0
    backend.insertPendingMedia = async (row) => {
      calls++
      await realInsert(row)
      if (calls === 1) lockVault()
    }
    queue.add([file('1.jpg', jpeg('1')), file('2.jpg', jpeg('2'))], null)
    const entries = await settled(queue)
    expect(entries.map((e) => e.status)).toEqual(['failed', 'failed'])
    expect(calls).toBe(1)
    expect(backend.media.size).toBe(0)
  })
})

describe('move and permanent deletion (no trash)', () => {
  async function three(folderId: string | null = null) {
    const ids: string[] = []
    for (const n of ['a', 'b', 'c']) ids.push(await uploadFile(backend, VAULT, file(`${n}.jpg`, jpeg(n)), { folderId, makeThumbnail: fakeThumbs }))
    return ids
  }

  it('move sends only opaque ids and reports what moved', async () => {
    const target = await createFolder(backend, VAULT, null, 'HB_SPACE_TEST Secret album')
    const ids = await three()
    const result = await moveItems(backend, VAULT, ids.slice(0, 2), target)
    expect(result.done).toHaveLength(2)
    expect([...backend.media.values()].map((r) => r.folder_id)).toEqual([target, target, null])
    const body = backend.log.find((r) => r.op === 'setMediaFolder')!.body as Record<string, unknown>
    expect(JSON.stringify(body)).not.toMatch(/Secret|album/)
  })

  it('Delete permanently removes content + thumbnail objects first, then the row, with progress (no trash step)', async () => {
    const ids = await three()
    const progress: number[] = []
    const result = await purgeItems(backend, VAULT, (await items()).map((i) => i.record), (done) => progress.push(done))
    expect(result).toEqual({ done: expect.arrayContaining(ids), failed: [] })
    expect(progress).toEqual([1, 2, 3])
    expect(backend.media.size).toBe(0)
    expect(backend.objects.size).toBe(0)
  })

  it('a partial failure is reported and the failed item stays intact (row and objects)', async () => {
    const ids = await three()
    backend.failFor.deleteObjects = new Set([`${VAULT}/${ids[1]}`])
    const result = await purgeItems(backend, VAULT, (await items()).map((i) => i.record))
    expect(result.failed).toEqual([ids[1]])
    expect(result.done.sort()).toEqual([ids[0], ids[2]].sort())
    expect(backend.media.has(ids[1])).toBe(true)
    expect(backend.objects.has(`${VAULT}/${ids[1]}`)).toBe(true)
    expect(backend.objects.has(`${VAULT}/${ids[1]}.t`)).toBe(true)
  })
})

describe('downloads and local ZIPs', () => {
  function savingTo(out: { blob: Blob; name: string }[]) {
    return (blob: Blob, name: string) => {
      out.push({ blob, name })
    }
  }

  it('single image: decrypted locally and saved under its original (decrypted) filename', async () => {
    const original = jpeg('HB_SPACE_TEST holiday photo')
    await uploadFile(backend, VAULT, file('HB_SPACE_TEST holiday.jpg', original))
    const [item] = ready(await items())
    const saved: { blob: Blob; name: string }[] = []
    await downloadItem(backend, VAULT, item, savingTo(saved))
    expect(saved[0].name).toBe('HB_SPACE_TEST holiday.jpg')
    expect(saved[0].blob.type).toBe('application/octet-stream')
    expect(equalBytes(await readBlob(saved[0].blob), original)).toBe(true)
  })

  it('single video: byte-exact, original name', async () => {
    const original = mp4('HB_SPACE_TEST video')
    await uploadFile(backend, VAULT, file('clip.mp4', original))
    const [item] = ready(await items())
    const saved: { blob: Blob; name: string }[] = []
    await downloadItem(backend, VAULT, item, savingTo(saved))
    expect(saved[0].name).toBe('clip.mp4')
    expect(equalBytes(await readBlob(saved[0].blob), original)).toBe(true)
  })

  it('multiple files separately: one at a time, failures reported', async () => {
    await uploadFile(backend, VAULT, file('a.jpg', jpeg('a')))
    await uploadFile(backend, VAULT, file('b.jpg', jpeg('b')))
    const list = ready(await items())
    const [, second] = list
    const bytes = backend.objects.get(`${VAULT}/${second.id}`)!
    bytes[50] ^= 1
    const saved: { blob: Blob; name: string }[] = []
    const result = await downloadSeparately(backend, VAULT, list, { save: savingTo(saved), gapMs: 0 })
    expect(result.done).toHaveLength(1)
    expect(result.failed).toEqual([second.id])
    expect(saved).toHaveLength(1)
  })

  it('ZIP of a selection: built locally, exact bytes, original names, duplicates renamed, never uploaded', async () => {
    const a = jpeg('HB_SPACE_TEST first')
    const b = jpeg('HB_SPACE_TEST second')
    const c = mp4('HB_SPACE_TEST third')
    await uploadFile(backend, VAULT, file('same.jpg', a))
    await uploadFile(backend, VAULT, file('same.jpg', b))
    await uploadFile(backend, VAULT, file('clip.mp4', c))
    const list = ready(await items())
    const before = backend.log.length
    const { blob, failed } = await buildZip(backend, VAULT, entriesForItems(list))
    expect(failed).toEqual([])
    expect(backend.log.slice(before).every((r) => r.op === 'downloadObject')).toBe(true) // nothing sent up
    const files = unzipSync(await readBlob(blob))
    expect(Object.keys(files).sort()).toEqual(['clip.mp4', 'same (2).jpg', 'same.jpg'])
    const byBytes = Object.values(files)
    for (const original of [a, b, c]) expect(byBytes.some((f) => equalBytes(f, original))).toBe(true)
  })

  it('folder "Download all": includes subfolders by decrypted name; excludes other folders and unfinished uploads; includes items trashed by an earlier version', async () => {
    const trip = await createFolder(backend, VAULT, null, 'Trip')
    const tripFolder = (await listVaultFolders(backend, VAULT)).folders.find((f) => f.id === trip)!
    const day = await createFolder(backend, VAULT, tripFolder, 'Day 1')
    const other = await createFolder(backend, VAULT, null, 'Other')
    await uploadFile(backend, VAULT, file('top.jpg', jpeg('top')), { folderId: trip })
    await uploadFile(backend, VAULT, file('inner.jpg', jpeg('inner')), { folderId: day })
    const trashed = await uploadFile(backend, VAULT, file('trashed.jpg', jpeg('trashed')), { folderId: trip })
    await uploadFile(backend, VAULT, file('elsewhere.jpg', jpeg('elsewhere')), { folderId: other })
    await uploadFile(backend, VAULT, file('root.jpg', jpeg('root')))
    await backend.setMediaTrashed(VAULT, [trashed], true) // legacy trash state: no longer hides anything
    const { folders } = await listVaultFolders(backend, VAULT)
    const entries = entriesForFolder(await items(), folders, trip)
    expect(entries.map((e) => e.path).sort()).toEqual(['Day 1/inner.jpg', 'top.jpg', 'trashed.jpg'])
    const files = unzipSync(await readBlob((await buildZip(backend, VAULT, entries)).blob))
    expect(Object.keys(files).sort()).toEqual(['Day 1/inner.jpg', 'top.jpg', 'trashed.jpg'])
    expect(equalBytes(files['Day 1/inner.jpg'], jpeg('inner'))).toBe(true)
    // Vault root "Download all": every active item, laid out by folder.
    const all = entriesForFolder(await items(), folders, null).map((e) => e.path).sort()
    expect(all).toEqual(['Other/elsewhere.jpg', 'Trip/Day 1/inner.jpg', 'Trip/top.jpg', 'Trip/trashed.jpg', 'root.jpg'])
  })

  it('ZIP entry names cannot escape the archive', async () => {
    const id = await createFolder(backend, VAULT, null, '..')
    await uploadFile(backend, VAULT, file('../../evil.jpg', jpeg('x')), { folderId: id })
    const { folders } = await listVaultFolders(backend, VAULT)
    const paths = entriesForFolder(await items(), folders, null).map((e) => e.path)
    expect(paths).toHaveLength(1)
    for (const path of paths) {
      for (const part of path.split('/')) expect(part === '..' || part === '.' || part === '').toBe(false)
      expect(path).not.toMatch(/\\/)
    }
  })

  it('an undecryptable item is reported and left out of the ZIP; all failing aborts', async () => {
    await uploadFile(backend, VAULT, file('ok.jpg', jpeg('ok')))
    await uploadFile(backend, VAULT, file('bad.jpg', jpeg('bad')))
    const list = ready(await items())
    const bad = list.find((i) => i.meta.name === 'bad.jpg')!
    backend.objects.get(`${VAULT}/${bad.id}`)![60] ^= 1
    const { blob, failed } = await buildZip(backend, VAULT, entriesForItems(list))
    expect(failed).toEqual([bad.id])
    expect(Object.keys(unzipSync(await readBlob(blob)))).toEqual(['ok.jpg'])
    await expect(buildZip(backend, VAULT, entriesForItems([bad]))).rejects.toBeTruthy()
  })

  it('refuses selections above the in-browser ZIP limit before decrypting anything', async () => {
    await uploadFile(backend, VAULT, file('a.jpg', jpeg('a')))
    const [item] = ready(await items())
    const huge = { ...item, meta: { ...item.meta, size: ZIP_MAX_BYTES + 1 } }
    backend.log = []
    await expect(buildZip(backend, VAULT, entriesForItems([huge]))).rejects.toBeTruthy()
    expect(backend.log).toHaveLength(0)
  })

  it('locking during a ZIP stops it and yields nothing', async () => {
    await uploadFile(backend, VAULT, file('a.jpg', jpeg('a')))
    await uploadFile(backend, VAULT, file('b.jpg', jpeg('b')))
    const list = ready(await items())
    await expect(
      buildZip(backend, VAULT, entriesForItems(list), {
        onProgress: () => lockVault(),
      }),
    ).rejects.toMatchObject({ userMessage: MEDIA_MESSAGES.locked })
  })
})

describe('leak scan: nothing private reaches the server', () => {
  it('no plaintext filename, folder name, thumbnail, or media bytes are sent or stored', async () => {
    const folderId = await createFolder(backend, VAULT, null, 'HB_SPACE_LEAK_FOLDER')
    const img = jpeg('HB_SPACE_LEAK_IMAGE_BYTES')
    const vid = mp4('HB_SPACE_LEAK_VIDEO_BYTES')
    const a = await uploadFile(backend, VAULT, file('HB_SPACE_LEAK_NAME_1.jpg', img), { folderId, makeThumbnail: fakeThumbs })
    await uploadFile(backend, VAULT, file('HB_SPACE_LEAK_NAME_2.mp4', vid), { makeThumbnail: fakeThumbs })
    const folder = (await listVaultFolders(backend, VAULT)).folders[0]
    await renameFolder(backend, VAULT, folder, 'HB_SPACE_LEAK_RENAMED')
    await moveItems(backend, VAULT, [a], null)
    const needles = [
      'HB_SPACE_LEAK_FOLDER',
      'HB_SPACE_LEAK_RENAMED',
      'HB_SPACE_LEAK_NAME',
      'HB_SPACE_LEAK_IMAGE_BYTES',
      'HB_SPACE_LEAK_VIDEO_BYTES',
      'HB_SPACE_TEST_THUMBNAIL_PIXELS',
      PASSPHRASE,
    ].map((s) => [s, utf8(s)] as const)
    for (const blob of [...backend.sentBytes(), ...backend.persistedBytes()]) {
      for (const [label, needle] of needles) expect(contains(blob, needle), label).toBe(false)
    }
    // Every stored object is ciphertext in the HBS format, never a viewable JPEG/MP4.
    for (const [path, bytes] of backend.objects) {
      expect(path).toMatch(/^[0-9a-f-]{36}\/[0-9a-f-]{36}(\.t)?$/)
      expect(equalBytes(bytes.subarray(0, 4), FORMAT_MAGIC)).toBe(true)
    }
  })
})
