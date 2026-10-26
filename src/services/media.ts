import { readBlob, wipe } from '../lib/crypto/bytes'
import {
  decryptItemContent,
  decryptItemMetadata,
  decryptItemThumbnail,
  encryptItem,
  isAcceptableThumbnail,
  type ItemMetadata,
  type MediaFacts,
} from '../lib/crypto/item'
import { ciphertextLength } from '../lib/crypto/mediaFormat'
import { INLINE_TYPES, sniffType, type SniffedType } from '../lib/crypto/sniff'
import {
  BackendError,
  BUCKET_OBJECT_LIMIT,
  MAX_THUMBNAIL_OBJECT,
  objectPathFor,
  thumbnailPathFor,
  type MediaRecord,
  type VaultBackend,
} from './vaultBackend'
import { createTrackedObjectUrl, getUnlockedKey } from './vaultSession'

/**
 * Encrypted upload / list / open / organise / delete. Plaintext exists only in
 * this browser; the backend receives ciphertext, encrypted metadata, and opaque ids.
 */

/** Largest plaintext accepted. Keeps the ciphertext under the 50 MiB bucket limit. */
export const MAX_UPLOAD_BYTES = 49 * 1024 * 1024

/** Upload allow-list, decided from the file's own bytes (never its name or File.type). */
export const ACCEPTED_UPLOAD_TYPES: ReadonlySet<SniffedType> = new Set<SniffedType>([
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'image/avif',
  'image/heic',
  'video/mp4',
  'video/quicktime',
  'video/webm',
])

export const MEDIA_MESSAGES = {
  locked: 'The vault is locked. Unlock it first.',
  tooLarge: `That file is too large. The limit is ${MAX_UPLOAD_BYTES / (1024 * 1024)} MB.`,
  unsupported: 'Not a supported photo or video (JPEG, PNG, GIF, WebP, AVIF, HEIC, MP4, MOV, WebM).',
  uploadFailed: 'Upload failed. Nothing was saved.',
  cancelled: 'Upload cancelled. Nothing was saved.',
  openFailed: 'Unable to open this item. It may be damaged or was not encrypted with this vault key.',
  deleteFailed: 'Could not delete this item. Please try again.',
  listFailed: 'Could not load the vault contents. Please try again.',
  updateFailed: 'Could not update the selected items. Please try again.',
  notSetUp: 'The vault database is not set up for this version yet.',
  network: 'Cannot reach the server. Check your connection and try again.',
} as const

export class MediaError extends Error {
  readonly userMessage: string
  constructor(userMessage: string) {
    super(userMessage)
    this.name = 'MediaError'
    this.userMessage = userMessage
  }
}

export function backendAware(error: unknown, fallback: string): MediaError {
  if (error instanceof MediaError) return error
  if (error instanceof BackendError && error.kind === 'network') return new MediaError(MEDIA_MESSAGES.network)
  if (error instanceof BackendError && error.kind === 'not-set-up') return new MediaError(MEDIA_MESSAGES.notSetUp)
  return new MediaError(fallback)
}

export function requireKey(vaultId: string): CryptoKey {
  const key = getUnlockedKey(vaultId)
  if (!key) throw new MediaError(MEDIA_MESSAGES.locked)
  return key
}

export interface FileLike {
  name: string
  size: number
  lastModified?: number
}

/** A locally generated preview: small raster image bytes plus measured facts. Never leaves the device unencrypted. */
export interface ThumbnailResult {
  bytes: Uint8Array<ArrayBuffer>
  facts: MediaFacts
}

export type ThumbnailMaker = (file: Blob, type: SniffedType) => Promise<ThumbnailResult | null>

export type UploadStage = 'checking' | 'encrypting' | 'uploading' | 'finishing'

export interface UploadOptions {
  /** Opaque folder id, or null for the vault root. */
  folderId?: string | null
  /** Browser thumbnail generator; omitted = no thumbnail. Failures fall back to no thumbnail. */
  makeThumbnail?: ThumbnailMaker
  signal?: AbortSignal
  onStage?: (stage: UploadStage) => void
}

/**
 * Checks size and the real content type (magic bytes) before anything else.
 * Returns the sniffed type. Reads only the first 64 bytes.
 */
export async function checkUploadable(file: Blob & FileLike): Promise<SniffedType> {
  if (file.size > MAX_UPLOAD_BYTES) throw new MediaError(MEDIA_MESSAGES.tooLarge)
  if (file.size === 0) throw new MediaError(MEDIA_MESSAGES.unsupported)
  const head = await readBlob(file.slice(0, 64))
  const type = sniffType(head)
  if (!ACCEPTED_UPLOAD_TYPES.has(type)) throw new MediaError(MEDIA_MESSAGES.unsupported)
  return type
}

function checkAborted(signal: AbortSignal | undefined) {
  if (signal?.aborted) throw new MediaError(MEDIA_MESSAGES.cancelled)
}

/**
 * Upload flow:
 *  1 size + real type check   2 vault unlocked   3 random media id
 *  4 local thumbnail (optional; failures => none)
 *  5 encrypt content, metadata, thumbnail locally (fresh DEK and IVs)
 *  6 create pending record (opaque folder id, has_thumbnail)   7 upload ciphertext (+ encrypted thumbnail)
 *  8 mark ready (server checks stored size and thumbnail)   9 wipe plaintext.
 * On any failure or cancel, best-effort removal of what was created.
 * Nothing is sent before encryption has succeeded.
 */
export async function uploadFile(
  backend: VaultBackend,
  vaultId: string,
  file: Blob & FileLike,
  options: UploadOptions = {},
): Promise<string> {
  const { folderId = null, makeThumbnail, signal, onStage } = options
  onStage?.('checking')
  const type = await checkUploadable(file)
  let vmk = requireKey(vaultId)
  checkAborted(signal)
  const itemId = crypto.randomUUID()
  const path = objectPathFor(vaultId, itemId)
  const thumbPath = thumbnailPathFor(vaultId, itemId)

  let plaintext: Uint8Array<ArrayBuffer> | null = null
  let thumbnail: ThumbnailResult | null = null
  let rowCreated = false
  const objectsCreated: string[] = []
  try {
    onStage?.('encrypting')
    if (makeThumbnail) {
      try {
        thumbnail = await makeThumbnail(file, type)
        if (thumbnail && !isAcceptableThumbnail(thumbnail.bytes)) thumbnail = null
      } catch {
        thumbnail = null // a preview is optional; never block the upload on it
      }
    }
    checkAborted(signal)

    plaintext = await readBlob(file)
    if (plaintext.length !== file.size || plaintext.length > MAX_UPLOAD_BYTES) throw new MediaError(MEDIA_MESSAGES.uploadFailed)
    // The file must still be what we checked (it could have changed on disk meanwhile).
    if (sniffType(plaintext.subarray(0, 64)) !== type) throw new MediaError(MEDIA_MESSAGES.unsupported)

    const encrypted = await encryptItem(
      vmk,
      itemId,
      plaintext,
      { name: file.name, modified: file.lastModified ?? null, facts: thumbnail?.facts },
      thumbnail?.bytes ?? null,
    )
    wipe(plaintext, thumbnail?.bytes)
    plaintext = null

    const expected = ciphertextLength(file.size)
    if (encrypted.content.length !== expected || expected > BUCKET_OBJECT_LIMIT) throw new MediaError(MEDIA_MESSAGES.uploadFailed)

    // If the vault was locked or the upload cancelled while encrypting, stop before anything leaves the device.
    vmk = requireKey(vaultId)
    checkAborted(signal)

    onStage?.('uploading')
    await backend.insertPendingMedia({
      id: itemId,
      vaultId,
      wrappedDek: encrypted.wrappedDek,
      encryptedMeta: encrypted.encryptedMeta,
      ciphertextSize: encrypted.content.length,
      folderId,
      hasThumbnail: encrypted.thumbnail !== null,
    })
    rowCreated = true
    // Between network steps: stop (and clean up) if cancelled or if the vault was locked.
    const checkpoint = () => {
      checkAborted(signal)
      requireKey(vaultId)
    }
    checkpoint()
    await backend.uploadObject(path, encrypted.content)
    objectsCreated.push(path)
    if (encrypted.thumbnail) {
      checkpoint()
      await backend.uploadObject(thumbPath, encrypted.thumbnail)
      objectsCreated.push(thumbPath)
    }
    checkpoint()
    onStage?.('finishing')
    await backend.markReady(itemId)
    return itemId
  } catch (error) {
    if (objectsCreated.length > 0) await backend.deleteObjects(objectsCreated).catch(() => undefined)
    if (rowCreated) await backend.deleteMedia(itemId).catch(() => undefined)
    throw backendAware(error, MEDIA_MESSAGES.uploadFailed)
  } finally {
    wipe(plaintext, thumbnail?.bytes)
  }
}

// ---------------------------------------------------------------------------
// Listing
// ---------------------------------------------------------------------------

export type VaultItem =
  | { id: string; state: 'ready'; createdAt: string; meta: ItemMetadata; record: MediaRecord }
  | { id: string; state: 'unreadable'; createdAt: string; record: MediaRecord }
  | { id: string; state: 'incomplete'; createdAt: string; record: MediaRecord }

export type ReadyItem = Extract<VaultItem, { state: 'ready' }>

/** Decrypts in batches so a large vault does not start thousands of crypto jobs at once. */
const DECRYPT_BATCH = 64

/** Lists every item and decrypts its metadata. Items whose metadata fails authentication are marked unreadable. */
export async function listVaultItems(backend: VaultBackend, vaultId: string): Promise<{ items: VaultItem[]; damaged: number }> {
  const vmk = requireKey(vaultId)
  let listing: Awaited<ReturnType<VaultBackend['listMedia']>>
  try {
    listing = await backend.listMedia(vaultId)
  } catch (error) {
    throw backendAware(error, MEDIA_MESSAGES.listFailed)
  }
  const items: VaultItem[] = []
  for (let i = 0; i < listing.records.length; i += DECRYPT_BATCH) {
    const batch = listing.records.slice(i, i + DECRYPT_BATCH)
    items.push(
      ...(await Promise.all(
        batch.map(async (record): Promise<VaultItem> => {
          if (record.status !== 'ready') return { id: record.id, state: 'incomplete', createdAt: record.createdAt, record }
          try {
            const meta = await decryptItemMetadata(vmk, record.id, record.wrappedDek, record.encryptedMeta)
            return { id: record.id, state: 'ready', createdAt: record.createdAt, meta, record }
          } catch {
            return { id: record.id, state: 'unreadable', createdAt: record.createdAt, record }
          }
        }),
      )),
    )
    requireKey(vaultId) // locked mid-way: stop and drop what was decrypted
  }
  return { items, damaged: listing.damaged }
}

// ---------------------------------------------------------------------------
// Opening / decrypting
// ---------------------------------------------------------------------------

export interface DecryptedFile {
  /** The plaintext. Callers must wipe it when done. */
  bytes: Uint8Array<ArrayBuffer>
  /** Type re-sniffed from the decrypted bytes; never taken from metadata or the server. */
  type: SniffedType
}

/**
 * ciphertext -> check declared size -> validate format -> authenticated decrypt.
 * Any failure yields one generic error; nothing partial is returned.
 */
export async function decryptVaultItem(backend: VaultBackend, vaultId: string, record: MediaRecord): Promise<DecryptedFile> {
  const vmk = requireKey(vaultId)
  if (record.status !== 'ready' || record.vaultId !== vaultId) throw new MediaError(MEDIA_MESSAGES.openFailed)
  let ciphertext: Uint8Array<ArrayBuffer>
  try {
    ciphertext = await backend.downloadObject(objectPathFor(vaultId, record.id), record.ciphertextSize)
  } catch (error) {
    throw backendAware(error, MEDIA_MESSAGES.openFailed)
  }
  if (ciphertext.length !== record.ciphertextSize) throw new MediaError(MEDIA_MESSAGES.openFailed)
  let plaintext: Uint8Array<ArrayBuffer>
  try {
    plaintext = await decryptItemContent(vmk, record.id, record.wrappedDek, ciphertext)
  } catch {
    throw new MediaError(MEDIA_MESSAGES.openFailed)
  }
  // Locked while downloading/decrypting? Do not hand out plaintext.
  if (!getUnlockedKey(vaultId)) {
    wipe(plaintext)
    throw new MediaError(MEDIA_MESSAGES.locked)
  }
  return { bytes: plaintext, type: sniffType(plaintext.subarray(0, 64)) }
}

export interface OpenedItem {
  url: string
  /** Type re-sniffed from the decrypted bytes; never taken from metadata or the server. */
  type: string
  inline: boolean
}

/**
 * Download flow for viewing: decrypt -> temporary blob: URL (tracked; revoked on close and on lock).
 * Only safe image/video types are given their real type; everything else is octet-stream.
 */
export async function openVaultItem(backend: VaultBackend, vaultId: string, record: MediaRecord): Promise<OpenedItem> {
  const file = await decryptVaultItem(backend, vaultId, record)
  try {
    requireKey(vaultId)
    const inline = INLINE_TYPES.has(file.type)
    const type = inline ? file.type : 'application/octet-stream'
    const url = createTrackedObjectUrl(new Blob([file.bytes], { type }))
    return { url, type, inline }
  } finally {
    wipe(file.bytes)
  }
}

/**
 * Downloads and decrypts the encrypted thumbnail. Returns a tracked blob: URL for a
 * small JPEG/WebP/PNG, or throws. The original is never fetched for this.
 */
export async function loadThumbnailUrl(backend: VaultBackend, vaultId: string, record: MediaRecord): Promise<string> {
  const vmk = requireKey(vaultId)
  if (!record.hasThumbnail || record.status !== 'ready') throw new MediaError(MEDIA_MESSAGES.openFailed)
  let ciphertext: Uint8Array<ArrayBuffer>
  try {
    ciphertext = await backend.downloadObject(thumbnailPathFor(vaultId, record.id), MAX_THUMBNAIL_OBJECT)
  } catch (error) {
    throw backendAware(error, MEDIA_MESSAGES.openFailed)
  }
  let plain: Uint8Array<ArrayBuffer>
  try {
    plain = await decryptItemThumbnail(vmk, record.id, record.wrappedDek, ciphertext)
  } catch {
    throw new MediaError(MEDIA_MESSAGES.openFailed)
  }
  try {
    requireKey(vaultId)
    return createTrackedObjectUrl(new Blob([plain], { type: sniffType(plain.subarray(0, 64)) }))
  } finally {
    wipe(plain)
  }
}

// ---------------------------------------------------------------------------
// Organising: move between folders (reversible; never destroys anything)
// ---------------------------------------------------------------------------

export interface BulkResult {
  done: string[]
  failed: string[]
}

function settle(requested: string[], updated: string[]): BulkResult {
  const ok = new Set(updated)
  return { done: requested.filter((id) => ok.has(id)), failed: requested.filter((id) => !ok.has(id)) }
}

export async function moveItems(backend: VaultBackend, vaultId: string, ids: string[], folderId: string | null): Promise<BulkResult> {
  requireKey(vaultId)
  try {
    return settle(ids, await backend.setMediaFolder(vaultId, ids, folderId))
  } catch (error) {
    throw backendAware(error, MEDIA_MESSAGES.updateFailed)
  }
}

// ---------------------------------------------------------------------------
// Permanent deletion. There is no trash (owner decision, 2026-10-23): Delete
// always destroys, after a confirmation that names what will be destroyed.
// ---------------------------------------------------------------------------

/** An unfinished upload younger than this may still be in progress on the other member's device. */
export const STALE_UPLOAD_MS = 60 * 60 * 1000

/**
 * Permanently deletes ONE item: encrypted objects first (their policy needs the
 * row), then the row. The row is removed only if the object removal request
 * succeeded, so a failure never leaves an orphaned object behind a deleted row.
 */
export async function deleteVaultItem(backend: VaultBackend, vaultId: string, record: MediaRecord): Promise<void> {
  try {
    const paths = [objectPathFor(vaultId, record.id)]
    if (record.hasThumbnail) paths.push(thumbnailPathFor(vaultId, record.id))
    await backend.deleteObjects(paths)
    await backend.deleteMedia(record.id)
  } catch (error) {
    throw backendAware(error, MEDIA_MESSAGES.deleteFailed)
  }
}

/** Sequential permanent deletion with progress; reports exactly which items failed. */
export async function purgeItems(
  backend: VaultBackend,
  vaultId: string,
  records: MediaRecord[],
  onProgress?: (done: number, total: number) => void,
): Promise<BulkResult> {
  const result: BulkResult = { done: [], failed: [] }
  for (const record of records) {
    try {
      await deleteVaultItem(backend, vaultId, record)
      result.done.push(record.id)
    } catch {
      result.failed.push(record.id)
    }
    onProgress?.(result.done.length + result.failed.length, records.length)
  }
  return result
}
