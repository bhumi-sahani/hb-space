import { Zip, ZipPassThrough } from 'fflate'
import { wipe } from '../lib/crypto/bytes'
import { cleanFileName } from '../lib/crypto/item'
import { descendantIds, type VaultFolder } from './folders'
import { decryptVaultItem, MediaError, requireKey, type BulkResult, type ReadyItem, type VaultItem } from './media'
import type { VaultBackend } from './vaultBackend'
import { createTrackedObjectUrl, revokeTrackedObjectUrl } from './vaultSession'

/**
 * Local downloads. Everything happens in this browser:
 *   encrypted object -> download ciphertext -> decrypt -> Blob -> save
 * ZIPs are assembled locally with fflate (store only; photos/videos are already
 * compressed), one file at a time. Nothing is ever uploaded; no server-side ZIP.
 */

/** Above this total, the UI warns that the browser may run short of memory. */
export const ZIP_WARN_BYTES = 1024 * 1024 * 1024
/** Hard stop: the ZIP is built in browser memory (no ZIP64, and phones have limited RAM). */
export const ZIP_MAX_BYTES = 2 * 1024 * 1024 * 1024

export const DOWNLOAD_MESSAGES = {
  failed: 'Could not download this item. Please try again.',
  tooBig: 'That selection is too large to zip in the browser (over 2 GB). Download fewer items at a time.',
  empty: 'There is nothing to download here.',
  cancelled: 'Download cancelled.',
} as const

/** Hands a Blob to the browser as a file download. Replaceable in tests. */
export type Saver = (blob: Blob, filename: string) => void

/**
 * Default saver: a temporary, tracked blob: URL clicked through a detached link.
 * The URL is revoked after the browser has had time to start the download (and
 * immediately on vault lock).
 */
export const browserSaver: Saver = (blob, filename) => {
  const url = createTrackedObjectUrl(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = filename
  link.rel = 'noopener'
  link.style.display = 'none'
  document.body.append(link)
  link.click()
  link.remove()
  window.setTimeout(() => revokeTrackedObjectUrl(url), 60_000)
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

/** One safe path segment for a download or ZIP entry (no separators, reserved characters, or dot-only names). */
export function safeSegment(name: string): string {
  // eslint-disable-next-line no-control-regex
  let out = name.replace(/[<>:"/\\|?*\x00-\x1f\x7f]/g, '_').trim()
  out = out.replace(/[. ]+$/, '') // Windows drops trailing dots/spaces
  if (out === '' || /^\.+$/.test(out)) out = '_'
  return out.slice(0, 200)
}

export function downloadName(item: ReadyItem): string {
  return safeSegment(cleanFileName(item.meta.name))
}

/** "photo.jpg" -> "photo (2).jpg" until unique (case-insensitive) within `used`. */
export function uniqueName(name: string, used: Set<string>): string {
  const dot = name.lastIndexOf('.')
  const base = dot > 0 ? name.slice(0, dot) : name
  const ext = dot > 0 ? name.slice(dot) : ''
  let candidate = name
  for (let n = 2; used.has(candidate.toLowerCase()); n++) candidate = `${base} (${n})${ext}`
  used.add(candidate.toLowerCase())
  return candidate
}

export function zipFileName(label: string, now = new Date()): string {
  const date = now.toISOString().slice(0, 10)
  return `${safeSegment(label) || 'HB Space'} ${date}.zip`
}

// ---------------------------------------------------------------------------
// Single and separate downloads
// ---------------------------------------------------------------------------

/** Decrypts one item and saves it under its original (decrypted) filename. */
export async function downloadItem(backend: VaultBackend, vaultId: string, item: ReadyItem, save: Saver = browserSaver): Promise<void> {
  const file = await decryptVaultItem(backend, vaultId, item.record)
  try {
    requireKey(vaultId)
    // Always octet-stream: the browser saves it instead of rendering it.
    save(new Blob([file.bytes], { type: 'application/octet-stream' }), downloadName(item))
  } finally {
    wipe(file.bytes)
  }
}

export interface ProgressOptions {
  onProgress?: (done: number, total: number) => void
  signal?: AbortSignal
}

/** One file at a time, with a short gap so browsers accept multiple downloads. */
export async function downloadSeparately(
  backend: VaultBackend,
  vaultId: string,
  items: ReadyItem[],
  options: ProgressOptions & { save?: Saver; gapMs?: number } = {},
): Promise<BulkResult> {
  const { onProgress, signal, save = browserSaver, gapMs = 600 } = options
  const result: BulkResult = { done: [], failed: [] }
  for (const item of items) {
    if (signal?.aborted) break
    try {
      await downloadItem(backend, vaultId, item, save)
      result.done.push(item.id)
    } catch (error) {
      if (error instanceof MediaError && !requireKeySafe(vaultId)) throw error
      result.failed.push(item.id)
    }
    onProgress?.(result.done.length + result.failed.length, items.length)
    if (gapMs > 0) await new Promise((resolve) => setTimeout(resolve, gapMs))
  }
  return result
}

function requireKeySafe(vaultId: string): boolean {
  try {
    requireKey(vaultId)
    return true
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// ZIP
// ---------------------------------------------------------------------------

export interface ZipEntry {
  item: ReadyItem
  /** Path inside the ZIP, built from sanitised decrypted names: "Folder/Sub/photo.jpg". */
  path: string
}

export function totalBytes(entries: ZipEntry[]): number {
  return entries.reduce((sum, e) => sum + e.item.meta.size, 0)
}

/** Flat entries for a selection, with duplicate names made unique. */
export function entriesForItems(items: ReadyItem[]): ZipEntry[] {
  const used = new Set<string>()
  return items.map((item) => ({ item, path: uniqueName(downloadName(item), used) }))
}

/**
 * Entries for "Download all" in a folder (or the vault root when folderId is null):
 * every ACTIVE ready item in it and in its subfolders, laid out by decrypted folder names.
 * Unfinished uploads are excluded.
 */
export function entriesForFolder(items: VaultItem[], folders: VaultFolder[], folderId: string | null): ZipEntry[] {
  const byId = new Map(folders.map((f) => [f.id, f]))
  const scope = folderId === null ? null : descendantIds(folders, folderId)
  // Directory path (relative to the downloaded folder) for every folder in scope.
  const dirPath = new Map<string | null, string>([[folderId, '']])
  const usedDirs = new Map<string | null, Set<string>>()
  const resolveDir = (id: string | null): string | null => {
    if (dirPath.has(id)) return dirPath.get(id) as string
    if (id === null) return null // root outside a folder download scope
    const folder = byId.get(id)
    if (!folder) return null
    const parent = resolveDir(folder.parentId)
    if (parent === null) return null
    const siblings = usedDirs.get(folder.parentId) ?? new Set<string>()
    usedDirs.set(folder.parentId, siblings)
    const name = uniqueName(safeSegment(folder.name ?? 'Unreadable folder'), siblings)
    const path = parent ? `${parent}/${name}` : name
    dirPath.set(id, path)
    return path
  }

  const usedFiles = new Map<string, Set<string>>()
  const entries: ZipEntry[] = []
  for (const item of items) {
    if (item.state !== 'ready') continue
    const itemFolder = item.record.folderId
    if (scope && (itemFolder === null || !scope.has(itemFolder))) continue
    const dir = resolveDir(itemFolder)
    if (dir === null) continue
    const used = usedFiles.get(dir) ?? new Set<string>()
    usedFiles.set(dir, used)
    const name = uniqueName(downloadName(item), used)
    entries.push({ item, path: dir ? `${dir}/${name}` : name })
  }
  return entries
}

function zipDate(item: ReadyItem): Date {
  const time = item.meta.modified ?? Date.parse(item.createdAt)
  const min = Date.UTC(1980, 0, 2)
  const max = Date.UTC(2099, 11, 31)
  return new Date(Number.isFinite(time) ? Math.min(Math.max(time, min), max) : Date.now())
}

export interface ZipResult {
  blob: Blob
  /** Item ids that could not be downloaded/decrypted and are NOT in the ZIP. */
  failed: string[]
}

/**
 * Builds a ZIP locally: for each entry, download ciphertext -> decrypt -> add to
 * the ZIP -> wipe the plaintext, strictly one at a time. Finished parts are moved
 * into Blobs as we go, so the browser can page them out of JS memory.
 */
export async function buildZip(backend: VaultBackend, vaultId: string, entries: ZipEntry[], options: ProgressOptions = {}): Promise<ZipResult> {
  const { onProgress, signal } = options
  if (entries.length === 0) throw new MediaError(DOWNLOAD_MESSAGES.empty)
  if (totalBytes(entries) > ZIP_MAX_BYTES) throw new MediaError(DOWNLOAD_MESSAGES.tooBig)
  requireKey(vaultId)

  const parts: Blob[] = []
  let pending: Uint8Array[] = []
  let zipError: Error | null = null
  const zip = new Zip((error, chunk) => {
    if (error) zipError = error
    else pending.push(chunk)
  })
  const flush = () => {
    if (pending.length > 0) parts.push(new Blob(pending as BlobPart[])) // copies the bytes
    pending = []
  }

  const failed: string[] = []
  let done = 0
  for (const entry of entries) {
    if (signal?.aborted) throw new MediaError(DOWNLOAD_MESSAGES.cancelled)
    let bytes: Uint8Array<ArrayBuffer> | null = null
    try {
      bytes = (await decryptVaultItem(backend, vaultId, entry.item.record)).bytes
    } catch (error) {
      if (!requireKeySafe(vaultId)) throw error
      failed.push(entry.item.id)
    }
    if (bytes) {
      const file = new ZipPassThrough(entry.path)
      file.mtime = zipDate(entry.item)
      zip.add(file)
      file.push(bytes, true)
      flush()
      wipe(bytes)
    }
    if (zipError) throw new MediaError(DOWNLOAD_MESSAGES.failed)
    onProgress?.(++done, entries.length)
  }
  if (failed.length === entries.length) throw new MediaError(DOWNLOAD_MESSAGES.failed)
  zip.end()
  flush()
  if (zipError) throw new MediaError(DOWNLOAD_MESSAGES.failed)
  requireKey(vaultId)
  return { blob: new Blob(parts, { type: 'application/zip' }), failed }
}
