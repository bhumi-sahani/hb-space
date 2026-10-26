import { loadThumbnailUrl } from './media'
import type { MediaRecord, VaultBackend } from './vaultBackend'
import { revokeTrackedObjectUrl } from './vaultSession'

/**
 * Lazily downloads + decrypts encrypted thumbnails for tiles that scroll into view.
 *
 * - At most `concurrency` thumbnails are fetched at once.
 * - Decrypted thumbnails are held as tracked blob: URLs. Tiles acquire/release
 *   them; unused URLs are kept up to `capacity` and the least recently used are
 *   revoked beyond that. lockVault() revokes every tracked URL regardless, and
 *   dispose() (on unmount/lock) revokes everything this loader created.
 * - Originals are never downloaded for the gallery.
 */

type Entry =
  | { state: 'loading'; promise: Promise<string | null>; refs: number }
  | { state: 'ready'; url: string; refs: number }
  | { state: 'failed'; refs: number }

export class ThumbnailLoader {
  private cache = new Map<string, Entry>()
  private queue: (() => void)[] = []
  private active = 0
  private disposed = false
  private readonly backend: VaultBackend
  private readonly vaultId: string
  private readonly concurrency: number
  private readonly capacity: number

  constructor(backend: VaultBackend, vaultId: string, options: { concurrency?: number; capacity?: number } = {}) {
    this.backend = backend
    this.vaultId = vaultId
    this.concurrency = options.concurrency ?? 4
    this.capacity = options.capacity ?? 240
  }

  /** Returns a blob: URL for the item's thumbnail, or null if it has none / it failed. Increments the ref count. */
  async acquire(record: MediaRecord): Promise<string | null> {
    if (this.disposed || !record.hasThumbnail || record.status !== 'ready') return null
    const existing = this.cache.get(record.id)
    if (existing) {
      existing.refs++
      this.touch(record.id, existing)
      if (existing.state === 'ready') return existing.url
      if (existing.state === 'failed') return null
      return existing.promise
    }
    const promise = this.schedule(record)
    this.cache.set(record.id, { state: 'loading', promise, refs: 1 })
    return promise
  }

  release(id: string) {
    const entry = this.cache.get(id)
    if (!entry) return
    entry.refs = Math.max(0, entry.refs - 1)
    this.evict()
  }

  dispose() {
    this.disposed = true
    for (const entry of this.cache.values()) if (entry.state === 'ready') revokeTrackedObjectUrl(entry.url)
    this.cache.clear()
    this.queue = []
  }

  /** Number of decrypted thumbnails currently held (for tests). */
  get size(): number {
    let n = 0
    for (const entry of this.cache.values()) if (entry.state === 'ready') n++
    return n
  }

  private touch(id: string, entry: Entry) {
    this.cache.delete(id)
    this.cache.set(id, entry) // Map order = LRU order
  }

  private evict() {
    let held = this.size
    if (held <= this.capacity) return
    for (const [id, entry] of this.cache) {
      if (held <= this.capacity) break
      if (entry.state === 'ready' && entry.refs === 0) {
        revokeTrackedObjectUrl(entry.url)
        this.cache.delete(id)
        held--
      }
    }
  }

  private schedule(record: MediaRecord): Promise<string | null> {
    return new Promise<string | null>((resolve) => {
      const run = async () => {
        this.active++
        let url: string | null = null
        try {
          if (!this.disposed) url = await loadThumbnailUrl(this.backend, this.vaultId, record)
        } catch {
          url = null
        } finally {
          this.active--
          this.next()
        }
        const entry = this.cache.get(record.id)
        if (this.disposed || !entry) {
          if (url) revokeTrackedObjectUrl(url)
          resolve(null)
          return
        }
        const refs = entry.refs
        this.cache.set(record.id, url ? { state: 'ready', url, refs } : { state: 'failed', refs })
        this.evict()
        resolve(url)
      }
      this.queue.push(() => void run())
      this.next()
    })
  }

  private next() {
    while (this.active < this.concurrency && this.queue.length > 0) {
      const job = this.queue.shift()
      job?.()
    }
  }
}
