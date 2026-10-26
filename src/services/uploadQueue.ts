import { MediaError, MEDIA_MESSAGES, type FileLike, type UploadStage } from './media'

/**
 * Upload queue: files are encrypted and uploaded strictly one at a time.
 *
 * - Each selected file becomes ONE entry with a random key when it is added. The
 *   worker loop lives in this object (not in React state), and an entry moves
 *   queued -> active exactly once per attempt, so re-renders can never start a
 *   second upload of the same entry.
 * - Retry re-queues a failed entry (a new attempt gets a new random media id; the
 *   failed attempt has already cleaned up after itself).
 * - Cancel removes a queued entry, or aborts an active one at its next safe
 *   checkpoint (before anything is sent, or with cleanup of what was sent).
 * - File names shown here come from the local File object and never leave the device.
 */

export type EntryStatus = 'queued' | UploadStage | 'done' | 'failed' | 'cancelled'

export interface QueueEntry {
  key: string
  name: string
  size: number
  folderId: string | null
  status: EntryStatus
  error?: string
  /** False for failures that cannot succeed on retry (unsupported type, too large). */
  retryable?: boolean
  itemId?: string
}

export type Uploader = (
  file: Blob & FileLike,
  folderId: string | null,
  signal: AbortSignal,
  onStage: (stage: UploadStage) => void,
) => Promise<string>

interface Internal {
  entry: QueueEntry
  file: (Blob & FileLike) | null
  controller: AbortController | null
}

export class UploadQueue {
  private entries: Internal[] = []
  private snapshot: QueueEntry[] = []
  private listeners = new Set<() => void>()
  private running = false
  private disposed = false
  private readonly upload: Uploader
  private readonly onUploaded: (itemId: string) => void

  constructor(upload: Uploader, onUploaded: (itemId: string) => void = () => undefined) {
    this.upload = upload
    this.onUploaded = onUploaded
  }

  subscribe = (listener: () => void): (() => void) => {
    this.listeners.add(listener)
    return () => this.listeners.delete(listener)
  }

  getSnapshot = (): QueueEntry[] => this.snapshot

  private emit() {
    this.snapshot = this.entries.map((i) => ({ ...i.entry }))
    for (const listener of this.listeners) listener()
  }

  add(files: (Blob & FileLike)[], folderId: string | null): string[] {
    if (this.disposed) return []
    const keys: string[] = []
    for (const file of files) {
      const key = crypto.randomUUID()
      keys.push(key)
      this.entries.push({ entry: { key, name: file.name, size: file.size, folderId, status: 'queued' }, file, controller: null })
    }
    this.emit()
    void this.pump()
    return keys
  }

  retry(key: string) {
    const target = this.entries.find((i) => i.entry.key === key)
    if (!target || target.entry.status !== 'failed' || !target.file) return
    target.entry = { ...target.entry, status: 'queued', error: undefined, retryable: undefined }
    this.emit()
    void this.pump()
  }

  cancel(key: string) {
    const target = this.entries.find((i) => i.entry.key === key)
    if (!target) return
    if (target.entry.status === 'queued') {
      target.entry = { ...target.entry, status: 'cancelled' }
      target.file = null
      this.emit()
    } else if (target.controller) {
      target.controller.abort()
    }
  }

  /** Drops finished, cancelled, and failed entries (and their File references). */
  clearFinished() {
    this.entries = this.entries.filter((i) => !['done', 'cancelled', 'failed'].includes(i.entry.status))
    this.emit()
  }

  get busy(): boolean {
    return this.entries.some((i) => i.entry.status !== 'done' && i.entry.status !== 'failed' && i.entry.status !== 'cancelled')
  }

  /** Aborts everything and drops all file references (vault locked / view closed). */
  dispose() {
    this.disposed = true
    for (const i of this.entries) {
      i.controller?.abort()
      i.file = null
    }
    this.entries = []
    this.emit()
    this.listeners.clear()
  }

  private async pump() {
    if (this.running) return
    this.running = true
    try {
      for (;;) {
        if (this.disposed) return
        const next = this.entries.find((i) => i.entry.status === 'queued')
        if (!next || !next.file) return
        const controller = new AbortController()
        next.controller = controller
        next.entry = { ...next.entry, status: 'checking' }
        this.emit()
        try {
          const itemId = await this.upload(next.file, next.entry.folderId, controller.signal, (stage) => {
            if (this.disposed || next.entry.status === 'cancelled') return
            next.entry = { ...next.entry, status: stage }
            this.emit()
          })
          next.entry = { ...next.entry, status: 'done', itemId }
          next.file = null // no retry needed; release the file
          this.emit()
          this.onUploaded(itemId)
        } catch (error) {
          if (controller.signal.aborted) {
            next.entry = { ...next.entry, status: 'cancelled' }
            next.file = null
          } else {
            const message = error instanceof MediaError ? error.userMessage : MEDIA_MESSAGES.uploadFailed
            // Wrong type or too large will never succeed: no retry, release the file.
            const retryable = message !== MEDIA_MESSAGES.unsupported && message !== MEDIA_MESSAGES.tooLarge
            next.entry = { ...next.entry, status: 'failed', error: message, retryable }
            if (!retryable) next.file = null
          }
          this.emit()
        } finally {
          next.controller = null
        }
      }
    } finally {
      this.running = false
    }
  }
}
