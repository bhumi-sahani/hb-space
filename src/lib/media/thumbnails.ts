import type { MediaFacts } from '../crypto/item'
import type { SniffedType } from '../crypto/sniff'

/**
 * Local thumbnail generation (Phase 4). Runs entirely in this browser on the
 * user's own file. The result is encrypted by the caller before upload; no
 * plaintext preview ever leaves the device, and no third-party service is used.
 *
 * - Images: decoded with createImageBitmap (EXIF orientation applied), scaled
 *   down to at most THUMB_MAX_EDGE px on the long edge (never upscaled), and
 *   re-encoded as JPEG. Re-encoding drops all EXIF metadata, including GPS.
 * - Videos: one frame is captured from a local blob: URL of the file after
 *   seeking to ~1 s (or 10 % of a short clip). Unsupported codecs, decode
 *   errors, or timeouts return null and the gallery shows a generic video tile.
 * - Anything the browser cannot decode (e.g. HEIC outside Safari) returns null.
 */

export const THUMB_MAX_EDGE = 320
const JPEG_QUALITY = 0.78
const VIDEO_TIMEOUT_MS = 8000

export interface Thumbnail {
  bytes: Uint8Array<ArrayBuffer>
  facts: MediaFacts
}

function scaled(width: number, height: number): { w: number; h: number } {
  const scale = Math.min(1, THUMB_MAX_EDGE / Math.max(width, height))
  return { w: Math.max(1, Math.round(width * scale)), h: Math.max(1, Math.round(height * scale)) }
}

async function encodeCanvas(source: CanvasImageSource, width: number, height: number): Promise<Uint8Array<ArrayBuffer> | null> {
  const { w, h } = scaled(width, height)
  if (typeof OffscreenCanvas === 'function') {
    const canvas = new OffscreenCanvas(w, h)
    const ctx = canvas.getContext('2d')
    if (!ctx) return null
    ctx.fillStyle = '#000'
    ctx.fillRect(0, 0, w, h)
    ctx.drawImage(source, 0, 0, w, h)
    const blob = await canvas.convertToBlob({ type: 'image/jpeg', quality: JPEG_QUALITY })
    return new Uint8Array(await blob.arrayBuffer())
  }
  const canvas = document.createElement('canvas')
  canvas.width = w
  canvas.height = h
  const ctx = canvas.getContext('2d')
  if (!ctx) return null
  ctx.fillStyle = '#000'
  ctx.fillRect(0, 0, w, h)
  ctx.drawImage(source, 0, 0, w, h)
  const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/jpeg', JPEG_QUALITY))
  canvas.width = 0
  canvas.height = 0
  return blob ? new Uint8Array(await blob.arrayBuffer()) : null
}

async function imageThumbnail(file: Blob): Promise<Thumbnail | null> {
  if (typeof createImageBitmap !== 'function') return null
  const bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' })
  try {
    const bytes = await encodeCanvas(bitmap, bitmap.width, bitmap.height)
    return bytes ? { bytes, facts: { width: bitmap.width, height: bitmap.height } } : null
  } finally {
    bitmap.close()
  }
}

function once(target: EventTarget, ok: string, timeoutMs: number): Promise<void> {
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => {
      cleanup()
      reject(new Error('timeout'))
    }, timeoutMs)
    const onOk = () => {
      cleanup()
      resolve()
    }
    const onError = () => {
      cleanup()
      reject(new Error('media error'))
    }
    const cleanup = () => {
      window.clearTimeout(timer)
      target.removeEventListener(ok, onOk)
      target.removeEventListener('error', onError)
    }
    target.addEventListener(ok, onOk)
    target.addEventListener('error', onError)
  })
}

async function videoThumbnail(file: Blob): Promise<Thumbnail | null> {
  if (typeof document === 'undefined') return null
  const video = document.createElement('video')
  // A local, short-lived URL of the user's own file; never sent anywhere.
  const url = URL.createObjectURL(file)
  try {
    video.muted = true
    video.playsInline = true
    video.preload = 'auto'
    const loaded = once(video, 'loadeddata', VIDEO_TIMEOUT_MS)
    video.src = url
    await loaded
    const duration = Number.isFinite(video.duration) ? video.duration : 0
    const width = video.videoWidth
    const height = video.videoHeight
    if (!width || !height) return null
    const target = duration > 0 ? Math.min(1, duration * 0.1) : 0
    if (target > 0) {
      const seeked = once(video, 'seeked', VIDEO_TIMEOUT_MS)
      video.currentTime = target
      await seeked
    }
    const bytes = await encodeCanvas(video, width, height)
    const facts: MediaFacts = { width, height }
    if (duration > 0) facts.duration = duration
    return bytes ? { bytes, facts } : null
  } finally {
    video.removeAttribute('src')
    video.load()
    URL.revokeObjectURL(url)
  }
}

/** Never throws: any failure means "no thumbnail". */
export async function makeThumbnail(file: Blob, type: SniffedType): Promise<Thumbnail | null> {
  try {
    if (type.startsWith('image/')) return await imageThumbnail(file)
    if (type.startsWith('video/')) return await videoThumbnail(file)
    return null
  } catch {
    return null
  }
}
