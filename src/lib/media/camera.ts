import { MAX_UPLOAD_BYTES } from '../../services/media'

/**
 * In-app camera helpers (Phase 4).
 *
 * Captures are made from the live camera stream inside this page
 * (getUserMedia). They exist only in this tab's memory until the upload queue
 * encrypts them: the phone's camera app is never involved, so nothing is
 * written to the device's photo gallery, and no plaintext copy is stored.
 * Photos are drawn from the video frame onto a canvas and encoded as JPEG,
 * so they carry no EXIF or GPS metadata.
 */

/**
 * Recording stops automatically at this size, leaving headroom below the
 * upload limit for the encryption overhead and the final recorder chunk.
 */
export const RECORDING_LIMIT_BYTES = MAX_UPLOAD_BYTES - 3 * 1024 * 1024

/** ~2.5 Mbit/s video: about 2.5 minutes before the size limit. */
export const VIDEO_BITS_PER_SECOND = 2_500_000
export const AUDIO_BITS_PER_SECOND = 128_000
export const PHOTO_QUALITY = 0.92

/**
 * Recorder formats in order of preference. MP4 (H.264/AAC) plays almost
 * everywhere, including iPhone; WebM is the fallback for browsers that can
 * only record WebM. Both are on the upload allow-list.
 */
const RECORDER_TYPES = [
  'video/mp4;codecs=avc1,mp4a',
  'video/mp4',
  'video/webm;codecs=vp9,opus',
  'video/webm;codecs=vp8,opus',
  'video/webm',
] as const

export function pickRecorderType(isTypeSupported: (type: string) => boolean): string | null {
  for (const type of RECORDER_TYPES) {
    try {
      if (isTypeSupported(type)) return type
    } catch {
      // Some browsers throw for unknown codec strings; try the next one.
    }
  }
  return null
}

export function extensionFor(mimeType: string): 'jpg' | 'mp4' | 'webm' {
  if (mimeType.startsWith('image/')) return 'jpg'
  return mimeType.startsWith('video/mp4') ? 'mp4' : 'webm'
}

const two = (n: number) => String(n).padStart(2, '0')

/** "Photo 2026-10-23 14-05-09.jpg". Local time; the name is encrypted like any other. */
export function captureFileName(kind: 'photo' | 'video', mimeType: string, at: Date): string {
  const stamp = `${at.getFullYear()}-${two(at.getMonth() + 1)}-${two(at.getDate())} ${two(at.getHours())}-${two(at.getMinutes())}-${two(at.getSeconds())}`
  return `${kind === 'photo' ? 'Photo' : 'Video'} ${stamp}.${extensionFor(mimeType)}`
}

export function formatDuration(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  return `${Math.floor(s / 60)}:${two(s % 60)}`
}

/** Why the in-app camera can't run here, or null if it can be tried. */
export function cameraUnavailableReason(): string | null {
  if (typeof window !== 'undefined' && window.isSecureContext === false) {
    return 'The in-app camera needs a secure (https) connection.'
  }
  if (typeof navigator === 'undefined' || !navigator.mediaDevices || typeof navigator.mediaDevices.getUserMedia !== 'function') {
    return "This browser doesn't support the in-app camera."
  }
  return null
}

export function cameraErrorMessage(error: unknown): string {
  const name = error instanceof DOMException || error instanceof Error ? error.name : ''
  switch (name) {
    case 'NotAllowedError':
    case 'SecurityError':
      return 'Camera access was blocked. Allow the camera for this site in your browser settings, then try again.'
    case 'NotFoundError':
    case 'OverconstrainedError':
      return 'No camera was found on this device.'
    case 'NotReadableError':
    case 'AbortError':
      return 'The camera is being used by another app. Close it and try again.'
    default:
      return "The camera couldn't be started."
  }
}
