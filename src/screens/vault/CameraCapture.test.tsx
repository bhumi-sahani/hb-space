import { act, cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  cameraErrorMessage,
  captureFileName,
  extensionFor,
  formatDuration,
  pickRecorderType,
  RECORDING_LIMIT_BYTES,
} from '../../lib/media/camera'
import { MAX_UPLOAD_BYTES } from '../../services/media'
import { CameraCapture } from './CameraCapture'

// ---------------------------------------------------------------------------
// Fakes for the browser camera APIs jsdom doesn't have
// ---------------------------------------------------------------------------

interface FakeTrack {
  kind: string
  stop: ReturnType<typeof vi.fn>
}

function fakeStream(audio: boolean): MediaStream & { tracks: FakeTrack[] } {
  const tracks: FakeTrack[] = [{ kind: 'video', stop: vi.fn() }]
  if (audio) tracks.push({ kind: 'audio', stop: vi.fn() })
  return { tracks, getTracks: () => tracks } as unknown as MediaStream & { tracks: FakeTrack[] }
}

class FakeRecorder {
  static instances: FakeRecorder[] = []
  static isTypeSupported = (type: string) => type.startsWith('video/webm')
  state: 'inactive' | 'recording' = 'inactive'
  ondataavailable: ((e: { data: Blob }) => void) | null = null
  onstop: (() => void) | null = null
  stream: MediaStream
  options: MediaRecorderOptions
  constructor(stream: MediaStream, options: MediaRecorderOptions) {
    this.stream = stream
    this.options = options
    FakeRecorder.instances.push(this)
  }
  start = vi.fn(() => {
    this.state = 'recording'
  })
  stop = vi.fn(() => {
    if (this.state === 'inactive') return
    this.state = 'inactive'
    this.onstop?.()
  })
  emit(size: number) {
    this.ondataavailable?.({ data: new Blob([new Uint8Array(size)]) })
  }
}

let streams: ReturnType<typeof fakeStream>[]
let getUserMedia: ReturnType<typeof vi.fn>

beforeEach(() => {
  streams = []
  FakeRecorder.instances = []
  getUserMedia = vi.fn(async (c: MediaStreamConstraints) => {
    const s = fakeStream(Boolean(c.audio))
    streams.push(s)
    return s
  })
  Object.defineProperty(navigator, 'mediaDevices', { configurable: true, value: { getUserMedia } })
  vi.stubGlobal('MediaRecorder', FakeRecorder)
  Object.defineProperty(window, 'isSecureContext', { configurable: true, value: true })
  Object.defineProperty(HTMLMediaElement.prototype, 'srcObject', { configurable: true, writable: true, value: null })
  HTMLMediaElement.prototype.play = vi.fn(async () => undefined)
  Object.defineProperty(HTMLVideoElement.prototype, 'videoWidth', { configurable: true, get: () => 1280 })
  Object.defineProperty(HTMLVideoElement.prototype, 'videoHeight', { configurable: true, get: () => 720 })
  HTMLCanvasElement.prototype.getContext = vi.fn(() => ({ drawImage: vi.fn() })) as never
  HTMLCanvasElement.prototype.toBlob = function (cb: BlobCallback, type?: string) {
    cb(new Blob([new Uint8Array([0xff, 0xd8, 0xff, 0xe0])], { type }))
  }
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
})

function renderCamera() {
  const onCapture = vi.fn()
  const onClose = vi.fn()
  const utils = render(<CameraCapture onCapture={onCapture} onClose={onClose} />)
  return { ...utils, onCapture, onClose }
}

// ---------------------------------------------------------------------------

describe('camera helpers', () => {
  it('prefers MP4, falls back to WebM, and survives browsers that throw', () => {
    expect(pickRecorderType(() => true)).toBe('video/mp4;codecs=avc1,mp4a')
    expect(pickRecorderType((t) => t.startsWith('video/webm'))).toBe('video/webm;codecs=vp9,opus')
    expect(pickRecorderType(() => false)).toBeNull()
    expect(
      pickRecorderType((t) => {
        if (t.includes('mp4')) throw new Error('unknown')
        return t === 'video/webm'
      }),
    ).toBe('video/webm')
  })

  it('names captures by local time with the right extension', () => {
    const at = new Date(2026, 9, 3, 4, 5, 6)
    expect(captureFileName('photo', 'image/jpeg', at)).toBe('Photo 2026-10-03 04-05-06.jpg')
    expect(captureFileName('video', 'video/mp4', at)).toBe('Video 2026-10-03 04-05-06.mp4')
    expect(captureFileName('video', 'video/webm', at)).toBe('Video 2026-10-03 04-05-06.webm')
    expect(extensionFor('video/webm;codecs=vp8')).toBe('webm')
    expect(formatDuration(75.9)).toBe('1:15')
  })

  it('keeps recordings safely under the upload limit', () => {
    expect(RECORDING_LIMIT_BYTES).toBeLessThan(MAX_UPLOAD_BYTES)
    expect(RECORDING_LIMIT_BYTES).toBeGreaterThan(MAX_UPLOAD_BYTES * 0.9)
  })

  it('explains camera errors in plain words', () => {
    expect(cameraErrorMessage(new DOMException('x', 'NotAllowedError'))).toMatch(/blocked/)
    expect(cameraErrorMessage(new DOMException('x', 'NotFoundError'))).toMatch(/No camera/)
    expect(cameraErrorMessage(new DOMException('x', 'NotReadableError'))).toMatch(/another app/)
  })
})

describe('in-app camera', () => {
  it('takes a photo from the live stream and hands it straight to the upload queue', async () => {
    const user = userEvent.setup()
    const { onCapture } = renderCamera()
    await screen.findByRole('button', { name: 'Take photo' })
    // Photo mode never asks for the microphone; back camera first.
    expect(getUserMedia).toHaveBeenCalledWith(expect.objectContaining({ audio: false }))
    expect(getUserMedia.mock.calls[0][0].video.facingMode).toEqual({ ideal: 'environment' })

    await user.click(screen.getByRole('button', { name: 'Take photo' }))
    await waitFor(() => expect(onCapture).toHaveBeenCalledTimes(1))
    const photo = onCapture.mock.calls[0][0] as File
    expect(photo).toBeInstanceOf(File)
    expect(photo.type).toBe('image/jpeg')
    expect(photo.name).toMatch(/^Photo \d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2}\.jpg$/)
    expect(screen.getByRole('status').textContent).toMatch(/added to uploads/)

    await user.click(screen.getByRole('button', { name: 'Take photo' }))
    await waitFor(() => expect(onCapture).toHaveBeenCalledTimes(2))
  })

  it('releases the camera when closed, and on unmount (vault locked)', async () => {
    const { unmount } = renderCamera()
    await screen.findByRole('button', { name: 'Take photo' })
    const [stream] = streams
    unmount()
    for (const track of stream.tracks) expect(track.stop).toHaveBeenCalled()
  })

  it('switching lens restarts the stream with the front camera and stops the old one', async () => {
    const user = userEvent.setup()
    renderCamera()
    await screen.findByRole('button', { name: 'Take photo' })
    await user.click(screen.getByRole('button', { name: 'Switch to front camera' }))
    await waitFor(() => expect(getUserMedia).toHaveBeenCalledTimes(2))
    expect(getUserMedia.mock.calls[1][0].video.facingMode).toEqual({ ideal: 'user' })
    expect(streams[0].tracks[0].stop).toHaveBeenCalled()
  })

  it('records a video with sound and uploads it when stopped', async () => {
    const user = userEvent.setup()
    const { onCapture, onClose } = renderCamera()
    await user.click(await screen.findByRole('button', { name: 'Video' }))
    await screen.findByRole('button', { name: 'Start recording' })
    expect(getUserMedia).toHaveBeenLastCalledWith(expect.objectContaining({ audio: true }))

    await user.click(screen.getByRole('button', { name: 'Start recording' }))
    const [recorder] = FakeRecorder.instances
    expect(recorder.options.mimeType).toBe('video/webm;codecs=vp9,opus')
    expect(recorder.start).toHaveBeenCalledWith(1000)
    // While recording, the camera can't be closed or switched by accident.
    expect((screen.getByRole('button', { name: 'Close camera' }) as HTMLButtonElement).disabled).toBe(true)
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClose).not.toHaveBeenCalled()

    act(() => {
      recorder.emit(1000)
      recorder.emit(2000)
    })
    await user.click(screen.getByRole('button', { name: 'Stop recording' }))
    expect(onCapture).toHaveBeenCalledTimes(1)
    const clip = onCapture.mock.calls[0][0] as File
    expect(clip.type).toBe('video/webm')
    expect(clip.name).toMatch(/^Video .*\.webm$/)
    expect(clip.size).toBe(3000)
  })

  it('stops recording automatically before the upload limit', async () => {
    const user = userEvent.setup()
    const { onCapture } = renderCamera()
    await user.click(await screen.findByRole('button', { name: 'Video' }))
    await user.click(await screen.findByRole('button', { name: 'Start recording' }))
    const [recorder] = FakeRecorder.instances
    act(() => recorder.emit(RECORDING_LIMIT_BYTES))
    expect(recorder.stop).toHaveBeenCalled()
    expect(onCapture).toHaveBeenCalledTimes(1)
    expect((onCapture.mock.calls[0][0] as File).size).toBeLessThan(MAX_UPLOAD_BYTES)
  })

  it('throws a recording away if the vault locks mid-recording', async () => {
    const user = userEvent.setup()
    const { onCapture, unmount } = renderCamera()
    await user.click(await screen.findByRole('button', { name: 'Video' }))
    await user.click(await screen.findByRole('button', { name: 'Start recording' }))
    const [recorder] = FakeRecorder.instances
    act(() => recorder.emit(5000))
    const stream = streams[streams.length - 1]
    unmount()
    expect(recorder.stop).toHaveBeenCalled()
    expect(onCapture).not.toHaveBeenCalled()
    for (const track of stream.tracks) expect(track.stop).toHaveBeenCalled()
  })

  it('still records (silently) if the microphone is refused', async () => {
    getUserMedia.mockImplementation(async (c: MediaStreamConstraints) => {
      if (c.audio) throw new DOMException('no mic', 'NotAllowedError')
      const s = fakeStream(false)
      streams.push(s)
      return s
    })
    const user = userEvent.setup()
    renderCamera()
    await user.click(await screen.findByRole('button', { name: 'Video' }))
    expect(await screen.findByText(/Recording without sound/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Start recording' })).toBeTruthy()
  })

  it('explains a blocked camera and offers the device camera as a fallback', async () => {
    getUserMedia.mockRejectedValue(new DOMException('denied', 'NotAllowedError'))
    const { onCapture } = renderCamera()
    expect(await screen.findByText(/Camera access was blocked/)).toBeTruthy()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeTruthy()
    const input = screen.getByLabelText('Take a photo or video with the device camera') as HTMLInputElement
    expect(input.getAttribute('capture')).toBe('environment')
    const shot = new File([new Uint8Array([0xff, 0xd8, 0xff])], 'IMG_0001.jpg', { type: 'image/jpeg' })
    fireEvent.change(input, { target: { files: [shot] } })
    expect(onCapture).toHaveBeenCalledWith(shot)
  })

  it('without https it never asks for the camera and explains why', async () => {
    Object.defineProperty(window, 'isSecureContext', { configurable: true, value: false })
    renderCamera()
    expect(await screen.findByText(/needs a secure \(https\) connection/)).toBeTruthy()
    expect(getUserMedia).not.toHaveBeenCalled()
    expect(screen.queryByRole('button', { name: 'Try again' })).toBeNull()
  })
})
