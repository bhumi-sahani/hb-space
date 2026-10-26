import { useCallback, useEffect, useId, useRef, useState, type ChangeEvent } from 'react'
import { Alert, Button, IconButton } from '../../components/ui'
import {
  AUDIO_BITS_PER_SECOND,
  cameraErrorMessage,
  cameraUnavailableReason,
  captureFileName,
  formatDuration,
  PHOTO_QUALITY,
  pickRecorderType,
  RECORDING_LIMIT_BYTES,
  VIDEO_BITS_PER_SECOND,
} from '../../lib/media/camera'

type Mode = 'photo' | 'video'
type Facing = 'environment' | 'user'
type Status = { kind: 'starting' } | { kind: 'live'; withAudio: boolean } | { kind: 'error'; message: string }

interface Recording {
  recorder: MediaRecorder
  chunks: Blob[]
  bytes: number
  type: string
  startedAt: number
  /** True when the recording must be thrown away (camera closed or vault locked mid-recording). */
  discard: boolean
}

/**
 * Full-screen in-app camera. Every photo or video is handed to `onCapture`
 * (the encrypted upload queue) straight from memory: no camera app, no device
 * gallery, no temporary file. The camera and microphone are released when
 * this closes, when the mode or lens changes, and when the vault locks (the
 * whole vault view unmounts).
 */
export function CameraCapture({ onCapture, onClose }: { onCapture: (file: File) => void; onClose: () => void }) {
  const titleId = useId()
  const video = useRef<HTMLVideoElement>(null)
  const stream = useRef<MediaStream | null>(null)
  const recording = useRef<Recording | null>(null)
  const fallbackInput = useRef<HTMLInputElement>(null)
  const unavailable = useState(() => cameraUnavailableReason())[0]
  const recorderType = useState(() =>
    typeof MediaRecorder === 'function' && typeof MediaRecorder.isTypeSupported === 'function'
      ? pickRecorderType((t) => MediaRecorder.isTypeSupported(t))
      : null,
  )[0]

  const [mode, setMode] = useState<Mode>('photo')
  const [facing, setFacing] = useState<Facing>('environment')
  const [status, setStatus] = useState<Status>(unavailable ? { kind: 'error', message: unavailable } : { kind: 'starting' })
  const [attempt, setAttempt] = useState(0)
  const [isRecording, setIsRecording] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const [sent, setSent] = useState(0)
  const [flash, setFlash] = useState(false)
  const [announce, setAnnounce] = useState('')

  // ---- camera stream -------------------------------------------------------
  useEffect(() => {
    if (unavailable) return
    let cancelled = false
    let own: MediaStream | null = null
    const element = video.current
    setStatus({ kind: 'starting' })

    const videoConstraints: MediaTrackConstraints = {
      facingMode: { ideal: facing },
      width: { ideal: 1920 },
      height: { ideal: 1080 },
    }
    const start = async () => {
      let withAudio = mode === 'video'
      try {
        try {
          own = await navigator.mediaDevices.getUserMedia({ video: videoConstraints, audio: withAudio })
        } catch (error) {
          // Microphone refused or missing: still allow silent video.
          if (!withAudio) throw error
          withAudio = false
          own = await navigator.mediaDevices.getUserMedia({ video: videoConstraints, audio: false })
        }
        if (cancelled) return
        stream.current = own
        if (element) {
          element.srcObject = own
          await element.play().catch(() => undefined)
        }
        if (!cancelled) setStatus({ kind: 'live', withAudio })
      } catch (error) {
        if (!cancelled) setStatus({ kind: 'error', message: cameraErrorMessage(error) })
      }
    }
    void start()

    return () => {
      cancelled = true
      const active = recording.current
      if (active) {
        active.discard = true
        if (active.recorder.state !== 'inactive') active.recorder.stop()
        recording.current = null
      }
      own?.getTracks().forEach((track) => track.stop())
      if (stream.current === own) stream.current = null
      if (element) element.srcObject = null
    }
  }, [mode, facing, attempt, unavailable])

  // Elapsed time while recording.
  useEffect(() => {
    if (!isRecording) return
    const timer = window.setInterval(() => {
      const active = recording.current
      if (active) setElapsed((Date.now() - active.startedAt) / 1000)
    }, 250)
    return () => window.clearInterval(timer)
  }, [isRecording])

  const delivered = useCallback(
    (file: File, label: string) => {
      onCapture(file)
      setSent((n) => n + 1)
      setAnnounce(`${label} added to uploads. It is encrypted before it leaves this device.`)
    },
    [onCapture],
  )

  // ---- photo ---------------------------------------------------------------
  async function takePhoto() {
    const element = video.current
    if (!element || status.kind !== 'live') return
    const width = element.videoWidth
    const height = element.videoHeight
    if (!width || !height) {
      setAnnounce('The camera is not ready yet.')
      return
    }
    const canvas = document.createElement('canvas')
    canvas.width = width
    canvas.height = height
    try {
      const ctx = canvas.getContext('2d')
      if (!ctx) throw new Error('no canvas')
      ctx.drawImage(element, 0, 0, width, height)
      const blob = await new Promise<Blob | null>((resolve) => canvas.toBlob(resolve, 'image/jpeg', PHOTO_QUALITY))
      if (!blob) throw new Error('encode failed')
      setFlash(true)
      window.setTimeout(() => setFlash(false), 180)
      const at = new Date()
      delivered(new File([blob], captureFileName('photo', 'image/jpeg', at), { type: 'image/jpeg', lastModified: at.getTime() }), 'Photo')
    } catch {
      setAnnounce("The photo couldn't be taken. Try again.")
    } finally {
      // Release the canvas's copy of the frame.
      canvas.width = 0
      canvas.height = 0
    }
  }

  // ---- video ---------------------------------------------------------------
  function startRecording() {
    const own = stream.current
    if (!own || !recorderType || status.kind !== 'live') return
    let recorder: MediaRecorder
    try {
      recorder = new MediaRecorder(own, {
        mimeType: recorderType,
        videoBitsPerSecond: VIDEO_BITS_PER_SECOND,
        audioBitsPerSecond: AUDIO_BITS_PER_SECOND,
      })
    } catch {
      setAnnounce("Recording couldn't be started on this browser.")
      return
    }
    const active: Recording = { recorder, chunks: [], bytes: 0, type: recorderType.split(';')[0], startedAt: Date.now(), discard: false }
    recording.current = active
    recorder.ondataavailable = (event: BlobEvent) => {
      if (!event.data || event.data.size === 0) return
      active.chunks.push(event.data)
      active.bytes += event.data.size
      // Stay under the upload limit: stop automatically.
      if (active.bytes >= RECORDING_LIMIT_BYTES && recorder.state === 'recording') {
        setAnnounce('Maximum video length reached. Recording stopped.')
        recorder.stop()
      }
    }
    recorder.onstop = () => {
      const chunks = active.chunks
      active.chunks = []
      if (recording.current === active) recording.current = null
      setIsRecording(false)
      setElapsed(0)
      if (active.discard || chunks.length === 0) return
      const at = new Date()
      const blob = new Blob(chunks, { type: active.type })
      delivered(new File([blob], captureFileName('video', active.type, at), { type: active.type, lastModified: at.getTime() }), 'Video')
    }
    recorder.start(1000) // 1 s chunks, so the size limit is checked as it grows
    setElapsed(0)
    setIsRecording(true)
  }

  function stopRecording() {
    const active = recording.current
    if (active && active.recorder.state !== 'inactive') active.recorder.stop()
  }

  // ---- fallback: the system camera via a file input --------------------------
  function handleFallback(event: ChangeEvent<HTMLInputElement>) {
    const files = Array.from(event.target.files ?? [])
    event.target.value = ''
    for (const file of files) delivered(file, file.type.startsWith('video/') ? 'Video' : 'Photo')
  }

  // ---- keyboard ---------------------------------------------------------------
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !isRecording) onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [isRecording, onClose])

  const live = status.kind === 'live'
  const canRecord = recorderType !== null

  return (
    <div className="camera" role="dialog" aria-modal="true" aria-labelledby={titleId}>
      <div className="camera__bar camera__bar--top">
        <IconButton icon="close" label="Close camera" onClick={onClose} disabled={isRecording} />
        <h2 id={titleId} className="camera__title">
          Camera
        </h2>
        {sent > 0 && (
          <span className="camera__sent" aria-hidden="true">
            {sent} added to uploads
          </span>
        )}
      </div>

      <div className="camera__stage">
        <video
          ref={video}
          className={`camera__preview${facing === 'user' ? ' camera__preview--mirrored' : ''}`}
          autoPlay
          playsInline
          muted
          aria-label="Camera preview"
          hidden={!live}
        />
        {flash && <div className="camera__flash" aria-hidden="true" />}
        {status.kind === 'starting' && <p className="camera__message">Starting the camera…</p>}
        {status.kind === 'error' && (
          <div className="camera__message stack">
            <Alert tone="warning">{status.message}</Alert>
            {!unavailable && (
              <Button variant="secondary" onClick={() => setAttempt((n) => n + 1)}>
                Try again
              </Button>
            )}
            <Button variant="secondary" onClick={() => fallbackInput.current?.click()}>
              Use the device camera instead
            </Button>
            <p className="small camera__note">
              This opens your phone's own camera. Some camera apps may keep their own copy in the gallery; the in-app camera never
              does.
            </p>
            <input
              ref={fallbackInput}
              type="file"
              hidden
              accept="image/*,video/*"
              capture="environment"
              onChange={handleFallback}
              aria-label="Take a photo or video with the device camera"
            />
          </div>
        )}
        {isRecording && (
          <p className="camera__timer" aria-live="off">
            <span className="camera__dot" aria-hidden="true" /> {formatDuration(elapsed)}
          </p>
        )}
      </div>

      <p className="visually-hidden" role="status" aria-live="polite">
        {announce}
      </p>

      {live && (
        <div className="camera__bar camera__bar--bottom">
          <div className="camera__modes" role="group" aria-label="Camera mode">
            <button type="button" className="camera__mode" aria-pressed={mode === 'photo'} disabled={isRecording} onClick={() => setMode('photo')}>
              Photo
            </button>
            <button
              type="button"
              className="camera__mode"
              aria-pressed={mode === 'video'}
              disabled={isRecording || !canRecord}
              title={canRecord ? undefined : "This browser can't record video"}
              onClick={() => setMode('video')}
            >
              Video
            </button>
          </div>

          <div className="camera__controls">
            <span className="camera__spacer" />
            {mode === 'photo' ? (
              <button type="button" className="camera__shutter" aria-label="Take photo" onClick={() => void takePhoto()} />
            ) : isRecording ? (
              <button type="button" className="camera__shutter camera__shutter--stop" aria-label="Stop recording" onClick={stopRecording} />
            ) : (
              <button type="button" className="camera__shutter camera__shutter--record" aria-label="Start recording" onClick={startRecording} />
            )}
            <IconButton
              icon="switchCamera"
              label={facing === 'environment' ? 'Switch to front camera' : 'Switch to back camera'}
              disabled={isRecording}
              onClick={() => setFacing((f) => (f === 'environment' ? 'user' : 'environment'))}
            />
          </div>

          <p className="small camera__note">
            {mode === 'video' && status.kind === 'live' && !status.withAudio ? 'Recording without sound (no microphone access). ' : ''}
            Captures go straight to the encrypted upload, never to your device's gallery.
          </p>
        </div>
      )}
    </div>
  )
}
