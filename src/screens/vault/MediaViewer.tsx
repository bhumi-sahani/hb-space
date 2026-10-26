import { useCallback, useEffect, useRef, useState, type TouchEvent } from 'react'
import { Alert, Button, IconButton, Spinner } from '../../components/ui'
import { MediaError, openVaultItem, type OpenedItem, type ReadyItem } from '../../services/media'
import { revokeTrackedObjectUrl } from '../../services/vaultSession'
import { formatBytes, formatDate, formatDuration, formatMillis } from './formFields'
import { useVaultUi } from './hooks'

type Loaded = { status: 'loading' } | { status: 'error'; message: string } | { status: 'ok'; opened: OpenedItem }

interface MediaViewerProps {
  items: ReadyItem[]
  index: number
  onIndex: (index: number) => void
  onClose: () => void
  onDownload: (item: ReadyItem) => void
  /** Asks for confirmation, then deletes permanently. */
  onDelete: (item: ReadyItem) => void
  downloading: boolean
}

/**
 * Full-screen viewer. Only the CURRENT item is decrypted, into a tracked blob:
 * URL that is revoked as soon as the user moves to another item, closes the
 * viewer, or locks the vault. Neighbours are never pre-decrypted.
 */
export function MediaViewer({ items, index, onIndex, onClose, onDownload, onDelete, downloading }: MediaViewerProps) {
  const { backend, vaultId } = useVaultUi()
  const item = items[index]
  const [loaded, setLoaded] = useState<Loaded>({ status: 'loading' })
  const [zoomed, setZoomed] = useState(false)
  const [showInfo, setShowInfo] = useState(false)
  const touch = useRef<{ x: number; y: number } | null>(null)
  const closeButton = useRef<HTMLButtonElement>(null)

  const itemId = item?.id
  const record = item?.record

  useEffect(() => {
    if (!record) return
    let alive = true
    let url: string | null = null
    setLoaded({ status: 'loading' })
    setZoomed(false)
    openVaultItem(backend, vaultId, record)
      .then((opened) => {
        url = opened.url
        if (alive) setLoaded({ status: 'ok', opened })
        else revokeTrackedObjectUrl(opened.url)
      })
      .catch((error) => {
        if (alive) setLoaded({ status: 'error', message: error instanceof MediaError ? error.userMessage : 'Unable to open this item.' })
      })
    return () => {
      alive = false
      if (url) revokeTrackedObjectUrl(url) // release the decrypted media immediately
    }
  }, [backend, vaultId, itemId, record])

  const go = useCallback(
    (delta: number) => {
      const next = index + delta
      if (next >= 0 && next < items.length) onIndex(next)
    },
    [index, items.length, onIndex],
  )

  useEffect(() => {
    closeButton.current?.focus()
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose()
      else if (event.key === 'ArrowRight') go(1)
      else if (event.key === 'ArrowLeft') go(-1)
    }
    window.addEventListener('keydown', onKey)
    const previousOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      window.removeEventListener('keydown', onKey)
      document.body.style.overflow = previousOverflow
    }
  }, [go, onClose])

  if (!item) return null

  function onTouchStart(event: TouchEvent) {
    if (zoomed || event.touches.length !== 1) return
    touch.current = { x: event.touches[0].clientX, y: event.touches[0].clientY }
  }

  function onTouchEnd(event: TouchEvent) {
    const start = touch.current
    touch.current = null
    if (!start || zoomed) return
    const dx = event.changedTouches[0].clientX - start.x
    const dy = event.changedTouches[0].clientY - start.y
    if (Math.abs(dx) > 60 && Math.abs(dx) > Math.abs(dy) * 1.5) go(dx < 0 ? 1 : -1)
    else if (dy > 110 && Math.abs(dy) > Math.abs(dx) * 1.5) onClose()
  }

  const meta = item.meta
  const isImage = loaded.status === 'ok' && loaded.opened.inline && loaded.opened.type.startsWith('image/')
  const isVideo = loaded.status === 'ok' && loaded.opened.inline && loaded.opened.type.startsWith('video/')

  return (
    <div className="viewer" role="dialog" aria-modal="true" aria-label={`Viewing ${meta.name}`}>
      <div className="viewer__bar viewer__bar--top">
        <IconButton icon="close" label="Close viewer" onClick={onClose} ref={closeButton} />
        <div className="viewer__title">
          <span className="viewer__name">{meta.name}</span>
          <span className="viewer__count">
            {index + 1} / {items.length}
          </span>
        </div>
        {isImage && (
          <IconButton icon={zoomed ? 'zoomOut' : 'zoomIn'} label={zoomed ? 'Fit to screen' : 'Zoom in'} onClick={() => setZoomed((z) => !z)} />
        )}
      </div>

      <div className={`viewer__stage${zoomed ? ' viewer__stage--zoomed' : ''}`} onTouchStart={onTouchStart} onTouchEnd={onTouchEnd}>
        {loaded.status === 'loading' && <Spinner label="Decrypting" />}
        {loaded.status === 'error' && (
          <div className="viewer__message">
            <Alert tone="error">{loaded.message}</Alert>
          </div>
        )}
        {isImage && loaded.status === 'ok' && (
          <img
            className="viewer__image"
            src={loaded.opened.url}
            alt={meta.name}
            onDoubleClick={() => setZoomed((z) => !z)}
            draggable={false}
          />
        )}
        {isVideo && loaded.status === 'ok' && (
          // Native controls: play/pause, seek, volume, fullscreen. Source is a local, revocable blob: URL.
          <video className="viewer__video" src={loaded.opened.url} controls playsInline preload="metadata" controlsList="nodownload" />
        )}
        {loaded.status === 'ok' && !loaded.opened.inline && (
          <div className="viewer__message">
            <p>This file can't be shown in the browser (for example HEIC outside Safari). It decrypted correctly; download it to view.</p>
          </div>
        )}
        {index > 0 && <IconButton className="viewer__nav viewer__nav--prev" icon="chevronLeft" label="Previous" onClick={() => go(-1)} />}
        {index < items.length - 1 && (
          <IconButton className="viewer__nav viewer__nav--next" icon="chevronRight" label="Next" onClick={() => go(1)} />
        )}
      </div>

      {showInfo && (
        <dl className="facts viewer__info">
          <dt>Name</dt>
          <dd>{meta.name}</dd>
          <dt>Type</dt>
          <dd>{meta.mime}</dd>
          <dt>Size</dt>
          <dd>{formatBytes(meta.size)}</dd>
          {meta.width !== undefined && meta.height !== undefined && (
            <>
              <dt>Dimensions</dt>
              <dd>
                {meta.width} × {meta.height}
              </dd>
            </>
          )}
          {meta.duration !== undefined && (
            <>
              <dt>Length</dt>
              <dd>{formatDuration(meta.duration)}</dd>
            </>
          )}
          {meta.modified !== null && (
            <>
              <dt>File date</dt>
              <dd>{formatMillis(meta.modified)}</dd>
            </>
          )}
          <dt>Uploaded</dt>
          <dd>{formatDate(item.createdAt)}</dd>
        </dl>
      )}

      <div className="viewer__bar viewer__bar--bottom">
        <Button variant="ghost" icon={undefined} onClick={() => setShowInfo((s) => !s)} aria-pressed={showInfo}>
          Info
        </Button>
        <Button variant="secondary" busy={downloading} onClick={() => onDownload(item)}>
          Download
        </Button>
        <Button variant="ghost" onClick={() => onDelete(item)}>
          Delete
        </Button>
      </div>
    </div>
  )
}
