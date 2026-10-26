import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Alert, Button, Spinner } from '../../components/ui'
import { makeThumbnail } from '../../lib/media/thumbnails'
import type { Route } from '../../lib/router'
import {
  browserSaver,
  buildZip,
  downloadItem,
  downloadSeparately,
  entriesForItems,
  totalBytes,
  zipFileName,
  ZIP_WARN_BYTES,
  type Saver,
  type ZipEntry,
} from '../../services/downloads'
import { MediaError, purgeItems, uploadFile, type ReadyItem, type ThumbnailMaker, type VaultItem } from '../../services/media'
import { ThumbnailLoader } from '../../services/thumbnailLoader'
import { UploadQueue } from '../../services/uploadQueue'
import type { VaultBackend } from '../../services/vaultBackend'
import { ConfirmDialog, DeleteDialog, ProgressDialog } from './Dialogs'
import { formatBytes, plural } from './formFields'
import { Gallery } from './Gallery'
import { useOwned, useVaultIndex, VaultUiContext } from './hooks'
import { MediaViewer } from './MediaViewer'

export type Notice = { tone: 'info' | 'error' | 'warning'; text: string } | null

export interface VaultActions {
  /** Opens the full-screen viewer on `list[index]`. */
  open: (list: ReadyItem[], index: number) => void
  /** One item: direct download. Several: ZIP or separate files (asks first). */
  download: (items: ReadyItem[], zipLabel: string) => void
  /** Downloads prepared ZIP entries (folder "Download all"). */
  downloadZip: (entries: ZipEntry[], zipLabel: string) => void
  notify: (notice: Notice) => void
  reload: () => Promise<void>
  /**
   * Asks for confirmation, then PERMANENTLY deletes the items (there is no
   * trash). `onDone` runs after the deletion finished (e.g. to clear a selection).
   */
  remove: (items: VaultItem[], onDone?: () => void) => void
}

interface VaultHomeProps {
  vaultId: string
  backend: VaultBackend
  route: Extract<Route, { name: 'vault' }>
  navigate: (route: Route, options?: { replace?: boolean }) => void
  /** Injectable for tests; defaults to the browser implementations. */
  thumbnailMaker?: ThumbnailMaker
  saver?: Saver
}

type DownloadAsk = { items: ReadyItem[]; label: string } | null
type ZipAsk = { entries: ZipEntry[]; label: string } | null
type Progress = { title: string; done: number; total: number; cancel?: () => void } | null
type DeleteAsk = { items: VaultItem[]; onDone?: () => void } | null

/**
 * The unlocked vault. All decrypted names, thumbnails, and media live in this
 * subtree only; it unmounts when the vault locks, and the thumbnail loader and
 * upload queue are disposed with it.
 */
export function VaultHome({ vaultId, backend, route, navigate, thumbnailMaker = makeThumbnail, saver = browserSaver }: VaultHomeProps) {
  const { state, reload } = useVaultIndex(backend, vaultId)
  const [notice, setNotice] = useState<Notice>(null)
  const [viewer, setViewer] = useState<{ list: ReadyItem[]; index: number } | null>(null)
  const [askDownload, setAskDownload] = useState<DownloadAsk>(null)
  const [askZip, setAskZip] = useState<ZipAsk>(null)
  const [progress, setProgress] = useState<Progress>(null)
  const [downloading, setDownloading] = useState(false)
  const [deleteAsk, setDeleteAsk] = useState<DeleteAsk>(null)

  const thumbnails = useOwned(useCallback(() => new ThumbnailLoader(backend, vaultId), [backend, vaultId]))

  // Reload (debounced) after uploads finish, so new items appear without hammering the server.
  const reloadTimer = useRef<number | null>(null)
  const scheduleReload = useCallback(() => {
    if (reloadTimer.current !== null) window.clearTimeout(reloadTimer.current)
    reloadTimer.current = window.setTimeout(() => {
      reloadTimer.current = null
      void reload()
    }, 400)
  }, [reload])
  useEffect(() => () => {
    if (reloadTimer.current !== null) window.clearTimeout(reloadTimer.current)
  }, [])

  const queue = useOwned(
    useCallback(
      () =>
        new UploadQueue(
          (file, folderId, signal, onStage) =>
            uploadFile(backend, vaultId, file, { folderId, makeThumbnail: thumbnailMaker, signal, onStage }),
          scheduleReload,
        ),
      [backend, vaultId, thumbnailMaker, scheduleReload],
    ),
  )

  const ui = useMemo(() => (thumbnails ? { vaultId, backend, thumbnails } : null), [vaultId, backend, thumbnails])

  // ---- downloads ---------------------------------------------------------

  const runZip = useCallback(
    async (entries: ZipEntry[], label: string) => {
      const controller = new AbortController()
      setProgress({ title: 'Preparing ZIP on this device', done: 0, total: entries.length, cancel: () => controller.abort() })
      try {
        const { blob, failed } = await buildZip(backend, vaultId, entries, {
          signal: controller.signal,
          onProgress: (done, total) => setProgress((p) => (p ? { ...p, done, total } : p)),
        })
        saver(blob, zipFileName(label))
        setNotice(
          failed.length > 0
            ? { tone: 'warning', text: `ZIP saved, but ${plural(failed.length, 'item')} could not be decrypted and ${failed.length === 1 ? 'is' : 'are'} missing from it.` }
            : { tone: 'info', text: `ZIP with ${plural(entries.length, 'item')} saved.` },
        )
      } catch (error) {
        setNotice({ tone: 'error', text: error instanceof MediaError ? error.userMessage : 'Could not create the ZIP.' })
      } finally {
        setProgress(null)
      }
    },
    [backend, vaultId, saver],
  )

  const downloadZip = useCallback(
    (entries: ZipEntry[], label: string) => {
      if (entries.length === 0) {
        setNotice({ tone: 'info', text: 'There is nothing to download here.' })
        return
      }
      if (totalBytes(entries) > ZIP_WARN_BYTES) setAskZip({ entries, label })
      else void runZip(entries, label)
    },
    [runZip],
  )

  const downloadOne = useCallback(
    async (item: ReadyItem) => {
      setDownloading(true)
      try {
        await downloadItem(backend, vaultId, item, saver)
      } catch (error) {
        setNotice({ tone: 'error', text: error instanceof MediaError ? error.userMessage : 'Could not download this item.' })
      } finally {
        setDownloading(false)
      }
    },
    [backend, vaultId, saver],
  )

  const download = useCallback(
    (items: ReadyItem[], label: string) => {
      if (items.length === 0) return
      if (items.length === 1) void downloadOne(items[0])
      else setAskDownload({ items, label })
    },
    [downloadOne],
  )

  async function runSeparate(items: ReadyItem[]) {
    const controller = new AbortController()
    setProgress({ title: 'Downloading files', done: 0, total: items.length, cancel: () => controller.abort() })
    try {
      const result = await downloadSeparately(backend, vaultId, items, {
        save: saver,
        signal: controller.signal,
        onProgress: (done, total) => setProgress((p) => (p ? { ...p, done, total } : p)),
      })
      setNotice(
        result.failed.length > 0
          ? { tone: 'warning', text: `${plural(result.done.length, 'file')} downloaded; ${result.failed.length} failed.` }
          : { tone: 'info', text: `${plural(result.done.length, 'file')} downloaded.` },
      )
    } catch (error) {
      setNotice({ tone: 'error', text: error instanceof MediaError ? error.userMessage : 'Download failed.' })
    } finally {
      setProgress(null)
    }
  }

  // ---- permanent deletion (no trash) ---------------------------------------

  async function runDelete(ask: NonNullable<DeleteAsk>) {
    setDeleteAsk(null)
    const records = ask.items.map((i) => i.record)
    setProgress({ title: 'Deleting permanently', done: 0, total: records.length })
    try {
      const result = await purgeItems(backend, vaultId, records, (done, total) => setProgress((p) => (p ? { ...p, done, total } : p)))
      const gone = new Set(result.done)
      setViewer((v) => {
        if (!v) return v
        const list = v.list.filter((i) => !gone.has(i.id))
        if (list.length === 0) return null
        return { list, index: Math.min(v.index, list.length - 1) }
      })
      ask.onDone?.()
      setNotice(
        result.failed.length > 0
          ? {
              tone: 'error',
              text: `${plural(result.done.length, 'item')} permanently deleted. ${plural(result.failed.length, 'item')} could NOT be deleted and ${result.failed.length === 1 ? 'is' : 'are'} still in the vault.`,
            }
          : { tone: 'info', text: `${plural(result.done.length, 'item')} permanently deleted.` },
      )
      await reload()
    } finally {
      setProgress(null)
    }
  }

  const actions: VaultActions = useMemo(
    () => ({
      open: (list, index) => setViewer({ list, index }),
      download,
      downloadZip,
      notify: setNotice,
      reload,
      remove: (items, onDone) => {
        if (items.length > 0) setDeleteAsk({ items, onDone })
      },
    }),
    [download, downloadZip, reload],
  )

  // ---- render --------------------------------------------------------------

  // The thumbnail loader and upload queue are created by an effect; until then
  // (one frame after mounting) show the loading state.
  let body
  if (state.status === 'loading' || !queue || !ui) {
    body = (
      <div className="panel inline-status">
        <Spinner label="Decrypting your vault" />
      </div>
    )
  } else if (state.status === 'error') {
    body = (
      <section className="panel stack" aria-labelledby="vault-load-failed">
        <h2 id="vault-load-failed" className="panel__title">
          Couldn't load the vault
        </h2>
        <Alert tone="error">{state.message}</Alert>
        <Button variant="secondary" onClick={() => void reload()}>
          Try again
        </Button>
      </section>
    )
  } else {
    body = (
      <Gallery
        items={state.items}
        folders={state.folders}
        folderId={route.folderId}
        damaged={state.damaged}
        refreshing={state.refreshing}
        queue={queue}
        navigate={navigate}
        actions={actions}
      />
    )
  }

  return (
    <VaultUiContext.Provider value={ui}>
      <div className="stack stack--loose vault-home">
        {notice && (
          <div className="notice-row">
            <Alert tone={notice.tone}>{notice.text}</Alert>
            <Button variant="ghost" onClick={() => setNotice(null)}>
              Dismiss
            </Button>
          </div>
        )}
        {body}
      </div>

      {viewer && viewer.list[viewer.index] && (
        <MediaViewer
          items={viewer.list}
          index={viewer.index}
          onIndex={(index) => setViewer((v) => (v ? { ...v, index } : v))}
          onClose={() => setViewer(null)}
          onDownload={(item) => void downloadOne(item)}
          onDelete={(item) => actions.remove([item])}
          downloading={downloading}
        />
      )}

      {deleteAsk && (
        <DeleteDialog
          items={deleteAsk.items}
          folders={state.status === 'ok' ? state.folders : []}
          onConfirm={() => void runDelete(deleteAsk)}
          onCancel={() => setDeleteAsk(null)}
        />
      )}

      {askDownload && (
        <ConfirmDialog
          title={`Download ${plural(askDownload.items.length, 'item')}`}
          confirmLabel="Download as one ZIP"
          onConfirm={() => {
            const ask = askDownload
            setAskDownload(null)
            downloadZip(entriesForItems(ask.items), ask.label)
          }}
          onCancel={() => setAskDownload(null)}
        >
          <p>
            The files are decrypted one at a time on this device ({formatBytes(askDownload.items.reduce((s, i) => s + i.meta.size, 0))}{' '}
            in total). Nothing is uploaded.
          </p>
          <Button
            variant="secondary"
            onClick={() => {
              const ask = askDownload
              setAskDownload(null)
              void runSeparate(ask.items)
            }}
          >
            Download as separate files
          </Button>
          <p className="muted small">Some phones only allow one download at a time; the ZIP is more reliable there.</p>
        </ConfirmDialog>
      )}

      {askZip && (
        <ConfirmDialog
          title="Large download"
          confirmLabel="Create ZIP anyway"
          onConfirm={() => {
            const ask = askZip
            setAskZip(null)
            void runZip(ask.entries, ask.label)
          }}
          onCancel={() => setAskZip(null)}
        >
          <p>
            This ZIP will be about {formatBytes(totalBytes(askZip.entries))}. It is built in this browser's memory, which can fail or
            be slow on phones. Consider downloading smaller selections.
          </p>
        </ConfirmDialog>
      )}

      {progress && <ProgressDialog title={progress.title} done={progress.done} total={progress.total} onCancel={progress.cancel} />}
    </VaultUiContext.Provider>
  )
}
