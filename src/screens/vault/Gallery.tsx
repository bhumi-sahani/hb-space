import { useCallback, useMemo, useRef, useState, type ChangeEvent } from 'react'
import { Alert, Button, Icon, IconButton, LockIcon } from '../../components/ui'
import type { Route } from '../../lib/router'
import { entriesForFolder } from '../../services/downloads'
import {
  createFolder,
  deleteFolder,
  folderLabel,
  folderPath,
  renameFolder,
  sortFolders,
  type VaultFolder,
} from '../../services/folders'
import { MAX_UPLOAD_BYTES, MediaError, moveItems, STALE_UPLOAD_MS, type ReadyItem, type VaultItem } from '../../services/media'
import type { UploadQueue } from '../../services/uploadQueue'
import { storageLimitBytes } from '../../config/storage'
import { CameraCapture } from './CameraCapture'
import { ConfirmDialog, MoveDialog, NameDialog } from './Dialogs'
import { plural } from './formFields'
import { useGalleryView, useIncremental, useSelection, useVaultUi } from './hooks'
import { activeItemsIn, itemTitle, vaultUsedBytes } from './items'
import { FolderTile, MediaTile, type TileAction } from './Tiles'
import { StorageMeter } from './StorageMeter'
import { UploadPanel } from './UploadPanel'
import type { VaultActions } from './VaultHome'

interface GalleryProps {
  items: VaultItem[]
  folders: VaultFolder[]
  folderId: string | null
  damaged: number
  refreshing: boolean
  queue: UploadQueue
  navigate: (route: Route, options?: { replace?: boolean }) => void
  actions: VaultActions
}

type Dialog =
  | { kind: 'new-folder' }
  | { kind: 'rename-folder' }
  | { kind: 'delete-folder' }
  | { kind: 'move'; ids: string[] }
  | null

function messageOf(error: unknown, fallback: string): string {
  return error instanceof MediaError ? error.userMessage : fallback
}

export function Gallery({ items, folders, folderId, damaged, refreshing, queue, navigate, actions }: GalleryProps) {
  const { backend, vaultId } = useVaultUi()
  const [query, setQuery] = useState('')
  const [dialog, setDialog] = useState<Dialog>(null)
  const [busy, setBusy] = useState(false)
  const [dialogError, setDialogError] = useState<string | null>(null)
  const fileInput = useRef<HTMLInputElement>(null)
  const [cameraOpen, setCameraOpen] = useState(false)
  const [view, setView] = useGalleryView()
  // Each capture goes straight into the encrypted upload queue, into the folder being viewed.
  const addCapture = useCallback((file: File) => queue.add([file], folderId), [queue, folderId])
  const closeCamera = useCallback(() => setCameraOpen(false), [])

  const folderMap = useMemo(() => new Map(folders.map((f) => [f.id, f])), [folders])
  const current = folderId ? (folderMap.get(folderId) ?? null) : null
  const missing = folderId !== null && current === null
  const trail = useMemo(() => folderPath(folderMap, folderId), [folderMap, folderId])

  const subfolders = useMemo(() => sortFolders(folders.filter((f) => f.parentId === folderId)), [folders, folderId])
  const counts = useMemo(() => {
    const map = new Map<string, number>()
    for (const item of items) {
      if (item.record.status !== 'ready' || !item.record.folderId) continue
      map.set(item.record.folderId, (map.get(item.record.folderId) ?? 0) + 1)
    }
    for (const f of folders) if (f.parentId) map.set(f.parentId, (map.get(f.parentId) ?? 0) + 1)
    return map
  }, [items, folders])

  const inFolder = useMemo(() => activeItemsIn(items, folderId), [items, folderId])
  const usedBytes = useMemo(() => vaultUsedBytes(items), [items])
  const needle = query.trim().toLocaleLowerCase()
  const shown = useMemo(
    () => (needle ? inFolder.filter((i) => i.state === 'ready' && i.meta.name.toLocaleLowerCase().includes(needle)) : inFolder),
    [inFolder, needle],
  )
  const shownIds = useMemo(() => shown.map((i) => i.id), [shown])
  const readyShown = useMemo(() => shown.filter((i): i is ReadyItem => i.state === 'ready'), [shown])
  const selection = useSelection(shownIds)
  const { count, sentinel, more } = useIncremental(shown.length, `${folderId ?? 'root'}|${needle}`)

  const selectedItems = shown.filter((i) => selection.selected.has(i.id))
  // Uploads that never finished (e.g. the connection dropped). Ones younger than
  // an hour may still be uploading on the other member's device, so are left alone.
  const staleUploads = useMemo(() => {
    const now = Date.now()
    return items.filter((i) => i.record.status === 'pending' && now - Date.parse(i.createdAt) > STALE_UPLOAD_MS)
  }, [items])
  const selectedReady = selectedItems.filter((i): i is ReadyItem => i.state === 'ready')

  if (missing) {
    return (
      <section className="panel stack" aria-labelledby="folder-missing">
        <h2 id="folder-missing" className="panel__title">
          Folder not found
        </h2>
        <p>This folder doesn't exist or was deleted on another device.</p>
        <Button variant="secondary" onClick={() => navigate({ name: 'vault', folderId: null }, { replace: true })}>
          Go to the vault
        </Button>
      </section>
    )
  }

  function handleFiles(event: ChangeEvent<HTMLInputElement>) {
    const files = Array.from(event.target.files ?? [])
    event.target.value = '' // drop the input's reference; the queue holds the files until done
    if (files.length > 0) queue.add(files, folderId)
  }

  function tileActions(item: VaultItem): TileAction[] {
    const remove: TileAction = { label: 'Delete', icon: 'trash', danger: true, onSelect: () => actions.remove([item]) }
    if (item.state !== 'ready') return [remove]
    return [
      { label: 'Download', icon: 'download', onSelect: () => actions.download([item], label) },
      { label: 'Move', icon: 'move', onSelect: () => setDialog({ kind: 'move', ids: [item.id] }) },
      remove,
    ]
  }

  function closeDialog() {
    if (busy) return
    setDialog(null)
    setDialogError(null)
  }

  async function run(task: () => Promise<void>, fallback: string) {
    setBusy(true)
    setDialogError(null)
    try {
      await task()
      setDialog(null)
    } catch (error) {
      setDialogError(messageOf(error, fallback))
    } finally {
      setBusy(false)
    }
  }

  const label = folderLabel(current)

  return (
    <>
      <header className="gallery-head" aria-labelledby="gallery-title">
        {(inFolder.length > 0 || needle || items.length > 0) && (
          <div className="gallery-search">
            <label className="search">
              <Icon name="search" size={18} />
              <span className="visually-hidden">Search names in this folder</span>
              <input
                type="search"
                value={query}
                placeholder={current ? `Search in ${label}` : 'Search in Vault'}
                onChange={(e) => setQuery(e.target.value)}
                autoComplete="off"
                enterKeyHint="search"
              />
            </label>
            <div className="view-toggle" role="group" aria-label="View">
              <button type="button" className="view-toggle__btn" aria-pressed={view === 'grid'} aria-label="Grid view" onClick={() => setView('grid')}>
                <Icon name="grid" size={18} />
              </button>
              <button type="button" className="view-toggle__btn" aria-pressed={view === 'list'} aria-label="List view" onClick={() => setView('list')}>
                <Icon name="list" size={18} />
              </button>
            </div>
          </div>
        )}

        {current && (
          <nav className="crumbs" aria-label="Folder path">
            <ol>
              <li>
                <button type="button" className="crumbs__link" onClick={() => navigate({ name: 'vault', folderId: null })}>
                  Vault
                </button>
              </li>
              {trail.map((f, i) => (
                <li key={f.id}>
                  {i === trail.length - 1 ? (
                    <span aria-current="page">{folderLabel(f)}</span>
                  ) : (
                    <button type="button" className="crumbs__link" onClick={() => navigate({ name: 'vault', folderId: f.id })}>
                      {folderLabel(f)}
                    </button>
                  )}
                </li>
              ))}
            </ol>
          </nav>
        )}

        <section className="vault-card" aria-label="Storage and upload">
          <div className="vault-card__info">
            <div className="vault-card__title-row">
              {current && (
                <IconButton
                  className="vault-card__back"
                  icon="chevronLeft"
                  label="Back"
                  onClick={() => navigate({ name: 'vault', folderId: current.parentId })}
                />
              )}
              <h2 id="gallery-title" className="vault-card__title">
                {label}
              </h2>
            </div>
            <StorageMeter used={usedBytes} limit={storageLimitBytes} />
          </div>
          <div className="vault-card__actions">
            <button type="button" className="vault-action vault-action--primary" onClick={() => fileInput.current?.click()}>
              <Icon name="upload" size={22} />
              <span>Upload</span>
            </button>
            <button type="button" className="vault-action" onClick={() => setCameraOpen(true)}>
              <Icon name="camera" size={22} />
              <span>Camera</span>
            </button>
          </div>
        </section>

        <input
          ref={fileInput}
          type="file"
          multiple
          hidden
          accept="image/jpeg,image/png,image/gif,image/webp,image/avif,image/heic,image/heif,video/mp4,video/quicktime,video/webm"
          onChange={handleFiles}
          aria-label="Choose photos or videos to encrypt and upload"
        />

        <div className="chips" role="toolbar" aria-label="Vault actions">
          <button type="button" className="chip" onClick={() => setDialog({ kind: 'new-folder' })}>
            <Icon name="plus" size={18} />
            <span>New folder</span>
          </button>
          <button
            type="button"
            className="chip"
            aria-pressed={selection.active}
            onClick={() => (selection.active ? selection.exit() : selection.setActive(true))}
            disabled={shown.length === 0}
          >
            <Icon name="select" size={18} />
            <span>{selection.active ? 'Done' : 'Select'}</span>
          </button>
          <button
            type="button"
            className="chip"
            onClick={() => actions.downloadZip(entriesForFolder(items, folders, folderId), label === 'Vault' ? 'HB Space' : label)}
            disabled={inFolder.length === 0 && subfolders.length === 0}
          >
            <Icon name="download" size={18} />
            <span>Download all</span>
          </button>
          {current && (
            <>
              <button type="button" className="chip" onClick={() => setDialog({ kind: 'rename-folder' })}>
                <Icon name="edit" size={18} />
                <span>Rename</span>
              </button>
              <button type="button" className="chip" onClick={() => setDialog({ kind: 'delete-folder' })}>
                <Icon name="trash" size={18} />
                <span>Delete folder</span>
              </button>
            </>
          )}
        </div>

        {refreshing && <p className="gallery-head__meta" role="status">Refreshing…</p>}
        {damaged > 0 && <Alert tone="warning">{plural(damaged, 'record')} could not be read and are hidden.</Alert>}
        {folderId === null && staleUploads.length > 0 && (
          <div className="notice-row">
            <Alert tone="info">
              {plural(staleUploads.length, 'upload')} never finished and {staleUploads.length === 1 ? 'holds' : 'hold'} no viewable media.
            </Alert>
            <Button variant="ghost" onClick={() => actions.remove(staleUploads)}>
              Remove
            </Button>
          </div>
        )}
      </header>

      <UploadPanel queue={queue} />
      {cameraOpen && <CameraCapture onCapture={addCapture} onClose={closeCamera} />}

      {subfolders.length > 0 && !needle && (
        <section aria-labelledby="folders-title" className="stack">
          <h2 id="folders-title" className="section-title">
            Folders <span className="section-title__count">{subfolders.length}</span>
          </h2>
          <ul className="folder-grid">
            {subfolders.map((f) => (
              <FolderTile key={f.id} folder={f} count={counts.get(f.id) ?? 0} onOpen={() => navigate({ name: 'vault', folderId: f.id })} />
            ))}
          </ul>
        </section>
      )}

      <section aria-labelledby="media-title" className="stack">
        <h2 id="media-title" className="section-title">
          {needle ? 'Results' : 'Photos & videos'} <span className="section-title__count">{needle ? shown.length : inFolder.length}</span>
        </h2>
        {shown.length === 0 ? (
          <div className="empty">
            <Icon name="image" size={32} />
            <p>{needle ? 'No names match your search.' : subfolders.length > 0 ? 'No photos or videos directly in this folder.' : 'Nothing here yet. Upload photos or videos to get started.'}</p>
          </div>
        ) : (
          <>
            <ul className={view === 'list' ? 'grid grid--list' : 'grid'} aria-label={`${label} contents`}>
              {shown.slice(0, count).map((item) => (
                <MediaTile
                  key={item.id}
                  item={item}
                  selecting={selection.active}
                  selected={selection.selected.has(item.id)}
                  onToggle={() => selection.toggle(item.id)}
                  onLongPress={() => selection.toggle(item.id)}
                  actions={tileActions(item)}
                  onOpen={() => {
                    const index = readyShown.findIndex((r) => r.id === item.id)
                    if (index >= 0) actions.open(readyShown, index)
                    else actions.notify({ tone: 'error', text: `${itemTitle(item)} cannot be opened with this vault key.` })
                  }}
                />
              ))}
            </ul>
            {count < shown.length && (
              <div ref={sentinel} className="grid-more">
                <Button variant="ghost" onClick={more}>
                  Show more ({shown.length - count} left)
                </Button>
              </div>
            )}
          </>
        )}
      </section>

      <p className="gallery-foot">
        <LockIcon /> Encrypted on this device before upload · up to {MAX_UPLOAD_BYTES / (1024 * 1024)} MB per file · search runs
        locally
      </p>

      {selection.active && (
        <div className="selection-bar" role="region" aria-label="Selection">
          <span className="selection-bar__count" role="status">
            {selection.selected.size} selected
          </span>
          <div className="selection-bar__actions">
            <Button variant="ghost" onClick={() => selection.selectAll(shownIds)} disabled={selection.selected.size === shown.length}>
              {needle ? `Select all ${shown.length} matching` : `Select all ${shown.length} in this folder`}
            </Button>
            <Button variant="ghost" onClick={selection.clear} disabled={selection.selected.size === 0}>
              Clear
            </Button>
            <Button
              variant="secondary"
              icon={<Icon name="download" />}
              disabled={selectedReady.length === 0}
              onClick={() => actions.download(selectedReady, label === 'Vault' ? 'HB Space' : label)}
            >
              Download
            </Button>
            <Button
              variant="secondary"
              icon={<Icon name="move" />}
              disabled={selectedItems.length === 0}
              onClick={() => setDialog({ kind: 'move', ids: selectedItems.map((i) => i.id) })}
            >
              Move
            </Button>
            <Button
              variant="danger"
              icon={<Icon name="trash" />}
              disabled={selectedItems.length === 0}
              onClick={() => actions.remove(selectedItems, selection.exit)}
            >
              Delete
            </Button>
          </div>
        </div>
      )}

      {dialog?.kind === 'new-folder' && (
        <NameDialog
          title={current ? `New folder in ${label}` : 'New folder'}
          submitLabel="Create folder"
          busy={busy}
          error={dialogError}
          onCancel={closeDialog}
          onSubmit={(name) =>
            void run(async () => {
              await createFolder(backend, vaultId, current, name)
              await actions.reload()
            }, 'Could not create the folder.')
          }
        />
      )}

      {dialog?.kind === 'rename-folder' && current && (
        <NameDialog
          title="Rename folder"
          initial={current.name ?? ''}
          submitLabel="Rename"
          busy={busy}
          error={dialogError}
          onCancel={closeDialog}
          onSubmit={(name) =>
            void run(async () => {
              await renameFolder(backend, vaultId, current, name)
              await actions.reload()
            }, 'Could not rename the folder.')
          }
        />
      )}

      {dialog?.kind === 'delete-folder' && current && (
        <ConfirmDialog
          title="Delete this folder?"
          confirmLabel="Delete folder"
          danger
          busy={busy}
          error={dialogError}
          onCancel={closeDialog}
          onConfirm={() =>
            void run(async () => {
              await deleteFolder(backend, vaultId, current)
              navigate({ name: 'vault', folderId: current.parentId }, { replace: true })
              await actions.reload()
            }, 'Could not delete the folder.')
          }
        >
          {inFolder.length > 0 || subfolders.length > 0 ? (
            <p>
              <strong className="break">{label}</strong> still contains {plural(inFolder.length, 'photo or video', 'photos or videos')}
              {subfolders.length > 0 ? ` and ${plural(subfolders.length, 'subfolder')}` : ''}. Only empty folders can be deleted: move
              or delete its contents first.
            </p>
          ) : (
            <p>
              <strong className="break">{label}</strong> is empty and will be deleted.
            </p>
          )}
        </ConfirmDialog>
      )}

      {dialog?.kind === 'move' && (
        <MoveDialog
          folders={folders}
          currentFolderId={folderId}
          count={dialog.ids.length}
          busy={busy}
          error={dialogError}
          onCancel={closeDialog}
          onMove={(target) =>
            void run(async () => {
              const result = await moveItems(backend, vaultId, dialog.ids, target)
              selection.exit()
              await actions.reload()
              actions.notify(
                result.failed.length > 0
                  ? { tone: 'warning', text: `${plural(result.done.length, 'item')} moved; ${result.failed.length} could not be moved.` }
                  : { tone: 'info', text: `${plural(result.done.length, 'item')} moved to ${folderLabel(target ? (folderMap.get(target) ?? null) : null)}.` },
              )
            }, 'Could not move the items.')
          }
        />
      )}
    </>
  )
}
