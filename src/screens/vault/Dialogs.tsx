import { useEffect, useId, useRef, useState, type FormEvent, type ReactNode } from 'react'
import { Alert, Button, Icon, TextField } from '../../components/ui'
import { MAX_FOLDER_NAME_LENGTH } from '../../lib/crypto/folder'
import { folderLabel, sortFolders, type VaultFolder } from '../../services/folders'
import type { VaultItem } from '../../services/media'
import { plural } from './formFields'
import { itemTitle } from './items'

/** Accessible modal: labelled, Escape closes (unless busy), focus moves in and returns on close. */
export function Modal({
  title,
  children,
  onClose,
  busy = false,
  tone,
}: {
  title: string
  children: ReactNode
  onClose: () => void
  busy?: boolean
  tone?: 'danger'
}) {
  const titleId = useId()
  const panel = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null
    const first = panel.current?.querySelector<HTMLElement>('input, button:not([disabled]), [href], select, textarea')
    first?.focus()
    return () => previous?.focus?.()
  }, [])

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busy) onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [busy, onClose])

  return (
    <div className="modal" role="presentation" onClick={(e) => e.target === e.currentTarget && !busy && onClose()}>
      <div ref={panel} className={`modal__panel${tone === 'danger' ? ' modal__panel--danger' : ''}`} role="dialog" aria-modal="true" aria-labelledby={titleId}>
        <h2 id={titleId} className="modal__title">
          {title}
        </h2>
        {children}
      </div>
    </div>
  )
}

export function ConfirmDialog({
  title,
  children,
  confirmLabel,
  danger = false,
  busy = false,
  error,
  onConfirm,
  onCancel,
}: {
  title: string
  children: ReactNode
  confirmLabel: string
  danger?: boolean
  busy?: boolean
  error?: string | null
  onConfirm: () => void
  onCancel: () => void
}) {
  return (
    <Modal title={title} onClose={onCancel} busy={busy} tone={danger ? 'danger' : undefined}>
      <div className="stack">
        {children}
        {error && <Alert tone="error">{error}</Alert>}
        <div className="modal__actions">
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button variant={danger ? 'danger' : 'primary'} onClick={onConfirm} busy={busy}>
            {confirmLabel}
          </Button>
        </div>
      </div>
    </Modal>
  )
}

/** Folder name input. The name is encrypted before it is sent; it never leaves the device in plaintext. */
export function NameDialog({
  title,
  initial = '',
  submitLabel,
  busy,
  error,
  onSubmit,
  onCancel,
}: {
  title: string
  initial?: string
  submitLabel: string
  busy: boolean
  error: string | null
  onSubmit: (name: string) => void
  onCancel: () => void
}) {
  const [name, setName] = useState(initial)
  function submit(event: FormEvent) {
    event.preventDefault()
    onSubmit(name)
  }
  return (
    <Modal title={title} onClose={onCancel} busy={busy}>
      <form className="stack" onSubmit={submit}>
        <TextField
          label="Folder name"
          name="folder-name"
          value={name}
          maxLength={MAX_FOLDER_NAME_LENGTH}
          autoComplete="off"
          onChange={(e) => setName(e.target.value)}
          hint="Encrypted on this device. The server never sees the name."
          required
        />
        {error && <Alert tone="error">{error}</Alert>}
        <div className="modal__actions">
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
          <Button type="submit" busy={busy} disabled={!name.trim()}>
            {submitLabel}
          </Button>
        </div>
      </form>
    </Modal>
  )
}

/** Pick a destination folder (or the vault root). */
export function MoveDialog({
  folders,
  currentFolderId,
  count,
  busy,
  error,
  onMove,
  onCancel,
}: {
  folders: VaultFolder[]
  currentFolderId: string | null
  count: number
  busy: boolean
  error: string | null
  onMove: (folderId: string | null) => void
  onCancel: () => void
}) {
  const rows: { folder: VaultFolder | null; depth: number }[] = [{ folder: null, depth: 0 }]
  const children = (parent: string | null) => sortFolders(folders.filter((f) => f.parentId === parent))
  const walk = (parent: string | null, depth: number, seen: Set<string>) => {
    for (const f of children(parent)) {
      if (seen.has(f.id)) continue
      seen.add(f.id)
      rows.push({ folder: f, depth })
      walk(f.id, depth + 1, seen)
    }
  }
  walk(null, 1, new Set())

  return (
    <Modal title={`Move ${count === 1 ? '1 item' : `${count} items`} to…`} onClose={onCancel} busy={busy}>
      <div className="stack">
        <ul className="move-list" aria-label="Destination folders">
          {rows.map(({ folder, depth }) => {
            const id = folder?.id ?? null
            const here = id === currentFolderId
            return (
              <li key={id ?? 'root'}>
                <button
                  type="button"
                  className="move-list__row"
                  style={{ paddingLeft: `${12 + depth * 18}px` }}
                  disabled={busy || here}
                  onClick={() => onMove(id)}
                >
                  <Icon name={folder ? 'folder' : 'image'} size={18} />
                  <span>{folderLabel(folder)}</span>
                  {here && <span className="muted small">(current)</span>}
                </button>
              </li>
            )
          })}
        </ul>
        {error && <Alert tone="error">{error}</Alert>}
        <div className="modal__actions">
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
        </div>
      </div>
    </Modal>
  )
}

export function ProgressDialog({ title, done, total, detail, onCancel }: { title: string; done: number; total: number; detail?: string; onCancel?: () => void }) {
  const percent = total > 0 ? Math.round((done / total) * 100) : 0
  return (
    <Modal title={title} onClose={() => onCancel?.()} busy={!onCancel}>
      <div className="stack">
        <progress className="progress" value={done} max={Math.max(total, 1)} aria-label={title} />
        <p className="muted small" role="status">
          {done} of {total} ({percent}%){detail ? ` · ${detail}` : ''}
        </p>
        {onCancel && (
          <div className="modal__actions">
            <Button variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
          </div>
        )}
      </div>
    </Modal>
  )
}

const NAMES_SHOWN = 8

/**
 * Confirmation for PERMANENT deletion (there is no trash). Shows exactly how
 * many items will be destroyed and lists their names, so nothing is deleted
 * by surprise.
 */
export function DeleteDialog({
  items,
  folders,
  onConfirm,
  onCancel,
}: {
  items: VaultItem[]
  folders: VaultFolder[]
  onConfirm: () => void
  onCancel: () => void
}) {
  const folderMap = new Map(folders.map((f) => [f.id, f]))
  const count = items.length
  return (
    <ConfirmDialog
      title={count === 1 ? 'Delete permanently?' : `Delete ${plural(count, 'item')} permanently?`}
      confirmLabel={count === 1 ? 'Delete permanently' : `Delete ${count} permanently`}
      danger
      onConfirm={onConfirm}
      onCancel={onCancel}
    >
      <Alert tone="warning">
        This permanently destroys {count === 1 ? 'this item' : `these ${count} items`} for both of you. It cannot be undone, and there is
        no copy anywhere.
      </Alert>
      <ul className="purge-list" aria-label="Items that will be permanently deleted">
        {items.slice(0, NAMES_SHOWN).map((item) => {
          const folder = item.record.folderId ? (folderMap.get(item.record.folderId) ?? null) : null
          return (
            <li key={item.id}>
              <span className="break">{itemTitle(item)}</span>
              {folder ? <span className="muted small"> · in {folderLabel(folder)}</span> : null}
            </li>
          )
        })}
        {count > NAMES_SHOWN && <li className="muted">…and {plural(count - NAMES_SHOWN, 'more item')}</li>}
      </ul>
    </ConfirmDialog>
  )
}
