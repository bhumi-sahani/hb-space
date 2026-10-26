import { useEffect, useId, useRef, useState } from 'react'
import { Icon, Spinner, type IconName } from '../../components/ui'
import { folderLabel, type VaultFolder } from '../../services/folders'
import type { VaultItem } from '../../services/media'
import { formatBytes, formatDuration, formatRelative } from './formFields'
import { useInView, useLongPress, useVaultUi } from './hooks'
import { isVideo, itemTitle } from './items'

/** Decrypted thumbnail for a tile once it is near the viewport; released when the tile goes away. */
function useThumbnail(item: VaultItem, visible: boolean): { url: string | null; loading: boolean } {
  const { thumbnails } = useVaultUi()
  const [state, setState] = useState<{ id: string; url: string | null; loading: boolean }>({ id: item.id, url: null, loading: false })
  const wanted = visible && item.state === 'ready' && item.record.hasThumbnail

  useEffect(() => {
    if (!wanted) return
    let alive = true
    setState({ id: item.id, url: null, loading: true })
    void thumbnails.acquire(item.record).then((url) => {
      if (alive) setState({ id: item.id, url, loading: false })
    })
    return () => {
      alive = false
      thumbnails.release(item.id)
    }
  }, [wanted, item.id, item.record, thumbnails])

  return state.id === item.id ? { url: state.url, loading: state.loading } : { url: null, loading: false }
}

export interface TileAction {
  label: string
  icon: IconName
  onSelect: () => void
  danger?: boolean
}

/** The "..." menu on a tile. Closes on Escape, outside click, or after a choice. */
function TileMenu({ title, actions }: { title: string; actions: TileAction[] }) {
  const [open, setOpen] = useState(false)
  const root = useRef<HTMLDivElement>(null)
  const trigger = useRef<HTMLButtonElement>(null)
  const menuId = useId()

  useEffect(() => {
    if (!open) return
    root.current?.querySelector<HTMLButtonElement>('[role="menuitem"]')?.focus()
    const onPointer = (event: PointerEvent) => {
      if (!root.current?.contains(event.target as Node)) setOpen(false)
    }
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation()
        setOpen(false)
        trigger.current?.focus()
      }
    }
    document.addEventListener('pointerdown', onPointer)
    document.addEventListener('keydown', onKey, true)
    return () => {
      document.removeEventListener('pointerdown', onPointer)
      document.removeEventListener('keydown', onKey, true)
    }
  }, [open])

  return (
    <div className="tile-menu" ref={root}>
      <button
        ref={trigger}
        type="button"
        className="tile-menu__trigger"
        aria-label={`More actions for ${title}`}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        onClick={() => setOpen((v) => !v)}
      >
        <Icon name="more" size={18} />
      </button>
      {open && (
        <div className="tile-menu__list" role="menu" id={menuId} aria-label={`Actions for ${title}`}>
          {actions.map((action) => (
            <button
              key={action.label}
              type="button"
              role="menuitem"
              className={`tile-menu__item${action.danger ? ' tile-menu__item--danger' : ''}`}
              onClick={() => {
                setOpen(false)
                action.onSelect()
              }}
            >
              <Icon name={action.icon} size={18} />
              {action.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

interface MediaTileProps {
  item: VaultItem
  selecting: boolean
  selected: boolean
  onOpen: () => void
  onToggle: () => void
  onLongPress: () => void
  /** Actions for the "..." menu (not shown while selecting). */
  actions?: TileAction[]
}

export function MediaTile({ item, selecting, selected, onOpen, onToggle, onLongPress, actions = [] }: MediaTileProps) {
  const [ref, visible] = useInView<HTMLLIElement>()
  const { url, loading } = useThumbnail(item, visible)
  const press = useLongPress(onLongPress)
  const title = itemTitle(item)
  const video = isVideo(item)
  const kind = item.state !== 'ready' ? 'Item' : video ? 'Video' : 'Photo'

  function handleClick() {
    if (press.consumeLongPress()) return
    if (selecting) onToggle()
    else onOpen()
  }

  return (
    <li ref={ref} className={`tile${selected ? ' tile--selected' : ''}`}>
      <button
        type="button"
        className="tile__open"
        onClick={handleClick}
        onPointerDown={press.onPointerDown}
        onPointerMove={press.onPointerMove}
        onPointerUp={press.onPointerUp}
        onPointerCancel={press.onPointerCancel}
        onContextMenu={press.onContextMenu}
        aria-label={selecting ? `${selected ? 'Deselect' : 'Select'} ${kind.toLowerCase()} ${title}` : `Open ${kind.toLowerCase()} ${title}`}
        aria-pressed={selecting ? selected : undefined}
      >
        <span className="tile__thumb">
          {url ? (
            <img src={url} alt="" draggable={false} />
          ) : (
            <span className="tile__placeholder" aria-hidden="true">
              {loading ? <Spinner /> : <Icon name={video ? 'play' : item.state === 'ready' ? 'image' : 'close'} size={28} />}
            </span>
          )}
          {video && (
            <span className="tile__badge">
              <Icon name="play" size={12} />
              {item.state === 'ready' && item.meta.duration !== undefined ? formatDuration(item.meta.duration) : 'Video'}
            </span>
          )}
        </span>
      </button>
      <span className="tile__info">
        <span className="tile__text">
          <span className="tile__name">{title}</span>
          <span className="tile__meta">
            {item.state === 'ready' ? formatRelative(item.createdAt) : 'Not finished'}
            <span className="tile__size"> · {formatBytes(item.record.ciphertextSize)}</span>
          </span>
        </span>
        {!selecting && actions.length > 0 && <TileMenu title={title} actions={actions} />}
      </span>
      {(selecting || selected) && (
        <span className={`tile__check${selected ? ' tile__check--on' : ''}`} aria-hidden="true">
          {selected && <Icon name="check" size={16} />}
        </span>
      )}
    </li>
  )
}

interface FolderTileProps {
  folder: VaultFolder
  count: number
  onOpen: () => void
}

export function FolderTile({ folder, count, onOpen }: FolderTileProps) {
  const name = folderLabel(folder)
  return (
    <li>
      <button type="button" className="folder-tile" onClick={onOpen} aria-label={`Open folder ${name}`}>
        <span className="folder-tile__icon" aria-hidden="true">
          <Icon name="folder" size={26} />
        </span>
        <span className="folder-tile__body">
          <span className="folder-tile__name">{name}</span>
          <span className="folder-tile__meta">{count === 1 ? '1 item' : `${count} items`}</span>
        </span>
        <span className="folder-tile__chevron" aria-hidden="true">
          <Icon name="chevronRight" size={18} />
        </span>
      </button>
    </li>
  )
}
