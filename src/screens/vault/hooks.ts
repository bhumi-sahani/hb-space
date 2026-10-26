import { createContext, useCallback, useContext, useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from 'react'
import { listVaultFolders, type VaultFolder } from '../../services/folders'
import { listVaultItems, MediaError, type VaultItem } from '../../services/media'
import type { ThumbnailLoader } from '../../services/thumbnailLoader'
import type { VaultBackend } from '../../services/vaultBackend'

// ---------------------------------------------------------------------------
// Context shared by the unlocked vault views
// ---------------------------------------------------------------------------

export interface VaultUi {
  vaultId: string
  backend: VaultBackend
  thumbnails: ThumbnailLoader
}

export const VaultUiContext = createContext<VaultUi | null>(null)

/**
 * Creates a disposable object for the lifetime of the component, inside an
 * effect. (Creating it in useMemo and disposing it in an effect cleanup breaks
 * under React StrictMode: the dev double-mount disposes the object and then
 * keeps using it, so e.g. the upload queue silently ignored every file.)
 * Returns null until the first effect has run, and a fresh instance whenever
 * `create` changes.
 */
export function useOwned<T extends { dispose(): void }>(create: () => T): T | null {
  const [owned, setOwned] = useState<T | null>(null)
  useEffect(() => {
    const instance = create()
    setOwned(instance)
    return () => {
      instance.dispose()
      setOwned((current) => (current === instance ? null : current))
    }
  }, [create])
  return owned
}

export function useVaultUi(): VaultUi {
  const value = useContext(VaultUiContext)
  if (!value) throw new Error('VaultUiContext missing')
  return value
}

// ---------------------------------------------------------------------------
// Decrypted index of the vault (items + folders). Lives only in component state,
// so it disappears when the vault locks and the unlocked view unmounts.
// ---------------------------------------------------------------------------

export type IndexState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ok'; items: VaultItem[]; folders: VaultFolder[]; damaged: number; refreshing: boolean }

export function useVaultIndex(backend: VaultBackend, vaultId: string) {
  const [state, setState] = useState<IndexState>({ status: 'loading' })
  const generation = useRef(0)

  const reload = useCallback(async () => {
    const mine = ++generation.current
    setState((previous) => (previous.status === 'ok' ? { ...previous, refreshing: true } : { status: 'loading' }))
    try {
      const [media, folderList] = await Promise.all([listVaultItems(backend, vaultId), listVaultFolders(backend, vaultId)])
      if (mine !== generation.current) return
      setState({
        status: 'ok',
        items: media.items,
        folders: folderList.folders,
        damaged: media.damaged + folderList.damaged,
        refreshing: false,
      })
    } catch (error) {
      if (mine !== generation.current) return
      setState({ status: 'error', message: error instanceof MediaError ? error.userMessage : 'Could not load the vault contents.' })
    }
  }, [backend, vaultId])

  useEffect(() => {
    void reload()
    const counter = generation
    return () => {
      counter.current++ // ignore results that arrive after unmount (a counter, not a DOM ref)
    }
  }, [reload])

  return { state, reload }
}

// ---------------------------------------------------------------------------
// Visibility and incremental rendering
// ---------------------------------------------------------------------------

/** True once the element is near the viewport. Falls back to "visible" where IntersectionObserver is missing. */
export function useInView<T extends Element>(rootMargin = '300px'): [(node: T | null) => void, boolean] {
  const [visible, setVisible] = useState(typeof IntersectionObserver === 'undefined')
  const observer = useRef<IntersectionObserver | null>(null)
  const ref = useCallback(
    (node: T | null) => {
      observer.current?.disconnect()
      observer.current = null
      if (!node || typeof IntersectionObserver === 'undefined') return
      observer.current = new IntersectionObserver((entries) => setVisible(entries.some((e) => e.isIntersecting)), { rootMargin })
      observer.current.observe(node)
    },
    [rootMargin],
  )
  useEffect(() => () => observer.current?.disconnect(), [])
  return [ref, visible]
}

/**
 * Renders a long list in batches: `count` grows by `step` whenever the sentinel
 * scrolls near the viewport. Resets when `resetKey` changes (e.g. another folder).
 */
export function useIncremental(total: number, resetKey: string, step = 120): { count: number; sentinel: (node: Element | null) => void; more: () => void } {
  const [state, setState] = useState({ key: resetKey, count: step })
  const count = state.key === resetKey ? state.count : step
  if (state.key !== resetKey) setState({ key: resetKey, count: step })
  const more = useCallback(() => setState((s) => ({ key: resetKey, count: (s.key === resetKey ? s.count : step) + step })), [resetKey, step])
  const observer = useRef<IntersectionObserver | null>(null)
  const sentinel = useCallback(
    (node: Element | null) => {
      observer.current?.disconnect()
      observer.current = null
      if (!node || typeof IntersectionObserver === 'undefined') return
      observer.current = new IntersectionObserver((entries) => {
        if (entries.some((e) => e.isIntersecting)) more()
      }, { rootMargin: '600px' })
      observer.current.observe(node)
    },
    [more],
  )
  useEffect(() => () => observer.current?.disconnect(), [])
  return { count: Math.min(count, total), sentinel, more }
}

// ---------------------------------------------------------------------------
// Selection, keyed by opaque item ids (never by list position)
// ---------------------------------------------------------------------------

export function useSelection(validIds: string[]) {
  const [selected, setSelected] = useState<ReadonlySet<string>>(() => new Set())
  const [active, setActive] = useState(false)

  // Drop ids that are no longer in view (moved, trashed, deleted, or another folder).
  const validKey = validIds.join(',')
  useEffect(() => {
    const valid = new Set(validKey ? validKey.split(',') : [])
    setSelected((current) => {
      const next = new Set([...current].filter((id) => valid.has(id)))
      return next.size === current.size ? current : next
    })
  }, [validKey])

  const toggle = useCallback((id: string) => {
    setActive(true)
    setSelected((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }, [])

  const selectAll = useCallback((ids: string[]) => {
    setActive(true)
    setSelected(new Set(ids))
  }, [])

  const clear = useCallback(() => setSelected(new Set()), [])
  const exit = useCallback(() => {
    setSelected(new Set())
    setActive(false)
  }, [])

  return { selected, active, setActive, toggle, selectAll, clear, exit }
}

// ---------------------------------------------------------------------------
// Long press (touch) to start selecting
// ---------------------------------------------------------------------------

export function useLongPress(onLongPress: () => void, delay = 450) {
  const timer = useRef<number | null>(null)
  const origin = useRef<{ x: number; y: number } | null>(null)
  const fired = useRef(false)

  const cancel = useCallback(() => {
    if (timer.current !== null) window.clearTimeout(timer.current)
    timer.current = null
    origin.current = null
  }, [])

  useEffect(() => cancel, [cancel])

  return {
    onPointerDown: (event: ReactPointerEvent) => {
      fired.current = false
      if (event.pointerType === 'mouse') return
      origin.current = { x: event.clientX, y: event.clientY }
      timer.current = window.setTimeout(() => {
        fired.current = true
        timer.current = null
        onLongPress()
      }, delay)
    },
    onPointerMove: (event: ReactPointerEvent) => {
      if (!origin.current) return
      if (Math.abs(event.clientX - origin.current.x) > 10 || Math.abs(event.clientY - origin.current.y) > 10) cancel()
    },
    onPointerUp: cancel,
    onPointerCancel: cancel,
    onContextMenu: (event: { preventDefault: () => void }) => {
      if (origin.current || fired.current) event.preventDefault()
    },
    /** True if the click that follows should be ignored because a long press fired. */
    consumeLongPress: () => {
      const was = fired.current
      fired.current = false
      return was
    },
  }
}

// ---------------------------------------------------------------------------
// Grid / list preference (a per-device convenience; holds no private data)
// ---------------------------------------------------------------------------

export type GalleryView = 'grid' | 'list'
const VIEW_KEY = 'hbspace.galleryView'

function readView(): GalleryView {
  try {
    return localStorage.getItem(VIEW_KEY) === 'list' ? 'list' : 'grid'
  } catch {
    return 'grid'
  }
}

export function useGalleryView(): [GalleryView, (view: GalleryView) => void] {
  const [view, setViewState] = useState<GalleryView>(readView)
  const setView = useCallback((next: GalleryView) => {
    setViewState(next)
    try {
      localStorage.setItem(VIEW_KEY, next)
    } catch {
      // Private mode or blocked storage: the choice just isn't remembered.
    }
  }, [])
  return [view, setView]
}
