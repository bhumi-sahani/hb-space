import { useCallback, useEffect, useSyncExternalStore } from 'react'
import { isUuid } from './crypto/bytes'

/**
 * Minimal hash router (Phase 4). Hash URLs need no server rewrite rules, so a
 * refresh on any route always loads the app. Routes carry only opaque random
 * ids, never folder names, file names, or keys:
 *
 *   #/                      vault root
 *   #/folder/<uuid>         a folder
 *   #/settings              settings
 *
 * The route says WHERE the user is; it never grants access. Authentication is
 * checked by the auth bootstrap, data access by RLS, and the vault key lives only
 * in memory (a refresh always comes back locked).
 */

export type Route = { name: 'vault'; folderId: string | null } | { name: 'settings' }

export const ROOT_ROUTE: Route = { name: 'vault', folderId: null }

/** Parses a location hash. Returns null for anything unrecognised. */
export function parseHash(hash: string): Route | null {
  const path = hash.replace(/^#/, '').replace(/\/+$/, '') || '/'
  if (path === '/' || path === '/vault') return ROOT_ROUTE
  if (path === '/settings') return { name: 'settings' }
  const folder = /^\/folder\/([0-9a-fA-F-]{36})$/.exec(path)
  if (folder && isUuid(folder[1].toLowerCase())) return { name: 'vault', folderId: folder[1].toLowerCase() }
  return null
}

export function routeToHash(route: Route): string {
  switch (route.name) {
    case 'vault':
      return route.folderId ? `#/folder/${route.folderId}` : '#/'
    case 'settings':
      return '#/settings'
  }
}

export function sameRoute(a: Route, b: Route): boolean {
  return routeToHash(a) === routeToHash(b)
}

function subscribe(listener: () => void): () => void {
  window.addEventListener('hashchange', listener)
  window.addEventListener('popstate', listener)
  return () => {
    window.removeEventListener('hashchange', listener)
    window.removeEventListener('popstate', listener)
  }
}

function currentHash(): string {
  return window.location.hash
}

/** Normalises an unknown/invalid hash to the vault root without adding a history entry. */
export function normaliseLocation(): Route {
  const route = parseHash(window.location.hash)
  if (route) return route
  window.history.replaceState(window.history.state, '', `${window.location.pathname}${window.location.search}#/`)
  return ROOT_ROUTE
}

export function navigate(route: Route, options: { replace?: boolean } = {}) {
  const hash = routeToHash(route)
  if (window.location.hash === hash) return
  if (options.replace) {
    window.history.replaceState(window.history.state, '', `${window.location.pathname}${window.location.search}${hash}`)
    window.dispatchEvent(new HashChangeEvent('hashchange'))
  } else {
    window.location.hash = hash
  }
}

export function useRoute(): [Route, typeof navigate] {
  const hash = useSyncExternalStore(subscribe, currentHash, () => '')
  const parsed = parseHash(hash)
  const route = parsed ?? ROOT_ROUTE
  // Unknown routes fall back to the vault root (and the address bar is corrected).
  const invalid = parsed === null
  useEffect(() => {
    if (invalid) normaliseLocation()
  }, [invalid, hash])
  const go = useCallback(navigate, [])
  return [route, go]
}
