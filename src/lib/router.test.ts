import { act, renderHook, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { navigate, parseHash, routeToHash, useRoute, type Route } from './router'

const ID = '7d7d7d7d-1111-4222-8333-444444444444'

afterEach(() => {
  window.history.replaceState(null, '', '/')
})

describe('parseHash', () => {
  it.each([
    ['', { name: 'vault', folderId: null }],
    ['#', { name: 'vault', folderId: null }],
    ['#/', { name: 'vault', folderId: null }],
    ['#/vault', { name: 'vault', folderId: null }],
    ['#/settings', { name: 'settings' }],
    [`#/folder/${ID}`, { name: 'vault', folderId: ID }],
    [`#/folder/${ID.toUpperCase()}`, { name: 'vault', folderId: ID }],
  ])('%s', (hash, route) => {
    expect(parseHash(hash)).toEqual(route)
  })

  it.each(['#/folder/Vacation', '#/folder/../../etc', `#/folder/${ID}/x`, '#/admin', '#/trash', '#/settings?x=1', '#/folder/', 'javascript:alert(1)'])(
    'rejects %s',
    (hash) => {
      expect(parseHash(hash)).toBeNull()
    },
  )

  it('round-trips every route; URLs carry only opaque ids', () => {
    const routes: Route[] = [{ name: 'vault', folderId: null }, { name: 'vault', folderId: ID }, { name: 'settings' }]
    for (const route of routes) expect(parseHash(routeToHash(route))).toEqual(route)
    expect(routeToHash({ name: 'vault', folderId: ID })).toBe(`#/folder/${ID}`)
  })
})

describe('useRoute', () => {
  it('reads the current hash (what a refresh would restore) and follows navigation', async () => {
    window.history.replaceState(null, '', `/#/folder/${ID}`)
    const { result } = renderHook(() => useRoute())
    expect(result.current[0]).toEqual({ name: 'vault', folderId: ID })
    act(() => navigate({ name: 'settings' }))
    expect(window.location.hash).toBe('#/settings')
    await waitFor(() => expect(result.current[0]).toEqual({ name: 'settings' }))
  })

  it('an invalid route falls back to the vault root and the address bar is corrected', () => {
    window.history.replaceState(null, '', '/#/not-a-route')
    const { result } = renderHook(() => useRoute())
    expect(result.current[0]).toEqual({ name: 'vault', folderId: null })
    expect(window.location.hash).toBe('#/')
  })
})
