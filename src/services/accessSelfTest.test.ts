import type { SupabaseClient } from '@supabase/supabase-js'
import { describe, expect, it, vi } from 'vitest'
import { runAccessSelfTest } from './accessSelfTest'

type Op = 'select' | 'insert' | 'update' | 'delete'
type Response = { data: unknown; error: unknown }

/** Minimal chainable stand-in for the PostgREST builder and Storage client. */
function fakeClient(opts: {
  table: (table: string, op: Op) => Response
  upload?: () => Response
  download?: () => Response
}) {
  const remove = vi.fn(async () => ({ data: [], error: null }))
  const from = (table: string) => {
    let op: Op = 'select'
    const builder = {
      insert: () => ((op = 'insert'), builder),
      update: () => ((op = 'update'), builder),
      delete: () => ((op = 'delete'), builder),
      select: () => builder,
      eq: () => builder,
      limit: () => builder,
      single: () => builder,
      then: (resolve: (r: Response) => unknown, reject: (e: unknown) => unknown) =>
        Promise.resolve(opts.table(table, op)).then(resolve, reject),
    }
    return builder
  }
  const client = {
    from,
    auth: { getUser: async () => ({ data: { user: { id: 'user-1' } }, error: null }) },
    storage: {
      from: () => ({
        upload: async () => (opts.upload ?? (() => ({ data: null, error: { message: 'denied' } })))(),
        download: async () => (opts.download ?? (() => ({ data: null, error: { message: 'not found' } })))(),
        list: async () => ({ data: [], error: null }),
        remove,
      }),
    },
  }
  return { client: client as unknown as SupabaseClient, remove }
}

const denied = { data: null, error: { code: '42501', message: 'denied' } }
const empty = { data: [], error: null }

describe('runAccessSelfTest (non-member)', () => {
  it('passes when the server refuses writes and returns no rows', async () => {
    const { client } = fakeClient({ table: (_t, op) => (op === 'select' ? empty : denied) })
    const results = await runAccessSelfTest(client, null)
    expect(results.length).toBeGreaterThan(5)
    expect(results.filter((r) => r.outcome !== 'pass')).toEqual([])
  })

  it('fails loudly if a membership insert is accepted', async () => {
    const { client } = fakeClient({
      table: (table, op) => (table === 'vault_members' && op === 'insert' ? { data: null, error: null } : op === 'select' ? empty : denied),
    })
    const results = await runAccessSelfTest(client, null)
    expect(results.find((r) => r.name === 'Cannot add anyone to the vault')?.outcome).toBe('fail')
  })

  it('fails if vault data is visible, and cleans up an accepted upload', async () => {
    const { client, remove } = fakeClient({
      table: (table, op) => (op === 'select' ? (table === 'media_items' ? { data: [{ id: 'x' }], error: null } : empty) : denied),
      upload: () => ({ data: { path: 'p' }, error: null }),
    })
    const results = await runAccessSelfTest(client, null)
    expect(results.find((r) => r.name === 'Sees no rows in media_items')?.outcome).toBe('fail')
    expect(results.find((r) => r.name === 'Cannot upload to a guessed storage path')?.outcome).toBe('fail')
    expect(remove).toHaveBeenCalled()
  })
})

describe('runAccessSelfTest (member): key envelope protection (F2)', () => {
  const VAULT = '5a5a5a5a-1111-4222-8333-444444444444'
  const envelope = { data: [{ kind: 'passphrase', iv: '\\x000102030405060708090a0b', key_verifier: '\\x00' }], error: null }

  function memberClient(envelopeUpdate: Response) {
    return fakeClient({
      table: (table, op) => {
        if (table === 'vault_key_envelopes') return op === 'select' ? envelope : envelopeUpdate
        if (table === 'media_items' && op === 'insert') return { data: { uploaded_by: 'user-1', status: 'pending', object_path: 'x' }, error: null }
        return op === 'select' ? empty : denied
      },
    }).client
  }

  const name = 'Cannot rewrite vault key envelopes with only a login session'

  it('passes when the server refuses an envelope update without the key proof', async () => {
    const results = await runAccessSelfTest(memberClient(denied), VAULT)
    expect(results.find((r) => r.name === name)?.outcome).toBe('pass')
  })

  it('fails loudly when such an update is accepted', async () => {
    const results = await runAccessSelfTest(memberClient({ data: [{ kind: 'passphrase' }], error: null }), VAULT)
    expect(results.find((r) => r.name === name)).toMatchObject({ outcome: 'fail', detail: expect.stringMatching(/migration/) })
  })

  it('is skipped before the vault key exists', async () => {
    const client = fakeClient({ table: (_t, op) => (op === 'select' ? empty : denied) }).client
    const results = await runAccessSelfTest(client, VAULT)
    expect(results.find((r) => r.name === name)?.outcome).toBe('skip')
  })
})
