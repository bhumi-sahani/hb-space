// @vitest-environment node
import type { SupabaseClient } from '@supabase/supabase-js'
import { describe, expect, it } from 'vitest'
import { equalBytes, readBlob, toByteaHex, utf8 } from '../lib/crypto/bytes'
import { encryptItem } from '../lib/crypto/item'
import { generateRawVmk, importVmk } from '../lib/crypto/envelope'
import { BackendError, createSupabaseVaultBackend, LIST_PAGE_SIZE, parseEnvelopeRow, parseFolderRow, parseMediaRow } from './vaultBackend'

const VAULT = '5a5a5a5a-1111-4222-8333-444444444444'
const ITEM = '6b6b6b6b-1111-4222-8333-444444444444'
const FOLDER = '7d7d7d7d-1111-4222-8333-444444444444'

interface Call {
  target: string
  method: string
  args: unknown[]
}

/** Records every call made through a supabase-js-shaped chain and answers with `result`. */
function fakeClient(result: (call: Call[]) => unknown) {
  const calls: Call[] = []
  function chain(target: string, trail: Call[]): unknown {
    return new Proxy(
      {},
      {
        get(_t, method: string) {
          if (method === 'then') {
            const value = result(trail)
            return (resolve: (v: unknown) => void) => resolve(value)
          }
          return (...args: unknown[]) => {
            const call = { target, method, args }
            calls.push(call)
            return chain(target, [...trail, call])
          }
        },
      },
    )
  }
  const client = {
    from: (table: string) => chain(`table:${table}`, [{ target: table, method: 'from', args: [table] }]),
    storage: { from: (bucket: string) => chain(`bucket:${bucket}`, [{ target: bucket, method: 'bucket', args: [bucket] }]) },
  }
  return { client: client as unknown as SupabaseClient, calls }
}

describe('Supabase adapter: what leaves the browser', () => {
  it('uploads exactly the given ciphertext bytes, as octet-stream, write-once, to the private bucket', async () => {
    const vmk = await importVmk(generateRawVmk())
    const original = utf8('HB_SPACE_PHASE3_TEST_FILE adapter check')
    const enc = await encryptItem(vmk, ITEM, original, { name: 'secret-name.jpg', modified: null })
    const { client, calls } = fakeClient(() => ({ data: { path: 'x' }, error: null }))
    await createSupabaseVaultBackend(client).uploadObject(`${VAULT}/${ITEM}`, enc.content)

    const upload = calls.find((c) => c.method === 'upload')!
    expect(upload.target).toBe('bucket:private-media')
    expect(upload.args[0]).toBe(`${VAULT}/${ITEM}`)
    const body = upload.args[1] as Blob
    const sent = await readBlob(body)
    expect(equalBytes(sent, enc.content)).toBe(true)
    expect(equalBytes(sent, original)).toBe(false)
    expect(body.type).toBe('application/octet-stream')
    expect(upload.args[2]).toMatchObject({ contentType: 'application/octet-stream', upsert: false })
  })

  it('inserts a pending media row with only opaque/encrypted columns', async () => {
    const { client, calls } = fakeClient(() => ({ data: null, error: null }))
    await createSupabaseVaultBackend(client).insertPendingMedia({
      id: ITEM,
      vaultId: VAULT,
      wrappedDek: new Uint8Array(60).fill(1),
      encryptedMeta: new Uint8Array(284).fill(2),
      ciphertextSize: 100,
      folderId: FOLDER,
      hasThumbnail: true,
    })
    const insert = calls.find((c) => c.method === 'insert')!.args[0] as Record<string, unknown>
    expect(Object.keys(insert).sort()).toEqual(
      ['ciphertext_size', 'encrypted_meta', 'folder_id', 'format_version', 'has_thumbnail', 'id', 'vault_id', 'wrapped_dek'].sort(),
    )
    expect(insert.has_thumbnail).toBe(true)
    expect(insert.folder_id).toBe(FOLDER)
    expect(insert.wrapped_dek).toBe(toByteaHex(new Uint8Array(60).fill(1)))
  })

  it('envelope updates always carry the proof and the expected revision', async () => {
    const { client, calls } = fakeClient(() => ({ data: [{ revision: 3 }], error: null }))
    await createSupabaseVaultBackend(client).updateEnvelope(
      VAULT,
      {
        kind: 'passphrase',
        formatVersion: 1,
        kdf: 'argon2id-v1',
        kdfParams: { m: 65536, t: 3, p: 1 },
        salt: new Uint8Array(16),
        iv: new Uint8Array(12),
        wrappedKey: new Uint8Array(48),
      },
      new Uint8Array(32).fill(9),
      2,
    )
    const update = calls.find((c) => c.method === 'update')!.args[0] as Record<string, unknown>
    expect(update.key_proof).toBe(toByteaHex(new Uint8Array(32).fill(9)))
    expect(update).not.toHaveProperty('key_verifier')
    expect(calls.filter((c) => c.method === 'eq').map((c) => c.args)).toEqual([
      ['vault_id', VAULT],
      ['kind', 'passphrase'],
      ['revision', 2],
    ])
  })

  it('a concurrent change (no row updated) is reported as a conflict', async () => {
    const { client } = fakeClient(() => ({ data: [], error: null }))
    const env = {
      kind: 'passphrase' as const,
      formatVersion: 1 as const,
      kdf: 'argon2id-v1' as const,
      kdfParams: { m: 65536, t: 3, p: 1 },
      salt: new Uint8Array(16),
      iv: new Uint8Array(12),
      wrappedKey: new Uint8Array(48),
    }
    await expect(createSupabaseVaultBackend(client).updateEnvelope(VAULT, env, new Uint8Array(32), 1)).rejects.toMatchObject({ kind: 'conflict' })
  })

  it('maps a missing column (migration not applied) to not-set-up, and never exposes raw errors', async () => {
    const { client } = fakeClient(() => ({ data: null, error: { code: 'PGRST204', message: 'column key_verifier not found' } }))
    const error = await createSupabaseVaultBackend(client).listEnvelopes(VAULT).catch((e: unknown) => e)
    expect(error).toBeInstanceOf(BackendError)
    expect((error as BackendError).kind).toBe('not-set-up')
    expect((error as Error).message).not.toMatch(/key_verifier/)
  })
})

describe('server rows are untrusted', () => {
  const goodMedia = {
    id: ITEM,
    vault_id: VAULT,
    status: 'ready',
    uploaded_by: null,
    format_version: 1,
    object_path: `${VAULT}/${ITEM}`,
    wrapped_dek: toByteaHex(new Uint8Array(60)),
    encrypted_meta: toByteaHex(new Uint8Array(284)),
    ciphertext_size: 100,
    created_at: '2026-01-01T00:00:00Z',
    folder_id: null,
    trashed_at: null,
    has_thumbnail: true,
    thumbnail_path: `${VAULT}/${ITEM}.t`,
  }

  it('accepts a well-formed media row', () => {
    expect(parseMediaRow(goodMedia, VAULT)).toMatchObject({ folderId: null, trashedAt: null, hasThumbnail: true })
    expect(parseMediaRow({ ...goodMedia, folder_id: FOLDER, trashed_at: '2026-02-01T00:00:00Z' }, VAULT)).toMatchObject({
      folderId: FOLDER,
      trashedAt: '2026-02-01T00:00:00Z',
    })
  })

  it.each([
    ['other vault', { vault_id: '7c7c7c7c-1111-4222-8333-444444444444' }],
    ['path not derived from ids', { object_path: `${VAULT}/photo.jpg` }],
    ['bad id', { id: '../x' }],
    ['unknown status', { status: 'public' }],
    ['format version', { format_version: 2 }],
    ['short wrapped key', { wrapped_dek: toByteaHex(new Uint8Array(59)) }],
    ['unpadded metadata', { encrypted_meta: toByteaHex(new Uint8Array(290)) }],
    ['not hex', { wrapped_dek: 'not-hex' }],
    ['size too small', { ciphertext_size: 10 }],
    ['size not integer', { ciphertext_size: '100' }],
    ['thumbnail path not derived from ids', { thumbnail_path: `${VAULT}/thumb.jpg` }],
    ['non-uuid folder id (e.g. a plaintext folder name)', { folder_id: 'Vacation/Bali' }],
    ['non-string trash time', { trashed_at: 5 }],
    ['missing has_thumbnail (migration 5 not applied)', { has_thumbnail: undefined }],
    ['a pending item marked as trashed', { status: 'pending', trashed_at: '2026-02-01T00:00:00Z' }],
  ])('rejects a media row with %s', (_label, change) => {
    expect(parseMediaRow({ ...goodMedia, ...change }, VAULT)).toBeNull()
  })

  const goodFolder = {
    id: FOLDER,
    vault_id: VAULT,
    parent_id: null,
    depth: 0,
    encrypted_meta: toByteaHex(new Uint8Array(284)),
    revision: 1,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
  }

  it('accepts a well-formed folder row', () => {
    expect(parseFolderRow(goodFolder, VAULT)).toMatchObject({ id: FOLDER, parentId: null, depth: 0, revision: 1 })
  })

  it.each([
    ['other vault', { vault_id: ITEM }],
    ['self parent', { parent_id: FOLDER }],
    ['non-uuid parent', { parent_id: 'Vacation' }],
    ['depth out of range', { depth: 8 }],
    ['unpadded encrypted name', { encrypted_meta: toByteaHex(new Uint8Array(300)) }],
    ['plaintext name instead of ciphertext', { encrypted_meta: 'Vacation' }],
    ['bad revision', { revision: 0 }],
  ])('rejects a folder row with %s', (_label, change) => {
    expect(parseFolderRow({ ...goodFolder, ...change }, VAULT)).toBeNull()
  })
})

describe('Supabase adapter: Phase 4 calls', () => {
  it('lists media in pages until a short page, past the 1000-row API cap', async () => {
    const row = (n: number) => ({
      id: `6b6b6b6b-1111-4222-8333-${String(n).padStart(12, '0')}`,
      vault_id: VAULT,
      status: 'ready',
      uploaded_by: null,
      format_version: 1,
      object_path: `${VAULT}/6b6b6b6b-1111-4222-8333-${String(n).padStart(12, '0')}`,
      wrapped_dek: toByteaHex(new Uint8Array(60)),
      encrypted_meta: toByteaHex(new Uint8Array(284)),
      ciphertext_size: 100,
      created_at: '2026-01-01T00:00:00Z',
      folder_id: null,
      trashed_at: null,
      has_thumbnail: false,
      thumbnail_path: `${VAULT}/6b6b6b6b-1111-4222-8333-${String(n).padStart(12, '0')}.t`,
    })
    const { client, calls } = fakeClient((trail) => {
      const range = trail.find((c) => c.method === 'range')!.args as [number, number]
      const from = range[0]
      const count = from < 1000 ? LIST_PAGE_SIZE : 37
      return { data: Array.from({ length: count }, (_, i) => row(from + i)), error: null }
    })
    const { records, damaged } = await createSupabaseVaultBackend(client).listMedia(VAULT)
    expect(records).toHaveLength(1037)
    expect(damaged).toBe(0)
    expect(calls.filter((c) => c.method === 'range').map((c) => c.args)).toEqual([
      [0, LIST_PAGE_SIZE - 1],
      [LIST_PAGE_SIZE, 2 * LIST_PAGE_SIZE - 1],
      [2 * LIST_PAGE_SIZE, 3 * LIST_PAGE_SIZE - 1],
    ])
  })

  it('trash/restore send only the trash flag, scoped to the vault and to ready items', async () => {
    const { client, calls } = fakeClient(() => ({ data: [{ id: ITEM }], error: null }))
    const updated = await createSupabaseVaultBackend(client).setMediaTrashed(VAULT, [ITEM, 'not-a-uuid'], true)
    expect(updated).toEqual([ITEM])
    const update = calls.find((c) => c.method === 'update')!.args[0] as Record<string, unknown>
    expect(Object.keys(update)).toEqual(['trashed_at'])
    expect(calls.filter((c) => c.method === 'eq').map((c) => c.args)).toEqual([
      ['vault_id', VAULT],
      ['status', 'ready'],
    ])
    expect(calls.find((c) => c.method === 'in')!.args).toEqual(['id', [ITEM]])
  })

  it('moving sends only an opaque folder id', async () => {
    const { client, calls } = fakeClient(() => ({ data: [{ id: ITEM }], error: null }))
    await createSupabaseVaultBackend(client).setMediaFolder(VAULT, [ITEM], FOLDER)
    expect(calls.find((c) => c.method === 'update')!.args[0]).toEqual({ folder_id: FOLDER })
    await expect(createSupabaseVaultBackend(client).setMediaFolder(VAULT, [ITEM], 'Vacation')).rejects.toBeInstanceOf(BackendError)
  })

  it('creates folders with only ids and the encrypted name', async () => {
    const { client, calls } = fakeClient(() => ({ data: null, error: null }))
    await createSupabaseVaultBackend(client).insertFolder({ id: FOLDER, vaultId: VAULT, parentId: null, encryptedMeta: new Uint8Array(284).fill(3) })
    const insert = calls.find((c) => c.method === 'insert')!.args[0] as Record<string, unknown>
    expect(Object.keys(insert).sort()).toEqual(['encrypted_meta', 'id', 'parent_id', 'vault_id'])
    expect(insert.encrypted_meta).toBe(toByteaHex(new Uint8Array(284).fill(3)))
  })

  it('maps a refused folder delete to not-empty', async () => {
    for (const code of ['23514', '23503']) {
      const { client } = fakeClient(() => ({ data: null, error: { code, message: 'folder is not empty' } }))
      await expect(createSupabaseVaultBackend(client).deleteFolder(VAULT, FOLDER)).rejects.toMatchObject({ kind: 'not-empty' })
    }
  })

  it('a folder rename that matches no row (changed elsewhere) is a conflict', async () => {
    const { client, calls } = fakeClient(() => ({ data: [], error: null }))
    await expect(createSupabaseVaultBackend(client).updateFolderMeta(VAULT, FOLDER, new Uint8Array(284), 3)).rejects.toMatchObject({ kind: 'conflict' })
    expect(calls.filter((c) => c.method === 'eq').map((c) => c.args)).toContainEqual(['revision', 3])
  })

  it('refuses oversized downloads (e.g. a huge "thumbnail")', async () => {
    const { client } = fakeClient(() => ({ data: new Blob([new Uint8Array(2000)]), error: null }))
    await expect(createSupabaseVaultBackend(client).downloadObject(`${VAULT}/${ITEM}.t`, 1000)).rejects.toBeInstanceOf(BackendError)
  })

  it('rejects envelope rows with weakened KDF parameters, extra fields, or wrong lengths', () => {
    const good = {
      vault_id: VAULT,
      kind: 'passphrase',
      format_version: 1,
      kdf: 'argon2id-v1',
      kdf_params: { m: 65536, t: 3, p: 1 },
      salt: toByteaHex(new Uint8Array(16)),
      iv: toByteaHex(new Uint8Array(12)),
      wrapped_key: toByteaHex(new Uint8Array(48)),
      key_verifier: toByteaHex(new Uint8Array(32)),
      revision: 1,
    }
    expect(parseEnvelopeRow(good, VAULT)).not.toBeNull()
    expect(parseEnvelopeRow({ ...good, kdf_params: { m: 1024, t: 1, p: 1 } }, VAULT)).toBeNull()
    expect(parseEnvelopeRow({ ...good, kdf: 'pbkdf2' }, VAULT)).toBeNull()
    expect(parseEnvelopeRow({ ...good, salt: toByteaHex(new Uint8Array(8)) }, VAULT)).toBeNull()
    expect(parseEnvelopeRow({ ...good, key_verifier: null }, VAULT)).toBeNull()
    expect(parseEnvelopeRow({ ...good, vault_id: ITEM }, VAULT)).toBeNull()
  })
})
