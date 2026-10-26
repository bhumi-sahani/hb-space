// @vitest-environment node
/// <reference types="vite/client" />
/**
 * Executes the real migration SQL on PGlite (Postgres compiled to WASM) with a
 * minimal Supabase stub, then probes every table and Storage operation as
 * anon, an authenticated outsider, and both members.
 *
 * This proves the SQL and policy logic behave as designed on real Postgres.
 * It does NOT prove a hosted Supabase project is configured correctly; run
 * supabase/tests/rls_verification.sql and the in-app access self-test for that.
 */
import { PGlite } from '@electric-sql/pglite'
import { beforeAll, describe, expect, it } from 'vitest'
import stubSql from './supabase-stub.sql?raw'
import verificationSql from './rls_verification.sql?raw'

const migrationFiles = import.meta.glob('../migrations/*.sql', { query: '?raw', import: 'default', eager: true }) as Record<
  string,
  string
>

const A = '11111111-1111-4111-8111-111111111111' // member
const B = '22222222-2222-4222-8222-222222222222' // member
const C = '33333333-3333-4333-8333-333333333333' // authenticated, NOT a member
const NO_SUCH_VAULT = '44444444-4444-4444-8444-444444444444'

type Actor = 'anon' | { sub: string } | { sub: null }

let db: PGlite
let vaultId: string

function bytes(length: number, fill = 7): Uint8Array {
  return new Uint8Array(length).fill(fill)
}

/** Runs one statement as the given actor inside its own transaction. */
async function as<T = Record<string, unknown>>(actor: Actor, sql: string, params: unknown[] = []) {
  return db.transaction(async (tx) => {
    if (actor === 'anon') {
      await tx.query(`select set_config('role', 'anon', true), set_config('request.jwt.claims', '{"role":"anon"}', true)`)
    } else {
      const claims = JSON.stringify(actor.sub ? { sub: actor.sub, role: 'authenticated' } : { role: 'authenticated' })
      await tx.query(`select set_config('role', 'authenticated', true), set_config('request.jwt.claims', $1, true)`, [claims])
    }
    return tx.query<T>(sql, params)
  })
}

async function expectPgError(promise: Promise<unknown>, code: string) {
  await expect(promise).rejects.toMatchObject({ code })
}

const PERMISSION_DENIED = '42501' // also used by Postgres for RLS WITH CHECK violations
const CHECK_VIOLATION = '23514'
const UNIQUE_VIOLATION = '23505'
const GENERATED_ALWAYS = '428C9' // writing to a generated column
const FOREIGN_KEY = '23503'

const member = (sub: string) => ({ sub })

// Key-possession proof (migration 4, finding F2). The vault's verifier is SHA-256(PROOF).
const PROOF = bytes(32, 5)
const WRONG_PROOF = bytes(32, 6)
let VERIFIER: Uint8Array
let WRONG_VERIFIER: Uint8Array

function envelopeParams(
  overrides: Partial<{ kind: string; kdf: string; params: unknown; verifier: Uint8Array; proof: Uint8Array | null }> = {},
) {
  return [
    vaultId,
    overrides.kind ?? 'passphrase',
    overrides.kdf ?? 'argon2id-v1',
    overrides.params === undefined ? JSON.stringify({ m: 65536, t: 3, p: 1 }) : overrides.params,
    bytes(16),
    bytes(12),
    bytes(48),
    overrides.verifier ?? VERIFIER,
    overrides.proof === undefined ? PROOF : overrides.proof,
  ]
}

const INSERT_ENVELOPE = `insert into public.vault_key_envelopes (vault_id, kind, format_version, kdf, kdf_params, salt, iv, wrapped_key, key_verifier, key_proof)
  values ($1, $2, 1, $3, $4::jsonb, $5, $6, $7, $8, $9) returning *`

const INSERT_MEDIA = `insert into public.media_items (id, vault_id, format_version, has_thumbnail, wrapped_dek, encrypted_meta, ciphertext_size)
  values ($1, $2, 1, $3, $4, $5, $6) returning *`

function mediaParams(id: string, vault: string, opts: { thumb?: boolean; size?: number } = {}) {
  return [id, vault, opts.thumb ?? false, bytes(60), bytes(284), opts.size ?? 1000]
}

const INSERT_OBJECT = `insert into storage.objects (bucket_id, name, metadata) values ($1, $2, $3::jsonb) returning name`

beforeAll(async () => {
  VERIFIER = new Uint8Array(await crypto.subtle.digest('SHA-256', PROOF))
  WRONG_VERIFIER = new Uint8Array(await crypto.subtle.digest('SHA-256', WRONG_PROOF))
  db = new PGlite()
  await db.exec(stubSql)
  for (const path of Object.keys(migrationFiles).sort()) {
    await db.exec(migrationFiles[path])
  }
  await db.query(`insert into auth.users (id, email) values ($1, 'a@test'), ($2, 'b@test'), ($3, 'c@test')`, [A, B, C])
  const result = await db.query<{ id: string }>('select private.provision_vault($1, $2) as id', [A, B])
  vaultId = result.rows[0].id
}, 60_000)

describe('provisioning invariants', () => {
  it('allows only one vault', async () => {
    await expectPgError(db.query('insert into public.vaults default values'), UNIQUE_VIOLATION)
  })

  it('allows at most two members', async () => {
    await expectPgError(db.query('insert into public.vault_members (vault_id, user_id) values ($1, $2)', [vaultId, C]), CHECK_VIOLATION)
  })

  it('makes membership rows immutable even for the owner', async () => {
    await expectPgError(db.query('update public.vault_members set user_id = $1 where user_id = $2', [C, A]), PERMISSION_DENIED)
  })

  it('is not callable by API roles', async () => {
    await expectPgError(as(member(A), 'select private.provision_vault($1, $2)', [A, C]), PERMISSION_DENIED)
    await expectPgError(as('anon', 'select private.provision_vault($1, $2)', [A, C]), PERMISSION_DENIED)
  })
})

describe('anonymous users', () => {
  it.each(['vaults', 'vault_members', 'vault_key_envelopes', 'media_items', 'media_folders'])('cannot read public.%s at all', async (table) => {
    await expectPgError(as('anon', `select * from public.${table}`), PERMISSION_DENIED)
  })

  it('cannot write any table', async () => {
    await expectPgError(as('anon', 'insert into public.vault_members (vault_id, user_id) values ($1, $2)', [vaultId, C]), PERMISSION_DENIED)
    await expectPgError(as('anon', INSERT_MEDIA, mediaParams(crypto.randomUUID(), vaultId)), PERMISSION_DENIED)
    await expectPgError(as('anon', 'delete from public.media_items'), PERMISSION_DENIED)
  })

  it('cannot call the membership helper', async () => {
    await expectPgError(as('anon', 'select private.is_vault_member($1)', [vaultId]), PERMISSION_DENIED)
  })
})

describe('authenticated session without a user id', () => {
  it('sees nothing', async () => {
    for (const table of ['vaults', 'vault_members', 'vault_key_envelopes', 'media_items']) {
      const result = await as({ sub: null }, `select * from public.${table}`)
      expect(result.rows, table).toHaveLength(0)
    }
  })
})

describe('vault membership', () => {
  it('members see the vault and only their own membership row', async () => {
    expect((await as(member(A), 'select id from public.vaults')).rows).toEqual([{ id: vaultId }])
    const rows = (await as<{ user_id: string }>(member(A), 'select user_id from public.vault_members')).rows
    expect(rows).toEqual([{ user_id: A }])
  })

  it('outsiders see no vault and no memberships', async () => {
    expect((await as(member(C), 'select * from public.vaults')).rows).toHaveLength(0)
    expect((await as(member(C), 'select * from public.vault_members')).rows).toHaveLength(0)
  })

  it('outsiders cannot add themselves', async () => {
    await expectPgError(
      as(member(C), 'insert into public.vault_members (vault_id, user_id) values ($1, $2)', [vaultId, C]),
      PERMISSION_DENIED,
    )
  })

  it('members cannot add, alter, or remove members', async () => {
    await expectPgError(
      as(member(A), 'insert into public.vault_members (vault_id, user_id) values ($1, $2)', [vaultId, C]),
      PERMISSION_DENIED,
    )
    await expectPgError(as(member(A), 'update public.vault_members set user_id = $1 where user_id = $2', [C, A]), PERMISSION_DENIED)
    await expectPgError(as(member(A), 'delete from public.vault_members where user_id = $1', [B]), PERMISSION_DENIED)
    await expectPgError(as(member(A), 'delete from public.vault_members where user_id = $1', [A]), PERMISSION_DENIED)
  })

  it('cannot be spoofed with a client-supplied id in the helper', async () => {
    const result = await as<{ ok: boolean }>(member(C), 'select private.is_vault_member($1) as ok', [vaultId])
    expect(result.rows[0].ok).toBe(false)
  })
})

describe('vault key envelopes', () => {
  const RLS_REFUSAL = /row-level security/

  it('outsiders cannot create an envelope, even with a self-consistent proof (stopped by RLS)', async () => {
    await expect(as(member(C), INSERT_ENVELOPE, envelopeParams())).rejects.toMatchObject({
      code: PERMISSION_DENIED,
      message: expect.stringMatching(RLS_REFUSAL),
    })
  })

  it('the first envelope must carry a proof matching its own verifier (F2)', async () => {
    await expectPgError(as(member(A), INSERT_ENVELOPE, envelopeParams({ proof: null })), PERMISSION_DENIED)
    await expectPgError(as(member(A), INSERT_ENVELOPE, envelopeParams({ proof: WRONG_PROOF })), PERMISSION_DENIED)
    await expectPgError(as(member(A), INSERT_ENVELOPE, envelopeParams({ proof: bytes(16, 5) })), PERMISSION_DENIED)
    expect((await db.query('select count(*)::int as n from public.vault_key_envelopes')).rows[0]).toEqual({ n: 0 })
  })

  it('members create envelopes with server-stamped audit fields; the proof is not stored', async () => {
    const result = await as<{ created_by: string; updated_by: string; revision: number; key_proof: unknown; key_verifier: Uint8Array }>(
      member(A),
      INSERT_ENVELOPE,
      envelopeParams(),
    )
    expect(result.rows[0]).toMatchObject({ created_by: A, updated_by: A, revision: 1, key_proof: null })
    expect(Array.from(result.rows[0].key_verifier)).toEqual(Array.from(VERIFIER))
  })

  it('clients cannot set audit fields', async () => {
    await expectPgError(
      as(member(A), `insert into public.vault_key_envelopes (vault_id, kind, format_version, kdf, kdf_params, salt, iv, wrapped_key, created_by)
        values ($1, 'recovery', 1, 'hkdf-sha256-v1', null, $2, $3, $4, $5)`, [vaultId, bytes(16), bytes(12), bytes(48), B]),
      PERMISSION_DENIED,
    )
  })

  it('a second passphrase envelope cannot be inserted over the first', async () => {
    await expectPgError(as(member(B), INSERT_ENVELOPE, envelopeParams()), UNIQUE_VIOLATION)
  })

  it('further envelopes must use the vault verifier and its proof (F2)', async () => {
    const recovery = { kind: 'recovery', kdf: 'hkdf-sha256-v1', params: null }
    // A different, self-consistent key (e.g. an attacker's own VMK) is refused.
    await expectPgError(
      as(member(B), INSERT_ENVELOPE, envelopeParams({ ...recovery, verifier: WRONG_VERIFIER, proof: WRONG_PROOF })),
      PERMISSION_DENIED,
    )
    await expectPgError(as(member(B), INSERT_ENVELOPE, envelopeParams({ ...recovery, proof: null })), PERMISSION_DENIED)
    await expectPgError(as(member(B), INSERT_ENVELOPE, envelopeParams({ ...recovery, proof: WRONG_PROOF })), PERMISSION_DENIED)
  })

  it('outsiders can neither read nor replace an envelope', async () => {
    expect((await as(member(C), 'select * from public.vault_key_envelopes')).rows).toHaveLength(0)
    const update = await as(member(C), 'update public.vault_key_envelopes set wrapped_key = $1', [bytes(48, 9)])
    expect(update.affectedRows ?? 0).toBe(0)
    const withProof = await as(member(C), 'update public.vault_key_envelopes set wrapped_key = $1, key_proof = $2', [bytes(48, 9), PROOF])
    expect(withProof.affectedRows ?? 0).toBe(0)
    const stored = await db.query<{ wrapped_key: Uint8Array }>(`select wrapped_key from public.vault_key_envelopes where kind = 'passphrase'`)
    expect(stored.rows[0].wrapped_key[0]).toBe(7)
  })

  it('a signed-in member WITHOUT the key proof cannot replace key material (F2)', async () => {
    await expectPgError(
      as(member(B), `update public.vault_key_envelopes set wrapped_key = $1 where kind = 'passphrase'`, [bytes(48, 9)]),
      PERMISSION_DENIED,
    )
    await expectPgError(
      as(member(B), `update public.vault_key_envelopes set wrapped_key = $1, key_proof = $2 where kind = 'passphrase'`, [
        bytes(48, 9),
        WRONG_PROOF,
      ]),
      PERMISSION_DENIED,
    )
    const stored = await db.query<{ wrapped_key: Uint8Array; revision: number }>(
      `select wrapped_key, revision from public.vault_key_envelopes where kind = 'passphrase'`,
    )
    expect(stored.rows[0]).toMatchObject({ revision: 1 })
    expect(stored.rows[0].wrapped_key[0]).toBe(7)
  })

  it('the verifier can never be changed by a client, even with the proof', async () => {
    await expectPgError(
      as(member(A), `update public.vault_key_envelopes set key_verifier = $1, key_proof = $2 where kind = 'passphrase'`, [
        WRONG_VERIFIER,
        PROOF,
      ]),
      PERMISSION_DENIED,
    )
  })

  it('the other member can re-wrap with the proof; revision increments and updated_by is stamped', async () => {
    const result = await as<{ revision: number; updated_by: string; created_by: string; key_proof: unknown }>(
      member(B),
      `update public.vault_key_envelopes set wrapped_key = $1, salt = $2, key_proof = $3 where kind = 'passphrase' and revision = 1 returning *`,
      [bytes(48, 8), bytes(16, 8), PROOF],
    )
    expect(result.rows[0]).toMatchObject({ revision: 2, updated_by: B, created_by: A, key_proof: null })
  })

  it('no key proof is ever persisted', async () => {
    const result = await db.query<{ n: number }>('select count(*)::int as n from public.vault_key_envelopes where key_proof is not null')
    expect(result.rows[0].n).toBe(0)
  })

  it('a stale revision updates nothing (optimistic concurrency)', async () => {
    const result = await as(
      member(A),
      `update public.vault_key_envelopes set wrapped_key = $1, key_proof = $2 where kind = 'passphrase' and revision = 1`,
      [bytes(48, 1), PROOF],
    )
    expect(result.affectedRows ?? 0).toBe(0)
  })

  it('members cannot move an envelope, forge audit fields, or delete it', async () => {
    await expectPgError(as(member(A), `update public.vault_key_envelopes set vault_id = $1`, [NO_SUCH_VAULT]), PERMISSION_DENIED)
    await expectPgError(as(member(A), `update public.vault_key_envelopes set revision = 99`), PERMISSION_DENIED)
    await expectPgError(as(member(A), `delete from public.vault_key_envelopes`), PERMISSION_DENIED)
  })

  it.each([
    ['memory too low', { m: 1024, t: 3, p: 1 }],
    ['memory absurdly high', { m: 99999999, t: 3, p: 1 }],
    ['too many passes', { m: 65536, t: 50, p: 1 }],
    ['parallelism', { m: 65536, t: 3, p: 4 }],
    ['extra key', { m: 65536, t: 3, p: 1, x: 1 }],
    ['string number', { m: '65536', t: 3, p: 1 }],
    ['fractional', { m: 65536.5, t: 3, p: 1 }],
  ])('rejects unsafe KDF parameters (even with a valid proof): %s', async (_label, params) => {
    await expectPgError(
      as(member(A), `update public.vault_key_envelopes set kdf_params = $1::jsonb, key_proof = $2 where kind = 'passphrase'`, [
        JSON.stringify(params),
        PROOF,
      ]),
      CHECK_VIOLATION,
    )
  })

  it('rejects malformed envelope fields', async () => {
    await expectPgError(
      as(member(A), `update public.vault_key_envelopes set iv = $1, key_proof = $2 where kind = 'passphrase'`, [bytes(11), PROOF]),
      CHECK_VIOLATION,
    )
    await expectPgError(
      as(member(A), INSERT_ENVELOPE, envelopeParams({ kind: 'recovery', kdf: 'argon2id-v1' })),
      CHECK_VIOLATION,
    )
  })

  it('accepts a well-formed recovery envelope with the proof', async () => {
    const result = await as(member(B), INSERT_ENVELOPE, envelopeParams({ kind: 'recovery', kdf: 'hkdf-sha256-v1', params: null }))
    expect(result.rows).toHaveLength(1)
  })
})

describe('media items and storage objects', () => {
  const item = crypto.randomUUID()
  const thumbItem = crypto.randomUUID()
  let objectPath: string

  it('outsiders cannot insert media into the vault', async () => {
    await expectPgError(as(member(C), INSERT_MEDIA, mediaParams(crypto.randomUUID(), vaultId)), PERMISSION_DENIED)
  })

  it('members cannot insert media into a vault they do not belong to', async () => {
    await expectPgError(as(member(A), INSERT_MEDIA, mediaParams(crypto.randomUUID(), NO_SUCH_VAULT)), PERMISSION_DENIED)
  })

  it('clients cannot choose uploader, status, or storage path', async () => {
    await expectPgError(
      as(member(A), `insert into public.media_items (id, vault_id, format_version, wrapped_dek, encrypted_meta, ciphertext_size, uploaded_by)
        values ($1, $2, 1, $3, $4, 100, $5)`, [crypto.randomUUID(), vaultId, bytes(60), bytes(284), B]),
      PERMISSION_DENIED,
    )
    await expectPgError(
      as(member(A), `insert into public.media_items (id, vault_id, format_version, wrapped_dek, encrypted_meta, ciphertext_size, status)
        values ($1, $2, 1, $3, $4, 100, 'ready')`, [crypto.randomUUID(), vaultId, bytes(60), bytes(284)]),
      PERMISSION_DENIED,
    )
    await expectPgError(
      as(member(A), `insert into public.media_items (id, vault_id, format_version, wrapped_dek, encrypted_meta, ciphertext_size, object_path)
        values ($1, $2, 1, $3, $4, 100, 'x/y')`, [crypto.randomUUID(), vaultId, bytes(60), bytes(284)]),
      GENERATED_ALWAYS,
    )
  })

  it('rejects malformed ciphertext fields', async () => {
    await expectPgError(
      as(member(A), INSERT_MEDIA, [crypto.randomUUID(), vaultId, false, bytes(59), bytes(284), 1000]),
      CHECK_VIOLATION,
    )
    await expectPgError(
      as(member(A), INSERT_MEDIA, [crypto.randomUUID(), vaultId, false, bytes(60), bytes(300), 1000]),
      CHECK_VIOLATION,
    )
  })

  it('members insert pending media with a server-derived, filename-free path', async () => {
    const result = await as<{ uploaded_by: string; status: string; object_path: string }>(member(A), INSERT_MEDIA, mediaParams(item, vaultId))
    objectPath = result.rows[0].object_path
    expect(result.rows[0]).toMatchObject({ uploaded_by: A, status: 'pending', object_path: `${vaultId}/${item}` })
  })

  it('cannot reuse an existing item id', async () => {
    await expectPgError(as(member(B), INSERT_MEDIA, mediaParams(item, vaultId)), UNIQUE_VIOLATION)
  })

  it('the other member can read it; outsiders and anon cannot', async () => {
    expect((await as(member(B), 'select id from public.media_items where id = $1', [item])).rows).toHaveLength(1)
    expect((await as(member(C), 'select id from public.media_items')).rows).toHaveLength(0)
  })

  it('cannot be marked ready before the object exists', async () => {
    await expectPgError(as(member(A), `update public.media_items set status = 'ready' where id = $1`, [item]), CHECK_VIOLATION)
  })

  it('storage upload is refused for outsiders, other members, wrong paths, and other buckets', async () => {
    const meta = JSON.stringify({ size: 1000 })
    await expectPgError(as(member(C), INSERT_OBJECT, ['private-media', objectPath, meta]), PERMISSION_DENIED)
    await expectPgError(as('anon', INSERT_OBJECT, ['private-media', objectPath, meta]), PERMISSION_DENIED)
    // B is a member but not the uploader of this pending item.
    await expectPgError(as(member(B), INSERT_OBJECT, ['private-media', objectPath, meta]), PERMISSION_DENIED)
    // A guessed/free-form path inside the vault folder.
    await expectPgError(as(member(A), INSERT_OBJECT, ['private-media', `${vaultId}/${crypto.randomUUID()}`, meta]), PERMISSION_DENIED)
    await expectPgError(as(member(A), INSERT_OBJECT, ['private-media', `${vaultId}/photo.jpg`, meta]), PERMISSION_DENIED)
    // Thumbnail path for an item declared without a thumbnail.
    await expectPgError(as(member(A), INSERT_OBJECT, ['private-media', `${objectPath}.t`, meta]), PERMISSION_DENIED)
    // Same name in a different bucket: no policy grants it.
    await expectPgError(as(member(A), INSERT_OBJECT, ['other-bucket', objectPath, meta]), PERMISSION_DENIED)
  })

  it('the uploader can upload the pending object', async () => {
    const result = await as(member(A), INSERT_OBJECT, ['private-media', objectPath, JSON.stringify({ size: 999 })])
    expect(result.rows).toHaveLength(1)
  })

  it('cannot be marked ready if the stored size differs from the declared size', async () => {
    await expectPgError(as(member(A), `update public.media_items set status = 'ready' where id = $1`, [item]), CHECK_VIOLATION)
    await db.query(`update storage.objects set metadata = '{"size": 1000}' where name = $1`, [objectPath])
  })

  it('only the uploader can finalise', async () => {
    const byB = await as(member(B), `update public.media_items set status = 'ready' where id = $1`, [item])
    expect(byB.affectedRows ?? 0).toBe(0)
    const byC = await as(member(C), `update public.media_items set status = 'ready' where id = $1`, [item])
    expect(byC.affectedRows ?? 0).toBe(0)
  })

  it('the uploader finalises pending -> ready', async () => {
    const result = await as<{ status: string; ready_at: string | null }>(
      member(A),
      `update public.media_items set status = 'ready' where id = $1 returning status, ready_at`,
      [item],
    )
    expect(result.rows[0].status).toBe('ready')
    expect(result.rows[0].ready_at).not.toBeNull()
  })

  it('ready items cannot go back to pending or change other columns', async () => {
    await expectPgError(as(member(A), `update public.media_items set status = 'pending' where id = $1`, [item]), CHECK_VIOLATION)
    await expectPgError(as(member(A), `update public.media_items set ciphertext_size = 5 where id = $1`, [item]), PERMISSION_DENIED)
    await expectPgError(as(member(A), `update public.media_items set vault_id = $1 where id = $2`, [NO_SUCH_VAULT, item]), PERMISSION_DENIED)
  })

  it('no new objects can be attached to a ready item', async () => {
    await expectPgError(as(member(A), INSERT_OBJECT, ['private-media', `${objectPath}.t`, '{}']), PERMISSION_DENIED)
  })

  it('object reads: members yes, outsiders and anon no', async () => {
    const q = `select name from storage.objects where bucket_id = 'private-media'`
    expect((await as(member(A), q)).rows).toHaveLength(1)
    expect((await as(member(B), q)).rows).toHaveLength(1)
    expect((await as(member(C), q)).rows).toHaveLength(0)
    expect((await as('anon', q)).rows).toHaveLength(0)
  })

  it('objects can never be updated, moved, or overwritten', async () => {
    const result = await as(member(A), `update storage.objects set name = $1 where name = $2`, [`${vaultId}/moved`, objectPath])
    expect(result.affectedRows ?? 0).toBe(0)
  })

  it('a broad policy added later still cannot expose private-media (restrictive guards)', async () => {
    await db.exec(`create policy "misconfigured: everyone reads everything" on storage.objects for select to public using (true);
                   create policy "misconfigured: everyone writes" on storage.objects for insert to public with check (true);`)
    try {
      expect((await as(member(C), `select name from storage.objects where bucket_id = 'private-media'`)).rows).toHaveLength(0)
      expect((await as('anon', `select name from storage.objects where bucket_id = 'private-media'`)).rows).toHaveLength(0)
      await expectPgError(as(member(C), INSERT_OBJECT, ['private-media', `${vaultId}/${crypto.randomUUID()}`, '{}']), PERMISSION_DENIED)
      // ...while other buckets follow their own policies normally.
      const other = await as(member(C), INSERT_OBJECT, ['other-bucket', 'some/file', '{}'])
      expect(other.rows).toHaveLength(1)
    } finally {
      await db.exec(`drop policy "misconfigured: everyone reads everything" on storage.objects;
                     drop policy "misconfigured: everyone writes" on storage.objects;
                     delete from storage.objects where bucket_id = 'other-bucket';`)
    }
  })

  it('thumbnails follow the same rules', async () => {
    await as(member(B), INSERT_MEDIA, mediaParams(thumbItem, vaultId, { thumb: true, size: 500 }))
    const base = `${vaultId}/${thumbItem}`
    await as(member(B), INSERT_OBJECT, ['private-media', base, JSON.stringify({ size: 500 })])
    // Not ready until the thumbnail exists too.
    await expectPgError(as(member(B), `update public.media_items set status = 'ready' where id = $1`, [thumbItem]), CHECK_VIOLATION)
    await as(member(B), INSERT_OBJECT, ['private-media', `${base}.t`, JSON.stringify({ size: 80 })])
    await as(member(B), `update public.media_items set status = 'ready' where id = $1`, [thumbItem])
    expect((await as(member(A), `select name from storage.objects where name like $1`, [`${base}%`])).rows).toHaveLength(2)
    expect((await as(member(C), `select name from storage.objects where name like $1`, [`${base}%`])).rows).toHaveLength(0)
  })

  it('outsiders cannot delete media rows or objects', async () => {
    expect((await as(member(C), 'delete from public.media_items')).affectedRows ?? 0).toBe(0)
    expect((await as(member(C), `delete from storage.objects where bucket_id = 'private-media'`)).affectedRows ?? 0).toBe(0)
    expect((await as('anon', `delete from storage.objects where bucket_id = 'private-media'`)).affectedRows ?? 0).toBe(0)
    expect((await db.query('select count(*)::int as n from public.media_items')).rows[0]).toEqual({ n: 2 })
  })

  it('deletion requires the same authorization as reading: either member can delete', async () => {
    // Objects first (needs the row to still exist), then the row — the app's delete order.
    const removed = await as(member(B), `delete from storage.objects where name = $1 returning name`, [objectPath])
    expect(removed.rows).toHaveLength(1)
    const row = await as(member(B), 'delete from public.media_items where id = $1 returning id', [item])
    expect(row.rows).toHaveLength(1)
  })

  it('orphaned objects (row gone) are not readable by anyone via the API roles', async () => {
    const orphan = `${vaultId}/${thumbItem}`
    await db.query('delete from public.media_items where id = $1', [thumbItem])
    expect((await as(member(B), `select name from storage.objects where name like $1`, [`${orphan}%`])).rows).toHaveLength(0)
  })
})

describe('folders, moving, and trash (migration 5)', () => {
  const INSERT_FOLDER = `insert into public.media_folders (id, vault_id, parent_id, encrypted_meta) values ($1, $2, $3, $4) returning *`
  const INSERT_MEDIA_IN = `insert into public.media_items (id, vault_id, format_version, has_thumbnail, wrapped_dek, encrypted_meta, ciphertext_size, folder_id)
    values ($1, $2, 1, false, $3, $4, 1000, $5) returning *`
  const top = crypto.randomUUID()
  const child = crypto.randomUUID()
  const other = crypto.randomUUID()

  async function readyItem(folder: string | null, uploader = A): Promise<string> {
    const id = crypto.randomUUID()
    await as(member(uploader), INSERT_MEDIA_IN, [id, vaultId, bytes(60), bytes(284), folder])
    await as(member(uploader), INSERT_OBJECT, ['private-media', `${vaultId}/${id}`, JSON.stringify({ size: 1000 })])
    await as(member(uploader), `update public.media_items set status = 'ready' where id = $1`, [id])
    return id
  }

  async function itemRow(id: string) {
    const result = await db.query<{ folder_id: string | null; trashed_at: Date | null; status: string; object_path: string }>(
      'select folder_id, trashed_at, status, object_path from public.media_items where id = $1',
      [id],
    )
    return result.rows[0]
  }

  it('anon, outsiders, and id-less sessions can neither read nor create folders', async () => {
    await expectPgError(as('anon', INSERT_FOLDER, [crypto.randomUUID(), vaultId, null, bytes(284)]), PERMISSION_DENIED)
    await expectPgError(as(member(C), INSERT_FOLDER, [crypto.randomUUID(), vaultId, null, bytes(284)]), PERMISSION_DENIED)
    await expectPgError(as({ sub: null }, INSERT_FOLDER, [crypto.randomUUID(), vaultId, null, bytes(284)]), PERMISSION_DENIED)
  })

  it('members create folders with server-stamped fields; there is no plaintext name column', async () => {
    const result = await as<Record<string, unknown>>(member(A), INSERT_FOLDER, [top, vaultId, null, bytes(284)])
    expect(result.rows[0]).toMatchObject({ id: top, created_by: A, updated_by: A, depth: 0, revision: 1, parent_id: null })
    const columns = await db.query<{ column_name: string }>(
      `select column_name from information_schema.columns where table_schema = 'public' and table_name = 'media_folders'`,
    )
    expect(columns.rows.map((r) => r.column_name).sort()).toEqual(
      ['created_at', 'created_by', 'depth', 'encrypted_meta', 'id', 'parent_id', 'revision', 'updated_at', 'updated_by', 'vault_id'].sort(),
    )
  })

  it('clients cannot choose creator, depth, or revision', async () => {
    await expectPgError(
      as(member(A), `insert into public.media_folders (id, vault_id, encrypted_meta, created_by) values ($1, $2, $3, $4)`, [
        crypto.randomUUID(), vaultId, bytes(284), B,
      ]),
      PERMISSION_DENIED,
    )
    await expectPgError(
      as(member(A), `insert into public.media_folders (id, vault_id, encrypted_meta, depth) values ($1, $2, $3, 0)`, [
        crypto.randomUUID(), vaultId, bytes(284),
      ]),
      PERMISSION_DENIED,
    )
  })

  it('rejects malformed encrypted names and unknown parents or vaults', async () => {
    await expectPgError(as(member(A), INSERT_FOLDER, [crypto.randomUUID(), vaultId, null, bytes(300)]), CHECK_VIOLATION)
    await expectPgError(as(member(A), INSERT_FOLDER, [crypto.randomUUID(), vaultId, null, bytes(4380)]), CHECK_VIOLATION)
    await expectPgError(as(member(A), INSERT_FOLDER, [crypto.randomUUID(), vaultId, crypto.randomUUID(), bytes(284)]), FOREIGN_KEY)
    await expectPgError(as(member(A), INSERT_FOLDER, [crypto.randomUUID(), NO_SUCH_VAULT, null, bytes(284)]), PERMISSION_DENIED)
  })

  it('subfolders get a server-computed depth, limited to 8 levels', async () => {
    const result = await as<{ depth: number }>(member(B), INSERT_FOLDER, [child, vaultId, top, bytes(284)])
    expect(result.rows[0].depth).toBe(1)
    let parent = child
    for (let level = 2; level <= 7; level++) {
      const id = crypto.randomUUID()
      const r = await as<{ depth: number }>(member(A), INSERT_FOLDER, [id, vaultId, parent, bytes(284)])
      expect(r.rows[0].depth).toBe(level)
      parent = id
    }
    await expectPgError(as(member(A), INSERT_FOLDER, [crypto.randomUUID(), vaultId, parent, bytes(284)]), CHECK_VIOLATION)
  })

  it('both members see folders; outsiders see none', async () => {
    expect((await as(member(B), 'select id from public.media_folders where id = $1', [top])).rows).toHaveLength(1)
    expect((await as(member(C), 'select id from public.media_folders')).rows).toHaveLength(0)
  })

  it('rename changes only the encrypted name; revision and updated_by are stamped', async () => {
    const result = await as<{ revision: number; updated_by: string; created_by: string }>(
      member(B),
      'update public.media_folders set encrypted_meta = $1 where id = $2 returning revision, updated_by, created_by',
      [bytes(540, 9), top],
    )
    expect(result.rows[0]).toEqual({ revision: 2, updated_by: B, created_by: A })
  })

  it('folder structure is immutable: no re-parenting, id, or vault changes', async () => {
    await expectPgError(as(member(A), 'update public.media_folders set parent_id = $1 where id = $2', [child, top]), PERMISSION_DENIED)
    await expectPgError(as(member(A), 'update public.media_folders set id = $1 where id = $2', [crypto.randomUUID(), top]), PERMISSION_DENIED)
    await expectPgError(as(member(A), 'update public.media_folders set vault_id = $1 where id = $2', [NO_SUCH_VAULT, top]), PERMISSION_DENIED)
  })

  it('outsiders cannot rename or delete folders', async () => {
    expect((await as(member(C), 'update public.media_folders set encrypted_meta = $1', [bytes(284)])).affectedRows ?? 0).toBe(0)
    expect((await as(member(C), 'delete from public.media_folders')).affectedRows ?? 0).toBe(0)
    await expectPgError(as('anon', 'delete from public.media_folders'), PERMISSION_DENIED)
  })

  it('uploads can go straight into a folder; the storage path never contains it', async () => {
    const id = await readyItem(top)
    expect(await itemRow(id)).toMatchObject({ folder_id: top, status: 'ready', trashed_at: null, object_path: `${vaultId}/${id}` })
    await expectPgError(
      as(member(A), INSERT_MEDIA_IN, [crypto.randomUUID(), vaultId, bytes(60), bytes(284), crypto.randomUUID()]),
      FOREIGN_KEY,
    )
  })

  it('clients cannot insert an item that is already in the trash', async () => {
    await expectPgError(
      as(member(A), `insert into public.media_items (id, vault_id, format_version, wrapped_dek, encrypted_meta, ciphertext_size, trashed_at)
        values ($1, $2, 1, $3, $4, 1000, now())`, [crypto.randomUUID(), vaultId, bytes(60), bytes(284)]),
      PERMISSION_DENIED,
    )
  })

  it('pending uploads cannot be moved or trashed, even by the uploader', async () => {
    const id = crypto.randomUUID()
    await as(member(A), INSERT_MEDIA_IN, [id, vaultId, bytes(60), bytes(284), null])
    await expectPgError(as(member(A), 'update public.media_items set folder_id = $1 where id = $2', [top, id]), PERMISSION_DENIED)
    await expectPgError(as(member(A), 'update public.media_items set trashed_at = now() where id = $1', [id]), PERMISSION_DENIED)
    // The other member cannot touch someone else's pending item at all.
    expect((await as(member(B), 'update public.media_items set folder_id = $1 where id = $2', [top, id])).affectedRows ?? 0).toBe(0)
    await db.query('delete from public.media_items where id = $1', [id])
  })

  it('either member can move a ready item between folders and back to the root', async () => {
    const id = await readyItem(null, A)
    await as(member(B), 'update public.media_items set folder_id = $1 where id = $2', [child, id])
    expect((await itemRow(id)).folder_id).toBe(child)
    await as(member(A), 'update public.media_items set folder_id = null where id = $1', [id])
    expect((await itemRow(id)).folder_id).toBeNull()
    await expectPgError(as(member(B), 'update public.media_items set folder_id = $1 where id = $2', [crypto.randomUUID(), id]), FOREIGN_KEY)
  })

  it('trash time is stamped by the server; restore clears it; status cannot change', async () => {
    const id = await readyItem(null, A)
    await as(member(B), `update public.media_items set trashed_at = '2000-01-01' where id = $1`, [id])
    const trashed = await itemRow(id)
    expect(trashed.trashed_at).not.toBeNull()
    expect(new Date(trashed.trashed_at as Date).getUTCFullYear()).toBeGreaterThan(2000)
    await as(member(A), `update public.media_items set trashed_at = '2001-01-01' where id = $1`, [id])
    expect((await itemRow(id)).trashed_at).toEqual(trashed.trashed_at)
    await as(member(A), 'update public.media_items set trashed_at = null where id = $1', [id])
    expect((await itemRow(id)).trashed_at).toBeNull()
    await expectPgError(as(member(B), `update public.media_items set status = 'pending' where id = $1`, [id]), CHECK_VIOLATION)
  })

  it('organising never unlocks other columns of a ready item', async () => {
    const id = await readyItem(null, A)
    await expectPgError(as(member(B), 'update public.media_items set encrypted_meta = $1 where id = $2', [bytes(284, 1), id]), PERMISSION_DENIED)
    await expectPgError(as(member(B), 'update public.media_items set has_thumbnail = true where id = $1', [id]), PERMISSION_DENIED)
    await expectPgError(as(member(B), 'update public.media_items set uploaded_by = $1 where id = $2', [B, id]), PERMISSION_DENIED)
    await expectPgError(as(member(B), 'update public.media_items set ready_at = now() where id = $1', [id]), PERMISSION_DENIED)
  })

  it('outsiders and anon cannot move, trash, or restore items', async () => {
    const id = await readyItem(null, A)
    expect((await as(member(C), 'update public.media_items set trashed_at = now() where id = $1', [id])).affectedRows ?? 0).toBe(0)
    expect((await as(member(C), 'update public.media_items set folder_id = null where id = $1', [id])).affectedRows ?? 0).toBe(0)
    await expectPgError(as('anon', 'update public.media_items set trashed_at = now()'), PERMISSION_DENIED)
    expect((await itemRow(id)).trashed_at).toBeNull()
  })

  it('a folder with active items or subfolders cannot be deleted', async () => {
    // `top` holds an active item (uploaded above) and the subfolder `child`.
    await expectPgError(as(member(A), 'delete from public.media_folders where id = $1', [top]), CHECK_VIOLATION)
    await as(member(A), INSERT_FOLDER, [other, vaultId, null, bytes(284)])
    await as(member(A), INSERT_FOLDER, [crypto.randomUUID(), vaultId, other, bytes(284)])
    await expectPgError(as(member(B), 'delete from public.media_folders where id = $1', [other]), FOREIGN_KEY)
  })

  it('a folder with a pending upload cannot be deleted', async () => {
    const folder = crypto.randomUUID()
    await as(member(A), INSERT_FOLDER, [folder, vaultId, null, bytes(284)])
    const id = crypto.randomUUID()
    await as(member(A), INSERT_MEDIA_IN, [id, vaultId, bytes(60), bytes(284), folder])
    await expectPgError(as(member(B), 'delete from public.media_folders where id = $1', [folder]), CHECK_VIOLATION)
    await db.query('delete from public.media_items where id = $1', [id])
    expect((await as(member(B), 'delete from public.media_folders where id = $1 returning id', [folder])).rows).toHaveLength(1)
  })

  it('deleting a folder whose items are all in the trash keeps them in the trash, at the root', async () => {
    const folder = crypto.randomUUID()
    await as(member(A), INSERT_FOLDER, [folder, vaultId, null, bytes(284)])
    const id = await readyItem(folder, A)
    await as(member(B), 'update public.media_items set trashed_at = now() where id = $1', [id])
    expect((await as(member(B), 'delete from public.media_folders where id = $1 returning id', [folder])).rows).toHaveLength(1)
    const row = await itemRow(id)
    expect(row.folder_id).toBeNull()
    expect(row.trashed_at).not.toBeNull()
    expect(row.status).toBe('ready')
  })

  it('deleting one folder never touches items in another folder', async () => {
    const keep = crypto.randomUUID()
    const drop = crypto.randomUUID()
    await as(member(A), INSERT_FOLDER, [keep, vaultId, null, bytes(284)])
    await as(member(A), INSERT_FOLDER, [drop, vaultId, null, bytes(284)])
    const kept = await readyItem(keep, A)
    await as(member(A), 'delete from public.media_folders where id = $1', [drop])
    expect(await itemRow(kept)).toMatchObject({ folder_id: keep, trashed_at: null })
  })

  it('storage access is unchanged: objects of foldered items are readable by members only', async () => {
    const id = await readyItem(top, A)
    const q = `select name from storage.objects where name = $1`
    expect((await as(member(B), q, [`${vaultId}/${id}`])).rows).toHaveLength(1)
    expect((await as(member(C), q, [`${vaultId}/${id}`])).rows).toHaveLength(0)
    expect((await as('anon', q, [`${vaultId}/${id}`])).rows).toHaveLength(0)
  })
})

describe('SQL-editor verification script', () => {
  it('passes against the migrated schema and rolls everything back', async () => {
    const before = await db.query('select (select count(*) from public.media_items) + (select count(*) from storage.objects) as n')
    await expect(db.exec(verificationSql)).rejects.toThrow(/HB SPACE RLS VERIFICATION PASSED — script v5 /)
    const after = await db.query('select (select count(*) from public.media_items) + (select count(*) from storage.objects) as n')
    expect(after.rows).toEqual(before.rows)
  })

  it('passes on a vault that already has real key envelopes, and never changes them (the live project state after setup)', async () => {
    const live = new PGlite()
    try {
      await live.exec(stubSql)
      for (const path of Object.keys(migrationFiles).sort()) await live.exec(migrationFiles[path])
      await live.query(`insert into auth.users (id, email) values ($1, 'a@test'), ($2, 'b@test')`, [A, B])
      const vault = (await live.query<{ id: string }>('select private.provision_vault($1, $2) as id', [A, B])).rows[0].id
      // Created the way the app does it: as a member, with the key-possession proof.
      await live.transaction(async (tx) => {
        await tx.query(`select set_config('role', 'authenticated', true), set_config('request.jwt.claims', $1, true)`, [
          JSON.stringify({ sub: A, role: 'authenticated' }),
        ])
        const insert = `insert into public.vault_key_envelopes (vault_id, kind, format_version, kdf, kdf_params, salt, iv, wrapped_key, key_verifier, key_proof)
          values ($1, $2, 1, $3, $4::jsonb, $5, $6, $7, $8, $9)`
        await tx.query(insert, [vault, 'passphrase', 'argon2id-v1', JSON.stringify({ m: 65536, t: 3, p: 1 }), bytes(16, 1), bytes(12, 2), bytes(48, 3), VERIFIER, PROOF])
        await tx.query(insert, [vault, 'recovery', 'hkdf-sha256-v1', null, bytes(16, 4), bytes(12, 5), bytes(48, 6), VERIFIER, PROOF])
      })
      const snapshot = `select kind, encode(salt, 'hex') || encode(iv, 'hex') || encode(wrapped_key, 'hex') || encode(key_verifier, 'hex') as k,
        revision, updated_by, updated_at from public.vault_key_envelopes order by kind`
      const before = (await live.query(snapshot)).rows
      expect(before).toHaveLength(2)

      await expect(live.exec(verificationSql)).rejects.toThrow(/HB SPACE RLS VERIFICATION PASSED — script v5 /)
      expect((await live.query(snapshot)).rows).toEqual(before)
    } finally {
      await live.close()
    }
  }, 60_000)

  it('also passes on a freshly provisioned vault with no key envelopes yet (the live project state before first setup)', async () => {
    const fresh = new PGlite()
    try {
      await fresh.exec(stubSql)
      for (const path of Object.keys(migrationFiles).sort()) await fresh.exec(migrationFiles[path])
      await fresh.query(`insert into auth.users (id, email) values ($1, 'a@test'), ($2, 'b@test')`, [A, B])
      await fresh.query('select private.provision_vault($1, $2)', [A, B])
      await expect(fresh.exec(verificationSql)).rejects.toThrow(/HB SPACE RLS VERIFICATION PASSED — script v5 /)
      expect((await fresh.query('select count(*)::int as n from public.vault_key_envelopes')).rows[0]).toEqual({ n: 0 })
    } finally {
      await fresh.close()
    }
  }, 60_000)
})
